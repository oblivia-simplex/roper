#![allow(bad_style)]

extern crate rand;
extern crate unicorn;
extern crate time;
extern crate chrono;
extern crate rustc_serialize;
extern crate regex;
extern crate bio;


use std::cmp::Ordering::*;
use self::regex::*;
use self::chrono::prelude::*;
use self::chrono::offset::LocalResult;
use std::collections::{BTreeMap};
use std::hash::*;
use std::iter::repeat;
use self::rustc_serialize::json::{self, Json, ToJson};
use rand::*;
use unicorn::*;
use capstone::CsMode;
use std::fmt::{Display,format,Formatter,Result};
use std::collections::HashMap;
use std::cmp::*;
use std::sync::RwLock;
use std::ops::{Index,IndexMut};
use std::fs::{DirBuilder,File,OpenOptions};
use std::io::prelude::*;
use std::slice::{Iter,IterMut};
use std::env;

use self::bio::data_structures::interval_tree::{IntervalTree};
use self::bio::utils::Interval;

use roper::util::*;
use roper::evolve::*;
use roper::hatchery::*;
use roper::ontostructs::*;
use roper::interactive::*;
use roper::statistics::*;
pub const MAX_VISC : i32 = 100;
pub const MIN_VISC : i32 = 0;
pub const VISC_DROP_THRESH : i32 = 10;
pub const RIPENING_FACTOR : i32 = 4;
pub const MAX_FIT : f32 = 1.0;
const DEFAULT_MODE : MachineMode = MachineMode::ARM;

//pub static mut DISAS_PATH : str = "./DISASSEMBLY_FILE_DEFAULT_NAME.TXT";
pub type FIT_INT = u32;

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct Fingerprint (Vec<bool>);

impl Display for Fingerprint {
        fn fmt (&self, f: &mut Formatter) -> Result {
            let mut s = String::new();
            for b in self.0.iter() {
                s.push_str(if *b {"1"} else {"0"})
            }
            write!(f, "{}", s)
        }
}
impl Fingerprint {
        pub fn push (&mut self, x: bool) {
            self.0.push(x);
        }
        pub fn pop (&mut self) -> Option<bool> {
            self.0.pop()
        }
        pub fn new () -> Self {
            Fingerprint ( Vec::new() )
        }
        pub fn len (&self) -> usize {
            self.0.len()
        }
        pub fn iter (&self) -> Iter<bool> {
            self.0.iter()
        }
        pub fn iter_mut (&mut self) -> IterMut<bool> {
            self.0.iter_mut()
        }
        pub fn extend (&mut self, other: &Fingerprint) {
            for b in other.iter() {
                self.push(b.clone())
            }
        }
        pub fn distance (&self, other: &Fingerprint) -> usize {
            self.0.iter()
                        .zip(&other.0)
                        .map(|(x,y)| x ^ y)
                        .filter(|&b| b)
                        .count()
        }
}
impl Index<usize> for Fingerprint {
        type Output = bool;
        fn index(&self, index: usize) -> &bool {
            &self.0[index]
        }
}

#[derive(Clone,Debug)]
pub struct Clump {
        pub sp_delta:    i32, // how much does the sp change by?
        pub ret_offset:  usize, // how far down is the next address?
        pub exchange:    bool, // BX instruction? can we change mode?
        pub mode:        MachineMode,
        pub ret_addr:    u32,
        pub words:       Vec<u32>,
        pub viscosity:   i32,
        pub input_slots: Vec<(usize,usize)>, // (offset, input#)
        pub link_age:    i32,
        pub link_fit:    Option<f32>, // 
        pub enabled:     bool, // disabling a clump makes it into an explicit intron
}

// UPDATE THIS to_json with new fields TODO
impl ToJson for Clump {
        fn to_json(&self) -> Json {
            let mut b = BTreeMap::new();
            b.insert("sp_delta".to_string(), self.sp_delta.to_json());
            b.insert("ret_offset".to_string(), self.ret_offset.to_json());
            b.insert("exchange".to_string(), self.exchange.to_json()); 
            b.insert("mode".to_string(),format!("{:?}",self.mode).to_json());
            b.insert("ret_addr".to_string(),self.ret_addr.to_json());
            b.insert("words".to_string(), self.words.to_json());
            b.insert("viscosity".to_string(), self.viscosity.to_json());
            b.insert("link_fit".to_string(),
                format!("{:?}",self.link_fit).to_json());
            b.insert("enabled".to_string(), self.enabled.to_json());
            Json::Object(b)
        }
}
/* TODO
impl FromJson for Clump {
        fn from_json (json: Json) -> Self {
            
        }
}
*/
impl Display for Clump {
        fn fmt (&self, f: &mut Formatter) -> Result {
            let mut s = String::new();
            let vp : f32 = self.viscosity as f32 / MAX_VISC as f32;
            s.push_str("CLUMP:\n");
            s.push_str(&format!("enabled:    {:?}\n", self.enabled));
            s.push_str(&format!("mode:       {:?}\n", self.mode));
            s.push_str(&format!("sp_delta:   0x{:x}\n", self.sp_delta));
            s.push_str(&format!("ret_offset: 0x{:x}\n", self.ret_offset));
            s.push_str(&format!("viscosity:  %{}\n", vp * 100.0));
            s.push_str(&format!("link_age:   {}\n", self.link_age));
            s.push_str(&format!("link_fit:   {:?}\n", self.link_fit));
            s.push_str(&format!("ret_addr:   {:08x}\n", self.ret_addr));
            s.push_str(         "words:     ");
            for w in &self.words {
                s.push_str(&format!(" {:08x}", w));
            }
            write!(f, "{}\n", s)
        }
}

impl Default for Clump {
        fn default () -> Clump {
            Clump {
                sp_delta:   1,
                ret_offset: 1,
                ret_addr:   0,
                exchange:   false,
                mode:       MachineMode::THUMB,
                words:      Vec::new(),
                input_slots: Vec::new(),
                viscosity:  MAX_VISC, //(MAX_VISC - MIN_VISC) / 2 + MIN_VISC,
                link_age:   0,
                link_fit:   None, // (MAX_FIT/2),
                enabled:    true,
            }
        }
}
impl Clump {
        pub fn new () -> Clump {
            Clump {..Default::default()}
        }
        pub fn size (&self) -> usize {
            self.words.len()
        }
        pub fn gadlen (&self) -> usize {
            (self.ret_addr - self.words[0]) as usize
        }
        pub fn visc (&self) -> i32 {
            self.viscosity
        }
        pub fn addr (&self) -> u32 {
            self.words[0]
        }
        pub fn entry (&self) -> u32 { 
            self.addr()
        }
        pub fn exit (&self) -> u32 {
            self.ret_addr
        }
        pub fn sicken (&mut self) {
            self.link_fit = Some(MAX_FIT);
        }
}
pub trait Stack <T> {
        fn push (&mut self, t: T);
        fn pop (&mut self) -> Option<T>;
}
impl Stack <u32> for Clump {
        fn push (&mut self, t: u32) {
            self.words.push(t);
        }
        fn pop (&mut self) -> Option<u32> {
            self.words.pop()
        }
}
/*
impl Indexable<u32> for Clump {
fn index_of (&self, t: u32) -> usize {
        self.index_opt(t).unwrap()
}
fn index_opt (&self, t: u32) -> Option<usize> {
        self.words.iter().position(|x| x == &t)
}
}
*/
impl Index <usize> for Clump {
        type Output = u32;
        fn index (&self, index: usize) -> &u32 {
            &(self.words[index])
        }
}
impl IndexMut <usize> for Clump {
        fn index_mut (&mut self, index: usize) -> &mut u32 {
            &mut (self.words[index])
        }
}

pub fn saturated (gad: &Clump) -> bool {
        gad.words.len() as i32 == gad.sp_delta
}

/* why isn't this a trait? */
fn concatenate (clumps: &Vec<Clump>) -> Vec<u32> {
        let s : usize = clumps.iter()
                                                    .map(|ref x| x.words.len())
                                                    .sum();
        let mut c = vec![0; s];
        let mut rto = 0 as usize;
        let mut exchange = false;
        let mut i = 0;
        for ref gad in clumps {
            /* for debugging */
            /*****************/
            if !saturated(gad) {
                panic!("Attempting to concatenate unsaturated clumps");
            }
            assert!(gad.sp_delta >= 0);
            /* If clump is not enabled, don't pack it into the payload */
            if !gad.enabled && i > 0 { /* at least one clump should be enabled */
                continue;
            }
            let t : usize = rto + gad.sp_delta as usize;
            &c[rto..t].clone_from_slice(&(gad.words));
            if exchange && (gad.mode == MachineMode::THUMB) {
                /* If we BX, the LSB of the addr decides machine mode */
                c[rto] |= 1;
            }
            rto += gad.ret_offset as usize;
            exchange = gad.exchange;
            i += 1;
        }
        c[..rto].to_vec()
}

#[derive(Clone,Debug)]
pub struct Chain {
        pub clumps: Vec<Clump>, //Arr1K<Clump>, //[Clump; MAX_CHAIN_LENGTH], 
        //pub packed: Vec<u8>,
        pub fitness: Option<f32>,
        pub ab_fitness: Option<f32>, // unshared
        pub p_fitness: Option<f32>,
        pub generation: u32,
        pub input_slots: Vec<(usize,usize)>,
        pub verbose_tag: bool,
        pub crashes: Option<bool>,
        pub stray_rate: f32,
        pub season: usize,
        pub visited_map: HashMap<Problem, Vec<u32>>,
        pub runtime: Option<f32>,
        i: usize,
        // space-consuming, but it'll give us some useful data on
        // the destructiveness of the shufflefuck operator
}

impl ToJson for Chain {
        fn to_json (&self) -> Json {
            let mut b = BTreeMap::new();
            b.insert("clumps".to_string(), self.clumps.to_json());
            b.insert("fitness".to_string(), 
                              format!("{:?}", self.fitness).to_json());
            b.insert("generation".to_string(), self.generation.to_json());
            b.insert("crashes".to_string(), self.crashes.to_json());
            Json::Object(b)
        }
}

impl Display for Chain {
        fn fmt (&self, f: &mut Formatter) -> Result {
            let mut s = String::new();
            s.push_str("==================================================\n");
            s.push_str(&format!("Relative Fitness: {:?} [Season {}]\n", 
                                                    self.fitness, self.season));
            s.push_str(&format!("Absolute Fitness: {:?}\n", self.ab_fitness));
            s.push_str(&format!("Generation: {}\n", self.generation));
            s.push_str(&format!("Ancestral Fitness: {:?}\n",
                                                    self.p_fitness));
            s.push_str(&format!("Link ages: {:?}\n", 
                                &self.clumps
                                     .iter()
                                     .map(|ref c| c.link_age)
                                     .collect::<Vec<i32>>()));
            s.push_str(&format!("Link fitnesses: {:?}\n", 
                       &self.clumps
                            .iter()
                            .map(|ref c| {
                                    match c.link_fit {
                                        Some(x) => x,
                                        None    => 1.0,
                                    }
                                })
                            .collect::<Vec<f32>>()));
            s.push_str(&format!("Viscosities: {:?}\n", 
                       &self.clumps
                            .iter()
                            .map(|ref c| c.visc())
                            .collect::<Vec<i32>>()));
            s.push_str(&format!("Input slots on stack: {:?}\n", 
                                                    &self.input_slots));
            s.push_str("Clumps:\n");
            for clump in &self.clumps {
                if !clump.enabled {
                    s.push_str("[DISABLED] ");
                }
                s.push_str(&format!("<{:08x}> ", clump.ret_addr));
                let mut i = 0;
                for word in &clump.words {
                    match clump.input_slots
                                          .iter()
                                          .position(|&(off, _)| off == i) {
                        None => s.push_str(&format!("{:08x} ",word)),
                        Some(_) => s.push_str("*INPUT?* "),
                    };
                    i += 1;
                }
                s.push_str("\n");
            }
            s.push_str("Packed:\n");
            let mut j = 0;
            for b in &self.pack() {
                s.push_str(&format!("{:02x} ",b));
                j += 1;
                if j % 4 == 0 { s.push_str(" "); };
                if j % 16 == 0 { s.push_str("\n"); }
            }
            s.push_str("\n==================================================\n");
            write!(f, "{}", s)
        } 
}

impl Default for Chain {
        fn default () -> Chain {
            Chain {
                clumps: Vec::new(),
                // packed: Vec::new(),
                input_slots: Vec::new(),
                fitness: None,
                ab_fitness: None,
                p_fitness: None,
                generation: 0,
                season: 0,
                stray_rate: 0.0,
                verbose_tag: false,
                crashes: None,
                runtime: None,
                visited_map: HashMap::new(),
                i: 0,
            }
        } 
}

impl PartialEq for Chain {
        fn eq (&self, other: &Chain) -> bool {
            self.fitness == other.fitness
        }
}

impl Eq for Chain {}

impl PartialEq for Clump {
        fn eq (&self, other: &Clump) -> bool {
            self.words == other.words
        }
}

impl Indexable<Clump> for Chain {
        fn index_of (&self, t: Clump) -> usize {
            self.index_opt(t).unwrap()
        }
        fn index_opt (&self, t: Clump) -> Option<usize> {
            self.clumps.iter().position(|x| x == &t)
        }
}

impl Index <usize> for Chain {
        type Output = Clump;
        fn index (&self, index: usize) -> &Clump {
            &(self.clumps[index])
        }
}

impl IndexMut <usize> for Chain {
        fn index_mut (&mut self, index: usize) -> &mut Clump {
            &mut (self.clumps[index])
        }
}

impl Chain {
        /* NB: a Chain::new(c) takes ownership of its clump vec */
        pub fn new (clumps: Vec<Clump>) -> Chain {
            //let conc = concatenate(&clumps);
            //let pack = pack_word32le_vec(&conc);
            let mut chain = Chain {
                clumps: clumps,
                //packed: pack,
                ..Default::default()
            };
            chain.collate_input_slots();
            chain
        }

        pub fn pack (&self) -> Vec<u8> {
            pack_word32le_vec(&concatenate(&self.clumps))
        }

        pub fn collate_input_slots (&mut self) {
            self.input_slots = Vec::new();
            let mut offset = 0;
            for clump in self.clumps.iter_mut() {
                for &(off, inp) in clump.input_slots.iter() {
                    self.input_slots.push((off + offset, inp));
                }
                offset += clump.ret_offset;
            }
        }

        pub fn size (&self) -> usize {
            self.clumps.len()
        }

        pub fn effective_size (&self) -> usize {
            self.clumps
                .iter()
                .filter(|ref c| c.enabled)
                .count()
        }

        pub fn set_fitness (&mut self, n: f32) {
            self.fitness = Some(n);
        }

        pub fn excise (&mut self, idx: usize) {
            self.clumps.remove(idx);
            self.pack();
        }

        pub fn enabled_ratio (&self) -> f32 {
            self.clumps.iter().filter(|ref c| c.enabled).count() as f32 /
                (self.size() as f32)
        }

        pub fn avg_addr_coverage (&self) -> f32 {
            let mut c = 0.0;
            let mut sum = 0;
            for p in self.visited_map.keys() {
                c += 1.0;
                sum += self.visited_map.get(p).unwrap().iter().count();
            }
            (sum as f32) / c
        }

        pub fn interval_tree (&self) -> IntervalTree<u32,usize> {
            let mut tree = IntervalTree::new();
            let mut idx = 0;
            for clump in &self.clumps {
                idx += 1;
                tree.insert(clump.entry()..clump.exit(), idx);
            }
            tree
        }

        pub fn strayed_but_did_not_crash (&self) -> bool {
            // NB: memoize the stray_addr_rate
            self.crashes == None && self.stray_addr_rate() > 0.0
        }

        pub fn stray_addr_rate (&self) -> f32 {
            // later do this nicely, with a binary search tree or smth
            let mut intervals = &mut self.clumps
                                     .iter()
                                     .map(|c| (c.entry(), c.exit()))
                                     .collect::<Vec<(u32,u32)>>();
            intervals.sort();
            let mut strays = 0;
            let mut hits   = 0;
            let mut count  = 0;
            
            for p in self.visited_map.keys() {
                let v = self.visited_map.get(p).unwrap();
                //println!("crash? {:?}",self.crashes);
                //println!("v> {:?}",v);
                //println!("intervals: {:?}",intervals); 
                for &addr in v.iter() {
                    let res = intervals.binary_search_by(
                        (|c| if c.0 <= addr && addr <= c.1 {
                          //  println!("Equal: c.0: {}, c.1: {}, addr: {}",c.0,c.1,addr);
                            Equal
                        } else if c.1 < addr {
                        //    println!("Less: c.0: {}, c.1: {}, addr: {}",c.0,c.1,addr);
                            Less
                        } else { 
                      //      println!("Greater: c.0: {}, c.1: {}, addr: {}",c.0,c.1,addr);
                            Greater
                        }));
                    //println!("---> res: {:?}",res);
                    count += 1;
                    match res {
                        Ok(_)  => hits += 1,
                        Err(_) => {
                            //println!("* {} not found in {:?}", addr, intervals);
                            if self.crashes == None {
                                println!("[!] Strayed but did not crash:\nv> {:?}\nintervals: {:?}", v, intervals);
                            }
                            strays += 1;
                        },
                    };
                }
            }
    //        println!(">> stray: {}, hit: {}, count: {}\n", strays, hits, count);

            strays as f32 / count as f32
        }

        pub fn stray_to_edi_rate (&self) -> f32 {
            let edirat = 1.0 - self.enabled_ratio();
            if edirat == 0.0 { 0.0 } else { self.stray_addr_rate() / edirat }
        }

        pub fn dump_visited_map (&self, path: &str) {
            println!("DUMPING VISIT MAP TO {}",path);
            let mut file = OpenOptions::new()
                                       .truncate(true)
                                       .write(true)
                                       .create(true)
                                       .open(path)
                                       .unwrap();
            for p in self.visited_map.keys() {
                let pname = p.identifier();
                file.write(&format!("--- BEGIN VISIT MAP FOR PROBLEM {} ---\n",
                                    pname).as_bytes());
                for addr in self.visited_map.get(p).unwrap() {
                    file.write(&format!("{:0x}\n", addr).as_bytes());
                }
                file.write(&format!("--- END VISIT MAP FOR PROBLEM {} ---\n",
                                    pname).as_bytes());
            }
            file.flush().unwrap();
        }
            
}

impl PartialOrd for Chain {
        fn partial_cmp (&self, other: &Chain) -> Option<Ordering> {
            self.fitness.partial_cmp(&other.fitness)
        }
}

impl Ord for Chain {
        fn cmp (&self, other: &Chain) -> Ordering {
            self.partial_cmp(other).unwrap_or(Ordering::Equal)
        }
}

const POPSIZE : usize = 400;

#[derive(Clone)]
pub struct Population  {
        pub deme: Vec<Chain>,
        pub best: Option<Chain>,
        pub iteration: usize,
        pub season: usize,
        pub params: Params,
        pub primordial_ooze: Vec<Clump>,
}

unsafe impl Send for Population {}

impl Population {
        pub fn new (params: &Params, engine: &mut Engine) -> Population {
            let mut clumps = reap_gadgets(&params.code, 
                                                                        params.code_addr, 
                                                                        MachineMode::ARM);
            println!("[*] Harvested {} ARM gadgets from {}",
                              clumps.len(), params.binary_path);
            let thumb_clumps = &reap_gadgets(&params.code,
                                                                              params.code_addr,
                                                                              MachineMode::THUMB);
            println!("[*] Harvested {} THUMB gadgets from {}",
                              thumb_clumps.len(), params.binary_path);
            clumps.extend_from_slice(&thumb_clumps);
        
            let mut rng = rand::thread_rng();

            let mut clump_buckets : Vec<Vec<Clump>> = 
                vec![Vec::new(), Vec::new(), Vec::new(), Vec::new()];
            for clump in clumps.iter() {
                clump_buckets[test_clump(engine.unwrap_mut(), &clump)]
                    .push(clump.clone())
            }
            println!("[*] Size of buckets:\n[+] NOCHANGE_CRASH_BUCKET: {}\n[+] NOCHANGE_NOCRASH_BUCKET: {}\n[+] CHANGE_CRASH_BUCKET: {}\n[+] CHANGE_NOCRASH_BUCKET: {}\n",
                              clump_buckets[NOCHANGE_CRASH_BUCKET].len(),
                              clump_buckets[NOCHANGE_NOCRASH_BUCKET].len(),
                              clump_buckets[CHANGE_CRASH_BUCKET].len(),
                              clump_buckets[CHANGE_NOCRASH_BUCKET].len());

            let mut data_pool  = Mangler::new(&params.constants);
            let mut deme : Vec<Chain> = Vec::new();
            for _ in 0..params.population_size{
/*
                deme.push(random_chain_from_buckets(
                                                              &clump_buckets,
                                                              params.min_start_len,
                                                              params.max_start_len,
                                                              &mut data_pool,
                                                              &mut rand::thread_rng()));
                */
                deme.push(random_chain(&clumps,
                                                              &params,
                                                              &mut data_pool,
                                                              &mut rand::thread_rng()));
                                                              

            }
            Population {
                deme: deme,
                best: None,
                iteration: 0,
                season: 0,
                params: (*params).clone(),
                primordial_ooze: clumps,
            }
        }

        pub fn random_spawn (&self) -> Chain {
            let mut mangler = Mangler::new(&self.params.constants);
            random_chain(&self.primordial_ooze,
                                      &self.params,
                                      &mut mangler,
                                      &mut thread_rng())
        }

        pub fn avg_gen (&self) -> f32 {
          self.deme
              .iter()
              .map(|ref c| c.generation.clone())
              .sum::<u32>() as f32 / 
                   self.params.population_size as f32
        }

        pub fn avg_len (&self) -> f32 {
            self.deme
                .iter()
                .map(|ref c| c.size() as f32)
                .sum::<f32>() / 
                        self.params.population_size as f32
        }

        pub fn stray_nocrash_rate (&self) -> f32 {
            let total = self.deme
                .iter()
                .filter(|ref c| c.fitness != None)
                .count() as f32;
            self.deme
                .iter()
                .filter(|ref c| c.fitness != None)
                .filter(|ref c| c.crashes == None)
                .filter(|ref c| c.stray_addr_rate() > 0.0)
                .count() as f32 / total
        }

        pub fn avg_stray_to_edi_rate (&self) -> f32 {
            let total = self.deme
                            .iter()
                            .filter(|ref c| c.fitness != None)
                            .count();
            self.deme
                .iter()
                .filter(|ref c| c.fitness != None)
                .map(|ref c| c.stray_to_edi_rate())
                .sum::<f32>() /
                total as f32
        }

        pub fn avg_stray_addr_rate (&self) -> f32 {
            let total= self.deme
                           .iter()
                           .filter(|ref c| c.fitness != None)
                           .count(); // NEEDS REFACTORING, ALL THSI CRAP
            self.deme.iter()
                .filter(|ref c | c.fitness != None)
                .map(|ref c| c.stray_addr_rate())
                .sum::<f32>() /
                total as f32
        }



        pub fn proportion_unseen (&self, season: usize) -> f32 {
            self.deme
                    .iter()
                    .filter(|ref c| c.fitness == None
                                    && (season as isize - c.season as isize).abs() <= 1)
                    .count() as f32 / 
                        self.params.population_size as f32
        }

        pub fn crash_rate (&self) -> f32 {
            let cand = self.deme
                           .iter()
                           .filter(|ref c| c.crashes != None)
                           .count();
            if cand == 0 { return 0.0 }
            self.deme
                    .iter()
                    .filter(|ref c| c.crashes != None)
                    .map(|ref c| if c.crashes.clone().unwrap_or(false) {1.0} else {0.0})
                    .sum::<f32>() /
                        cand as f32
        }

        pub fn min_abfit (&self) -> f32 {
            self.deme
                    .iter()
                    .filter(|ref c| c.ab_fitness != None)
                    .map(|ref c| c.ab_fitness.clone().unwrap_or(1.0))
                    .min_by_key(|&x| (x * 100000.0) as usize)
                    .unwrap_or(1.0)
        }

        pub fn min_fit (&self, season: usize) -> f32 {
            self.deme
                    .iter()
                    .filter(|ref c| c.fitness != None
                                    && (c.season as isize - season as isize).abs() <= 8)
                    .map(|ref c| c.fitness.clone().unwrap_or(1.0))
                    .min_by_key(|&x| (x * 100000.0) as usize)
                    .unwrap_or(1.0)
        }


        pub fn avg_fit (&self, season: usize) -> f32 {
            let cand = self.deme.iter()
                           .filter(|ref c| c.fitness != None 
                                          && (c.season as isize - season as isize).abs() <= 8)
                           .count();
            self.deme
                    .iter()
                    .filter(|ref c| c.fitness != None
                                    && (c.season as isize - season as isize).abs() <= 8)
                    .map(|ref c| c.fitness.clone().unwrap())
                    .sum::<f32>() / 
                        cand as f32
        }

        pub fn stddev_abfit (&self) -> f32 {
            let cand = self.deme.iter()
                                          .filter(|ref c| c.ab_fitness != None)
                                          .map(|ref c| c.ab_fitness.clone().unwrap())
                                          .collect();
            standard_deviation(&cand)
        }

        pub fn avg_abfit (&self) -> f32 {
            let cand = self.deme.iter()
                                          .filter(|ref c| c.ab_fitness != None)
                                          .count();
            self.deme
                    .iter()
                    .filter(|ref c| c.ab_fitness != None)
                    .map(|ref c| c.ab_fitness.clone().unwrap())
                    .sum::<f32>() / 
                        cand as f32
        }

        pub fn ret_addrs (&self) -> Vec<u32> {
            let mut addrs = Vec::new();
            for chain in &self.deme {
                for clump in &chain.clumps {
                    addrs.push(clump.ret_addr);
                }
            }
            addrs
        }

        pub fn entry_addrs (&self) -> Vec<u32> {
            let mut addrs = Vec::new();
            for chain in &self.deme {
                for clump in &chain.clumps {
                    addrs.push(clump.words[0]);
                }
            }
            addrs
        }

        pub fn size (&self) -> usize {
            self.deme.len()
        }

        pub fn best_abfit (&self) -> Option<f32> {
            match self.best {
                Some(ref x) => x.ab_fitness,
                _           => None,
            }
        }

        pub fn best_crashes (&self) -> Option<bool> {
            match self.best {
                Some(ref x) => x.crashes,
                _           => None,
            }
        }

        pub fn set_best (&mut self, i: usize) {
            self.best = Some(self.deme[i].clone());
        }

        pub fn periodic_save (&self) {
            if self.iteration % self.params.save_period == 0 {
                println!("[*] Saving population to {}", &self.params.pop_path);
                self.save();
            }
        }

        pub fn avg_edi_rate (&self) -> f32{
            1.0 - mean(&self.deme.iter()
                                 .map(|ref x| x.enabled_ratio())
                                 .collect::<Vec<f32>>())
        }

        pub fn save (&self) {
            let mut json_file = OpenOptions::new()
                                            .truncate(true)
                                            .write(true)
                                            .create(true)
                                            .open(&self.params.pop_path)
                                            .unwrap();
            let json_string = format!("{}\n",self.deme.to_json());
            json_file.write(json_string.as_bytes()).unwrap();
            json_file.flush().unwrap();
        }

        /* Needs some refactoring. Maybe a macro. */
        pub fn log (&self, first: bool) -> bool {
            if self.best == None {
                return true;
            }
            let best = self.best.clone().unwrap();
            if best.fitness == None {
                return true;
            }
            println!("\n[Logging to {}]", self.params.csv_path);
            let nclasses = self.params.io_targets.num_classes;
            // todo: don't hardcode the number of classes
            let row = if first {
                let mut s = format!("{}\nITERATION,SEASON,AVG-GEN,AVG-FIT,AVG-ABFIT,MIN-FIT,MIN-ABFIT,CRASH,BEST-GEN,BEST-FIT,BEST-ABFIT,BEST-CRASH,AVG-LENGTH,BEST-LENGTH,BEST-RUNTIME,UNSEEN,EDI-RATE,STRAY-RATE,AVG-STRAY-TO-EDI,STRAY-NOCRASH",
                                self.params);
                for i in 0..nclasses {
                    s.push_str(&format!(",MEAN-DIF-C{},STD-DEV-C{}",i,i));
                }
                s.push_str("\n");
                s
            } else { "".to_string() };
            let season = self.season;
            let mut row = format!("{}{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                                  row,
                                  self.iteration.clone(),
                                  season,
                                  self.avg_gen(),
                                  self.avg_fit(season),
                                  self.avg_abfit(),
                                  self.min_fit(season),
                                  self.min_abfit(),
                                  self.crash_rate(),
                                  best.generation,
                                  best.fitness.unwrap_or(1.0),
                                  best.ab_fitness.unwrap_or(1.0),
                                  if best.crashes == Some(true) { 1 } else { 0 },
                                  self.avg_len(),
                                  best.size(),
                                  best.runtime.unwrap_or(0.0),
                                  self.proportion_unseen(season),
                                  /* Tracking EDIs */
                                  self.avg_edi_rate(),
                                  /* stray rate / extended gadgets */
                                  self.avg_stray_addr_rate(),
                                  self.avg_stray_to_edi_rate(),
                                  self.stray_nocrash_rate());
            let c_mn_dif = self.params.io_targets
                                      .class_mean_difficulties();
            let c_sd_dif = self.params.io_targets
                                      .class_stddev_difficulties();
            for i in 0..nclasses {
                row.push_str(&format!(",{},{}", c_mn_dif[i], c_sd_dif[i]));
            }
            row.push_str("\n");
            let mut csv_file = OpenOptions::new()
                                           .append(true)
                                           .create(true)
                                           .open(&self.params.csv_path)
                                           .unwrap();
            csv_file.write(row.as_bytes()).unwrap();
            csv_file.flush().unwrap();
            false
        }
}

/**
  * Constants and parameters
  */

#[derive(PartialEq,Debug,Clone,Copy)]
pub enum SelectionMethod {
        Tournament,
        Roulette,
}

#[derive(PartialEq,Debug,Clone)]
pub struct Params {
        pub label            : String,
        pub population_size  : usize,
        pub crossover_rate   : f32,
        pub max_iterations  : usize,
        pub selection_method : SelectionMethod,
        pub t_size           : usize,
        pub code             : Vec<u8>,
        pub code_addr        : u32,
        pub data             : Vec<Vec<u8>>,
        pub data_addrs       : Vec<u32>,
        pub brood_size       : usize,
        pub min_start_len    : usize,
        pub max_start_len    : usize,
        pub max_len          : usize,
        pub constants        : Vec<u32>,
        pub stack_input_sampling : f32,
        pub training_ht      : HashMap<Vec<i32>,usize>,
        pub fit_goal         : f32,
        pub fitness_sharing  : bool,
        pub season_divisor    : usize,
/*  pub ro_data_data     : Vec<u8>,
        pub ro_data_addr     : u32,
        pub text_data        : Vec<u8>,
        pub text_addr        : u32,
        */
        pub io_targets       : IoTargets,
        pub test_targets     : IoTargets,
        pub sample_ratio     : f32,
        pub cuck_rate        : f32,
        pub verbose          : bool,
        pub date_dir         : String,
        pub csv_path         : String,
        pub log_dir          : String,
        pub pop_path         : String,
        pub threads          : usize,
        pub num_demes        : usize,
        pub migration        : f32,
        pub save_period      : usize, 
        pub use_viscosity    : bool,
        pub outregs          : Vec<usize>,
        pub inregs           : Vec<usize>,
        pub binary_path      : String,
        pub fatal_crash      : bool,
        pub crash_penalty    : f32,
        pub host_port        : String,
        pub random_override  : bool,
        pub edi_toggle_rate         : f32,
        pub initial_edi_rate : f32,
}
            

impl Display for Params {
        fn fmt (&self, f: &mut Formatter) -> Result {
            let mut s = String::new(); 
            let rem = "% ";

            s.push_str(&format!("{} label: {}\n", rem, self.label));
            s.push_str(&format!("{} population_size: {}\n", rem, self.population_size));
            s.push_str(&format!("{} crossover_rate: {}\n", rem, self.crossover_rate));
            s.push_str(&format!("{} max_iterations: {}\n", rem, self.max_iterations));
            s.push_str(&format!("{} selection_method: {:?}\n", rem, self.selection_method));
            s.push_str(&format!("{} t_size: {}\n", rem, self.t_size));
            s.push_str(&format!("{} brood_size: {}\n", rem, self.brood_size));
            s.push_str(&format!("{} min_start_len: {}\n", rem, self.min_start_len));
            s.push_str(&format!("{} max_start_len: {}\n", rem, self.max_start_len));
            s.push_str(&format!("{} max_len: {}\n", rem, self.max_len));
            s.push_str(&format!("{} fit_goal: {}\n", rem, self.fit_goal));
            s.push_str(&format!("{} cuck_rate: {}\n", rem, self.cuck_rate));
            s.push_str(&format!("{} threads: {}\n", rem, self.threads));
            s.push_str(&format!("{} num_demes: {}\n", rem, self.num_demes));
            s.push_str(&format!("{} migration: {}\n", rem, self.migration));
            s.push_str(&format!("{} use_viscosity: {}\n", rem, self.use_viscosity));
            s.push_str(&format!("{} outregs: {:?}\n", rem, self.outregs));
            s.push_str(&format!("{} inregs: {:?}\n", rem, self.inregs));
            s.push_str(&format!("{} binary_path: {}\n", rem, self.binary_path));
            s.push_str(&format!("{} fitness_sharing: {}\n", rem, self.fitness_sharing));
            s.push_str(&format!("{} fatal_crash: {}\n", rem, self.fatal_crash));
            s.push_str(&format!("{} random_override: {}\n", rem, self.random_override));
            s.push_str(&format!("{} edi_toggle_rate: {}\n", rem, self.edi_toggle_rate));
            s.push_str(&format!("{} initial_edi_rate: {}\n", rem, self.initial_edi_rate));
        
            write!(f, "{}",s)
        }
            
}
impl Params {
        pub fn new (label: &str) -> Params {
            let t = Local::now();
            let datepath  = t.format("%y/%m/%d").to_string();
            let timestamp = t.format("%H-%M-%S").to_string();
            Params {
                label:            label.to_string(),
                population_size:  2048,
                crossover_rate:   0.50,
                max_iterations:   800000,
                selection_method: SelectionMethod::Tournament,
                t_size:           7,
                code:             Vec::new(),
                code_addr:        0,
                data:             Vec::new(),
                data_addrs:       Vec::new(),
                brood_size:       2,
                min_start_len:    2,
                max_start_len:    32,
                max_len:          256,
                training_ht:      HashMap::new(),
                io_targets:       IoTargets::new(TargetKind::PatternMatch),
                test_targets:     IoTargets::new(TargetKind::PatternMatch),
                sample_ratio:     1.0,
                fit_goal:         0.1,  
                fitness_sharing:  true,
                season_divisor:    4,
                constants:        Vec::new(),
                stack_input_sampling: 0.1,
                cuck_rate:        0.15,
                verbose:          false,
                date_dir:         datepath.clone(),
                log_dir:          "UNSET".to_string(),
                csv_path:         format!("{}/{}_{}.csv", 
                                          &datepath, &label, &timestamp),
                pop_path:         format!("{}/{}-pop_{}.json", 
                                          &datepath, &label, &timestamp),
                save_period:      10000,
                threads:          5,
                num_demes:        4,
                migration:        0.05,
                use_viscosity:    true,
                // don't hardcode size and numbers of in/out regs.
                // make this dependent on the data
                inregs:           vec![1,2,3,4],
                outregs:          vec![5,6,7],
                binary_path:      "".to_string(),
                fatal_crash:      false,
                crash_penalty:    0.2,
                host_port:        "127.0.0.1:8888".to_string(),
                random_override:  false,
                edi_toggle_rate:  0.01,
                initial_edi_rate: 0.1,
            }
        }
        pub fn calc_season_length (&self, iteration: usize) -> usize {
            let base = self.population_size /
                (self.t_size * self.season_divisor);
            if iteration < base {
                base / 4
            } else {
                base
            }
        }
        pub fn set_season_divisor (&mut self, divisor: usize) {
            self.season_divisor = divisor;
        }
        pub fn set_init_difficulties (&mut self) {
            let mut io_targets = &mut self.io_targets;
            for ref mut problem in io_targets.iter_mut() {
                problem.set_difficulty(DEFAULT_DIFFICULTY as f32);
                problem.set_pfactor(self.population_size);
            }
        }

        pub fn set_log_dir (&mut self, dir: &str) {
            let ddir = format!("{}/{}",dir, self.date_dir);
            let d = DirBuilder::new()
                                                .recursive(true)
                                                .create(&ddir)
                                                .unwrap();
            self.csv_path = format!("{}/{}", dir, self.csv_path);
            self.pop_path = format!("{}/{}", dir, self.pop_path); 
            self.log_dir  = format!("{}", &ddir);
        } 
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Endian {
        LITTLE,
        BIG,
}

#[derive(Eq,PartialEq, Debug, Clone, Copy)]
pub enum MachineMode {
        THUMB,
        ARM,
}
impl MachineMode {
        pub fn uc(&self) -> Mode {
            match self {
              &MachineMode::THUMB => Mode::THUMB,
              &MachineMode::ARM   => Mode::LITTLE_ENDIAN,
            }
        }
        pub fn cs(&self) -> CsMode {
            match self {
                &MachineMode::THUMB => CsMode::MODE_THUMB,
                &MachineMode::ARM   => CsMode::MODE_LITTLE_ENDIAN,
            }
        }
}
impl Default for MachineMode {
        fn default() -> MachineMode { MachineMode::THUMB }
}

#[derive(Copy,Debug,Clone,Eq,PartialEq)]
pub enum TargetKind {
        PatternMatch,
        Classification,
        Game,
}

#[derive(Debug,Clone,Eq,PartialEq)]
pub struct IoTargets {
        v: Vec<Problem>,
        k: TargetKind, 
        pub num_classes: usize,
}

pub fn mk_class(c: usize) -> Target {
        Target::Vote(Classification::new(c))
}
pub fn mk_pattern(s: &str) -> Target {
        Target::Exact(RPattern::new(&s))
}

#[derive(Debug,Clone)]
pub struct Problem {
        pub input: Vec<i32>,
        difficulty: f32,
        predifficulty: f32,
        pfactor: f32,
        pub target: Target,
}

impl Hash for Problem {
        fn hash <H: Hasher> (&self, state: &mut H) {
            self.input.hash(state);
            self.target.hash(state);
        }
}
impl Problem {
        pub fn new (input: Vec<i32>, target: Target) -> Problem {
            Problem { 
                input: input, 
                difficulty: DEFAULT_DIFFICULTY,
                predifficulty: DEFAULT_DIFFICULTY,
                pfactor: 1.0,
                target: target,
            }
        }
        fn adj_cls_score_for_difficulty (&self, score: f32) -> f32 {
            // here, the higher the score, the better. 
            // difficulty is a float <= 1.0, and the lower the harder.
            f32::max(0.0, score * (1.0 - self.difficulty()))
            // = 0 if wrong, 1.0 - self.difficulty() if right
            // which is then inverted again: 1.0 - (1.0 - self.difficulty())
        }

        pub fn get_class (&self) -> Option<usize> {
            /* do this */
            match &self.target {
                &Target::Vote(ref i)  => Some(i.class),
                &Target::Game(ref ps) => Some(ps.params[0].clone() as usize),
                _ => None,
            }
            
        }

        pub fn get_input<'a> (&'a self, 
                              output: &Vec<u64>, 
                              random_override: bool,
                              verbose: bool) 
                              -> (Option<i32>, Vec<i32>) {
            match &self.target {
                &Target::Game(ref x) => {
                    if output.len() == 0 {
                        let mut p = Vec::new();
                        if verbose {
                            p.push(6);
                        } else {
                            p.push(0);
                        };
                        p.extend_from_slice(&x.params);
                        /*** RANDOMIZATION OVERRIDE ***/
                        if random_override {
                            p[1] = thread_rng().gen::<i32>();
                        }
                        /******************************/
                        (None, init_game(&p, &x.addr))
                    } else {
                        let out = output.iter()
                                        .map(|&x| (x & 0xFFFFFFFF) as i32)
                                        .collect::<Vec<i32>>();
                        play_game(&out, &x.addr)
                    }
                },
                _ => (None, self.input.clone()),
            }
        }
        /* 
          * Dispatch the relevant problem-specific fitness function
          */
        pub fn assess_output (&self,
                              output: &Vec<u64>,
                              uc: &CpuARM) 
                              -> (f32, f32) {
            match &self.target {
                &Target::Exact(ref rp) => {
                    // here we can try some sort of fitness sharing thing
                    // refactor later so that this returns a fingerprint
                    // as its first parameter
                    let r = f32::max(0.0, rp.distance(&output));
                    //let f = rp.matches(&output);
                    (r, r)
                },
                &Target::Vote(ref cls) => {
                    let b = max_bin(&output);
                    //let mut f = Fingerprint::new();
                    if b == cls.class {
                        //f.push(false);
                        (0.0, 1.0 - self.difficulty())
                    } else {
                        //f.push(true);
                        (1.0, 1.0)
                    } 
                } 
                &Target::Game(_) => {
                    let s = output[0].clone() as f32;
                    let af = (1.0 / s).sqrt();
                    //(af, (af + (1.0 - self.difficulty().powi(2)))/2.0)
                    (af, (af * (1.0 - self.difficulty())))
                }
            }
        }
        pub fn set_pfactor (&mut self, p: usize) {
            self.pfactor = p as f32
        }
        /* crying out for refactoring! */
        pub fn kind (&self) -> TargetKind {
            match self.target {
                Target::Exact(_) => TargetKind::PatternMatch,
                Target::Vote(_)  => TargetKind::Classification,
                Target::Game(_)  => TargetKind::Game,
            }
        }
        pub fn rotate_difficulty(&mut self, divisor: f32) {
            let pd = self.predifficulty();
            // pd: how many times this problem has been solved correctly
            // divisor: how many attempts have been made on it
            // so, the higher, the easier.
            self.set_difficulty(pd / divisor);
            self.set_predifficulty(DEFAULT_DIFFICULTY);
        }
        pub fn difficulty (&self) -> f32 {
            self.difficulty
        }
        pub fn predifficulty (&self) -> f32 {
            self.predifficulty
        }
        pub fn set_difficulty (&mut self, n: f32) {
            self.difficulty = f32::min(1.0, n);
            assert!(self.difficulty <= 1.0);
        }
        pub fn set_predifficulty (&mut self, n: f32) {
            self.predifficulty = n;
        }
        pub fn inc_predifficulty (&mut self, d_vec: &Vec<f32>) {
            let pd = self.predifficulty();
            self.set_predifficulty(pd + d_vec.iter().sum::<f32>());
        }
        pub fn identifier (&self) -> String {
            let mut s = String::new();
            for i in &self.input {
                s.push_str(&format!("{:08x}.", i));    
            }
            s
        }
}
impl PartialEq for Problem {
        fn eq (&self, other: &Problem) -> bool {
            self.input == other.input
        }
}
impl Eq for Problem {}

#[derive(Debug,Clone)]
pub struct Classification {
        pub class: usize,
        difficulty: f32,
        predifficulty: f32,
}
impl Hash for Classification {
        fn hash <H: Hasher> (&self, state: &mut H) {
            self.class.hash(state);
        }
}

impl PartialEq for Classification {
        fn eq (&self, other: &Self) -> bool {
            self.class == other.class
        }
}
impl Eq for Classification {}

impl Classification {
        pub fn new (val: usize) -> Self {
            Classification {
                class: val,
                difficulty: 1.0,
                predifficulty: 1.0,
            }
        }
}

pub static DEFAULT_DIFFICULTY : f32 = 0.0; // don't hardcode

pub fn suggest_constants (iot: &IoTargets) -> Vec<i32> {
        let mut cons : Vec<i32> = Vec::new();
        for ref p in iot.v.iter() {
            cons.extend_from_slice(&p.target.suggest_constants(&p.input));
        }
        cons
}

#[derive(Copy,Clone,Eq,PartialEq,Debug)]
pub enum Batch {
        TRAINING,
        TESTING,
}

/*
impl FromIterator<(Problem, Target)> for IoTargets {
        fn from_iter<I: IntoIterator<Item=(Problem,Target)>>(iter: I) -> Self {
            let mut iot = IoTargets::new();
        }
}
*/

impl IoTargets {
        pub fn shuffle (&self) -> IoTargets {
            let mut c = self.v.clone();
            thread_rng().shuffle(&mut c);
            IoTargets{v:c, k: self.k, num_classes: self.num_classes}
        }
        pub fn difficulty_profile (&self) -> Vec<f32> {
            self.iter()
                    .map(|x| x.difficulty())
                    .collect()
        }
        pub fn class_difficulties (&self) -> Vec<(usize,f32)> {
            self.v.iter()
                        .filter(|x| x.get_class() != None)
                        .map(|p| (p.get_class().unwrap(), p.difficulty()))
                        .collect::<Vec<(usize,f32)>>()
        }
        /*pub fn count_classes (&mut self) -> usize {
            let mut cd = self.class_difficulties()
                                      .iter()
                                      .map(|&p| p.0)
                                      .collect::<Vec<usize>>() ; // being lazy
            println!("cd before: {:?}",cd);
            let cd = cd.dedup();
            println!("cd after: {:?}",cd);
            self.num_classes = cd.len();
            self.num_classes
        }
        */
        pub fn difficulties_by_class (&self, i: usize) -> Vec<f32> {
            self.iter()
                    .filter(|ref p| p.get_class() == Some(i))
                    .map(|ref p| p.difficulty())
                    .collect::<Vec<f32>>()
        }
        // Note; these are not efficiently written, just lazily written. 
        // They're meant to be used sparingly, for the sake of 
        // readable output for curious humans, when running verbosely.
        pub fn class_mean_difficulties (&self) -> Vec<f32> {
            let mut res = Vec::new();
            for i in 0..self.num_classes {
                res.push(mean(&self.difficulties_by_class(i)));
            }
            res
        }
        pub fn class_stddev_difficulties (&self) -> Vec<f32> {
            let mut res = Vec::new();
            for i in 0..self.num_classes {
                res.push(standard_deviation(&self.difficulties_by_class(i)));
            }
            res
        }
        // this might be confusing later.
        pub fn push (&mut self, t: Problem) {
            self.v.push(t);
        }

        pub fn split_at (&self, i: usize) -> (IoTargets,IoTargets) {
            if self.k == TargetKind::PatternMatch {
                (self.clone(),self.clone())
            } else {
                let (a,b) = self.v.split_at(i);
                    (IoTargets::from_vec(self.k, a.to_vec(), self.num_classes),
                      IoTargets::from_vec(self.k, b.to_vec(), self.num_classes))
            }
        }

        // We need a balanced splitting function
        // assumes the IoTargets is balanced to begin with.
        // Improve on this later, so that it preserves ratios. See example in
        // GENLIN. 
        // TODO: Fix this. it doesn't work. 
        pub fn balanced_split_at (&self, i: usize) -> (IoTargets, IoTargets) {
            if self.k != TargetKind::Classification {
                (self.clone(),self.clone())
            } else {
                let mut unique_targets = self.iter()
                                                                          .map(|x| x.target.clone())
                                                                          .collect::<Vec<Target>>();
                unique_targets.dedup();
                let shuffled = self.shuffle();                         
                let num_classes : usize = unique_targets.len();
                let mut buckets : Vec<Vec<Problem>> = Vec::new();
                for j in 0..num_classes {
                    let mut class : Vec<Problem> = Vec::new();
                    for x in shuffled.iter() {
                        if x.get_class() == Some(j) {
                            class.push(x.clone());
                        }
                    }
                    /*= shuffled.iter()
                                                            .filter(|x| x.1 == Target::Vote(j))
                                                            .map(|&x| x.clone())
                                                            .collect();
                                                            */
                    buckets.push(class);
                }
                let mut part_1 = IoTargets::new(TargetKind::Classification);
                for j in 0..i {
                    match buckets[j % num_classes].pop() {
                        Some(item) => buckets[j % num_classes].push(item),
                        None       => (), 
                    }
                }
                let mut part_2 = IoTargets::new(TargetKind::Classification);
                for bucket in buckets {
                    for item in bucket {
                        part_2.push(item);
                    }
                }
                let (mut at, mut bt) = (part_1.shuffle(), part_2.shuffle());
                at.num_classes = self.num_classes;
                bt.num_classes = self.num_classes;
                println!(">> i == {}; at.len() == {}; bt.len() == {}",i, at.len(), bt.len());
                (at,bt)
            }
        }
  
        pub fn new (k: TargetKind) -> IoTargets {
            IoTargets{v:Vec::new(), k:k, num_classes: 1}
        }
        pub fn from_vec (k: TargetKind, v: Vec<Problem>, num_classes: usize) -> IoTargets {
            IoTargets{v:v, k:k, num_classes: num_classes}
        }
        pub fn to_vec (&self) -> &Vec<Problem> {
            &self.v
        }
        pub fn len (&self) -> usize {
            self.v.len()
        }
        pub fn iter (&self) -> Iter<Problem> {
            self.v.iter()
        }
        pub fn iter_mut (&mut self) -> IterMut<Problem> {
            self.v.iter_mut()
        }
        pub fn empty_clone (&self) -> IoTargets {
            let mut cl = self.clone();
            cl.v = Vec::new();
            cl
        }
}

pub type Score = u32;

#[derive(Hash,Eq,PartialEq,Debug,Clone)]
pub struct GameData {
        pub addr: String,
        pub params: Vec<i32>,
}


#[derive(Eq,PartialEq,Debug,Clone)]
pub enum Target {
        Exact(RPattern),
        Vote(Classification),
        Game(GameData),
}
impl Hash for Target {
        fn hash <H: Hasher> (&self, state: &mut H) {
            match self {
                &Target::Exact(ref r) => r.hash(state),
                &Target::Vote(ref c) => c.hash(state),
                &Target::Game(ref s) => s.hash(state),
            }
        }
}
impl Display for Target {
        fn fmt (&self, f: &mut Formatter) -> Result {
            match self {
                &Target::Exact(ref rp) => rp.fmt(f),
                &Target::Vote(ref i)   => i.class.fmt(f),
                &Target::Game(_)       => "[game]".fmt(f),
            }
        }
}

impl Target {
        pub fn suggest_constants (&self, input: &Vec<i32>) -> Vec<i32> {
            match self {
                &Target::Vote(_) => {
                    let mut cons : Vec<i32> = Vec::new();
                    let mut rng = rand::thread_rng();
                    for ut in input {
                        cons.push(rng.gen::<i32>() % (2 * (ut.abs()+1) as i32));
                    }
                    cons
                },
                &Target::Exact(ref r) => r.constants(),
                &Target::Game(_) => vec![2], // PLACEHOLDER TODO
            }
        }
        pub fn is_class (&self, c: usize) -> bool {
            match self {
                &Target::Vote(ref cls) => c == cls.class,
                _ => false,
            }
        }
        pub fn classifier (&self) -> &Classification {
            match self {
                &Target::Vote(ref cls) => cls,
                _ => panic!("Not a Classification"),
            }
        }
}

#[derive(Debug,Clone)]
struct RPatEq {
        pub reg_res: usize,
        pub reg_exp: Option<usize>,
        pub immed: u64,
        pub diff:  f32,
        pub prediff: f32,
}
/* Formula: match req.reg_exp {
  *  None => dist(regs[req.reg_res], req.immed),
  *  Some(r) => dist(regs[req.reg_res], regs[req.reg_exp.unwrap()]
  *                                     + immed),
  * }
  */

#[derive(Debug,Clone)]
pub struct RPattern2 (Vec<RPatEq>);

/* TODO:
  * reimplement Register Patterns in such a way that
  * the pattern can contain other register references.
  * e.g: r0 = sp+4
  * And then write a parser for a simple set of equations, 
  * instead of an int / wildcard pattern.
  */

#[derive(Debug,Clone)]
pub struct RPattern { 
        regvals_diff: Vec<(usize,u64,f32)>,
        regvals_prediff: Vec<(usize,u64,f32)>,
}
impl Hash for RPattern {
        fn hash <H: Hasher> (&self, state: &mut H) {
            self.clean().hash(state)
        }
}
impl PartialEq for RPattern {
        fn eq (&self, other: &Self) -> bool {
            let mut a = self.clean();
            let mut b = other.clean();
            a.sort();
            b.sort();
            a == b
        }
}
impl Eq for RPattern {}

impl RPattern {
        pub fn clean (&self) -> Vec<(usize,u64)> {
            self.regvals_diff
                    .iter()
                    .map(|&(x,y,_)| (x,y))
                    .collect::<Vec<(usize,u64)>>()
        }
        pub fn new (s: &str) -> Self {
            let mut parts = s.split(',');
            let mut rp : RPattern = RPattern {
                regvals_diff: Vec::new(),
                regvals_prediff: Vec::new(),
            };
            let mut i : usize = 0;
            for part in parts {
                if !part.starts_with("_") {
                    rp.push((i,u32::from_str_radix(part, 16)
                                        .expect("Failed to parse RPattern")
                                        as u64));
                }
                i += 1;
            }
            rp
        }
        pub fn shuffle_vec (&self) 
                                              -> Vec<(usize, u64, f32)> {
            let mut c = self.regvals_diff.clone();
            let mut rng = thread_rng(); // switch to seedable
            rng.shuffle(&mut c);
            c
        }
        pub fn push (&mut self, x: (usize, u64)) {
            self.regvals_diff.push((x.0,x.1,1.0));
        }
        pub fn constants (&self) -> Vec<i32> {
            self.regvals_diff
                    .iter()
                    .map(|&p| p.1 as i32)
                    .collect()
        }
        pub fn satisfy (&self, regs: &Vec<u64>) -> bool {
            for &(idx,val,_) in &self.regvals_diff {
                if regs[idx] != val { return false };
            }
            true
        }
        pub fn matches (&self, regs: &Vec<u64>) -> Fingerprint {
            let mut scorecard : Fingerprint = Fingerprint::new();
            for &(idx,val,diff) in &self.regvals_diff {
                if regs[idx] == val {
                    scorecard.push(false);
                } else {
                    scorecard.push(true);
                }
            }
            scorecard
        }
        fn vec_pair (&self, regs: &Vec<u64>) -> (Vec<u64>, Vec<u64>) {
            let mut ivec = Vec::new();
            let mut ovec = Vec::new();
            for &(idx,val,_) in &self.regvals_diff {
                ivec.push(regs[idx]);
                ovec.push(val);
            }
            (ivec, ovec)
        }
        pub fn distance_deref (&self, regs: &Vec<u64>) -> f32 {
        
            1.0 /* placeholder */
        }
        pub fn distance (&self, regs: &Vec<u64>) -> f32 {
            let (i, o) = self.vec_pair(&regs);
            //let h = hamming_distance(&i, &o);
            let a = arith_distance(&i, &o);
            //let m = count_matches(&i, &o);
            //(h + a) / 2.0 //(2.0 * m)
            //(h + a) / 2.0   
            a
        }
}
pub const MAXPATLEN : usize = 12;
impl Display for RPattern {
        fn fmt (&self, f: &mut Formatter) -> Result {
            let blank = "________ ";
            let mut s = String::new();
            let mut i : usize = 0;
            for &(idx,val,_) in &self.regvals_diff {
                while i < idx {
                    s.push_str(blank);
                    i += 1;
                }
                s.push_str(&format!("{:08x} ",val));
                i += 1;
            }
            write!(f, "{}\n",s)
        }
}

#[derive(PartialEq,Clone,Debug)]
pub struct RunningAvg {
        sum: f64,
        count: f64,
}

impl RunningAvg {
        pub fn new () -> RunningAvg {
            RunningAvg {
                sum:   0.0,
                count: 0.0,
            }
        }
        pub fn avg (&self) -> f32 {
            if self.count == 0.0 {1.0} else {(self.sum/self.count) as f32}
        }
        pub fn inc (&mut self, val: f32) {
            self.count += 1.0;
            self.sum   += val as f64;
        }
}


pub fn test_clump (uc: &mut unicorn::CpuARM,
                                          clump: &Clump) -> usize {
        let input = vec![2,2,2,2,
                                          2,2,2,2,
                                          2,2,2,2,
                                          2,2,2,2];
        let inregs = vec![ 0, 1, 2, 3,
                                              4, 5, 6, 7,
                                              8, 9,10,11,
                                            12,13,14,15];
        let mut twos = repeat(2);
        let mut cl = clump.clone();
        saturate_clump(&mut cl, &mut twos);
        let vanilla = Chain::new(vec![cl]);
        let res = hatch_chain(uc, &vanilla, &input, &inregs, true);
        //println!("\n{}",res);
        let mut differ = 0;
        for r in res.registers[..12].to_vec() {
            if r != 2 {
                differ = 1;
                break;
            }
        }
        let smooth = if res.error == None {2} else {0};
        differ | smooth
}

const NOCHANGE_CRASH_BUCKET    : usize = 0;
const CHANGE_CRASH_BUCKET      : usize = 1;
const NOCHANGE_NOCRASH_BUCKET  : usize = 2;
const CHANGE_NOCRASH_BUCKET    : usize = 3;

pub fn random_chain (clumps:  &Vec<Clump>,
                                              params:  &Params,
                                              pool:    &mut Mangler,
                                              rng:     &mut ThreadRng) -> Chain {
        let max_len = params.max_start_len;
        let min_len = params.min_start_len;
        let rlen  = rng.gen::<usize>() % (max_len - min_len) + min_len;
        let mut genes : Vec<Clump> = Vec::new();
        for _ in 0..rlen {
            let mut clump = clumps[rng.gen::<usize>() % clumps.len()].clone();
            saturate_clump(&mut clump, pool);
            for i in 1..clump.words.len() {
                let roll = rng.gen::<f32>();
                if roll < params.stack_input_sampling {
                    clump.input_slots.push((i, rng.gen::<usize>() % 
                                                                    params.inregs.len()));
                                                                
                }
            }
            if rng.gen::<f32>() < params.initial_edi_rate {
                clump.enabled = false;
            }
            genes.push(clump);
        }
        Chain::new(genes)
}

pub fn random_chain_from_buckets (clump_buckets:  &Vec<Vec<Clump>>,
                                                                        min_len: usize,
                                                                        max_len: usize,
                                                                        pool:    &mut Mangler,
                                                                        rng:     &mut ThreadRng) -> Chain {
        let rlen  = rng.gen::<usize>() % (max_len - min_len) + min_len;
        let mut genes : Vec<Clump> = Vec::new();
        for _ in 0..rlen {
            let clumps : &Vec<Clump>;
            
            let roll = rng.gen::<usize>() % 128;
            if roll == 0 { 
                clumps = &clump_buckets[NOCHANGE_CRASH_BUCKET];
            } else if 1 <= roll && roll < 4 {
                clumps = &clump_buckets[NOCHANGE_NOCRASH_BUCKET];
            } else if 4 <= roll && roll < 7 {
                clumps = &clump_buckets[CHANGE_CRASH_BUCKET];
            } else {
                clumps = &clump_buckets[CHANGE_NOCRASH_BUCKET];
            };

            let mut c = clumps[rng.gen::<usize>() % clumps.len()].clone();
            saturate_clump(&mut c, pool);
            genes.push(c);
        }
        Chain::new(genes)
}

