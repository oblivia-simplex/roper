extern crate rand;
extern crate unicorn;
extern crate time;
extern crate chrono;
extern crate rustc_serialize;

use self::chrono::prelude::*;
use self::chrono::offset::LocalResult;
use std::collections::BTreeMap;
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
use roper::util::*;
use roper::population::*;
use roper::hatchery::*;
use roper::ontostructs::*;

pub const MAX_VISC : i32 = 100;
pub const MIN_VISC : i32 = 0;
pub const VISC_DROP_THRESH : i32 = 10;
pub const RIPENING_FACTOR : i32 = 4;
pub const MAX_FIT : f32 = 1.0;
const DEFAULT_MODE : MachineMode = MachineMode::ARM;

pub type FIT_INT = u32;

#[derive(Clone,Debug)]
pub struct Clump {
  pub sp_delta:    i32, // how much does the sp change by?
  pub ret_offset:  i32, // how far down is the next address?
  pub exchange:    bool, // BX instruction? can we change mode?
  pub mode:        MachineMode,
  pub ret_addr:    u32,
  pub words:       Vec<u32>,
  pub viscosity:   i32,
  pub link_age:    i32,
  pub link_fit:    Option<f32>,
}

// JClumps are just a transitional data structure, used in the JSON
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
    Json::Object(b)
  }
}
impl Display for Clump {
  fn fmt (&self, f: &mut Formatter) -> Result {
    let mut s = String::new();
    let vp : f32 = self.viscosity as f32 / MAX_VISC as f32;
    s.push_str("CLUMP:\n");
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
      viscosity:  MAX_VISC, //(MAX_VISC - MIN_VISC) / 2 + MIN_VISC,
      link_age:   0,
      link_fit:   None, // (MAX_FIT/2),
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

fn concatenate (clumps: &Vec<Clump>) -> Vec<u32> {
  let s : usize = clumps.iter()
                        .map(|ref x| x.words.len())
                        .sum();
  let mut c = vec![0; s];
  //println!("s = {}; c.len() = {}", s, c.len());
  //let mut spd = 0;
  let mut rto = 0 as usize;
  let mut exchange = false;
  let mut i = 0;
  //let last = clumps.len()-1;
  for ref gad in clumps {
    /* for debugging */
    /*****************/
    if !saturated(gad) {
      panic!("Attempting to concatenate unsaturated clumps");
    }
    assert!(gad.sp_delta >= 0);
    //if i == last { 
   //   c[rto] = gad.words[0].clone();
   //   //
   // } else {
    let t : usize = rto + gad.sp_delta as usize;
    &c[rto..t].clone_from_slice(&(gad.words));
   // }
    if exchange && (gad.mode == MachineMode::THUMB) {
      /* If we BX, the LSB of the addr decides machine mode */
      c[rto] |= 1;
//      println!("*** exchange: adding 1 mask ***");
    }
    rto += gad.ret_offset as usize;
    //spd += gad.sp_delta as usize;
    exchange = gad.exchange;
//    println!("[{}] ==> {}",rto,gad);
    i += 1;
  }
  c[..rto].to_vec()
}
#[derive(Clone,Debug)]
pub struct Chain {
  pub clumps: Vec<Clump>, //Arr1K<Clump>, //[Clump; MAX_CHAIN_LENGTH], 
  pub packed: Vec<u8>,
  pub fitness: Option<f32>,
  pub ab_fitness: Option<f32>, // unshared
  pub generation: u32,
  pub verbose_tag: bool,
  pub crashes: Option<bool>,
  pub season: usize,
  i: usize,
//  pub ancestral_fitness: Vec<i32>,
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
    s.push_str("Clumps:\n");
    for clump in &self.clumps {
      for word in &clump.words {
        s.push_str(&format!("{:08x} ",word));
      }
      s.push_str("\n");
    }
    s.push_str("Packed:\n");
    let mut j = 0;
    for b in &self.packed {
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
      packed: Vec::new(),
      fitness: None,
      ab_fitness: None,
      generation: 0,
      season: 0,
      verbose_tag: false,
      crashes: None,
      i: 0,
    //  ancestral_fitness: Vec::new(),
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
    let conc = concatenate(&clumps);
    let pack = pack_word32le_vec(&conc);
    Chain {
      clumps: clumps,
      packed: pack,
      ..Default::default()
    }
  }
  pub fn pack (&mut self) {
    let conc  = concatenate(&self.clumps);
    self.packed = pack_word32le_vec(&conc);
  }
  pub fn size (&self) -> usize {
    self.clumps.len()
  }
  pub fn set_fitness (&mut self, n: f32) {
    self.fitness = Some(n);
  }
  pub fn excise (&mut self, idx: usize) {
    self.clumps.remove(idx);
    self.pack();
  }
}

impl PartialOrd for Chain {
  fn partial_cmp (&self, other: &Chain) -> Option<Ordering> {
    self.fitness.partial_cmp(&other.fitness)
    /*
    match (self.fitness, other.fitness) {
      (Some(a), Some(b)) => Some(a.cmp(&b)), // Note reversal
      (Some(_), None)    => Some(Ordering::Less),
      (None, Some(_))    => Some(Ordering::Greater),
      _                  => None,
    }
    */
  }
}
impl Ord for Chain {
  fn cmp (&self, other: &Chain) -> Ordering {
    self.partial_cmp(other).unwrap_or(Ordering::Equal)
  }
}


const POPSIZE : usize = 400;
pub type Pod<T> = RwLock<T>;
/*
#[derive(Clone,Debug)]
pub struct Pod<T> {
  nucleus: T,
}
impl <T> Pod <T>{
  pub fn new (t: T) -> Pod<T> {
    Pod {nucleus: t}
  }
  pub fn open_r (&self) -> T {
    self.nucleus
  }
  pub fn open_w (&mut self) -> T {
    self.nucleus
  }
}
*/
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
//unsafe impl Sync for Population {}

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
      deme.push(random_chain_from_buckets(
                             &clump_buckets,
                             params.min_start_len,
                             params.max_start_len,
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
                 self.params.min_start_len,
                 self.params.max_start_len,
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
                && (c.season as isize - season as isize).abs() <= 1)
        .map(|ref c| c.fitness.clone().unwrap_or(1.0))
        .min_by_key(|&x| (x * 100000.0) as usize)
        .unwrap_or(1.0)
  }
  pub fn avg_fit (&self, season: usize) -> f32 {
    let cand = self.deme.iter()
                   .filter(|ref c| c.fitness != None 
                           && (c.season as isize - season as isize).abs() <= 1)
                   .count();
    self.deme
        .iter()
        .filter(|ref c| c.fitness != None
                && (c.season as isize - season as isize).abs() <= 1)
        .map(|ref c| c.fitness.clone().unwrap())
        .sum::<f32>() / 
          cand as f32
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
  pub fn size (&self) -> usize {
    self.deme.len()
  }
  pub fn best_fit (&self) -> Option<f32> {
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
  pub fn save (&self) {
    let mut json_file = OpenOptions::new()
                                    .truncate(true)
                                    .write(true)
                                    .create(true)
                                    .open(&self.params.pop_path)
                                    .unwrap();
    let json_string = format!("{}\n",self.deme.to_json());
    json_file.write(json_string.as_bytes());
    json_file.flush();
  }
  pub fn log (&self) {
    if self.best == None {
      return;
    }
    let best = self.best.clone().unwrap();
    if best.fitness == None {
      return;
    }
    let row = if self.iteration == 1 {
      format!("{}\nITERATION,SEASON,AVG-GEN,AVG-FIT,AVG-ABFIT,MIN-FIT,MIN-ABFIT,CRASH,BEST-GEN,BEST-FIT,BEST-ABFIT,BEST-CRASH,AVG-LENGTH,BEST-LENGTH,UNSEEN\n",
              self.params)
    } else { "".to_string() };
    let season = self.season;
    let row = format!("{}{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
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
                      best.fitness.unwrap(),
                      best.ab_fitness.unwrap(),
                      if best.crashes == Some(true) { 1 } else { 0 },
                      self.avg_len(),
                      best.size(),
                      self.proportion_unseen(season));
    let mut csv_file = OpenOptions::new()
                                   .append(true)
                                   .create(true)
                                   .open(&self.params.csv_path)
                                   .unwrap();
    csv_file.write(row.as_bytes());
    csv_file.flush();
  }
}

/**
 * Constants and parameters
 */

type dword = u32;
type halfword = u16;
type byte = u8;

#[derive(PartialEq,Debug,Clone,Copy)]
pub enum SelectionMethod {
  Tournement,
  Roulette,
}

#[derive(PartialEq,Debug,Clone)]
pub struct Params {
  pub label            : String,
  pub population_size  : usize,
  pub mutation_rate    : f32,
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
  pub training_ht      : HashMap<Vec<i32>,usize>,
  pub fit_goal         : f32,
  pub fitness_sharing  : bool,
  pub season_length    : usize,
/*  pub ro_data_data     : Vec<u8>,
  pub ro_data_addr     : u32,
  pub text_data        : Vec<u8>,
  pub text_addr        : u32,
  */
  pub io_targets       : IoTargets,
  pub test_targets     : IoTargets,
  pub cuck_rate        : f32,
  pub verbose          : bool,
  pub date_dir         : String,
  pub csv_path         : String,
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
}
impl Default for Params {
  fn default () -> Params {
    let t = Local::now();
    let datepath  = t.format("%y/%m/%d").to_string();
    let timestamp = t.format("%H-%M-%S").to_string();
    Params {
      label:            format!("Fitness-sharing, {} {}", &datepath, &timestamp),
      population_size:  2048,
      mutation_rate:    0.45,
      max_iterations:  800000,
      selection_method: SelectionMethod::Tournement,
      t_size:           4,
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
      fit_goal:         0.1,  
      fitness_sharing:  true,
      season_length:    512,
      constants:        Vec::new(),
      cuck_rate:        0.15,
      verbose:          false,
      date_dir:         datepath.clone(),
      csv_path:         format!("{}/roper_{}.csv", 
                                &datepath, &timestamp),
      pop_path:         format!("{}/roper_pop_{}.json", 
                                &datepath, &timestamp),
      save_period:      10000,
      threads:          5,
      num_demes:        4,
      migration:        0.05,
      use_viscosity:    true,
      // don't hardcode size and numbers of in/out regs.
      // make this dependent on the data
      inregs:           vec![0,1,2,3],
      outregs:          vec![4,5,6],
      binary_path:      "".to_string(),
      fatal_crash:      false,
      crash_penalty:    0.2,
    }
  }
}
impl Display for Params {
  fn fmt (&self, f: &mut Formatter) -> Result {
    let rem = "% ";
    let mut s = String::new(); 
    s.push_str(&format!("{} label: {}\n",
                        rem, self.label));
    s.push_str(&format!("{} population_size: {}\n",
                        rem, self.population_size));
    s.push_str(&format!("{} mutation_rate: {}\n",
                        rem, self.mutation_rate));
    s.push_str(&format!("{} max_iterations: {}\n",
                        rem, self.max_iterations));
    s.push_str(&format!("{} selection_method: {:?}\n",
                        rem, self.selection_method));
    s.push_str(&format!("{} t_size: {}\n",
                        rem, self.t_size));
    s.push_str(&format!("{} brood_size: {}\n",
                        rem, self.brood_size));
    s.push_str(&format!("{} min_start_len: {}\n",
                        rem, self.min_start_len));
    s.push_str(&format!("{} max_start_len: {}\n",
                        rem, self.max_start_len));
    s.push_str(&format!("{} max_len: {}\n",
                        rem, self.max_len));
    s.push_str(&format!("{} fit_goal: {}\n",
                        rem, self.fit_goal));
    s.push_str(&format!("{} cuck_rate: {}\n",
                        rem, self.cuck_rate));
    s.push_str(&format!("{} threads: {}\n",
                        rem, self.threads));
    s.push_str(&format!("{} num_demes: {}\n",
                        rem, self.num_demes));
    s.push_str(&format!("{} migration: {}\n",
                        rem, self.migration));
    s.push_str(&format!("{} use_viscosity: {}\n",
                        rem, self.use_viscosity));
    s.push_str(&format!("{} outregs: {:?}\n",
                        rem, self.outregs));
    s.push_str(&format!("{} inregs: {:?}\n",
                        rem, self.inregs));
    s.push_str(&format!("{} binary_path: {}\n",
                        rem, self.binary_path));
    s.push_str(&format!("{} fitness_sharing: {}\n",
                        rem, self.fitness_sharing));
    s.push_str(&format!("{} fatal_crash: {}\n",
                        rem, self.fatal_crash));
    write!(f, "{}",s)
  }
    
}
impl Params {
  pub fn new () -> Params {
    Default::default()
  }
  pub fn set_season_length (&mut self, factor: usize) {
    self.season_length = self.population_size /
      (self.t_size * self.threads * factor); 
  }
  pub fn set_init_difficulties (&mut self, val: f32) {
    let mut io_targets = &mut self.io_targets;
    for &mut (ref mut problem, _) in io_targets.iter_mut() {
      problem.difficulty = val;
    }
  }

  pub fn set_log_dir (&mut self, dir: &str) {
    let ddir = format!("{}/{}",dir, self.date_dir);
    let d = DirBuilder::new()
                      .recursive(true)
                      .create(ddir)
                      .unwrap();
    self.csv_path = format!("{}/{}", dir, self.csv_path);
    self.pop_path = format!("{}/{}", dir, self.pop_path); 
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
}

#[derive(Debug,Clone,Eq,PartialEq)]
pub struct IoTargets {
  v: Vec<(Problem,Target)>,
  k: TargetKind, 
}

#[derive(Debug,Clone)]
pub struct Problem {
  pub input: Vec<i32>,
  pub difficulty: f32,
  pub predifficulty: f32,
}
impl Problem {
  pub fn new (input: Vec<i32>) -> Problem {
    Problem { 
      input: input, 
      difficulty: DEFAULT_DIFFICULTY,
      predifficulty: DEFAULT_DIFFICULTY,
    }
  }
}
impl PartialEq for Problem {
  fn eq (&self, other: &Problem) -> bool {
    self.input == other.input
  }
}
impl Eq for Problem {}

pub static DEFAULT_DIFFICULTY : f32 = 1.0; // don't hardcode

pub fn suggest_constants (iot: &IoTargets) -> Vec<u32> {
  let mut cons : Vec<u32> = Vec::new();
  for &(ref i, ref o) in iot.v.iter() {
    cons.extend_from_slice(&o.suggest_constants(&i.input));
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
    IoTargets{v:c, k: self.k}
  }
  pub fn difficulty_profile (&self) -> Vec<f32> {
    self.iter()
        .map(|x| x.0.difficulty)
        .collect()
  }
  // this might be confusing later.
  pub fn push (&mut self, t: (Problem,Target)) {
    self.v.push(t);
  }
  pub fn split_at (&self, i: usize) -> (IoTargets,IoTargets) {
    if self.k == TargetKind::PatternMatch {
      (self.clone(),self.clone())
    } else {
      let (a,b) = self.v.split_at(i);
      (IoTargets::from_vec(self.k, a.to_vec()),IoTargets::from_vec(self.k, b.to_vec()))
    }
  }
  // We need a balanced splitting function
  // assumes the IoTargets is balanced to begin with.
  // Improve on this later, so that it preserves ratios. See example in
  // GENLIN. 
  pub fn balanced_split_at (&self, i: usize) -> (IoTargets, IoTargets) {
    if self.k == TargetKind::PatternMatch {
      (self.clone(),self.clone())
    } else {
      let mut unique_targets = self.iter()
                                   .map(|x| x.1.clone())
                                   .collect::<Vec<Target>>();
      unique_targets.dedup();
      let shuffled = self.shuffle();                         
      let num_classes : usize = unique_targets.len();
      let mut buckets : Vec<Vec<(Problem,Target)>> = Vec::new();
      for j in 0..num_classes {
        let mut class : Vec<(Problem,Target)> = Vec::new();
        for x in shuffled.iter() {
          if x.1 == Target::Vote(j) {
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
      (part_1.shuffle(), part_2.shuffle())
    }
  }
 
  pub fn new (k: TargetKind) -> IoTargets {
    IoTargets{v:Vec::new(), k:k}
  }
  pub fn from_vec (k: TargetKind, v: Vec<(Problem,Target)>) -> IoTargets {
    IoTargets{v:v, k:k}
  }
  pub fn len (&self) -> usize {
    self.v.len()
  }
  pub fn iter (&self) -> Iter<(Problem, Target)> {
    self.v.iter()
  }
  pub fn iter_mut (&mut self) -> IterMut<(Problem, Target)> {
    self.v.iter_mut()
  }
}

#[derive(Eq,PartialEq,Debug,Clone)]
pub enum Target {
  Exact(RPattern),
  Vote(usize),
}

impl Display for Target {
  fn fmt (&self, f: &mut Formatter) -> Result {
    match self {
      &Target::Exact(ref rp) => rp.fmt(f),
      &Target::Vote(i)   => i.fmt(f),
    }
  }
}

impl Target {
  pub fn suggest_constants (&self, input: &Vec<i32>) -> Vec<u32> {
    match self {
      &Target::Vote(_) => {
        let mut cons : Vec<u32> = Vec::new();
        let mut rng = rand::thread_rng();
        for ut in input {
          cons.push(rng.gen::<u32>() % (2 * *ut as u32));
        }
        cons
      },
      &Target::Exact(ref r) => r.constants(),
    }
  }
}


#[derive(Debug,Clone,PartialEq,Eq)]
pub struct RPattern { regvals: Vec<(usize,i32)> }
impl RPattern {
  pub fn new (s: &str) -> RPattern {
    let mut parts = s.split_whitespace();
    let mut rp : RPattern = RPattern {
      regvals: Vec::new(),
    };
    let mut i : usize = 0;
    for part in parts {
      if !part.starts_with("_") {
        rp.push((i,u32::from_str_radix(part, 16)
                  .expect("Failed to parse RPattern")
                  as i32));
      }
      i += 1;
    }
    rp
  }
  pub fn push (&mut self, x: (usize, i32)) {
    self.regvals.push(x);
  }
  pub fn constants (&self) -> Vec<u32> {
    self.regvals
        .iter()
        .map(|&p| p.1 as u32)
        .collect()
  }
  pub fn satisfy (&self, regs: &Vec<i32>) -> bool {
    for &(idx,val) in &self.regvals {
      if regs[idx] != val { return false };
    }
    true
  }
  fn vec_pair (&self, regs: &Vec<i32>) -> (Vec<i32>, Vec<i32>) {
    let mut ivec = Vec::new();
    let mut ovec = Vec::new();
    for &(idx,val) in &self.regvals {
      ivec.push(regs[idx]);
      ovec.push(val);
    }
    (ivec, ovec)
  }
  pub fn distance (&self, regs: &Vec<i32>) -> f32 {
    let (i, o) = self.vec_pair(&regs);
    let h = hamming_distance(&i, &o);
    let a = arith_distance(&i, &o);
    let m = count_matches(&i, &o);
    (h + a) / (2.0 * m)
  }
}
pub const MAXPATLEN : usize = 12;
impl Display for RPattern {
  fn fmt (&self, f: &mut Formatter) -> Result {
    let blank = "________ ";
    let mut s = String::new();
    let mut i : usize = 0;
    for &(idx,val) in &self.regvals {
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
  let res = hatch_chain(uc, &vanilla.packed, &input, &inregs);
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
                     min_len: usize,
                     max_len: usize,
                     pool:    &mut Mangler,
                     rng:     &mut ThreadRng) -> Chain {
  let rlen  = rng.gen::<usize>() % (max_len - min_len) + min_len;
  let mut genes : Vec<Clump> = Vec::new();
  for _ in 0..rlen {
    let mut c = clumps[rng.gen::<usize>() % clumps.len()].clone();
    saturate_clump(&mut c, pool);
    genes.push(c);
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

