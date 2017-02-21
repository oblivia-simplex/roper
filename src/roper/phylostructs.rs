extern crate rand;
extern crate unicorn;

use std::cmp::*;
use std::cell::*;
use std::fmt::{Display,format,Formatter,Result};
use std::sync::RwLock;
use std::ops::{Index,IndexMut};
use roper::params::*;
use roper::util::*;
use roper::population::*;
use roper::hatchery::*;
use unicorn::{CpuARM};

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
  for ref gad in clumps {
    /* for debugging */
    /*****************/
    if !saturated(gad) {
      panic!("Attempting to concatenate unsaturated clumps");
    }
    assert!(gad.sp_delta >= 0);
    let t : usize = rto + gad.sp_delta as usize;
    &c[rto..t].clone_from_slice(&(gad.words));
    if exchange && (gad.mode == MachineMode::THUMB) {
      /* If we BX, the LSB of the addr decides machine mode */
      c[rto] |= 1;
      println!("*** exchange: adding 1 mask ***");
    }
    rto += gad.ret_offset as usize;
    //spd += gad.sp_delta as usize;
    exchange = gad.exchange;
//    println!("[{}] ==> {}",rto,gad);

  }
  c[..rto].to_vec()
}
#[derive(Clone,Debug)]
pub struct Chain {
  pub clumps: Vec<Clump>, //Arr1K<Clump>, //[Clump; MAX_CHAIN_LENGTH], 
  pub packed: Vec<u8>,
  pub fitness: Option<f32>,
  pub generation: u32,
  pub verbose_tag: bool,
  i: usize,
//  pub ancestral_fitness: Vec<i32>,
  // space-consuming, but it'll give us some useful data on
  // the destructiveness of the crossover operator
}
impl Display for Chain {
  fn fmt (&self, f: &mut Formatter) -> Result {
    let mut s = String::new();
    s.push_str("==================================================\n");
    s.push_str(&format!("Fitness: {:?}\n", self.fitness));
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
      generation: 0,
      verbose_tag: false,
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
#[derive(Debug)]
pub struct Population  {
  pub deme: Vec<Chain>,
  pub best: Option<Chain>,
  pub params: Params,
}

impl Population {
  pub fn new (params: &Params,
              rng: &mut rand::ThreadRng) -> Population {
    let mut clumps = reap_gadgets(&params.code, 
                                  params.code_addr, 
                                  MachineMode::ARM);
    clumps.extend_from_slice(&reap_gadgets(&params.code,
                                           params.code_addr,
                                           MachineMode::THUMB));
    let mut data_pool  = Mangler::new(&params.constants);
    let mut deme : Vec<Chain> = Vec::new();
    for _ in 0..params.population_size{
      deme.push(random_chain(&clumps,
                             params.min_start_len,
                             params.max_start_len,
                             &mut data_pool,
                             rng));
    }
    Population {
      deme: deme,
      best: None,
      params: (*params).clone(),
    }
  }
  pub fn size (&self) -> usize {
    self.deme.len()
  }
  pub fn best_fit (&self) -> Option<f32> {
    match self.best {
      Some(ref x) => x.fitness,
      _           => None,
    }
  }
  pub fn set_best (&mut self, i: usize) {
    self.best = Some(self.deme[i].clone());
  }
}



/*
impl PartialOrd for Pod<Chain> {
  fn partial_cmp (&self, other: &Pod<Chain>) -> Option<Ordering> {
    self.read().unwrap().partial_cmp(other.read().unwrap())
  }
}
impl Ord for Pod<Chain> {
  fn cmp (&self, other: &Pod<Chain>) -> Option<Ordering> {
    self.read().unwrap().cmp(other.read().unwrap())
  }
}
*/
/**** EXPERIMENTAL (but isn't everything?) *****

#[derive(Copy)]
struct Arr1K <T: Copy> {
  elems: [Option<T>; 1024],
  ptr:   usize,
  counter: usize,
}
impl <T: Copy> Clone for Arr1K <T> {
  fn clone (&self) -> Arr1K <T> {
    *self
  }
}
#[derive(Copy)]
struct Arr16 <T: Copy> {
  elems: [Option<T>; 16],
  ptr:   usize,
  counter: usize,
}
impl <T: Copy> Clone for Arr16 <T> {
  fn clone (&self) -> Arr16 <T> {
    *self
  }
}

trait Arr <T> {
  fn len (&self) -> usize;
  fn get (&self, i: usize) -> T;
  fn get_opt (&self, i: usize) -> Option<T>; 
}

impl <T: Copy> Arr1K <T> {
  fn new () -> Arr1K<T> {
    Arr1K {
      elems:   [None; 1024],
      ptr:     0,
      counter: 0,
    }
  }
}
impl <T: Copy> Arr16 <T> {
  fn new () -> Arr16<T> {
    Arr16 {
      elems:   [None; 16],
      ptr:     0,
      counter: 0,
    }
  }
}

impl <T: Copy> Stack <T> for Arr1K <T> {
  fn push (&mut self, t: T) {
    self.ptr += 1;
    self.elems[self.ptr] = Some(t);
  }
  fn pop (&mut self) -> T {
    let p = self.ptr;
    self.ptr -= 1;
    match self.elems[p] {
      Some(e) => e,
      None    => panic!("Nothing left to pop."),
    }
  }
}
impl <T: Copy> Arr <T> for Arr1K <T> {
  fn get_opt (&self, i: usize) -> Option<T> {
    self.elems[i]
  }
  fn get (&self, i: usize) -> T {
    match self.get_opt(i) {
      Some(x) => x,
      None    => panic!("Bad index."),
    }
  }
  fn len (&self) -> usize {
    self.elems.len()
  }
}

impl <T: Copy> Iterator for Arr1K <T> {
  type Item = T;
  
  fn next (&mut self) -> Option<T> {
    let c = self.counter;
    self.counter += 1;
    self.elems[c]
  }

}
impl <T: Copy> Index <usize> for Arr1K <T> {
  type Output = T;
  fn index(&self, index: usize) -> &T {
    &(self.get(index))
  }
}
impl <T: Copy> IndexMut <usize> for Arr1K <T> {
  fn index_mut(&mut self, index: usize) -> &mut T {
    &mut (self.get(index))
  }
}
/*** There must be a better way that cut-and-pasta! ***/
impl <T: Copy> Stack <T> for Arr16 <T> {
  fn push (&mut self, t: T) {
    self.ptr += 1;
    self.elems[self.ptr] = Some(t);
  }
  fn pop (&mut self) -> T {
    let p = self.ptr;
    self.ptr -= 1;
    match self.elems[p] {
      Some(e) => e,
      None    => panic!("Nothing left to pop."),
    }
  }
}

impl <T: Copy> Arr <T> for Arr16 <T> {
  fn get_opt (&self, i: usize) -> Option<T> {
    self.elems[i]
  }
  fn get (&self, i: usize) -> T {
    match self.get_opt(i) {
      Some(x) => x,
      None    => panic!("Bad index."),
    }
  }
  fn len (&self) -> usize {
    self.elems.len()
  }
}

impl <T: Copy> Iterator for Arr16 <T> {
  type Item = T;
  
  fn next (&mut self) -> Option<T> {
    let c = self.counter;
    self.counter += 1;
    self.elems[c]
  }

}
impl <T: Copy> Index <usize> for Arr16 <T> {
  type Output = T;
  fn index(&self, index: usize) -> &T {
    & (self.get(index))
  }
}
impl <T: Copy> IndexMut <usize> for Arr16 <T> {
  fn index_mut(&mut self, index: usize) -> &mut T {
    &mut (self.get(index))
  }
}
******************************************************/
