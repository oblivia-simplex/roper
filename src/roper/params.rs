/**
 * Constants and parameters
 */
extern crate rand;
use rand::*;
use unicorn::Mode;
use capstone::CsMode;
use roper::util::{distance};
use std::fmt::{Display,format,Formatter,Result};
use std::collections::HashMap;

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
  pub population_size  : u32,
  pub mutation_rate    : f32,
  pub max_generations  : usize,
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
/*  pub ro_data_data     : Vec<u8>,
  pub ro_data_addr     : u32,
  pub text_data        : Vec<u8>,
  pub text_addr        : u32,
  */
  pub io_targets       : IoTargets,
}
impl Default for Params {
  fn default () -> Params {
    Params {
      population_size:  2000,
      mutation_rate:    0.30,
      max_generations:  2000,
      selection_method: SelectionMethod::Tournement,
      t_size:           4,
      code:             Vec::new(),
      code_addr:        0,
      data:             Vec::new(),
      data_addrs:       Vec::new(),
      brood_size:       2,
      min_start_len:    2,
      max_start_len:    16,
      max_len:          256,
      training_ht:      HashMap::new(),
      io_targets:       Vec::new(),
      fit_goal:         0.0,  
    //                         (vec![1; 16],
      //                        RPattern { regvals: vec![(0,0xdead)]})], // junk
      constants:        Vec::new(),
    }
    // io_targets needs its own datatype. as it stands, it's kind
    // of awkward. 
  }
}
impl Params {
  pub fn new () -> Params {
    Default::default()
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

pub type IoTargets = Vec<(Vec<i32>,Target)>;

pub fn suggest_constants (iot: &IoTargets) -> Vec<u32> {
  let mut cons : Vec<u32> = Vec::new();
  for &(ref i, ref o) in iot {
    cons.extend_from_slice(&o.suggest_constants(i));
  }
  cons
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
    distance(&i, &o)
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
