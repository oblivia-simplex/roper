/**
 * Constants and parameters
 */
use rand::Rng;
use unicorn::Mode;
use capstone::CsMode;
use roper::util::{distance};
use std::fmt::{Display,format,Formatter,Result};

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
  pub max_generations  : u32,
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
      population_size:  20,
      mutation_rate:    0.10,
      max_generations:  2000,
      selection_method: SelectionMethod::Tournement,
      t_size:           4,
      code:             Vec::new(),
      code_addr:        0,
      data:             Vec::new(),
      data_addrs:       Vec::new(),
      brood_size:       8,
      min_start_len:    2,
      max_start_len:    16,
      max_len:          256,
      io_targets:       vec![(vec![0; 16], 
                              RPattern { regvals: vec![(0,1),
                                                       (3,0xdeadbeef),
                                                       (7,0x0000baab)]
                                       })], // junk
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

pub type IoTargets = Vec<(Vec<i32>,RPattern)>;

#[derive(Debug,Clone,PartialEq)]
pub struct RPattern { regvals: Vec<(usize,i32)> }
impl RPattern {
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
  pub fn distance (&self, regs: &Vec<i32>) -> i32 {
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
