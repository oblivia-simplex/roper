/**
 * Constants and parameters
 */
use rand::Rng;
use unicorn::Mode;
use capstone::CsMode;

type dword = u32;
type halfword = u16;
type byte = u8;

#[derive(PartialEq,Debug)]
pub enum SelectionMethod {
  tournement,
  roulette,
}

#[derive(PartialEq,Debug)]
pub struct Params {
  pub population_size  : u32,
  pub mutation_rate    : f32,
  pub max_generations  : u32,
  pub selection_method : SelectionMethod,
  pub t_size           : usize,
  pub code             : Vec<u8>,
  pub data             : Vec<Vec<u8>>,
  pub brood_size       : usize,
/*  pub ro_data_data     : Vec<u8>,
  pub ro_data_addr     : u32,
  pub text_data        : Vec<u8>,
  pub text_addr        : u32,
  */
  pub io_targets       : Vec<(Vec<i32>,Vec<i32>)>,
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

