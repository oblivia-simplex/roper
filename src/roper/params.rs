/**
 * Constants and parameters
 */
use rand::Rng;

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
  pub ro_data_32       : Vec<u32>,
  pub ro_data_addr     : u32,
  pub text_32          : Vec<u32>,
  pub text_addr        : u32,
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
impl Default for MachineMode {
  fn default() -> MachineMode { MachineMode::THUMB }
}
pub const MAX_VISC : i32 = 100;
pub const MIN_VISC : i32 = 0;
pub const RIPENING_FACTOR : i32 = 4;
pub const MAX_FIT : i32 = 1000;
