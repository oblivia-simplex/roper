/**
 * Constants and parameters
 */

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
  pub mutation_rates   : MutRates,
  pub population_size  : u32,
  pub max_generations  : u32,
  pub selection_method : SelectionMethod,
  pub code             : Vec<u8>,
  pub data             : Vec<Vec<u8>>,
}


#[derive(PartialEq,Debug)]
pub struct MutRates {
  pub general : f32,
  pub imm_mut : f32, // vs reg_mut
  pub x_over  : f32, // vs mutation
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Endian {
  LITTLE,
  BIG,
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum MachineMode {
  THUMB,
  ARM,
}
