extern crate unicorn;

use unicorn::*;

pub static REGISTERS : [RegisterARM; 16] = [RegisterARM::R0,
                                            RegisterARM::R1,
                                            RegisterARM::R2,
                                            RegisterARM::R3,
                                            RegisterARM::R4,
                                            RegisterARM::R5,
                                            RegisterARM::R6,
                                            RegisterARM::R7,
                       /****************/   RegisterARM::R8,
                       /****************/   RegisterARM::SB,
                       /* Not used in  */   RegisterARM::SL,
                       /* Thumb Mode   */   RegisterARM::FP,
                       /****************/   RegisterARM::IP,
                       /****************/   RegisterARM::SP,
                                            RegisterARM::LR,
                                            RegisterARM::PC];

pub fn read_registers (uc: &unicorn::Unicorn) -> Vec<i32> {
  REGISTERS.iter().map(|&x| uc.reg_read_i32(x.to_i32())
                              .expect("Error reading reg"))
                  .collect()
}

pub fn set_registers (uc: &unicorn::Unicorn, regs: &Vec<i32>) {
  let n : usize = regs.len();
  assert!(n <= REGISTERS.len());
  for i in 0..n {
    uc.reg_write_i32(REGISTERS[i].to_i32(), regs[i]);
  }
}
