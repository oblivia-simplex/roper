extern crate unicorn;

use unicorn::*;


pub fn read_registers (uc: &unicorn::Unicorn) -> Vec<i32> {
  let registers : Vec<RegisterARM> = vec![RegisterARM::R0,
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
  registers.iter().map(|&x| uc.reg_read_i32(x.to_i32())
                              .expect("Error reading reg"))
                  .collect()
}
