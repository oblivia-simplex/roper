extern crate unicorn; 

use unicorn::*;
use roper::util::*;
use roper::hatchery::*;
use unicorn::*;
use roper::params::*;
use roper::unitools::*;

pub const COUNTER_ADDR : u64 = 0x100;

/* Increments a counter located at COUNTER_ADDR, which point to
 * a location in writeable/readable memory that's unlikely to be
 * overwritten.
 */
pub fn counter_hook (u: &Unicorn, addr: u64, size: u32) {
  let n : usize = read_counter_u(u) + 1;
  let v : Vec<u8> = vec![(n & 0xFF) as u8, ((n & 0xFF00) >> 8) as u8];
  u.mem_write(COUNTER_ADDR, &v)
   .expect("Error incrementing counter with mem_write.");
}

/* make generic */
pub fn read_counter_u (u: &Unicorn) -> usize {
  let v = u.mem_read(COUNTER_ADDR, 2).unwrap();
  let n : u16 = v[0] as u16 | ((v[1] as u16) << 8);
  n as usize
}
pub fn read_counter (u: &CpuARM) -> usize {
  let v = u.mem_read(COUNTER_ADDR, 2).unwrap();
  let n : u16 = v[0] as u16 | ((v[1] as u16) << 8);
  n as usize
}

pub fn reset_counter (u: &CpuARM) {
  u.mem_write(COUNTER_ADDR, &[0,0]);
}

pub fn debug_hook (u: &unicorn::Unicorn, addr: u64, size: u32) {
  let sp : u64 = u.reg_read(RegisterARM::SP.to_i32())
                  .expect("Error reading SP");
  let instv : Vec<u8> = u.mem_read(addr, size as usize)
                        .expect("Error reading inst.");
  let mut inst_str = String::new();
  for i in &instv {
    inst_str.push_str(&format!("{:02x} ",i));
  }
  //let inst = get_word32le(&instv);
  let mo = u.query(unicorn::Query::MODE).unwrap();
  let mmo = if mo == 0 {MachineMode::ARM} 
            else {MachineMode::THUMB};
  let dis = disas(&instv, mmo);
  let regs = hexvec(&read_registers(u));
  println!("({:02x})-[{:08x}] {} ({}) SP: {:08x} | MODE: {:?} | {}\n    {}", 
           read_counter_u(u), addr, inst_str, size, sp, mo, dis, regs);
}

