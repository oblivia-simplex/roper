#[allow(dead_code)]
extern crate unicorn;
extern crate elf;

use std::fs::{File,OpenOptions};
use std::io::prelude::*;
use elf::*;
use unicorn::*; //{Cpu, CpuARM, uc_handle};
use roper::util::{disas,get_word32le, get_word16le, hexvec};
use roper::phylostructs::MachineMode;
use std::fmt::{Display,format,Formatter,Result};
use roper::ontostructs::*;
//use roper::hooks::*;
//use roper::unitools::*;


/*
fn elf_perm_to_uc (elf_perm: ProgFlag) -> unicorn::Protection {
  match elf_perm {
    // Note that the only difference is the order of bits. Why?
    PF_NONE => PROT_NONE,  // 0 -> 0
    PF_X    => PROT_EXEC,  // 1 -> 4
    PF_W    => PROT_WRITE, // 2 -> 2
    PF_R    => PROT_READ,  // 4 -> 1 
  }
}
*/
pub fn read_registers (uc: &unicorn::Unicorn) -> Vec<i32> {
  REGISTERS.iter().map(|&x| uc.reg_read_i32(x.to_i32())
                              .expect("Error reading reg"))
                  .collect()
}

pub fn set_registers (uc: &unicorn::Unicorn, 
                      input: &Vec<i32>,
                      inregs: &Vec<usize>) {
  let mut in_ptr = 0;
  for i in 0..REGISTERS.len() {
    let val = if in_ptr < inregs.len() && i == inregs[in_ptr] { 
      in_ptr += 1;
      input[in_ptr-1] 
    } else { 
      0
    };
    uc.reg_write_i32(REGISTERS[i].to_i32(), val);
  }
}
/**
 * Initializes the engine. Anchors the engine to the
 * lifetime of the text section, since text will be
 * used throughout (generation of gadgets, etc.).
 */
pub fn init_engine <'a,'b> (sections: &Vec<Sec>,//<(u64, Vec<u8>)>,
                            segments: &Vec<Seg>,
                            mode: MachineMode)
                           -> unicorn::CpuARM {
  let uc = CpuARM::new(mode.uc())
    .expect("failed to create emulator engine");
  
  let mo = uc.query(unicorn::Query::MODE).unwrap();
  println!("[*] Initialized. Mode: {:?}, {:?}: {:?}",
           mode, mode.uc(), mo);
  // next: map text and rodata separately
  // we need a smoother interface between the elf module and unicorn
  uc.mem_map(BASE_STACK, STACK_SIZE, PROT_READ|PROT_WRITE)
    .expect("Failed to map stack memory");
 
  for ref seg in segments.iter() {
    println!("[*] Mapping segment with size {:x}, addr {:x}, perm {:?}", seg.memsz, seg.addr, seg.perm);
    uc.mem_map(seg.floor(), seg.size(), seg.perm)
      .expect(&format!("Failed to map segment. Size: {:x}; Addr: {:x}, Perm: {:?}", seg.memsz, seg.addr, seg.perm));
    // paint unused memory with breakpoints
    let breakpoint : Vec<u8> = vec![0xFE, 0xDE, 0xFF, 0xE7];
    let mut i = seg.floor();
    while i < seg.size() as u64 {
      uc.mem_write(i, &breakpoint);
      i += 4;
    }
  }
  for ref sec in sections.iter() {
    //let &(addr, ref data) = pair
    println!("[*] Writing section named {}, from address {:08x}, with size of {:08x} bytes",
      sec.name, sec.addr, sec.size());
    uc.mem_write(sec.addr, &sec.data)
      .expect(&format!("Error writing {} section to memory", sec.name));
  }
  println!("ok, engine initialized");
  uc
}

pub fn add_debug_hooks (uc: &mut unicorn::CpuARM) {
  if _DEBUG {
    println!("Adding hooks...");
    let callback_c = 
    // add some hooks if in debugging mode
    uc.add_code_hook(CodeHookType::CODE,
                     BASE_ADDR,
                     BASE_ADDR+(MEM_SIZE as u64),
                     debug_hook)
      .expect("Error adding code hook");
  }
}


fn err_encode (e: Error) -> ErrorCode {
  // if you need to ask for a ref to the engine, go ahead.
//  println!("**** ERROR IN EMULATION ****\n");
  0.5 // placeholder. assign int to each error?
}

fn mk_zerostack(n: usize) -> Vec<u8> 
{
  let mut z : Vec<u8> = Vec::new();
  for _ in 0..n {
    z.push(0);
  }
  z
}

pub fn hatch_chain <'u,'s> (uc: &mut unicorn::CpuARM, 
                            stack: &Vec<u8>,
                            input: &Vec<i32>,
                            inregs:  &Vec<usize>) 
                            -> HatchResult {
                            //Vec<i32> {
  // Iinitalize the registers with reg_vec. This is input.
  // For single-case runs, it might just be set to 0..0. 
  let zerostack = vec![0; STACK_SIZE]; //mk_zerostack(STACK_SIZE);
  set_registers(uc.emu(), &input, &inregs);
  reset_counter(uc);
  uc.mem_write(BASE_STACK, &zerostack)
    .expect("Error zeroing out stack");
  uc.mem_write(STACK_INIT, stack)
    .expect("Error initializing stack memory");
  uc.reg_write(RegisterARM::SP, STACK_INIT+4) // pop
    .expect("Error writing SP register");
  let start_addr : u64 = get_word32le(stack, 0) as u64 ; //| 1;
  let ee = uc.emu_start(start_addr, STOP_ADDR, 0, MAX_STEPS);
  let e = match ee {
    Err(e) => Some(err_encode(e)),
    _      => None,
  };
  HatchResult { registers: read_registers(&(uc.emu())),
                error: e,
                counter: read_counter(uc),
  }
}

type ErrorCode = f32;
#[derive(Debug,Clone)]
pub struct HatchResult {
  pub registers : Vec<i32>,
  pub error     : Option<ErrorCode>,
  pub counter   : usize,
}
impl Display for HatchResult {
  fn fmt (&self, f: &mut Formatter) -> Result {
    let mut s = String::new();
    s.push_str("REG: ");
    s.push_str(&hexvec(&self.registers));
    s.push_str(&format!("\nCNT: {}", self.counter));
    s.push_str(&format!("\nERR: {:?}", self.error));
    write!(f, "{}\n", s)
  }
}
// *** HOOKS ***

pub const COUNTER_ADDR : u64 = 0x124;

/* Increments a counter located at COUNTER_ADDR, which point to
 * a location in writeable/readable memory that's unlikely to be
 * overwritten.
 */
pub fn counter_hook (u: &Unicorn, addr: u64, size: u32) {
  let n : usize = read_counter_u(u) + 1;
  let v : Vec<u8> = vec![(n & 0xFF) as u8, ((n & 0xFF00)>>8) as u8];
  // println!(":::: counter {} :::: {:?}", n, v);
  u.mem_write(COUNTER_ADDR, &v)
   .expect("Error incrementing counter with mem_write.");
}

/* make generic */
pub fn read_counter_u (u: &Unicorn) -> usize {
  let v = u.mem_read(COUNTER_ADDR, 2).unwrap();
  let n : u16 = v[0] as u16; // | ((v[1] as u16) << 8);
  n as usize
}

pub fn read_counter (u: &CpuARM) -> usize {
  let v = u.mem_read(COUNTER_ADDR, 2).unwrap();
  let n : u16 = v[0] as u16; //| ((v[1] as u16) << 8);
  n as usize
}

pub fn reset_counter (u: &CpuARM) {
  u.mem_write(COUNTER_ADDR, &[0,0,0,0]);
//  println!(">>>> Reset counter: {}", read_counter(u));
}

pub fn debug_hook (u: &unicorn::Unicorn, addr: u64, size: u32) {
  let sp : u64 = u.reg_read(RegisterARM::SP.to_i32())
                  .expect("Error reading SP");
  let instv : Vec<u8> = u.mem_read(addr, size as usize)
                        .expect("Error reading inst.");
//  let mut inst_str = String::new();
//  for i in &instv {
//    inst_str.push_str(&format!("{:02x} ",i));
//  }
  //let inst = get_word32le(&instv);
  let mo = u.query(unicorn::Query::MODE).unwrap();
  let mmo = if mo == 0 {MachineMode::ARM} 
            else {MachineMode::THUMB};
  let dis = disas(&instv, mmo);
  let regs = hexvec(&read_registers(u));
  // write to file instead. single name. but have wrapper
  // script rename it afterwards, as a silly kludge.
  let path = "/tmp/roper_disassembly.txt";
  
  /*let mut dfile = OpenOptions::new()
                              .append(true)
                              .write(true)
                              .create(true)
                              .open(&path)
                              .unwrap();
                              */
  let row = format!("({:02x})-[{:08x}] | {:?} | {}\n    {}\n", read_counter_u(u), addr, mmo, dis, regs);
  println!("{}",row);
  //dfile.write(&row.as_bytes()).unwrap();
}

