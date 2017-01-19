#[allow(dead_code)]
extern crate unicorn;
extern crate elf;

use unicorn::*; //{Cpu, CpuARM, uc_handle};
use roper::util::{disas,get_word32le, get_word16le};
use roper::params::MachineMode;

static _DEBUG : bool = true; //true;

static BASE_ADDR  : u64   = 0x000001000;
static MEM_SIZE   : usize = 0x100000000;
static STACK_INIT : u64   = 0x000001000; //0x0E0000000;
static MAX_STEPS  : usize = 0x1000;
static STOP_ADDR  : u64   = 0x00000000;




/**
 * Initializes the engine. Anchors the engine to the
 * lifetime of the text section, since text will be
 * used throughout (generation of gadgets, etc.).
 */
pub fn init_engine <'a,'b> (addr_data_vec: &Vec<(u64, Vec<u8>)>,
                            mode: MachineMode)
                           -> unicorn::CpuARM {
  let uc = CpuARM::new(mode.uc())
    .expect("failed to create emulator engine");
  
  let mo = uc.query(unicorn::Query::MODE).unwrap();
  println!("Initialized. Mode: {:?}, {:?}: {:?}",
           mode, mode.uc(), mo);
  uc.mem_map(BASE_ADDR, MEM_SIZE, unicorn::PROT_ALL)
    .expect("Failed to map memory region");
  
  for pair in addr_data_vec.iter() {
    let &(addr, ref data) = pair;
    uc.mem_write(addr, &data)
      .expect("Error writing .text section to memory.");
  }
  uc
}

pub fn add_hooks (uc: &mut unicorn::CpuARM) {
  if _DEBUG {
    println!("Adding hooks...");
    let callback_c = 
      move |u: &unicorn::Unicorn, addr: u64, size: u32| {
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
        println!("[{:08x}] {} ({}) SP: {:08x} | MODE: {:?} | {}", 
                 addr, inst_str, size, sp, mo, dis);
      };
    // add some hooks if in debugging mode
    uc.add_code_hook(CodeHookType::CODE,
                     BASE_ADDR,
                     BASE_ADDR+(MEM_SIZE as u64),
                     callback_c)
      .expect("Error adding code hook");
  }
}

fn read_registers (uc: &unicorn::CpuARM) -> Vec<i32> {
  let registers : Vec<RegisterARM> = vec![RegisterARM::R0,
                                          RegisterARM::R1,
                                          RegisterARM::R2,
                                          RegisterARM::R3,
                                          RegisterARM::R4,
                                          RegisterARM::R5,
                                          RegisterARM::R6,
                                          RegisterARM::R7,
                                      /*  RegisterARM::R8,
                                       *  RegisterARM::SB,
                          Not used in  *  RegisterARM::SL,
                          Thumb Mode   *  RegisterARM::FP,
                                       *  RegisterARM::IP,
                                       */ RegisterARM::SP,
                                          RegisterARM::LR,
                                          RegisterARM::PC];
  registers.iter().map(|&x| uc.reg_read_i32(x)
                              .expect("Error reading reg"))
                  .collect()
}

fn err_encode (e: Error) -> Vec<i32> {
  // return a vector that gives details on the error/
  // if you need to ask for a ref to the engine, go ahead.
  println!("**** There has been an error: {:?} ****", e);
  vec![0; 11] // dummy. 
}

pub fn hatch_chain <'u,'s> (uc: &mut unicorn::CpuARM, 
                            stack: &Vec<u8>,
                            reg_vec: &Vec<i32>) 
                            -> Vec<i32> {
  uc.mem_write(STACK_INIT, stack)
    .expect("Error initializing stack memory");
  uc.reg_write(RegisterARM::SP, STACK_INIT+4) // pop
    .expect("Error writing SP register");
  let start_addr : u64 = get_word32le(stack, 0) as u64 ; //| 1;
  if let Err(e) = uc.emu_start(start_addr, STOP_ADDR, 0, MAX_STEPS) {
    err_encode(e)
  } else {
    read_registers(&uc)
  }
}
