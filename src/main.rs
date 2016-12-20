#[allow(dead_code)]
extern crate elf;
extern crate unicorn;
extern crate capstone;
use std::path::PathBuf;
use unicorn::*;
// use std::io;
use capstone::instruction::Instructions;
use capstone::constants::{CsMode,CsArch};
use roper::dis::{disas_sec,Inst};
mod roper;

/* Just a debugging stub */
fn main() {
  // get the 
  let path = PathBuf::from("/home/oblivia/Projects/roper/data/openssl");
  let file = match elf::File::open_path(&path) {
    Ok(f)  => f,
    Err(e) => panic!("Error: {:?}", e),
  };

  let text  = match file.get_section(".text") {
    Some(s) => s,
    None    => panic!("Failed to look up .text section"),
  };

  let rodata = match file.get_section(".rodata") {
    Some(s) => s,
    None    => panic!("Failed to look up .rodata section"),
  };
  
  //let () = text;
  println!("text addr: {:?}, size: {:?}", 
           text.shdr.addr, text.shdr.size);

  /**************** Testing out Capstone *******************
  let cs_mode = CsMode::MODE_THUMB;
  let cs_mode_s = "Thumb";
  let dissed : Vec<Inst>
      = disas_sec(text, 
                  CsArch::ARCH_ARM, 
                  cs_mode);
  println!("{:?} instructions in {:?}",
           dissed.len(), cs_mode_s);
  let mut length = 0;
  for inst in dissed.iter() {
    let mnemonic = &inst.mnem;
    println!("{:x} > {:08x} {} {:?} {:?}",
             length,
             inst.addr,
             mnemonic,
             inst.src,
             inst.dst,);
  }
  *********************************************************/
  let mut uc = roper::init_engine(text, rodata);
  roper::add_hooks(&mut uc);
  
  
  let regions = uc.mem_regions()
    .expect("failed to retrieve memory regions");
  println!("Regions: {}", regions.len());
  for region in &regions {
    println!("> {:?}", region);
  }

  let pc = uc.reg_read(RegisterARM::PC)
    .expect("Failed to read register");
  println!("PC BEFORE >  {:08x}", pc);

  let phony_stack : Vec<u8> = vec![0x20,0x01,0x01,0x00,4,8,4,8];
  let ret : Vec<i32> = roper::hatch_chain(&mut uc, &phony_stack);
  println!("REGISTERS:\n{}", roper::hexvec(&ret));
  let pc = uc.reg_read(RegisterARM::PC)
    .expect("Failed to read register");
  println!("PC AFTER >   {:08x}", pc);

  for _ in 0..40 { print!("*"); }
  println!("\n  Round Two");
  for _ in 0..40 { print!("*"); }
  println!("");
  let ret2 : Vec <i32> = roper::hatch_chain(&mut uc, &phony_stack);
  println!("REGISTERS:\n{}", roper::hexvec(&ret2));

  let page_size = uc.query(unicorn::Query::PAGE_SIZE)
    .expect("Failed to query page size");
  let hardware_mode = uc.query(unicorn::Query::MODE)
    .expect("Failed to query hardware mode");
    println!(">> page size:     {}", page_size);
    println!(">> hardware mode: {}", hardware_mode);
}
