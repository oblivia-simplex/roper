extern crate roper;
extern crate elf;
extern crate unicorn;

use std::path::PathBuf;
use roper::hatchery::*;
use unicorn::*;

// use std::io;

/* Just a debugging stub */
fn main() {
  // get the 
  let path = PathBuf::from("data/ldconfig.real");
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
  println!("text addr: {:?}, size: {:?}", text.shdr.addr, text.shdr.size);

  let mut uc = init_engine(text, rodata);
  
  
  let regions = uc.mem_regions()
    .expect("failed to retrieve memory regions");
  println!("Regions: {}", regions.len());
  for region in &regions {
    println!("> {:?}", region);
  }

  let pc = uc.reg_read(RegisterARM::PC)
    .expect("Failed to read register");
  println!("PC BEFORE >  {:08x}", pc);

  let phony_stack : Vec<u8> = vec![4,2,4,8,16,32,64,128];
  hatch_chain(&mut uc, &phony_stack);
  
  let pc = uc.reg_read(RegisterARM::PC)
    .expect("Failed to read register");
  println!("PC AFTER >   {:08x}", pc);
  /*
  let page_size = uc.query(unicorn::Query::PAGE_SIZE)
    .expect("Failed to query page size");
  let hardware_mode = uc.query(unicorn::Query::MODE)
    .expect("Failed to query hardware mode");
    println!(">> page size:     {}", page_size);
    println!(">> hardware mode: {}", hardware_mode);
    */
}
