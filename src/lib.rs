pub mod hatchery {
  extern crate unicorn;
  extern crate elf;
  extern crate byteorder;

  use self::unicorn::{Cpu, CpuARM, uc_handle};
  //use elf::*;
  //use unicorn::*;
  //use byteorder::*;


  static _DEBUG : bool = true;

  static BASE_ADDR : u64 = 0x00000000;
  static MEM_SIZE  : usize = 0x40000000;

  pub fn init_engine <'a,'b> (text: &elf::Section 
                     ,rodata: &elf::Section) 
                     -> unicorn::CpuARM {

    let text_addr : u64 = text.shdr.addr;
    let text_size : u64 = text.shdr.size;

    let rodata_addr : u64 = rodata.shdr.addr;
    let rodata_size : u64 = rodata.shdr.size;
    
    let uc = CpuARM::new(unicorn::LITTLE_ENDIAN)
      .expect("failed to create emulator engine");

    
    uc.mem_map(BASE_ADDR, MEM_SIZE, unicorn::PROT_ALL)
      .expect("Failed to map memory region");
    
    if _DEBUG {
    }

    uc.mem_write(text_addr, &text.data)
      .expect("Error writing .text section to memory.");
    uc.mem_write(rodata_addr, &rodata.data)
      .expect("Error writing .rodata section to memory.");

    uc
  }

}    

  /*
  fn hatch_chain (uc: &unicorn::CpuARM, stack: &[u8]) -> [u64; 16] {
    
    // do the thing:
    //let start_addr = read_u64(stack);
    //println!("start_addr: {}", start_addr);
    // assume uc is already prepared
  }
  */



