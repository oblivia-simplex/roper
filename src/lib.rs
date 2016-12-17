pub mod hatchery {
  extern crate unicorn;
  extern crate elf;
  extern crate byteorder;

  use self::unicorn::*; //{Cpu, CpuARM, uc_handle};
  //use elf::*;
  //use unicorn::*;
  //use byteorder::*;


  static _DEBUG : bool = true;

  static BASE_ADDR  : u64 = 0x00000000;
  static MEM_SIZE   : usize = 0x40000000;
  static STACK_INIT : u64 = 0x4000;
  static MAX_STEPS  : usize = 0x1000;
  static STOP_ADDR  : u64 = 0;

  fn get_word32le (a: &Vec<u8>) -> u32 {
    let mut s : u32 = 0;
    for i in 0..4 {
      s |= (a[i] as u32) << (i*8);
    }
    s
  }

  pub fn init_engine <'a,'b> (text: &elf::Section 
                     ,rodata: &elf::Section) 
                     -> unicorn::CpuARM {

    let text_addr : u64 = text.shdr.addr;
    //let text_size : u64 = text.shdr.size;

    let rodata_addr : u64 = rodata.shdr.addr;
    //let rodata_size : u64 = rodata.shdr.size;
    
    let uc = CpuARM::new(unicorn::MODE_ARM)
      .expect("failed to create emulator engine");

    
    uc.mem_map(BASE_ADDR, MEM_SIZE, unicorn::PROT_ALL)
      .expect("Failed to map memory region");
    
    //if _DEBUG {
    //}

    uc.mem_write(text_addr, &text.data)
      .expect("Error writing .text section to memory.");
    uc.mem_write(rodata_addr, &rodata.data)
      .expect("Error writing .rodata section to memory.");

    uc
  }



  
  pub fn hatch_chain (uc: &mut unicorn::CpuARM, 
                  stack: &Vec<u8>) 
                  -> Vec<u64> {
    
    uc.mem_write(STACK_INIT, stack)
      .expect("Error initializing stack memory");
    uc.reg_write(RegisterARM::SP, STACK_INIT+4) // pop
      .expect("Error writing SP register");
    let start_addr : u64 = get_word32le(stack) as u64;
    if _DEBUG {
      println!("stack > {:?}", stack);
      println!("start_addr > {:08x}", start_addr);
    }
    //uc.reg_write(RegisterARM::PC, start_addr)
    //  .expect("Error writing PC register");
    uc.emu_start(start_addr, STOP_ADDR, 0, MAX_STEPS)
      .expect("Error running emulation");
    // do the thing:
    //let start_addr = read_u64(stack);
    //println!("start_addr: {}", start_addr);
    // assume uc is already prepared
    let dummy = vec![0; 16];
    dummy 
  }


}
