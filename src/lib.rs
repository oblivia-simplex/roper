pub mod hatchery {
  extern crate unicorn;
  extern crate elf;
  extern crate byteorder;

  use self::unicorn::*; //{Cpu, CpuARM, uc_handle};
  //use elf::*;
  //use unicorn::*;
  //use byteorder::*;


  static _DEBUG : bool = false; //true;

  static BASE_ADDR  : u64   = 0x00000000;
  static MEM_SIZE   : usize = 0x80000000;
  static STACK_INIT : u64   = 0x4000;
  static MAX_STEPS  : usize = 0x1000;
  static STOP_ADDR  : u64 = 0;


  fn get_word32le (a: &Vec<u8>) -> u32 {
    let mut s : u32 = 0;
    for i in 0..4 {
      s |= (a[i] as u32) << (i*8);
    }
    s
  }
  fn get_word16le (a: &Vec<u8>) -> u16 {
    let mut s : u16 = 0;
    for i in 0..2 {
      s |= (a[i] as u16) << (i*8);
    }
    s
  }

  fn callback_fn (u: &Unicorn, addr: u64, _: u32) {
    println!("[{:08x}]", addr);
    //u.emu_stop();
  }

  /**
   * Initializes the engine. Anchors the engine to the
   * lifetime of the text section, since text will be
   * used throughout (generation of gadgets, etc.).
   */
  pub fn init_engine <'a,'b> (text: &elf::Section 
                             ,rodata: &elf::Section) 
                             -> unicorn::CpuARM {

    let text_addr : u64 = text.shdr.addr;

    let rodata_addr : u64 = rodata.shdr.addr;
    
    let uc = CpuARM::new(unicorn::THUMB)
      .expect("failed to create emulator engine");
    
    uc.mem_map(BASE_ADDR, MEM_SIZE, unicorn::PROT_ALL)
      .expect("Failed to map memory region");
    
    uc.mem_write(text_addr, &text.data)
      .expect("Error writing .text section to memory.");
    uc.mem_write(rodata_addr, &rodata.data)
      .expect("Error writing .rodata section to memory.");

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
          let inst = get_word32le(&instv);
          println!("[{:08x}] {:08x} SP: {:08x}", addr, inst, sp);
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

  pub fn hatch_chain <'u,'s> (uc: &mut unicorn::CpuARM, 
                              stack: &Vec<u8>) 
                              -> Vec<i32> {
    uc.mem_write(STACK_INIT, stack)
      .expect("Error initializing stack memory");
    uc.reg_write(RegisterARM::SP, STACK_INIT+4) // pop
      .expect("Error writing SP register");
    let start_addr : u64 = get_word32le(stack) as u64;
    uc.emu_start(start_addr, STOP_ADDR, 0, MAX_STEPS)
      .expect("Error running emulation");
    read_registers(&uc)
  }
}

pub mod thumb {
  
  #[derive(PartialEq, Debug, Clone, Copy)]
  pub enum Lay {
    SWI,
    ASP,
    ALU,
    HROB,
    AS,
    MSR,
    MCAS,
    PCRL,
    LSSE,
    LSRO,
    LSIO,
    LSHW,
    SPLS,
    LA,
    PPR,
    MLS,
    CB,
    UB,
    LBL,
    RAWDATA,
  }
  
  // move this later
  pub fn mask16 (w: u16, lo: u16, hi: u16) -> u16 {
    if lo > hi { panic!("Error in mask16: lo > hi"); }
    ((2^hi-1) & w) >> lo
  }

  pub fn what_layout (w: u16) -> Lay {
    match mask16(w, 8, 16) {
      0xdf => Lay::SWI,
      0xb0 => Lay::ASP,
      _    => 
        match mask16(w,10,16) {
          0x08 => Lay::ALU,
          0x09 => Lay::HROB,
          _    => 
            match mask16(w,11,16) {
              0x03 => Lay::AS,
              0x09 => Lay::PCRL,
              0x1c => Lay::UB,
              _    => 
                match mask16(w,12,16) {
                  0x05 => if (1 << 9) & w != 0
                            { Lay::LSSE } else { Lay::LSRO },
                  0x08 => Lay::LSHW,
                  0x09 => Lay::SPLS,
                  0x0a => Lay::LA,
                  0x0b if mask16(w,9,11) == 0x02 => Lay::PPR,
                  0x0c => Lay::MLS,
                  0x0d => Lay::CB,
                  0x0f => Lay::LBL,
                  _    => 
                    match mask16(w,13,16) {
                      0x00 => Lay::MSR,
                      0x01 => Lay::MCAS,
                      0x03 => Lay::LSIO,
                      _    => Lay::RAWDATA,
                    },
                },
            },
        },
    }
  }



}

