extern crate unicorn;
extern crate rand;
extern crate elf;

use elf::types::*;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use roper::hatchery::*;
use roper::util::*;
use roper::phylostructs::*;
use unicorn::*;
use std::thread;
use rand::thread_rng;
use std::rc::Rc;
use std::cell::RefCell;
use std::sync::Arc;

pub static _DEBUG : bool = true; //true;

/* don't hard code these, read them from the elf */
pub const BASE_ADDR  : u64   = 0x000004000;
pub const MEM_SIZE   : usize = 0x010000000;
pub const BASE_STACK : u64   = 0x000000000;
pub const STACK_SIZE : usize = 0x000004000;
pub const STACK_INIT : u64   = 0x000001000; //0x0E0000000;
pub const MAX_STEPS  : usize = 0x800;
pub const STOP_ADDR  : u64   = 0x000000000;

pub trait PageAligned {
    fn floor (&self) -> u64;
    fn ceil  (&self) -> u64;
    fn size  (&self) -> usize;
}

#[derive(Debug,Clone)]
pub struct Seg {
        pub addr: u64, // virtual addr
        pub memsz: usize,
        pub perm: unicorn::Protection,
}
impl PageAligned for Seg {
        fn floor (&self) -> u64 {
            self.addr & 0xFFFFF000
        }
        fn ceil (&self) -> u64 {
            (self.addr + (self.memsz as u64) + 0x1000) & 0xFFFFF000
        }
        fn size (&self) -> usize {
            ((self.addr as usize & 0xFFF) + self.memsz as usize + 0x1000) & 0xFFFFF000
        }
}
#[derive(Debug,Clone)]
pub struct Sec {
        pub name: String,
        pub addr: u64,
        pub data: Vec<u8>,
        pub perm: unicorn::Protection,
}
impl PageAligned for Sec {
        fn floor (&self) -> u64 {
            self.addr & 0xFFFFF000
        }
        fn ceil (&self) -> u64 {
            (self.addr + (self.data.len() as u64) + 0x1000) & 0xFFFFF000
        }
        fn size (&self) -> usize {
            ((self.addr as usize & 0xFFF) + self.data.len() + 0x1000) & 0xFFFFF000
        }
}

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

const GBA_CARTRIDGE_ROM_START : u64 = 0x08000000;

fn load_file (path: &str) -> Vec<u8> {
        let mut f = File::open(path)
                                    .expect("Failed to open path");
        let mut buf : Vec<u8> = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
}

pub fn sec_is_exec (sec: &Sec, segs: &Vec<Seg>) -> bool {
    for seg in segs {
        if seg.perm & PROT_EXEC == PROT_NONE {
            continue; /* this segment isn't executable. skip it. */
        };
        if sec.addr >= seg.addr
           && sec.addr + sec.data.len() as u64 <= seg.addr + seg.memsz as u64 {
               return true;
        };
    }
    false
}

pub fn get_elf_addr_data (path: &str) 
                      -> (Vec<Sec>,Vec<Seg>) {
        let path = PathBuf::from(path);
        let file = match elf::File::open_path(&path) {
            Ok(f) => f,
            Err(e) => panic!("Error: {:?}",e),
        };
        let mut segments : Vec<Seg> = Vec::new();
        for phdr in file.phdrs.iter() {
            if phdr.progtype != PT_LOAD { continue };
            println!("===> phdr.progtype = {:?}",phdr.progtype);
            let seg = Seg {
                addr: phdr.vaddr,
                memsz: phdr.memsz as usize,
                // let's make the segments unwriteable by default
                // to add to the challenge, and ensure fast fails
                perm: unicorn::Protection::from_bits(phdr.flags.0)
                    .expect("Failed to convert permission flags") ^ unicorn::PROT_WRITE, //unicorn::PROT_ALL, // { phdr.flags.0 },
            };
            segments.push(seg);
        }
        
        let mut sections : Vec<Sec> = Vec::new();
        //for sec_name in secs.iter() {
        //    let sec = file.get_section(sec_name).expect("Unable to fetch section from elf");
        for sec in file.sections.iter() {
            println!("===> sec.shdr: {:?}", sec.shdr);
            let s = Sec {
                name: sec.shdr.name.to_string(),
                addr: sec.shdr.addr,
                data: sec.data.clone(),
                perm: unicorn::Protection::from_bits((sec.shdr.flags.0 & 0xFF) as u32)
                      .unwrap_or(unicorn::Protection::from_bits(0).unwrap()),
            };
            sections.push(s);
        }
        

        (sections,segments)
}
/* A struct to bundle together mutable machinery 
  * Each thread should have its own instance.
  */
pub struct Machinery {
//  pub rng: rand::ThreadRng,
        pub cluster:  Vec<Engine>,
        //pub mangler: Mangler,
}

/* Try to replace this with a safe data structure */
/* Cf. the Rc<RefCell<_>> construction in the hatch_chain callback */
pub struct Engine (Box<CpuARM>);
//unsafe impl Send for Engine {}
impl Send for Engine {}
impl Engine {
        pub fn new (uc: CpuARM) -> Engine {
            Engine(Box::new(uc))
        }
        pub fn unwrap (&self) -> &CpuARM {
            &(*self.0)
        }
        pub fn unwrap_mut (&mut self) -> &mut CpuARM {
            &mut (*self.0)
        }
}

impl Machinery {
        pub fn new (elf_path: &str, 
                                mode: MachineMode,
                                uc_num: usize,
                                debug: bool) -> Machinery {
            let (elf_sections,elf_segments) = get_elf_addr_data(elf_path);
                                                                
            let mut cluster = Vec::new();
            for i in 0..uc_num {
                println!("spinning up engine #{}",i);
                let mut uc = init_engine(&elf_sections, &elf_segments, mode);
                //if debug {
                //  add_debug_hooks(&mut uc);
                //}
                cluster.push(Engine::new(uc));
            }
            Machinery { 
                cluster: cluster, 
            }
        }
}
