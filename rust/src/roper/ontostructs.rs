extern crate unicorn;
extern crate rand;
extern crate elf;

use std::mem::size_of;
use std::process::exit;
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
use std::cell::{RefCell,Ref,RefMut};
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
        pub segtype: SegType,
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

#[derive(Copy,Clone,PartialEq,Eq,Debug)]
pub enum SegType {
    Null,
    Load,
    Dynamic,
    Interp,
    Note,
    ShLib,
    PHdr,
    Tls,
    GnuEhFrame,
    GnuStack,
    GnuRelRo,
    Other, /* KLUDGE: a temporary catchall */
}

impl SegType {
    fn new(raw: u32) -> Self {
        match raw {
            0 => SegType::Null,
            1 => SegType::Load,
            2 => SegType::Dynamic,
            3 => SegType::Interp,
            4 => SegType::Note,
            5 => SegType::ShLib,
            6 => SegType::PHdr,
            7 => SegType::Tls,
            0x6474e550 => SegType::GnuEhFrame,
            0x6474e551 => SegType::GnuStack,
            0x6474e552 => SegType::GnuRelRo,
            _ => SegType::Other,
        }
    }
}

pub fn mapped_segtype (t: SegType) -> bool {
    match t {
        SegType::Load |
        SegType::GnuStack => true,
        _ => false,
    }
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
            println!("===> phdr.progtype = {}",phdr.progtype);
            let segtype = SegType::new(phdr.progtype.0);
            println!("= {:?}", segtype);
            match segtype {
                _ => { //SegType::Load | SegType::GnuStack => {
                    let seg = Seg {
                        segtype: segtype,
                        addr: phdr.vaddr as u64,
                        memsz: phdr.memsz as usize,
                        perm: unicorn::Protection::from_bits(phdr.flags.0)
                                              .expect("Failed to convert flags"),
                    };
                    segments.push(seg);
                },/*
                _ => { 
                        println!("[-] skipping segment with segtype {:?}", segtype);
                        println!("{}",phdr);

                        continue 
                }, */
            }
        }
        
        let mut sections : Vec<Sec> = Vec::new();
        
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
pub struct Engine (Arc<RefCell<CpuARM>>);
//unsafe impl Send for Engine {}
unsafe impl Send for Engine {}
impl Engine {
        pub fn new (uc: CpuARM) -> Engine {
            Engine(Arc::new(RefCell::new(uc)))
        }
        pub fn unwrap (&self) -> Ref<CpuARM> {
            (self.0).borrow() //&(*self.0)
        }
        pub fn unwrap_mut (&mut self) -> RefMut<CpuARM> {
            (self.0).borrow_mut()//&mut (*self.0)
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
    // TODO: set stack to actual stack segment
    /* Allocate space for comment, metadata, etc. */
    uc.mem_map(0, 0x1000, PROT_READ);
    /* This shouldn't be hardcoded. Figure out where in elf to get info. */
    for ref seg in segments.iter() {
        /* enforce w xor x */
        match seg.segtype {
            SegType::Load => {
                let mut perm = seg.perm.clone();

                if perm.intersects(PROT_EXEC) {
                    perm.remove(PROT_WRITE);
                }
                if perm.intersects(PROT_WRITE) {
                    perm.remove(PROT_EXEC);
                }
                    
                println!("[*] Mapping segment with size {:x}, addr {:x}, perm {:?} -> {:?}",
                         seg.memsz, seg.addr, seg.perm, perm);
                uc.mem_map(seg.floor(), seg.size(), perm)
                    .expect(&format!("Failed to map segment. Size: {:x}; Addr: {:x}, Perm: {:?}",
                                     seg.memsz, seg.addr, seg.perm));
            },
            _ => {
                println!("[-] Not mapping segment {:?}",seg);
            },
        }
        // paint unused memory with breakpoints
        /*
        let breakpoint : Vec<u8> = vec![0xFE, 0xDE, 0xFF, 0xE7];
        let mut i = seg.floor();
        while i < seg.size() as u64 {
            uc.mem_write(i, &breakpoint);
            i += 4;
        }
        */
    }
    for ref sec in sections.iter() {
        //let &(addr, ref data) = pair
        println!("[*] Writing section named {}, from address {:08x}, with size of {:08x} bytes",
        sec.name, sec.addr, sec.size());
        match uc.mem_write(sec.addr, &sec.data) {
            Ok(x) => { println!("[+] Ok({:?}), wrote {}",x,sec.name); },
            Err(x) => { println!("[x] Failed to write {}, error: {:?}", sec.name, x);},
        }
    }
    //uc.mem_map(BASE_STACK, STACK_SIZE, PROT_READ|PROT_WRITE)
    //    .expect("Failed to map stack memory");
    let regions = uc.mem_regions().unwrap();
    let mut bottom = 0;
    for region in &regions {
        if region.end > bottom { bottom = region.end + 1; }; 
    }
    println!("[*] Mapping stack space of 0x{:x} bytes at 0x{:x}...", STACK_SIZE, bottom);
    let res = uc.mem_map(bottom, STACK_SIZE, PROT_READ|PROT_WRITE);
    match res {
        Ok(x) => { println!("[+] Ok({:?}), allocated stack",x); },
        Err(x) => { println!("[x] Error allocating stack: {:?}", x); }
    }
    let regions = uc.mem_regions().unwrap();
    println!("REGIONS:\n{:?}",regions);
    for region in &regions {
        println!("{:08x} -- {:08x} ({:?})", region.begin, region.end, region.perms);
    }
    println!("ok, engine initialized");
    let stack = find_stack(&uc);
    println!("Stack found: {:08x} -- {:08x} ({:?})", stack.begin, stack.end, stack.perms);
    //exit(99);
    uc
}

pub fn find_stack (uc: &CpuARM) -> MemRegion {
    let mut bottom : Option<u64> = None;
    let mut stack : Option<MemRegion> = None;
    let regions = &uc.mem_regions().unwrap();
    for region in regions.iter() {
        if region.perms.intersects(PROT_READ | PROT_WRITE) &&
           region.begin >= bottom.unwrap_or(0) {
               bottom = Some(region.begin);
               stack  = Some(region.clone());
           };
    }
    stack.expect(&format!("[!] Could not find stack bottom! Regions: {:?}",regions))
}
