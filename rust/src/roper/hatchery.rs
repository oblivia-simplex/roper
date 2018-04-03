#[allow(dead_code)]
extern crate unicorn;
extern crate elf;

use std::collections::HashSet;
use std::collections::HashMap;
use std::iter::FromIterator;
use std::rc::Rc;
use std::cell::RefCell;
use std::cell::RefMut;
use std::thread;
use std::fs::{File,OpenOptions};
use std::io::prelude::*;
use elf::*;
use unicorn::*; //{Cpu, CpuARM, uc_handle};
use roper::util::{disas,
                  get_word32le,
                  get_word16le,
                  hexvec,
                  pack_word32le};
use roper::phylostructs::{Chain,MachineMode};
use std::fmt::{Display,format,Formatter,Result};
use roper::ontostructs::*;

pub fn read_registers (uc: &unicorn::Unicorn) -> Vec<u32> {
    REGISTERS.iter().map(|&x| uc.reg_read(x.to_i32())
                                .expect("Error reading reg")
                                as u32)
                    .collect()
}

pub fn set_registers (uc: &unicorn::Unicorn, 
                      input: &Vec<i32>,
                      inregs: &Vec<usize>,
                      reset: bool) {
    let mut in_ptr = 0;
    for i in 0..REGISTERS.len() {
        if in_ptr < inregs.len() && i == inregs[in_ptr] { 
            in_ptr += 1;
            let val = input[in_ptr-1];
            uc.reg_write_i32(REGISTERS[i].to_i32(), val).unwrap();
        } else { 
            if reset {
                uc.reg_write_i32(REGISTERS[i].to_i32(), 0).unwrap();
            }
        };
    }
}

/*
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
    // TODO: set stack to actual stack segment
    uc.mem_map(BASE_STACK, STACK_SIZE, PROT_READ|PROT_WRITE)
        .expect("Failed to map stack memory");
  
    for ref seg in segments.iter() {
        println!("[*] Mapping segment with size {:x}, addr {:x}, perm {:?}",
                 seg.memsz, seg.addr, seg.perm);
        uc.mem_map(seg.floor(), seg.size(), seg.perm)
            .expect(&format!("Failed to map segment. Size: {:x}; Addr: {:x}, Perm: {:?}",
                             seg.memsz, seg.addr, seg.perm));
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
                            chain: &Chain,
                            input: &Vec<i32>,
                            inregs:  &Vec<usize>,
                            reset: bool) 
                            -> HatchResult {
    // Iinitalize the registers with reg_vec. This is input.
    // For single-case runs, it might just be set to 0..0. 
    
    /* The problem here is that we don't know until right after
      * this call whether or not the /packed/ chain will be empty.
      * A packed chain will be empty if it turns out to consist
      * entirely of *explicitly defined* introns. 
      */
    let mut stack = chain.pack();
    
    /* debugging */
    // println!("[*] [hatch_chain()] packed chain len: >> {}", stack.len());
    if (stack.len() == 0) {
        println!("[X] returning null HatchResult from hatch_chain...\n");
        return HatchResult::null();
    }
    // refactor ?
    let il = input.len();
    for &(off, inp) in chain.input_slots.iter() {
        let byte_offset = off * 4;
        let input_value = pack_word32le(input[inp % il] as u32);
        if byte_offset + 4 <= stack.len() {
            for i in 0..4 { 
                stack[byte_offset+i] = input_value[i]; 
            }
        } else {
            break;
        }
    }

    set_registers(uc.emu(), &input, &inregs, reset);
    //reset_counter(uc);
    if reset {
    let zerostack = vec![0; STACK_SIZE]; //mk_zerostack(STACK_SIZE);
        uc.mem_write(BASE_STACK, &zerostack)
            .expect("Error zeroing out stack");
    }
    uc.mem_write(STACK_INIT, &stack)
        .expect("Error initializing stack memory");
    uc.reg_write(RegisterARM::SP, STACK_INIT+4) // pop
        .expect("Error writing SP register");
    let start_addr : u64 = get_word32le(&stack, 0) as u64 ; //| 1;
    let mut visitor = Vec::new();
    let visitor_rc : Rc<RefCell<Vec<u32>>> = Rc::new(RefCell::new(visitor));
    let ee = {
        /* this will be a bit slower, but let us track which addrs are visited */
        // first, let's try to get the counter hook working right.
        // the way it's set up now is ludicrous
        let vis : Rc<RefCell<Vec<u32>>> = visitor_rc.clone();
        let callback = move |_: &unicorn::Unicorn, addr: u64, _: u32| {
            let mut v : RefMut<Vec<u32>> = vis.borrow_mut();
            v.push(addr as u32);
        };
        let _callback =  |u: &unicorn::Unicorn, addr: u64, size: u32| {
            println!("{:?} -- visiting {:08x}", thread::current().id(), addr);
        };
        // hook all the things
        let mut hooks = Vec::new();
        let h = uc.add_code_hook(unicorn::CodeHookType::CODE, 
                                 BASE_ADDR,
                                 BASE_ADDR+(MEM_SIZE as u64),
                                 callback);
        match h {
          Ok(h) => hooks.push(h),
          Err(e) => {},
        };
        // later handle the ret counts this way too, if it works
        let ee = uc.emu_start(start_addr, STOP_ADDR, 0, MAX_STEPS);
        for h in hooks.iter() {
            uc.remove_hook(*h);
        };
        ee
    };
    let e = match ee {
        Err(e) => Some(err_encode(e)),
        _      => None,
    };
    let vtmp = visitor_rc.clone();
    let visited_addrs : Vec<u32> = (vtmp.borrow()).clone().to_vec();
    let mut visited_addr_freq : HashMap<u32, usize> = HashMap::new();
    for addr in &visited_addrs {
        *visited_addr_freq.entry(*addr).or_insert(0) += 1;
    }
    // now count the returns *Correctly*
    let mut counter = 0;
    for clump in &chain.clumps {
        match visited_addr_freq.get(&clump.ret_addr) {
            Some(_) => {counter += 1;},
            None    => (),
        }
    }
    //println!("[*] [hatch_chain()] leaving function.\n");
    // cast registers to Vec<u32>
    let registers : Vec<u32> = read_registers(&(uc.emu())).iter()
                                                          .map(|&x| x as u32)
                                                          .collect();

    // what if we added a second register vector of derefences?
    // of type Vec<Option<u32>> ?
    let reg_deref : Vec<Option<u32>> = registers.iter()
                                        .map(|&a| deref(&(uc.emu()),a))
                                        .collect();
    HatchResult { registers: registers,
                  reg_deref: reg_deref,
                  error: e,
                  visited_freq: visited_addr_freq,
                  visited: visited_addrs.clone(),
                  counter: counter,
                  null: false,
    }
}

pub fn deref (uc: &unicorn::Unicorn, addr: u32) -> Option<u32> {
    match uc.mem_read(addr as u64, 4) {
        Ok(bytes) => Some(get_word32le(&bytes, 0)),
        Err(_)    => None,
    }
}


type ErrorCode = f32;
#[derive(Default,Debug,Clone)]
pub struct HatchResult {
    pub registers : Vec<u32>,
    pub reg_deref : Vec<Option<u32>>,
    pub error     : Option<ErrorCode>,
    pub counter   : usize,
    pub null      : bool,
    pub visited_freq   : HashMap<u32,usize>,
    pub visited   : Vec<u32>,
}

impl HatchResult {
    pub fn new () -> Self {
        HatchResult {
            registers : Vec::new(),
            reg_deref : Vec::new(),
            error     : None,
            counter   : 0,
            null      : false,
            visited_freq   : HashMap::new(),
            visited   : Vec::new(),
        }
    }
    /* a convenience function for null results. */
    pub fn null () -> Self {
        HatchResult {
            registers : Vec::new(),
            reg_deref : Vec::new(),
            error     : None,
            counter   : 0,
            null      : true,
            visited_freq  : HashMap::new(),
            visited   : Vec::new(),
        }
    }
    pub fn isnull (&self) -> bool {
        self.null
    }
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
 * This was batshit crazy, and is left here only as a monument to
 * batshit crazy code.
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

pub fn disas_addr (uc: &unicorn::CpuARM, addr: u32) -> String { // add support for thumb later
    let addr : u64 = addr as u64;
    let size : usize = if addr & 1 == 1 { 2 } else { 4 }; //thumb check
    let mode : MachineMode = if addr & 1 == 1 { MachineMode::THUMB } 
                             else { MachineMode::ARM };
    let instv = uc.mem_read(addr, size);
    match instv {
        Ok(v)  => disas(&v, mode),
        Err(_) => "unknown".to_string(),
    }
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
    let row = format!("[{:08x}] {}\n", addr, dis);
    //format!("({:02x})-[{:08x}] | {:?} | {}\n    {}\n", read_counter_u(u), addr, mmo, dis, regs);
    print!("{}",row);
    //dfile.write(&row.as_bytes()).unwrap();
}

