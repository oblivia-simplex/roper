#[allow(dead_code)]
extern crate unicorn;
extern crate elf;

use rand::{Rng,thread_rng};
use std::time::Instant;
use std::process::exit;
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
    //println!("in set_registers. input: {:?}, inregs: {:?}", input, inregs);
    //exit(99);
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
  * (out of date, but seems to work ok, so let's not break it.)
  */

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
    //println!("in hatch_chain: input: {:?}, inregs: {:?}", input, inregs);
    let mut packed = chain.pack();
    let stack : MemRegion = find_stack(&uc);
    
    /* save writeable regions so that they can be restored */
    let mut saved_regions = Vec::new();
    for region in uc.mem_regions().unwrap() {
        /* the stack will be zeroed out anyway, so skip it */
        if region.begin != stack.begin && region.perms.intersects(PROT_WRITE) {
            let data : Vec<u8> = uc.mem_read(region.begin,
                                             (region.end - region.begin) as usize)
                                   .unwrap();
            saved_regions.push((region.begin, data));
        }
    }
    /* debugging */
    // println!("[*] [hatch_chain()] packed chain len: >> {}", stack.len());
    if (packed.len() == 0) {
        println!("[X] returning null HatchResult from hatch_chain...\n");
        return HatchResult::new();
    }
    // refactor ?
    let il = input.len();
    for &(off, inp) in chain.input_slots.iter() {
        let byte_offset = off * 4;
        let input_value = pack_word32le(input[inp % il] as u32);
        if byte_offset + 4 <= packed.len() {
            for i in 0..4 { 
                packed[byte_offset+i] = input_value[i]; 
            }
        } else {
            break;
        }
    }
    let stack_space = (stack.end - stack.begin) as usize;
    let stack_entry = stack.begin + (stack_space / 2) as u64; /* smack in the middle */
    if (packed.len() > stack_space) {
        println!("[!] packed chain larger than allocated stack space. truncating.");
        packed.truncate(stack_space-4);
    }

    set_registers(uc.emu(), &input, &inregs, reset);
    //reset_counter(uc);
    if reset {
        /* refine: zero out all writeable memory */
        let zerostack = vec![0; stack_space]; //mk_zerostack(STACK_SIZE);
        uc.mem_write(stack.begin, &zerostack)
            .expect("Error zeroing out stack");
    }
    uc.mem_write(stack_entry, &packed)
        .expect("Error initializing stack memory");
    uc.reg_write(RegisterARM::SP, stack_entry+4) // pop
        .expect("Error writing SP register");
    let start_addr : u64 = get_word32le(&packed, 0) as u64 ; //| 1;
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
    let deref_size = 512; /* for starters */
    let reg_deref : Vec<Option<Vec<u8>>> = 
                                  registers.iter()
                                           .map(|&a| deref_vec(&(uc.emu()),
                                                            a,
                                                            deref_size))
                                           .collect();
    /* RESTORE REGIONS */
    for (addr,data) in saved_regions {
        uc.mem_write(addr, &data);
    }
    HatchResult { registers: registers,
                  reg_deref: reg_deref,
    //              memdump: memdump(&uc),
                  //rwmemory:  rwmemory,
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

pub fn deref_vec (uc: &unicorn::Unicorn, addr: u32, size: usize) -> Option<Vec<u8>> {
    match uc.mem_read(addr as u64, size) {
        Ok(bytes) => Some(bytes),
        Err(_)    => None,
    }
}


type ErrorCode = f32;
#[derive(Default,Debug,Clone)]
pub struct HatchResult {
    pub registers : Vec<u32>,
    pub reg_deref : Vec<Option<Vec<u8>>>,
    //pub memdump   : Vec<(u64,Vec<u8>)>,
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
     //       memdump   : Vec::new(),
            error     : None,
            counter   : 0,
            null      : false,
            visited_freq   : HashMap::new(),
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

pub fn memdump (uc: &CpuARM) -> Vec<(u64,Vec<u8>)> {
    let regions = uc.mem_regions().unwrap();
    let mut data : Vec<(u64,Vec<u8>)> = Vec::new();
    let start = Instant::now();
    for region in regions {
        assert!(region.end > region.begin);
        match uc.mem_read(region.begin, (region.end - region.begin) as usize) {
            Ok(d) => data.push((region.begin, d)),
            _     => { println!("Error dumping {:x} bytes from {:08x}", region.begin - region.end, region.begin); }
        }
    }
    //println!("-- memdump took {} nanoseconds", start.elapsed().subsec_nanos());
    data
}

pub fn seek_reference (bytes: &Vec<u8>, mem: &Vec<(u64,Vec<u8>)>) -> Option<u64> {
    let start = Instant::now();
    for region in mem.iter() {
        let begin = region.0 as usize;
        let data  = &region.1;
        let size  = bytes.len();
        if data.len() - size <= 0 { continue };
        /* try randomizing the starting point. This will still preserve
         * the cyclic group property */
        let random_offset = thread_rng().gen::<usize>() % (data.len() - size);
        for i in 0..(data.len() - size) {
            // random offset experiment
            let i = (i + random_offset) % (data.len() - size);
            let peek = &data[i..(i+size)];
            let mut ok = true;
            for j in 0..size {
                if peek[j] != bytes[j] { 
                    ok = false; break; 
                } else {
                    continue 
                };
            }
            if ok { 
                //println!("+++ found {:?} at {:08x} in {} nanoseconds", bytes, begin+i, start.elapsed().subsec_nanos());
                return Some((begin + i) as u64); 
            };
        }
    }
    //println!("+++ did not find {:?} in {} nanoseconds", bytes, start.elapsed().subsec_nanos());
    None
}

pub fn seek_str (string: &str, mem: &Vec<(u64,Vec<u8>)>) -> Option<u64> {
    seek_reference(&string.as_bytes().to_vec(), mem)
}

pub fn seek_word (word: u32, mem: &Vec<(u64,Vec<u8>)>) -> Option<u64> {
    seek_reference(&pack_word32le(word), mem)
}

pub fn uc_seek_word (word: u32, uc: &CpuARM) -> Option<u64> {
    let mem = memdump(&uc);
    seek_word(word, &mem)
}

fn printable (byte: u8) -> bool { 0x20 <= byte && byte < 0x80 }

pub fn dump_strings (uc: &CpuARM, minlen: usize, nullterm: bool) 
                    -> Vec<(u64,String)> {
    let mut strings = Vec::new();
    let mem = memdump(&uc);
    for region in mem.iter() {
        let begin = region.0;
        let data = &region.1;
        let mut bytes = Vec::new();
        let mut i = 0;
        for byte in data {
            if printable(*byte) {
                print!("{}", *byte as char);
                bytes.push(*byte);
            } else {
                if bytes.len() >= minlen && (!nullterm || *byte == 0) {
                    println!("");
                    match String::from_utf8(bytes.clone()) {
                        Ok(s) => strings.push((begin+i-(bytes.len() as u64), s)),
                        _ => { println!("[x] failed to encode {:?} as utf8",&bytes); },
                    }
                };
                bytes.truncate(0);
            }
            i += 1;

        }
    }
    strings
}
