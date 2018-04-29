extern crate rand;

use std::fmt::{Display};
use std::fmt;
use std::collections::HashMap;
use emu::loader::{Mode,Seg,align_inst_addr};
use par::statics::*;

use self::rand::isaac::Isaac64Rng;
use self::rand::{Rng,SeedableRng};

#[derive(IntoValue,StructValue,ForeignValue,FromValue,FromValueRef,Clone,Copy,Debug,PartialEq,Eq)]
pub struct Gadget {
    pub ret_addr : u64,
    pub entry    : u64,
    pub sp_delta : usize,
    pub mode     : Mode,
}
//unsafe impl Send for Gadget {}

impl Display for Gadget {
    fn fmt (&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[Entry: {}, Ret: {}, SpD: {:x}, Mode: {:?}]",
               wf(self.entry),
               wf(self.ret_addr),
               self.sp_delta,
               self.mode)
    }
}

#[derive(ForeignValue,FromValue,FromValueRef,IntoValue,Copy,Clone,Eq,PartialEq,Debug)]
pub enum Endian {
    Big,
    Little,
}

#[derive(ForeignValue,FromValue,FromValueRef,IntoValue,Clone,Copy,Debug,PartialEq,Eq)]
pub enum Pad {
    Const(u64),
    Input(usize),
}
//unsafe impl Send for Pad {}

impl Display for Pad {
    fn fmt (&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Pad::Const(x) => write!(f, "[Const {}]", wf(x)),
            &Pad::Input(i) => write!(f, "[Input Slot #{}]", i),
        }
    }
}

#[derive(StructValue,ForeignValue,FromValue,FromValueRef,Clone,Debug,PartialEq)]
pub struct Chain {
    pub gads: Vec<Gadget>,
    pub pads: Vec<Pad>,
    pub wordsize: usize,
    pub endian: Endian,
    pub metadata: Metadata,
}

//unsafe impl Send for Chain {}

impl Display for Chain {
    fn fmt (&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut s = Vec::new();
        let mut pad_offset = 0;
        for gad in self.gads.iter() {
            s.push(format!("{}",gad));
            if gad.sp_delta <= 1 { continue };
            let padnum = self.pads.len();
            if padnum == 0 { continue };
            for i in 0..(gad.sp_delta-1) {
                let o = i + pad_offset;
                let w = self.pads[o % padnum];
                s.push(format!("{}",w));
            }
        }
        write!(f, "{}", s.join("\n\t"))
    }
}

impl Chain {
    pub fn pack(&self, input: &Vec<u64>) -> Vec<u8> {
        let mut p: Vec<u8> = Vec::new();
        let mut pad_offset = 0;
        for gad in self.gads.iter() {
            let mut w = gad.entry;
            /* Jumps to thumb addresses are indicated by a LSB of 1 */
            /* NB: Check to make sure Unicorn is actually following this */
            if gad.mode == Mode::Thumb { w |= 1 };
            let wp = pack_word(w, self.wordsize, self.endian);
            p.extend_from_slice(&wp);
            /* now, pack as many pads as needed to saturate sp_delta */
            if gad.sp_delta <= 1 { continue };
            let padnum = self.pads.len();
            if padnum == 0 { continue };
            for i in 0..(gad.sp_delta-1) {
                let o = i + pad_offset;
                let w = match self.pads[o % padnum] {
                    Pad::Const(x) => x,
                    Pad::Input(i) => if input.len() > 0 { 
                        input[o % input.len()] 
                    } else { 0 },
                };
                let wp = pack_word(w, self.wordsize, self.endian);
                p.extend_from_slice(&wp);
            }
        }
        p
    }

    pub fn entry(&self) -> u64 {
        assert!(self.gads.len() > 0);
        self.gads[0].entry
    }

    /* 
     *
    /* TODO: create a separate thread that maintains the
     * pool of random seeds, and serves them on request,
     * over a channel, maybe. 
     */
    /* TODO alignment function, which depends on ARCHITECTURE */
    pub fn from_seed(seed: &[u64],
                     len_range: (usize, usize)) -> Self {
        
        let mut rng = Isaac64Rng::from_seed(seed);
        let exec_segs = MEM_IMAGE.iter()
                                 .filter(|s| s.is_executable())
                                 .collect::<Vec<Seg>>();
        let pick_addr = (|| -> u64 {
                let rng = &mut rng;
                /* TODO weight this, so that small segs are overly sampled */
                let seg = &exec_segs[rng.gen::<usize>() % exec_segs.len()];
                let addr = seg.aligned_start() + rng.gen::<u64>() % seg.aligned_size();
                let mode = ARCHITECTURE.mode(); /* choose mode randomly if ARM */
                let aligned_addr = align_inst_addr(addr, mode);
                (aligned_addr,mode)
            });

        let mut gads = Vec<Gadget>;
        let (min_len, max_len) = len_range;
        let glen = rng.gen::<usize>() % (max_len - min_len) + min_len;

        for 0..glen {
            let (addr,mode) = pick_addr();
            let mut gad = Gadget {
                entry: addr,
                ret_addr: 0, /* TODO */
                sp_delta: 0, /* TODO */
                mode: mode,  /* TODO - for ARM decide mode */
            };
            gads.push(gad);
        }
        /* if i initialize the spd at random, will evolution bring it into 
         * alignment with the actual spd?
         */
    /* define crossover and mutation operations as traits of the genome 
     * but allow for them to take callbacks, scripts, etc., eventually 
     */
      */  
}

/* by using a hashmap instead of separate struct fields
 * for the various bits of metadata, we end up with a 
 * much more flexible structure, that won't require
 * dozens of fiddly signature changes every time we
 * want to add or modify a field. f32 should work 
 * for most of the fields we're interested in.
 * We can dispense with Option fields, by just letting
 * "None" be the absence of a field in the hashmap. 
 * Accessor functions will provide an easy interface. 
 */

#[derive(ForeignValue,FromValue,IntoValue,Clone,Debug,PartialEq)]
pub struct Metadata(pub HashMap<&'static str,f32>);
impl Metadata {
    pub fn new() -> Self {
        Metadata( HashMap::new() )
    }
}


fn pack_word(word: u64, size: usize, endian: Endian) -> Vec<u8> {
    let mut p : Vec<u8> = Vec::new();
    match size {
        4 => { 
            let w32 = if endian == Endian::Big {
                (word & 0xFFFFFFFF00000000) as u32
            } else {
                (word & 0x00000000FFFFFFFF) as u32
            };
            p = pack_word32le(w32)
        },
        8 => p = pack_word64le(word),
        _ => panic!("Bad word size. Must be either 4 or 8."),
    }
    if endian == Endian::Big {
        p.reverse()
    };
    p
}

pub fn pack_word32le (word: u32) -> Vec<u8> {
    let mut p : Vec<u8> = Vec::new();
    p.extend_from_slice(&[(word & 0xFF) as u8,
                          ((word & 0xFF00) >> 0x08) as u8,
                          ((word & 0xFF0000) >> 0x10) as u8,
                          ((word & 0xFF000000) >> 0x18) as u8]);
    p
}

pub fn pack_word32le_vec (v: &Vec<u32>) -> Vec<u8> {
    let mut p : Vec<u8> = Vec::new();
    for word in v {
        p.extend_from_slice(&pack_word32le(*word))
    }
    p
}

pub fn pack_word64le (word: u64) -> Vec<u8> {
    let (hi,lo) = (((word & 0xFFFFFFFF00000000) >> 0x20) as u32, (word & 0xFFFFFFFF) as u32);
    let mut p = pack_word32le(lo);
    p.extend_from_slice(&pack_word32le(hi));
    p
}

pub fn pack_word64le_vec (v: &Vec<u64>) -> Vec<u8> {
    let mut p : Vec<u8> = Vec::new();
    for word in v {
        p.extend_from_slice(&pack_word64le(*word));
    }
    p
}
