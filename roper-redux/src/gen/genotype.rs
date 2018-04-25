use std::collections::HashMap;
use emu::loader::Mode;


#[derive(Clone,Debug,PartialEq,Eq)]
pub struct Gadget {
    pub ret_addr : u64,
    pub entry    : u64,
    pub sp_delta : usize,
    pub mode     : Mode,
}
unsafe impl Send for Gadget {}

#[derive(Copy,Clone,Eq,PartialEq,Debug)]
pub enum Endian {
    Big,
    Little,
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Pad {
    Const(u64),
    Input(usize),
}
unsafe impl Send for Pad {}

#[derive(Clone,Debug,PartialEq)]
pub struct Chain {
    pub gads: Vec<Gadget>,
    pub pads: Vec<Pad>,
    pub wordsize: usize,
    pub endian: Endian,
    pub metadata: Metadata,
}

unsafe impl Send for Chain {}

impl Chain {
    pub fn pack(&self, input: &Vec<u64>) -> Vec<u8> {
        let mut p: Vec<u8> = Vec::new();
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
                let w = match self.pads[i % padnum] {
                    Pad::Const(x) => x,
                    Pad::Input(i) => if input.len() > 0 { 
                        input[i % input.len()] 
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
pub type Metadata = HashMap<&'static str,f32>;

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
