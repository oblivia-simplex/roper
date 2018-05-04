extern crate rand;

use std::fmt::Display;
use std::fmt;
use std::collections::HashMap;
use emu::loader::{align_inst_addr, Mode, Seg, MEM_IMAGE};
use par::statics::*;

use self::rand::Rng;

#[derive(IntoValue, StructValue, ForeignValue, FromValue, FromValueRef, Clone, Copy, Debug,
         PartialEq, Eq)]
pub struct Gadget {
    pub ret_addr: u64,
    pub entry: u64,
    pub sp_delta: usize,
    pub mode: Mode,
}
//unsafe impl Send for Gadget {}

pub const ENDIAN: Endian = Endian::Little;

impl Display for Gadget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[Entry: {}, Ret: {}, SpD: {:x}, Mode: {:?}]",
            wf(self.entry),
            wf(self.ret_addr),
            self.sp_delta,
            self.mode
        )
    }
}

#[derive(ForeignValue, FromValue, FromValueRef, IntoValue, Copy, Clone, Eq, PartialEq, Debug)]
pub enum Endian {
    Big,
    Little,
}

#[derive(ForeignValue, FromValue, FromValueRef, IntoValue, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Allele {
    //Const(u64),
    Input(usize),
    Gadget(Gadget),
}

impl Allele {
    pub fn entry(&self) -> Option<u64> {
        match self {
            &Allele::Gadget(g) => Some(g.entry),
            _ => None,
        }
    }
}
//unsafe impl Send for Allele {}

impl Display for Allele {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            //&Allele::Const(x) => write!(f, "[Const {}]", wf(x)),
            &Allele::Input(i) => write!(f, "[Input Slot #{}]", i),
            &Allele::Gadget(g) => write!(f, "{}", g),
        }
    }
}

#[derive(StructValue, ForeignValue, FromValue, FromValueRef, Clone, Debug, PartialEq)]
pub struct Chain {
    pub alleles: Vec<Allele>,
    pub metadata: Metadata,
    pub xbits: u64, /* used to coordinate crossover and speciation */
}

//unsafe impl Send for Chain {}

impl Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        //let mut s = Vec::new();
        //let mut pad_offset = 0;
        for allele in self.alleles.iter() {
            write!(f, "\t{}\n", allele);
        }
        /*
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
            pad_offset += gad.sp_delta-1;
        }
        */
        write!(f, "\tXBITS: {:064b}\n", self.xbits)
    }
}

impl Chain {
    pub fn pack(&self, input: &Vec<u64>) -> Vec<u8> {
        let mut p: Vec<u8> = Vec::new();
        /*
        let mut pad_offset = 0;
        for gad in self.gads.iter() {
            let mut w = gad.entry;
            /* Jumps to thumb addresses are indicated by a LSB of 1 */
            /* NB: Check to make sure Unicorn is actually following this */
            if gad.mode == Mode::Thumb { w |= 1 };
            let wp = pack_word(w, *ADDR_WIDTH, ENDIAN);
            p.extend_from_slice(&wp);
            /* now, pack as many pads as needed to saturate sp_delta */
            if gad.sp_delta <= 1 { continue };
            let padnum = self.pads.len();
            if padnum == 0 { continue };
            for i in 0..(gad.sp_delta-1) {
                let o = i + pad_offset;
                let w = match self.pads[o % padnum] {
                    Allele::Const(x) => x,
                    Allele::Input(i) => if input.len() > 0 { 
                        input[o % input.len()] 
                    } else { 0 },
                };
                let wp = pack_word(w, *ADDR_WIDTH, ENDIAN);
                p.extend_from_slice(&wp);
            }
            pad_offset += gad.sp_delta-1;
        }
        */
        let mut start = false;
        for allele in self.alleles.iter() {
            if allele.entry() == None && !start {
                continue;
            } else {
                start = true;
            };
            let w = match allele {
                //&Allele::Const(c) => c,
                &Allele::Input(i) => if input.len() > 0 {
                    input[i % input.len()]
                } else {
                    0
                },
                &Allele::Gadget(g) => g.entry,
            };
            p.extend_from_slice(&pack_word(w, *ADDR_WIDTH, ENDIAN));
        }
        p
    }

    pub fn entry(&self) -> Option<u64> {
        for allele in self.alleles.iter() {
            if let Some(e) = allele.entry() {
                return Some(e);
            };
        }
        println!("WARNING! NO ENTRY! NO GADGETS IN CHAIN?");
        println!("{}", self);
        None
    }

    /* TODO: create a separate thread that maintains the
     * pool of random seeds, and serves them on request,
     * over a channel, maybe.
     */
    /* TODO alignment function, which depends on ARCHITECTURE */
    pub fn from_seed<R>(rng: &mut R, len_range: (usize, usize)) -> Self
    where
        R: Rng,
    {
        let xbits: u64 = rng.gen::<u64>();

        let input_slot_freq = INPUT_SLOT_FREQ;
        let exec_segs = MEM_IMAGE
            .iter()
            .filter(|s| s.is_executable())
            .collect::<Vec<&Seg>>();

        let mut alleles: Vec<Allele> = Vec::new();
        let (min_len, max_len) = len_range;
        let glen = rng.gen::<usize>() % (max_len - min_len) + min_len;

        for _ in 0..glen {
            let seg = &exec_segs[rng.gen::<usize>() % exec_segs.len()];
            let unaligned_addr = seg.aligned_start() + rng.gen::<u64>() % seg.aligned_size() as u64;
            let mode = ARCHITECTURE.mode(); /* choose mode randomly if ARM */
            let addr = align_inst_addr(unaligned_addr, mode);
            /* sp_delta-informed chance of choosing const or input TODO */
            if alleles.len() > 0 && rng.gen::<f32>() < input_slot_freq {
                /* NOTE: Artificially adding an upper bound on the number of inputs
                 * at 15. This will almost certainly be more than enough, and will
                 * make the input slots easier to read.
                 */
                alleles.push(Allele::Input(rng.gen::<usize>() & 0x0F));
            } else {
                let mut gad = Gadget {
                    entry: addr,
                    ret_addr: 0, /* TODO */
                    sp_delta: 0, /* TODO */
                    mode: mode,  /* TODO - for ARM decide mode */
                };

                alleles.push(Allele::Gadget(gad));
            }
        }

        /*
        let pad_num = gads.iter()
                          .map(|x| x.sp_delta)
                          .sum::<usize>();
        let mut pads = Vec::new();
        for _ in 0..pad_num {
            let pad = if rng.gen::<f32>() < input_slot_freq {
                Allele::Input(rng.gen::<usize>())
            } else {
                Allele::Const(rng.gen::<u64>())  /* TODO take const range param? */
            };
            pads.push(pad);
        }
        */

        let genome = Chain {
            alleles: alleles,
            xbits: xbits,
            metadata: Metadata::new(),
        };

        genome
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

#[derive(ForeignValue, FromValue, IntoValue, Clone, Debug, PartialEq)]
pub struct Metadata(pub HashMap<&'static str, f32>);
impl Metadata {
    pub fn new() -> Self {
        Metadata(HashMap::new())
    }
}

fn pack_word(word: u64, size: usize, endian: Endian) -> Vec<u8> {
    let mut p = match size {
        4 => {
            let w32 = if endian == Endian::Big {
                (word & 0xFFFFFFFF00000000) as u32
            } else {
                (word & 0x00000000FFFFFFFF) as u32
            };
            pack_word32le(w32)
        }
        8 => pack_word64le(word),
        _ => panic!("Bad word size. Must be either 4 or 8."),
    };
    if endian == Endian::Big {
        p.reverse()
    };
    p
}

pub fn pack_word32le(word: u32) -> Vec<u8> {
    let mut p: Vec<u8> = Vec::new();
    p.extend_from_slice(&[
        (word & 0xFF) as u8,
        ((word & 0xFF00) >> 0x08) as u8,
        ((word & 0xFF0000) >> 0x10) as u8,
        ((word & 0xFF000000) >> 0x18) as u8,
    ]);
    p
}

pub fn pack_word32le_vec(v: &Vec<u32>) -> Vec<u8> {
    let mut p: Vec<u8> = Vec::new();
    for word in v {
        p.extend_from_slice(&pack_word32le(*word))
    }
    p
}

pub fn pack_word64le(word: u64) -> Vec<u8> {
    let (hi, lo) = (
        ((word & 0xFFFFFFFF00000000) >> 0x20) as u32,
        (word & 0xFFFFFFFF) as u32,
    );
    let mut p = pack_word32le(lo);
    p.extend_from_slice(&pack_word32le(hi));
    p
}

pub fn pack_word64le_vec(v: &Vec<u64>) -> Vec<u8> {
    let mut p: Vec<u8> = Vec::new();
    for word in v {
        p.extend_from_slice(&pack_word64le(*word));
    }
    p
}
