
use std::io::{BufReader,BufRead};
use std::fs::File;
use std::path::Path;


use roper::params::*;

use roper::util::{pack_word32le,
                  pack_word32le_vec,
                  u8s_to_u16s};

use roper::thumb::{reap_thumb_gadgets};

/*
#[derive(PartialEq,Debug)]
pub enum GadKind {
  imm,
  reg,
}

fn str_gadkind (s: &str) -> GadKind {
  match s {
    "imm" => GadKind::imm,
    "reg" => GadKind::reg,
    _     => panic!("Couldn't match GadKind to {}",s),
  }
}
*/

// tmp
#[derive(PartialEq,Debug,Clone)]
pub struct Clump {
  // pub kind:        GadKind,
  pub sp_delta:    i32, // how much does the sp change by?
  pub ret_offset:  i32, // how far down is the next address?
  pub exchange:    bool, // are we returning with a BX instruction? can we change mode?
  pub mode:        MachineMode,
  pub words:       Vec<u32>,
  // pub size:        usize,
  // consider adding operation field
}

pub trait Gadget {
  fn addr (&self) -> u32; 
  fn pack (&self) -> Vec<u8>;
}

impl Gadget for Clump {
  fn addr (&self) -> u32 {
    self.words[0]
  }
  fn pack (&self) -> Vec<u8> {
    let mut p : Vec<u8> = Vec::new();
    for ref w in &(self.words) {
      p.extend(pack_word32le(**w).iter())
    }
    p
  }
}
// nb: ret_offset is not always going to equal sp_delta
// e.g. pop {r1,r2,r3,r4,r5}; bxr r3
// has an sp_delta of +5, and a ret_offset of +3

pub struct Chain {
  pub clumps: Vec<Clump>, 
  pub packed: Vec<u8>,
  pub fitness: Option<f32>,
  pub generation: u32,
}

fn saturated (gad: &Clump) -> bool {
  gad.words.len() as i32 == gad.sp_delta
}

fn concatenate (clumps: &Vec<Clump>) -> Vec<u32> {
  let s : usize = clumps.iter()
                        .map(|ref x| x.words.len())
                        .sum();
  let mut c = Vec::with_capacity(s);
  let mut spd = 0;
  let mut rto = 0 as usize;
  let mut exchange = false;
  for ref gad in clumps {
    if !saturated(gad) {
      panic!("Attempting to concatenate unsaturated clumps");
    }
    assert!(gad.sp_delta >= 0);
    let t : usize = rto + gad.sp_delta as usize;
    &c[rto..t].clone_from_slice(&(gad.words));
    if exchange && (gad.mode == MachineMode::THUMB) {
      /* If we BX, the LSB of the addr decides machine mode */
      c[rto] |= 1;
    }
    rto += gad.ret_offset as usize;
    spd += gad.sp_delta as usize;
    exchange = gad.exchange;
  }
  c
}



pub fn mk_chain (clumps: &Vec<Clump>) -> Chain {
  let conc = concatenate(clumps);
  let pack = pack_word32le_vec(conc);
  Chain {
    clumps: (*clumps).clone(),
    packed: pack,
    fitness: None,
    generation: 0,
  }
}

pub struct Population {
  pub chains: Vec<Chain>,
  pub params: Params,
}


fn read_popfile (path: &str) -> Vec<Vec<Clump>> {
  let f = File::open(path).expect("Failed to read file");
  let mut file = BufReader::new(&f);
  file.lines()
      .map(|x| deserialize_chain(&(x.unwrap())))
      .collect()
}

// have a separate file format and function to read 
// parameters. no reason not to keep these distinct.

// let the format for each gadget be:
// sp_delta;ret_offset;addr,pad,pad...
fn deserialize_clump(gad: &str) -> Clump {
  let fields : Vec<&str> = gad.split(';').collect();
  let words : Vec<u32> = fields[4].split(',')
                                  .map(|x| x.parse::<u32>()
                                             .unwrap())
                                  .collect();
  
  let mode : MachineMode = match fields[0] {
    "THUMB" => MachineMode::THUMB,
    "ARM"   => MachineMode::ARM,
    _       => panic!("Failed to parse MachineMode"),
  };

  let exchange : bool = match fields[1] {
    "X" => true,
    _   => false,
  };
  //let a = fields[2].parse::<u32>().unwrap();
  Clump {
    mode       : mode,
    exchange   : exchange,
    sp_delta   : fields[0].parse::<i32>().unwrap(),
    ret_offset : fields[1].parse::<i32>().unwrap(),
    words      : words,
  } 
  
}

fn deserialize_chain (row: &str) -> Vec<Clump> {
  row.split(' ').map(deserialize_clump).collect()
}

pub fn saturate_clumps <'a,I> (unsat: &Vec<Clump>,
                               pool:  &mut I,//Vec<u32>,
                               desired: usize) 
                              -> Vec<Clump> 
    where I: Iterator <Item=u32> {
  let mut u : usize = 0;
  let mut d : usize = 0;
  let mut sat: Vec<Clump> = Vec::new();
  while d < desired {
    let mut w = unsat[u].words.clone();
    let taken = (unsat[u].sp_delta-1) as usize;
    // slow way. optimize later:
    for i in 0..taken {
      match pool.next() {
        Some(x) => w.push(x),
        _       => return sat,
      }
    }
    //w.extend((poo).take(taken).clone()); //pool[p..taken]);
    sat.push(Clump {
      sp_delta   : unsat[u].sp_delta,
      ret_offset : unsat[u].ret_offset,
      exchange   : unsat[u].exchange,
      mode       : unsat[u].mode,
      words      : w,
    });
    d += 1;
    u = d % unsat.len();
  }
  sat
}


// replace mode str with mode enum at some point
pub fn reap_gadgets (code: &Vec<u8>, 
                     start_addr: u32, 
                     mode: MachineMode) 
                    -> Vec<Clump> {
  match mode {
    MachineMode::THUMB => reap_thumb_gadgets(code, start_addr),
    MachineMode::ARM   => panic!("unimplemented"),
  }
}


/*
pub fn reap_arm_gadgets (code: &Vec<u8>,
                         start_addr: u32)
                         -> Vec<Clump>
{
  let mut gads : Vec<Clump> = Vec::new();
  // TODO: COMPLETE THIS STUB, and write an ARM lib.
  panic!("Unimplemented.");
  gads
}

*/


/*
 * Mutation algorithm:
 *
 * 1/n chance of imm gad mutation
 * 1-1/n chance of reg gad mutation
 *
 * imm gads can be a perturbation of the immediate value
 * two kinds of perturbation:
 * (a) logico-arithmetical perturbation
 *     (the idea being that they would complement ALU ops)
 * (b) indirection
 *
 * indirection can only be used in some cases:
 * - scan rodata and text for a value equal to, or close
 *   to, the value being mutated
 * - replace the value being mutated with a pointer to
 *   its counterpart in rodata/text
 *
 *   if indirection is unavailable -- if there are no candidate
 *   values in rodata/text to dereference to -- fall back on
 *   arithmetical mutation.
 *
 * reg gad mutations:
 * - these have to operate at the level of clumps, not
 *   individual gadget, where a clump is defined as a 
 *   regular gadget, followed by a number of immgads equal
 *   to its sp_delta.
 *
 * ----
 *
 * it would be handy to maintain a struct that holds bits
 * of relatively global information -- params, data, text,
 * etc.
 *
 */

/* Note:
 * BX can switch between ARM and THUMB mode, depending on
 * the LSB of the address.
 *
 * bit 0 = ARM
 * bit 1 = THUMB
 *
 * the ret scraper should also return an instruction type flag
 * in the tuple. if it's BX, then we need this information so
 * that we can control the machine mode
 */

/* Refactor scan_for_gadgets 
 * Build a clump struct right away, and then enrich it with
 * successive passes.
 */

