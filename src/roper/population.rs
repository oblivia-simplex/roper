use std::io::{BufReader,BufRead};
use std::fs::File;
use std::path::Path;

use roper::util::{pack_word32le};

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

#[derive(PartialEq,Debug)]
pub enum SelectionMethod {
  tournement,
  roulette,
}

#[derive(PartialEq,Debug)]
pub struct EvoParams {
  pub mutation_rate:    f32,
  pub population_size:  u32,
  pub max_generations:  u32,
  pub selection_method: SelectionMethod,
}
// tmp
#[derive(PartialEq,Debug)]
pub struct Gadget {
  pub kind:     GadKind,
  pub sp_delta: i32,
  pub addr:     u32,
  pub p_addr:   Vec<u8>, // [u8; 4]
  // consider adding operation field
}

pub struct Chain {
  pub gads: Vec<Gadget>,
  pub packed: Vec<u8>,
}

pub struct Population {
  pub chains: Vec<Chain>,
  pub params: EvoParams,
}

fn pack_chain (gads: &Vec<Gadget>) -> Vec<u8> {
  let mut p : Vec<u8> = Vec::new();
  gads.iter().map(|g| p.extend(g.p_addr.iter()));
  p
}

fn read_popfile (path: &str) -> Vec<Vec<Gadget>> {
  let f = File::open(path).expect("Failed to read file");
  let mut file = BufReader::new(&f);
  file.lines()
      .map(|x| deserialize_chain(&(x.unwrap())))
      .collect()
}

// have a separate file format and function to read 
// parameters. no reason not to keep these distinct.

// let the format for each gadget be:
// kind,sp_delta,addr
fn deserialize_gadget (gad: &str) -> Gadget {
  let fields : Vec<&str> = gad.split(',').collect();
  let a = fields[2].parse::<u32>().unwrap();
  Gadget {
    kind     : str_gadkind(fields[0]),
    sp_delta : fields[1].parse::<i32>().unwrap(),
    addr     : a,
    p_addr   : pack_word32le(a),
  } 
}

fn deserialize_chain (row: &str) -> Vec<Gadget> {
  row.split(' ').map(deserialize_gadget).collect()
}


