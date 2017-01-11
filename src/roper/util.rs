#[allow(dead_code)]

use roper::params::*;
use rand::*;

/*
trait Maskable {
  fn mask (&self<T>, lo: T, hi: T) -> i32;
}


impl Maskable for dword {
  fn mask (&self, lo: dword, hi: dword) -> i32 {
    if lo > hi || lo < 0 || hi < 0 
    { panic!("Bad indices for mask") }
    else
      { ((2^hi-1) & *self) >> lo }
  }
}

impl Maskable for halfword {
  fn mask (&self, lo: halfword, hi: halfword) -> i32 {
    if lo > hi || lo < 0 || hi < 0 
    { panic!("Bad indices for mask") }
    else
      { ((2^hi-1) & *self) >> lo }
  }
}    
*/
pub fn get_word32le (a: &Vec<u8>) -> u32 {
  let mut s : u32 = 0;
  for i in 0..4 {
    s |= (a[i] as u32) << (i*8);
  }
  s
}

pub fn pack_word32le (n: u32) -> Vec<u8> {
  let mut v = Vec::new();
  for i in 0..4 {
    v.push(((n & (0xFF << i)) >> i) as u8);
  }
  v
}   

pub fn pack_word32le_vec (v: &Vec<u32>) -> Vec<u8> {
  let mut p : Vec<u8> = Vec::new();
  for ref w in v {
    p.extend(pack_word32le(**w).iter())
  }
  p
}


pub fn get_word16le (a: &Vec<u8>) -> u16 {
  let mut s : u16 = 0;
  for i in 0..2 {
    s |= (a[i] as u16) << (i*8);
  }
  s
}

// pretty-print the contents of a vector in hex
pub fn hexvec (v: &Vec<i32>) -> String{
  let vs : Vec<String> = v.iter()
                          .map(|x| format!("{:08x}",x))
                          .collect();
  vs.join(" ")
}

// can be used as part of a crude fitness function
pub fn distance (x: &Vec<i32>, y: &Vec<i32>) -> f32 {
  assert_eq!(x.len(), y.len());
  x.iter().zip(y.iter()).fold(0_f32, |acc, (xx, yx)| {
    let diff = (xx - yx) as f32;
    acc + diff * diff
  }).sqrt()
}

pub trait Indexable <T: PartialEq> {
  fn index (&self, t: T) -> usize;
  fn index_opt (&self, t: T) -> Option<usize>;
}

impl <T: PartialEq> Indexable <T> for Vec<T> {
  fn index (&self, t: T) -> usize {
    self.index_opt(t).unwrap() 
  }
  fn index_opt (&self, t: T) -> Option<usize> {
    self.iter().position(|x| x == &t)
  }
}

pub fn u8s_to_u16s (bytes: &Vec<u8>, endian: Endian) -> Vec<u16> {
  let be = if endian == Endian::BIG {8} else {0};
  let le = if endian == Endian::LITTLE {8} else {0};
  let l = bytes.len();
  let mut i = 0;
  let mut out = Vec::new();
  while i < l {
    out.push(((bytes[i] as u16) << be) | ((bytes[i+1] as u16) << le));
    i += 2;
  }
  out
}

/*
type Mangler<'a> = std::iter::Cycle<'a, u32>;

pub fn mangle (v: &Vec<u32>) -> Mangler {
  /* what this needs to do:
   * - take a vector of 'significant' u32s
   * - create a swarm of variations off of them, by
   *   performing common, elementary operations
   *   (negating, 2's comping, adding, subtracting, masking, etc.)
   * - shuffle 
   *   (this can be done by maintaining a small delay stack, shuffling
   *   it each tick, and stochastically popping it or pushing to it)
   * - return an iterator looping over this mangling operation
   */
}

*/
pub fn deref_mang (x: u32, 
                   data: &Vec<u32>, 
                   offset: u32) -> u32 {
  match data.index_opt(x) {
    Some(p) => (p as u32 * 4 as u32) + offset,
    None    => x,
  }
}

pub fn mang (x: u32, rng: &mut ThreadRng) -> u32 {
  let die : u8 = rng.gen::<u8>() % 40;
  match die {
    0  => x << 1,
    1  => x << 2,
    3  => x << 4,
    4  => x.rotate_right(8),
    5  => x & 0xFF,
    6  => x & 0xFFFF0000,
    7  => x & 0x0000FFFF,
    8  => !x,
    9  => x + 1,
    10 => x + 2,
    11 => x + 4,
    12 => x + 8,
    13 => x - 1,
    14 => x - 2,
    15 => x - 4,
    16 => x - 8,
    17 => x >> 1,
    18 => x >> 2,
    19 => x >> 4,
    _  => x,
  }
}

/*
pub struct Mangler {
  pub words: Vec<u32>,
  pub rng:   rand::Rng,
  cursor:    usize,
}

impl Mangler {
  fn new(ws: &Vec<u32>) -> Mangler {
    Mangler {
      words  : ws.clone(),
      rng    : rand::thread_rng(),
    }
  }
}


impl Iterator <Item:u32> for Mangler {
  fn next(&mut self) -> Option<u32> {
    Some(mang(self.words[self.rng.gen() % 
              self.words.len()], self.rng))
  }
}
*/


