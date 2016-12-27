#[allow(dead_code)]

type dword = u32;
type halfword = u16;
type byte = u8;

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
}

impl <T: PartialEq> Indexable <T> for Vec<T> {
  fn index (&self, t: T) -> usize {
    self.iter().position(|x| x == &t).unwrap()
  }
}
