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

pub fn get_word16le (a: &Vec<u8>) -> u16 {
  let mut s : u16 = 0;
  for i in 0..2 {
    s |= (a[i] as u16) << (i*8);
  }
  s
}

pub fn hexvec (v: &Vec<i32>) -> String{
  let vs : Vec<String> = v.iter()
                          .map(|x| format!("{:08x}",x))
                          .collect();
  vs.join(" ")
}
