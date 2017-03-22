// TODO: maybe I should treat thumb instructions as u32s
//       since not all of them will be u16.
//
// * copy of thumb.rs. Edit to match arm requirements. 
// * shouldn't take long. an hour, tops?

const _DEBUG : u8 = 1;
const MIN_GAD_LEN : usize = 2;

use roper::util::*;
use roper::population::*;
use roper::phylostructs::*;

static PC : usize = 15;
static LR : usize = 14;
static SP : usize = 13;

#[derive(PartialEq, Debug, Clone, Copy)]
enum Lay {
  DP,
  MULT,
  MULT_L,
  SDS,
  BX,
  HDT_R,
  HDT_I,
  SDT,
  UNDEF,
  BDT,
  BR,
  CDT,
  CDO,
  CRT,
  SWI,
  RAWDATA,
}

static MASK_VEC : &'static [(u32,u32,Lay)] = &[
  (0b00001100000000000000000000000000,
   0b00000000000000000000000000000000,
   Lay::DP),
  (0b00001111110000000000000011110000,
   0b00000000000000000000000010010000,
   Lay::MULT),
  (0b00001111100000000000000011110000,
   0b00000000100000000000000010010000,
   Lay::MULT_L),
  (0b00001111101100000000111111110000,
   0b00000001000000000000000010010000,
   Lay::SDS),
  (0b00001111111111111111111111110000,
   0b00000001001011111111111100010000,
   Lay::BX),
  (0b00001110010000000000111110010000,
   0b00000000000000000000000010010000,
   Lay::HDT_R),
  (0b00001110010000000000000010010000,
   0b00000000010000000000000010010000,
   Lay::HDT_I),
  (0b00001100000000000000000000000000,
   0b00000100000000000000000000000000,
   Lay::SDT),
  (0b00001110000000000000000000010000,
   0b00000110000000000000000000010000,
   Lay::UNDEF),
  (0b00001110000000000000000000000000,
   0b00001000000000000000000000000000,
   Lay::BDT),
  (0b00001110000000000000000000000000,
   0b00001010000000000000000000000000,
   Lay::BR),
  (0b00001110000000000000000000000000,
   0b00001100000000000000000000000000,
   Lay::CDT),
  (0b00001111000000000000000000010000,
   0b00001110000000000000000000000000,
   Lay::CDO),
  (0b00001111000000000000000000010000,
   0b00001110000000000000000000010000,
   Lay::CRT),
  (0b00001111000000000000000000000000,
   0b00001111000000000000000000000000,
   Lay::SWI),
];

fn what_layout (w: u32) -> Lay
{
  if _DEBUG >= 3 {
    print!("what_layout >>> {} -> ", disas32(w, MachineMode::ARM));
  };
  for &(mask,sig,lay) in MASK_VEC.iter() {
    if mask & w == sig { 
      if _DEBUG >= 3 { println!("{:08x} -> {:?}", w, lay); }
      return lay 
    }
  }
  println!("{:?}", Lay::RAWDATA);
  Lay::RAWDATA
}

fn bdt_rlist (w: u32) -> Vec<usize> {
  (0..16).filter(|&i: &usize| w & (1 << i) != 0)
         .collect()
}

pub fn sp_delta (w: u32) -> Option<(i32, Vec<usize>)> {
  match what_layout(w) {
    Lay::BDT  => Some(sp_delta_bdt(w)),
    _         => None,
  }
}
/*
#[derive(Copy,Eq,Debug)]
enum BDT {
  STMED,
  STMEA,
  STMFD,
  STMFA,
  LDMFA,
  LDMFD,
  LDMEA,
  LDMED,
}

fn bdt_type (w: u32) -> (BDT, usize) {
  let writeback = (w & (1 << 21)) >> 21;
  let ls_bit = (w & (1 << 20)) >> 20;
  let ud_bit = (w & (1 << 23)) >> 20;
  let pp_bit = (w & (1 << 24)) >> 24;
  (match (ls_bit, pp_bit, ud_bit) {
    (0,0,0) => BDT::STMED,
    (0,0,1) => BDT::STMEA,
    (0,1,0) => BDT::STMFD,
    (0,1,1) => BDT::STMFA,
    (1,0,0) => BDT::LDMFA,
    (1,0,1) => BDT::LDMFD,
    (1,1,0) => BDT::LDMEA,
    (1,1,1) => BDT::LDMED,
  }, writeback)
}   
*/
fn bdt_stack_direction (w: u32) -> i32 {
  if ((w & (0x0F << 16)) >> 16) != SP as u32 {
    0
  } else {
    let writeback  = ((w & (1 << 21)) >> 21) as i32;
    let updown_bit = ((w & (1 << 23)) >> 23) as i32;
    writeback * if updown_bit == 0 {-1} else {1}
  }
}
// I don't think we need to worry too much about the pre/post
// bit. At worst, the gadget will grab from an unexpected stack
// slot, but the GP will work those details out.
fn sp_delta_bdt (w: u32) -> (i32, Vec<usize>) {
  let reglist = bdt_rlist(w);
  (bdt_stack_direction(w) * reglist.len() as i32, reglist)
}

// what we want to know is when we're able to control the
// argument of bx from the stack. so, look for situations
// where there's a pop R, bx R sequence. if the value in R
// is odd, the processor stays in thumb mode and rounds down
// if even, it switches to arm.






// Consider just having this function return an unsaturated
// clump. Follow it up with an "expand clump" function, that
// will do the backwards walk, and then a "saturate clump"
// function that will populate words.

fn special_reg (r: usize) -> bool {
  r == SP || r == PC
}

fn dp_dst_reg (w: u32) -> usize {
  ((w & (0x0F << 12)) >> 12) as usize
}

pub fn is_ctrl (w: u32) -> bool {
  // check for control-flow instructions
  // this leaves out edge cases where PC is directly manipulated
  // but that's ok. we're not aiming for exactness.
  // ** add disas hook for debugging
  //return false; // let's see what this does
  let res = match what_layout(w) {
    //Lay::BX  => true,
    //Lay::BR  => true,
    //Lay::BDT => bdt_stack_direction(w) != 0,
    Lay::SWI => true,
    //Lay::UNDEF => true,
    Lay::RAWDATA => true,
    //Lay::DP  => special_reg(dp_dst_reg(w)),
    _ => false,
  };
  if _DEBUG >= 2 && res {
    println!("is_ctrl >> {}", disas32(w,MachineMode::ARM));
  };
  res
}

fn arm_scan_for_rets (ws: &Vec<u32>) 
                     -> Vec<Clump> {
  // rets will be triplets of integers:
  // prior padding, offset of ret inst, post padding
  let mut rets : Vec<Clump> = Vec::new();
  let mut i    : usize = ws.len() as usize;
  while i > 0 {
    i -= 1;
    match what_layout(ws[i]) {
      Lay::BDT => {
        let (d, rs) = sp_delta_bdt(ws[i]);
        if d > 0 && rs.contains(&PC) {
          rets.push(Clump {
            exchange:   false,
            sp_delta:   rs.len() as i32,
            ret_offset: rs.len() as i32,
            words:      vec![i as u32],
            mode:       MachineMode::ARM,
            ..Default::default()
            });
        } else {
          //println!("{:08x} -> BDT but not ret.", i*4);
          //println!("         d = {:?}, rs = {:?}", d, rs);
        };
      },
      _ => (),
    }
  }
  rets
}
// Consider just having this function return an unsaturated
// clump. Follow it up with an "expand clump" function, that
// will do the backwards walk, and then a "saturate clump"
// function that will populate words.
pub fn reap_arm_gadgets (code: &Vec<u8>, 
                         start_addr: u32) 
                           -> Vec<Clump> {
  let mut gads : Vec<Clump> = Vec::new();
  let insts : Vec<u32>      = u8s_to_u32s(code, Endian::LITTLE);
  let mut rets : Vec<Clump> = arm_scan_for_rets(&insts); 
  // println!(">> {} rets found", rets.len());

  // rets = Vec<(prior padding, offset, post padding)>
  for clump in rets {
    // now start walking up from offset until you hit a 
    // control instruction
    let from : u32 = clump.words[0];
    let mut o = from.clone() as usize;
    while o > 0 && o > (from as usize - 8) && !is_ctrl(insts[o-1]) {
      o -= 1
    }
    let a = start_addr + (4 * o as u32);
    let c = Clump { 
      sp_delta   : clump.sp_delta,
      ret_offset : clump.ret_offset,
      words      : vec![a],
      ret_addr   : start_addr + (4 * from),
      mode       : clump.mode,
      exchange   : clump.exchange,
      ..Default::default()
    };
    // println!("{:?}",c);
    if c.gadlen() >= MIN_GAD_LEN { gads.push(c); }
  }
  gads
}

// Both here and in reap_thumb_gadgets, things are pretty sloppy,
// memory-wise. It would be better to mutate the clumps in place
// than to throw them away and build new, similar ones. 
