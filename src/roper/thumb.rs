// TODO: maybe I should treat thumb instructions as u32s
//       since not all of them will be u16.
//

use roper::util::*;
use roper::population::*;

use roper::params::*;

static PC : usize = 15;
static LR : usize = 14;
static SP : usize = 13;

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Lay {
  SWI,
  AOSP,
  ALU,
  HROB,
  AS,
  MSR,
  MCAS,
  PCRL,
  LSSE,
  LSRO,
  LSIO,
  LSHW,
  SPLS,
  LA,
  PPR,
  MLS,
  CB,
  UB,
  LBL,
  RAWDATA,
}

static MASK_VEC : &'static [(u16,u16,Lay)] = &[
    (0b1111111100000000,0b1101111100000000,Lay::SWI),
    (0b1111111100000000,0b1011000000000000,Lay::AOSP),
    (0b1111011000000000,0b1011010000000000,Lay::PPR),
    (0b1111110000000000,0b0100000000000000,Lay::ALU),
    (0b1111110000000000,0b0100010000000000,Lay::HROB),
    (0b1111100000000000,0b1110000000000000,Lay::UB),
    (0b1111100000000000,0b0100100000000000,Lay::PCRL),
    (0b1111100000000000,0b0001100000000000,Lay::AS),
    (0b1111001000000000,0b0101001000000000,Lay::LSSE),
    (0b1111001000000000,0b0101000000000000,Lay::LSRO),
    (0b1111000000000000,0b1101000000000000,Lay::CB),
    (0b1111000000000000,0b1100000000000000,Lay::MLS),
    (0b1111000000000000,0b1010000000000000,Lay::LA),
    (0b1111000000000000,0b1001000000000000,Lay::SPLS),
    (0b1111000000000000,0b1000000000000000,Lay::LSHW),
    (0b1111000000000000,0b1111000000000000,Lay::LBL),
    (0b1110000000000000,0b0110000000000000,Lay::LSIO),
    (0b1110000000000000,0b0010000000000000,Lay::MCAS), 
    (0b1110000000000000,0b0000000000000000,Lay::MSR),
];

pub fn what_layout (w: u16) -> Lay
{
  for &(mask,sig,lay) in MASK_VEC.iter() {
    if mask & w == sig { return lay }
  }
  Lay::RAWDATA
}

pub fn ppr_rlist (w: u16) -> Vec<usize> {
  (0..9).filter(|&i: &usize| w & (1 << i) != 0)
        .map(|x| match x == 8 {
                   false                 => x,
                   true if ppr_is_pop(w) => PC,
                   true                  => LR,})
        .collect()
}

fn ppr_is_pop (w: u16) -> bool {
  w & (1 << 11) != 0
}

/// Param:  instruction, as u16
/// Returns Some(sp_delta:usize,  [regs:usize]) (-len for push, +len for pop)
///         None, otherwise
pub fn sp_delta (w: u16) -> Option<(i32, Vec<usize>)> {
  match what_layout(w) {
    Lay::PPR  => Some(sp_delta_ppr(w)),
    _         => None,
  }
}

pub fn sp_delta_ppr (w: u16) -> (i32, Vec<usize>) {
  let rl = ppr_rlist(w);
  let de = if ppr_is_pop(w) {1} else {-1};
  (de * rl.len() as i32, rl)
}

// what we want to know is when we're able to control the
// argument of bx from the stack. so, look for situations
// where there's a pop R, bx R sequence. if the value in R
// is odd, the processor stays in thumb mode and rounds down
// if even, it switches to arm.
pub fn bx_reg (w: u16) -> Option<usize> {
  match what_layout(w) {
    Lay::HROB => Some(bx_reg_hrob(w)),
    _         => None,
  }
}

fn bx_reg_hrob (w: u16) -> usize {
  (w as usize & 0b00111000) << (if w & (1 << 6) != 0 {8} else {0})
}






// Consider just having this function return an unsaturated
// clump. Follow it up with an "expand clump" function, that
// will do the backwards walk, and then a "saturate clump"
// function that will populate words.
pub fn th_is_ctrl (w: u16) -> bool {
  // check for control-flow instructions
  // i.e. the kind we don't typically want in gadgets
  // at least not yet
    // stub
  false
}

fn th_scan_for_rets (ws: &Vec<u16>) 
                      -> Vec<Clump> {
  // rets will be triplets of integers:
  // prior padding, offset of ret inst, post padding
  let mut rets : Vec<Clump> = Vec::new();
  let mut i    : usize = ws.len() as usize;
  let mut bxr  : Option<(usize,usize)>  = None;
  while i > 0 {
    i -= 1;
    match what_layout(ws[i]) {
      // check to see if bxr, not just hrob
      // fix this
      Lay::HROB => {bxr = Some((bx_reg_hrob(ws[i]),i));}
      Lay::PPR  => {
        let rs = ppr_rlist(ws[i]);
        if rs.contains(&PC) { // you can't push pc in thumb
          rets.push(Clump {
            exchange:   false,
            sp_delta:   rs.len() as i32,
            ret_offset: rs.len() as i32,
            words:      vec![i as u32],
            mode:       MachineMode::THUMB,
          });//(rs.len(),i,0,false));
        } else {
          match bxr {
            Some((r,o)) if rs.contains(&r) => {
              rets.push(Clump {
                exchange:   true,
                sp_delta:   rs.len() as i32,
                ret_offset: (rs.index(r)+1) as i32,
                words:      vec![o as u32],
                mode:       MachineMode::THUMB,
              });
              /*(rs.len(), 
                         o, 
                         (rs.len()-(rs.index(r))),
                         true)) */
            },
            _                              => {bxr = None;},
          }
        }
      },
      _         => (),
    }
  }
  rets
}
// Consider just having this function return an unsaturated
// clump. Follow it up with an "expand clump" function, that
// will do the backwards walk, and then a "saturate clump"
// function that will populate words.
pub fn reap_thumb_gadgets (code: &Vec<u8>, 
                            start_addr: u32) 
                           -> Vec<Clump> {
  let mut gads : Vec<Clump> = Vec::new();
  let insts : Vec<u16>      = u8s_to_u16s(code, Endian::LITTLE);
  let mut rets : Vec<Clump> = th_scan_for_rets(&insts); 

  // rets = Vec<(prior padding, offset, post padding)>
  for clump in rets {
    // now start walking up from offset until you hit a 
    // control instruction
    let from : u32 = clump.words[0];
    let mut o = from.clone() as usize;
    while o > 0 && o > (from as usize - 8) {
      // any additional sp changes affect prior, but not post
      // so i could mutate p here, relative to insts[o]
      // but for now, we'll keep it simple
      if th_is_ctrl(insts[o - 1]) { break } else { o -= 1 }
    }
    let a = start_addr + (2 * o as u32);
    gads.push(Clump { 
      sp_delta   : clump.sp_delta,
      ret_offset : clump.ret_offset,
      words      : vec![a],
      mode       : clump.mode,
      exchange   : clump.exchange,
    });
  }
  gads
}
