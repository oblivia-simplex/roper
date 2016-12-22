// TODO: maybe I should treat thumb instructions as u32s
//       since not all of them will be u16.
//

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Endian {
  LITTLE,
  BIG,
}

static PC : i32 = 15;
static LR : i32 = 14;
static SP : i32 = 13;

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

pub fn ppr_rlist (w: u16) -> Vec<i32> {
  (0..9).filter(|&i: &i32| w & (1 << i) != 0)
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
/// Returns Some(sp_delta:i32,  [regs:i32]) (-len for push, +len for pop)
///         None, otherwise
pub fn sp_delta_ppr (w: u16) -> Option<(i32, Vec<i32>)> {
  match what_layout(w) {
    Lay::PPR  => {
      let rl = ppr_rlist(w);
      let de = if ppr_is_pop(w) {1} else {-1};
      Some((de * rl.len() as i32, rl))},
    _         => None,
  }
}

// what we want to know is when we're able to control the
// argument of bx from the stack. so, look for situations
// where there's a pop R, bx R sequence. if the value in R
// is odd, the processor stays in thumb mode and rounds down
// if even, it switches to arm.
pub fn bx_reg (w: u16) -> Option<i32> {
  match what_layout(w) {
    Lay::HROB => Some((w as i32 & 0b111000) 
                      << (if w & (1<<6) != 0 {8} else {0})),
    _         => None,
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


