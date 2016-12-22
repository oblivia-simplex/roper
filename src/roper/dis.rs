extern crate capstone;

pub struct Inst {
  pub raw  : u32,
  pub addr : u32,
  pub size : u32,
  pub mnem : String, 
  pub src  : Vec<u32>,
  pub dst  : Vec<u32>,
  pub imm  : Option<u32>,
  pub spd  : u32, 
}

static SP : u32 = 13;
static LR : u32 = 14;
static PC : u32 = 15;

fn reg_i(st: &str) -> u32 { 
  let s : &str = st.trim();
  match s.find('r') {
    Some(_) => s.split('r')
                .collect::<Vec<&str>>()[1]
                .parse::<u32>()
                .expect("Failed to parse register"),
    None    => 
      match s {
        "sp" => SP,
        "lr" => LR,
        "pc" => PC,
         _   => panic!("Failed to parse register"),
      },
  }
}

fn parse_op_str <'a> (s: &'a str) 
                     -> (Vec<u32>, Vec<u32>, Option<u32>) {
  match s.find(',') {
    None        => (vec![],vec![],Some(s.split("#")
                                        .collect::<Vec<&str>>()[1]
                                        .parse::<u32>()
                                        .expect("Imm parse fail"))),
    Some(comma) => {
      let comma_split : Vec<&str> = s.split(',')
                                     .collect::<Vec<&str>>();
      match s.find('{') {
        None => {
          let rd = reg_i(comma_split[0]);
          match s.find('#') {
            Some(_) => (vec![rd],vec![], Some(s.split("#")
                                  .collect::<Vec<&str>>()[1]
                                  .parse::<u32>()
                                  .expect("Imm parse fail"))),
            None    => (vec![rd],vec![reg_i(comma_split[1])],None),
          }},
        Some(brace) => {
          let brace_split = 
            s.split(|c| c == '{' || c == '}')
             .collect::<Vec<&str>>();
          let rlist : Vec<u32> = brace_split[1].split(',')
                                               .map(reg_i)
                                               .collect::<Vec<u32>>();
          if brace < comma { 
            (rlist, 
             vec![reg_i(brace_split[2].split(',')
                                      .collect::<Vec<&str>>()[1])],
             None) 
          } else {  
            (vec![reg_i(comma_split[0])],
             rlist,
             None)
          }},
      }},
  }
}
                                          
fn calc_sp_delta (mnemonic : &str,
                  dst_regs : &Vec<u32>,
                  src_regs : &Vec<u32>,
                  imm      : &Option<u32>)
                 -> u32 {
// we'll assume write-back for now, but eventually, we'll
// need to patch the capstone wrapper so that we can access
// the cs_details (and request them). 
  if (src_regs).contains(&13) {
    dst_regs.len() as u32
  } else {
    0
  }
 // TODO: Replace this with something more accurate. 
}


// TODO: add method to capstone-rs for getting bytes field
fn cs_to_inst <'a> (i: &'a capstone::Insn) -> Inst {
  let (ds,sr,im) = parse_op_str(i.op_str()
                                 .expect("Could not find op_str"));
  let mnemonic = i.mnemonic().expect("Couldn't read mnemonic");
  let sp_delta = calc_sp_delta(&mnemonic, &ds,&sr,&im);
  Inst {
    raw  : 0, // placeholder. need to patch library.
    addr : i.address as u32,
    size : i.size as u32,
    mnem : mnemonic.to_string(),
    src  : sr,
    dst  : ds,
    imm  : im,
    spd  : sp_delta,
  }
}
// the expects here may just be temporary, until I figure out
// if I really need to worry about the None cases. 

fn foobar (x: &capstone::Insn) -> Inst {
  Inst {
    raw : 1,
    addr: 2,
    size: 3,
    mnem: "hi".to_string(),
    src: vec![1],
    dst: vec![4,3],
    imm: Some(1),
    spd: 3
  }


}

pub fn disas_sec <'a> (section: &'a elf::Section,
                  arch: capstone::CsArch, 
                  mode: capstone::CsMode) 
                 -> Vec<Inst> {
  
  let e = capstone::Capstone::new(arch, mode)
          .expect("Failure to initiate capstone engine.");

  let s_addr   : u64     = section.shdr.addr;
  let s_code   : &[u8]   = &section.data;

  let ret = e.disasm(s_code, s_addr, 0)
             .expect("Disassembly failed.");
  
  ret.iter().map(|x| cs_to_inst(&x)).collect()
}

/*
pub fn disas_thumb_sec <'a> (section: &'a elf::Section) 
                       -> Vec<Inst> {
  disas_sec(section,
            capstone::constants::CsArch::ARCH_ARM,
            capstone::constants::CsMode::MODE_THUMB)
}

*/                
                        
