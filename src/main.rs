#[allow(dead_code)]
extern crate elf;
extern crate unicorn;
extern crate capstone;
use std::path::PathBuf;
use std::fs::File;
use std::io::prelude::*;
use unicorn::*;
// use std::io;
use capstone::instruction::Instructions;
use capstone::constants::{CsMode,CsArch};
//use roper::dis::{disas_sec,Inst};
use roper::thumb::*;
mod roper;

fn pretty (xs : &Vec<u16>) -> Vec<u16> {
   xs.iter().map(|&x| {println!("{:016b}: {:?} -> {:?}",
                       x, what_layout(x),
                       ppr_rlist(x)); x})
            .collect()
}

fn wordvec_analysis (wordvec : &Vec<u16>) {

  let sp_delta_info : Vec<Option<(i32, Vec<i32>)>> 
    = wordvec.iter()
                 .map(|&x| sp_delta_ppr(x))
                 .collect();
  let mut j = 0;
  let mut retcount = 0;
  for s in sp_delta_info.iter() {
    j += 1;
    match *s {
      None => (),
      Some((ref n, ref rs)) if *n > 0 => {
        if rs.contains(&15) { 
          retcount += 1;
          println!("[{}] RET! {:?}", j,rs)
        } else {
          println!("[{}] POP  {:?}",j,rs)
        }
      },
      Some((ref n, ref rs)) if *n < 0 => println!("[{}] PUSH {:?}",j,rs),
      Some(_) => (),
    }
  }
  println!("{} RETs counted over {} instructions",
           retcount, wordvec.len());
}

fn load_file (path: &str) -> Vec<u8>
{
  let mut f = File::open(path)
                .expect("Failed to open path");
  let mut buf : Vec<u8> = Vec::new();
  f.read_to_end(&mut buf);
  buf
}

fn get_elf_addr_data (path: &str, 
                      secs: &Vec<&str>) 
                      -> Vec<(u64, Vec<u8>)> {
  let path = PathBuf::from(path);
  let file = match elf::File::open_path(&path) {
    Ok(f) => f,
    Err(e) => panic!("Error: {:?}",e),
  };
  let mut pairs : Vec<(u64, Vec<u8>)> = Vec::new();
  for sec_name in secs.iter() {
    let sec = file.get_section(sec_name)
                  .expect("Unable to fetch section from elf");
    pairs.push((sec.shdr.addr, sec.data.clone()));
  }
  pairs 
}

fn get_gba_addr_data (path: &str) -> Vec<(u64, Vec<u8>)> {
  let addr = GBA_CARTRIDGE_ROM_START;
  let data = load_file(path);
  vec![(addr,data)]
}
                    

const GBA_CARTRIDGE_ROM_START : u64 = 0x08000000;

/* Just a debugging stub */
fn main() {
  let sample1 = "tomato-RT-AC3200-ARM-132-AIO-httpd";
  let sample2 = "tomato-RT-N18U-httpd";
  let sample3 = "openssl";
  let sample4 = "ldconfig.real";
  let sample_gba = "megaman_zero_4.gba";
  let sample_root = "/home/oblivia/Projects/roper/data/"
    .to_string();
  let elf_path = sample_root.clone() + sample3;
  let gba_path = sample_root.clone() + sample_gba;
  let elf_addr_data = get_elf_addr_data(&elf_path,
                                        &vec![".text",".rodata"]);
  let gba_addr_data = get_gba_addr_data(&gba_path);


  
 
  /* Testing out the decoder */
  //let foo : Vec<u16> = (0..0x200).map(|x| x | 0xb400).collect();
  //pretty(&foo);
  println!("****************** ELF {} **********************",
           elf_path);
  let (text_addr, ref text_data) = elf_addr_data[0];
  let (rodata_addr, ref rodata_data) = elf_addr_data[1];
  let wordvec_elf = u8s_to_u16s(&text_data, Endian::LITTLE);
  wordvec_analysis(&wordvec_elf);

  println!("******************* GBA {} **********************",
           gba_path);
  let (gba_addr, ref gba_data) = gba_addr_data[0];
  let wordvec_gba = u8s_to_u16s(gba_data, Endian::LITTLE);
  wordvec_analysis(&wordvec_gba);
  //pretty(&wordvec);

  //println!("sp_delta_info:\n{:?}\n", sp_delta_info);

  /**************** Testing out Capstone *******************
  let cs_mode = CsMode::MODE_THUMB;
  let cs_mode_s = "Thumb";
  let dissed : Vec<Inst>
      = disas_sec(text, 
                  CsArch::ARCH_ARM, 
                  cs_mode);
  println!("{:?} instructions in {:?}",
           dissed.len(), cs_mode_s);
  let mut length = 0;
  for inst in dissed.iter() {
    let mnemonic = &inst.mnem;
    println!("{:x} > {:08x} {} {:?} {:?}",
             length,
             inst.addr,
             mnemonic,
             inst.src,
             inst.dst,);
  }
  *********************************************************/
  let mut uc = roper::init_engine(&gba_addr_data);
  roper::add_hooks(&mut uc);
  
  
  let regions = uc.mem_regions()
    .expect("failed to retrieve memory regions");
  println!("Regions: {}", regions.len());
  for region in &regions {
    println!("> {:?}", region);
  }

  let pc = uc.reg_read(RegisterARM::PC)
    .expect("Failed to read register");
  println!("PC BEFORE >  {:08x}", pc);

  let phony_stack : Vec<u8> = vec![0x20,0x01,0x01,0x00,4,8,4,8];
  let ret : Vec<i32> = roper::hatch_chain(&mut uc, &phony_stack);
  println!("REGISTERS:\n{}", roper::hexvec(&ret));
  let pc = uc.reg_read(RegisterARM::PC)
    .expect("Failed to read register");
  println!("PC AFTER >   {:08x}", pc);

  for _ in 0..40 { print!("*"); }
  
  println!("\n  Round Two");
  for _ in 0..40 { print!("*"); }
  println!("");
  let ret2 : Vec <i32> = roper::hatch_chain(&mut uc, &phony_stack);
  println!("REGISTERS:\n{}", roper::hexvec(&ret2));

  println!("\n  Round Three");
  for _ in 0..40 { print!("*"); }
  println!("");
  let ret3 : Vec <i32> = roper::hatch_chain(&mut uc, &phony_stack);
  println!("REGISTERS:\n{}", roper::hexvec(&ret3));

  let page_size = uc.query(unicorn::Query::PAGE_SIZE)
    .expect("Failed to query page size");
  let hardware_mode = uc.query(unicorn::Query::MODE)
    .expect("Failed to query hardware mode");
    println!(">> page size:     {}", page_size);
    println!(">> hardware mode: {}", hardware_mode);

  println!("None: {:?}", None as Option<i32>);
}
