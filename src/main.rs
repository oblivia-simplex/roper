#[allow(dead_code)]
extern crate elf;
extern crate unicorn;
extern crate capstone;
extern crate rand;
extern crate getopts;

use getopts::Options;
use std::env;

mod roper;

use rand::{Rng,Generator};

use std::path::{Path,PathBuf};
use std::fs::File;
use std::io::prelude::*;
use unicorn::*;
// use std::io;
//use roper::dis::{disas_sec,Inst};
use roper::thumb::*;
use roper::util::*;
use roper::population::*;
use roper::hatchery::{add_hooks,Sec,HatchResult,hatch_chain};
use roper::phylostructs::*;
use roper::evolution::*;
use roper::ontostructs::*;
use roper::csv_reader::*;

fn print_usage (program: &str, opts: Options) {
  let brief = format!("Usage: {} [options]", program);
  print!("{}", opts.usage(&brief));
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
                      -> Vec<Sec> {
  let path = PathBuf::from(path);
  let file = match elf::File::open_path(&path) {
    Ok(f) => f,
    Err(e) => panic!("Error: {:?}",e),
  };
  let mut sections : Vec<Sec> = Vec::new();
  for sec_name in secs.iter() {
    let sec = file.get_section(sec_name)
                  .expect("Unable to fetch section from elf");
    sections.push(Sec {
      name: sec_name.to_string(),
      addr: sec.shdr.addr,
      data: sec.data.clone(),
      perm: PROT_ALL, // Placeholder. Need to convert from elf
    });
  }
  sections
}

fn get_gba_addr_data (path: &str) -> Vec<(u64, Vec<u8>)> {
  let addr = GBA_CARTRIDGE_ROM_START;
  let data = load_file(path);
  vec![(addr,data)]
}
                    

const GBA_CARTRIDGE_ROM_START : u64 = 0x08000000;

/* Just a debugging stub */
fn main() {
  
  let args: Vec<String> = env::args().collect();
  let program = args[0].clone();

  let mut opts = Options::new();
  opts.optopt("p", "", "set target pattern", "PATTERN");
  opts.optopt("d", "", "set data path", "PATH");
  opts.optopt("g", "", "set fitness goal (default 0)", "POSITIVE FLOAT <= 1");
  opts.optopt("o", "", "set log directory", "DIRECTORY");
  opts.optopt("h", "help", "print this help menu", "");
  let matches = match opts.parse(&args[1..]) {
    Ok(m)  => { m },
    Err(f) => { panic!(f.to_string()) },
  };
  if matches.opt_present("h") {
    print_usage(&program, opts);
    return;
  }
  let rpattern_str = matches.opt_str("p");
  let data_path    = matches.opt_str("d");
  let log_dir      = match matches.opt_str("o") {
    None    => {
      let p = Path::new("./logs/");
      if p.is_dir() { 
        p.to_str().unwrap().to_string() 
      } else { 
      "./".to_string()
      }
    },
    Some(p) => p,
  };
  let goal : f32 = match matches.opt_str("g") {
    None => 0.0,
    Some(s) => s.parse::<f32>()
                .expect("Error parsing fitness goal"),
  };
  println!(">> goal = {}", goal);
  let io_targets : IoTargets =
    match (rpattern_str, data_path) {
      (Some(s),None) => vec![(vec![1;16], 
                              Target::Exact(
                                RPattern::new(&s)
                                ))],
      (None,Some(s)) => process_data2(&s,4), // don't hardcode numfields. infer by analysing lines. 
      _              => {
        print_usage(&program, opts);
        return;
      },
    };
  
 
  /**************************************************/
  let sample1 = "tomato-RT-AC3200-ARM-132-AIO-httpd";
  let sample2 = "tomato-RT-N18U-httpd";
  let sample3 = "openssl";
  let sample4 = "ldconfig.real";
  let sample_gba = "megaman_zero_4.gba";
  let sample_root = "/home/oblivia/Projects/roper/data/"
    .to_string();
  let elf_path = sample_root.clone() + sample4;
  let gba_path = sample_root.clone() + sample_gba;
  let elf_addr_data = get_elf_addr_data(&elf_path,
                                        &vec![".text",".rodata"]);
  println!("****************** ELF {} **********************",
           elf_path);
  let text_addr = elf_addr_data[0].addr;
  let text_data = &elf_addr_data[0].data;
  let rodata_addr = elf_addr_data[1].addr;
  let rodata_data = &elf_addr_data[1].data;
  let wordvec_elf = u8s_to_u16s(&text_data, Endian::LITTLE);
  
  let mode = MachineMode::ARM;

  let iris_data = sample_root.clone() + "/iris.data";

  let elf_clumps = reap_gadgets(text_data,
                                text_addr as u32,
                                mode);

  let constants = suggest_constants(&io_targets);
  let mut params : Params = Params::new();

  params.code = text_data.clone();
  params.code_addr = text_addr as u32;
  params.data = vec![rodata_data.clone()];
  params.data_addrs   = vec![rodata_addr as u32];
  params.constants    = constants;
  params.io_targets   = io_targets;
  params.fit_goal     = goal;
  params.set_csv_dir(&log_dir);

  let mut rng = rand::thread_rng();
  let mut population = Population::new(&params, &mut rng);

  let mut machinery = Machinery::new(&elf_path,
                                     mode,
                                     &params.constants);

  let mut i : usize = 0;
  while population.best_fit() == None || population.best_fit() > Some(params.fit_goal) {
    tournement(&mut population, &mut machinery);
    i += 1;
  }
  println!("=> {} GENERATIONS", i);
  println!("=> BEST FIT: {:?}", population.best_fit());
  println!("=> RUNNING BEST:\n");
           
  add_hooks(&mut machinery.uc);
  let mut bclone = population.best.unwrap().clone();
  population.params.verbose = true;
  evaluate_fitness(&mut machinery.uc,
                   &mut bclone,
                   &population.params.io_targets,
                   population.params.verbose);
  for p in population.params.io_targets.iter() {
    println!("{}", p.1);
  }
  println!("\n{}", &bclone);
}
