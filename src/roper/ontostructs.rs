extern crate unicorn;
extern crate rand;
extern crate elf;

//use elf::*;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use roper::hatchery::*;
use roper::util::*;
use roper::phylostructs::*;
use unicorn::*;
use std::thread;
use rand::thread_rng;

const GBA_CARTRIDGE_ROM_START : u64 = 0x08000000;

fn load_file (path: &str) -> Vec<u8> {
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
      perm: unicorn::PROT_ALL, // Placeholder. Need to convert from elf
    });
  }
  sections
}
/* A struct to bundle together mutable machinery 
 * Each thread should have its own instance.
 */
pub struct Machinery {
//  pub rng: rand::ThreadRng,
  pub cluster:  Vec<Engine>,
  //pub mangler: Mangler,
}

pub struct Engine (Box<CpuARM>);
unsafe impl Send for Engine {}
impl Engine {
  pub fn new (uc: CpuARM) -> Engine {
    Engine(Box::new(uc))
  }
  pub fn unwrap (&self) -> &CpuARM {
    &(*self.0)
  }
  pub fn unwrap_mut (&mut self) -> &mut CpuARM {
    &mut (*self.0)
  }
}

impl Machinery {
  pub fn new (elf_path: &str, 
              mode: MachineMode,
              uc_num: usize,
              debug: bool) -> Machinery {
    let elf_addr_data = get_elf_addr_data(elf_path,
                                          &vec![".text", ".rodata"]);
    let mut cluster = Vec::new();
    for i in 0..uc_num {
      println!("spinning up engine #{}",i);
      let mut uc = init_engine(&elf_addr_data, mode);
      //if debug {
      //  add_debug_hooks(&mut uc);
      //}
      cluster.push(Engine::new(uc));
    }
    Machinery { 
      cluster: cluster, 
    }
  }
}
