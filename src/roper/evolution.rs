use roper::phylostructs::*;
use roper::population::*;
use roper::util::*;
use roper::param::*;
use rand::{Rng,ThreadRng};
use unicorn::{CpuARM};


const default_mode : MachineMode = MachineMode::ARM;
const GBA_CARTRIDGE_ROM_START : u64 = 0x08000000;

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



pub fn init_pop (popsize: usize,
                 text_data: &Vec<u8>,
                 text_addr: u32,
                 constants: &Vec<u32>,
                 rng: ThreadRng) -> Population {
  let mut clumps  = reap_gadgets(text_data, text_addr, default_mode);
  let data_pool = mangle(constants, &mut rng);
  saturate_clumps(&mut clumps, data_pool);
  
  /* Generate a random population of chains here */

  Population {
    
  }
}

pub fn init_machinery (path: String, mode: MachineMode) -> Machinery {
  let elf_addr_data = get_elf_addr_data(path,
                                        vec![".text", ".rodata"]);
  let uc = init_engine(&elf_addr_data, mode);
  let rng = ThreadRng;
  Machinery { uc: uc, rng: rng }
}

pub fn evolve (population: &Population,
               machinery: &mut Machinery)
              -> bool {
  let mut rng = &mut machinery.rng;
  let mut uc  = &mut machinery.uc;


}
