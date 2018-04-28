extern crate rand;
extern crate goblin;
extern crate num;

use std::fs::File;
use std::sync::{Arc,RwLock,Mutex};
use std::io::Read;
use std::path::Path;
use std::env;
use std::fmt;

use self::num::PrimInt;
use self::goblin::{Object,elf};
use self::goblin::elf::Elf;
use self::goblin::elf::header::machine_to_str;
use self::rand::{Rng,SeedableRng};
use self::rand::isaac::Isaac64Rng;

use emu::loader;
use emu::loader::{Arch,Mode,PROT_READ,PROT_WRITE,PROT_EXEC};


lazy_static! {
    pub static ref CONFIG_DIR: String 
        = match env::var("ROPER_CONFIG_DIR") {
                Err(_) => ".roper_config/".to_string(),
                Ok(d)  => d.to_string(),
          };
}

/// Reads the config file specified from the default config directory,
/// which is ~/ + CONFIG_DIR, and trims any trailing whitespace from
/// the result.
fn read_conf (filename: &str) -> String {
    let mut p = String::new();
    p.push_str(env::home_dir().unwrap().to_str().unwrap());
    p.push_str("/");
    p.push_str(&CONFIG_DIR);
    p.push_str("/");
    p.push_str(filename);
    let path = Path::new(&p);
    let mut fd = File::open(path).unwrap();
    let mut txt = String::new();
    fd.read_to_string(&mut txt).unwrap();
    while txt.ends_with("\n") || txt.ends_with(" ") || txt.ends_with("\t") {
        txt.pop();
    }
    txt
}

#[test]
fn test_read_conf() {
    assert_eq!(read_conf(".config_test"), "IT WORKS");
}



pub type RngSeed = Vec<u64>;

lazy_static! {
    pub static ref RNG_SEED: RngSeed /* for Isaac64Rng */
        = {
            let seed_txt = read_conf("isaac64_seed.txt");
            let mut seed_vec = Vec::new();
            for row in seed_txt.lines() {
                seed_vec.push(u64::from_str_radix(row,16)
                                 .expect("Failed to parse seed"));
            }
            seed_vec
        };
}

lazy_static! {
    pub static ref MUTABLE_RNG_SEED: Arc<RwLock<RngSeed>>
        = Arc::new(RwLock::new(RNG_SEED.clone()));
}
/* Wait: if this is accessed from multiple threads, there will be another
 * source of indeterminacy and unrepeatability: the order of access cannot
 * be assured. So make sure you only access this from a single thread, then
 * pass the seed to each spun thread. 
 *
 * Perhaps every thread could just take the base RNG_SEED, and xor it with 
 * its own thread id?
 */

lazy_static! {
    pub static ref CODE_BUFFER: Vec<u8>
        = {
            /* first, read the config */
            let bp = match env::var("ROPER_BINARY") {
                Ok(s)  => s,
                Err(_) => read_conf("binary_path.txt"),
            };
            //println!("[*] Read binary path as {:?}",bp);
            let path = Path::new(&bp);
            let mut fd = File::open(path).unwrap();
            let mut buffer = Vec::new();
            fd.read_to_end(&mut buffer).unwrap();
            buffer
        };
}

// set addr size here too. dispense with risc_width() calls, which are confused
lazy_static! {
    pub static ref ARCHITECTURE: Arch
        = {
            let arch_magic = match Object::parse(&CODE_BUFFER).unwrap() {
                Object::Elf(e) => machine_to_str(e.header.e_machine),
                _ => panic!("Binary format unimplemented."),
            };
            match arch_magic {
                "ARM" => Arch::Arm(Mode::Arm),
                "MIPS"  => Arch::Mips(Mode::Be),
                "MIPS_RS3_LE" => Arch::Mips(Mode::Le),
                "X86_64" => Arch::X86(Mode::Bits64),
                "386" => Arch::X86(Mode::Bits32),
                _  => panic!("arch_magic not recognized!"),
            }
        };
}

lazy_static! {
    pub static ref ADDR_WIDTH: usize
        = { 
            match *ARCHITECTURE {
                Arch::X86(_) => 8,
                _ => 4,
            }
        };
}

/// A tiny machine word formatter
#[inline]
pub fn wf<T: PrimInt + fmt::LowerHex> (w: T) -> String {
    match *ARCHITECTURE {
        Arch::X86(Mode::Bits64) => format!("{:016x}", w),
        Arch::X86(Mode::Bits16) => format!("{:04x}", w),
        _ => format!("{:08x}", w),
    }
}
