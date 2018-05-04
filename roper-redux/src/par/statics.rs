extern crate goblin;
extern crate num;
extern crate rand;

use std::fs::File;
use std::sync::{Arc, RwLock};
use std::io::Read;
use std::path::Path;
use std::env;
use std::fmt;

use self::num::PrimInt;
use self::goblin::Object;
use self::goblin::elf::header::machine_to_str;

use emu::loader::{Arch, Mode};

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
fn read_conf(filename: &str) -> String {
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

pub type RngSeed = [u8; 32];

lazy_static! {
    pub static ref RNG_SEED: RngSeed /* for Isaac64Rng */
        = {
            let seed_txt = read_conf("isaac64_seed.txt");
            let mut seed_vec = [0u8; 32];
            let mut i = 0;
            for octet in seed_txt.split_whitespace() {
                seed_vec[i] = u8::from_str_radix(octet,16).expect("Failed to parse seed");
                i += 1;
                if i == 32 { break };
            }
            while i < 32 { seed_vec[i] = 0 };
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
pub fn wf<T: PrimInt + fmt::LowerHex>(w: T) -> String {
    match *ARCHITECTURE {
        Arch::X86(Mode::Bits64) => format!("{:016x}", w),
        Arch::X86(Mode::Bits16) => format!("{:04x}", w),
        _ => format!("{:08x}", w),
    }
}

lazy_static! {
    pub static ref KILL_SWITCH: Arc<RwLock<bool>>
        = Arc::new(RwLock::new(false));
}

pub const INPUT_SLOT_FREQ: f32 = 0.1;

lazy_static! {
    pub static ref CROSSOVER_DEGREE: f32 = 0.5;
    /* TODO: Read this from a config file */
}

lazy_static! {
    /* if true, then homologous xbit crossover selects only those slots
     * for which mbit ^ pbit == 1. if false, it selects only those slots
     * for which mbit ^ pbit == 0.
     */
    pub static ref CROSSOVER_XBIT: bool = true;
    /* TODO read from config file */
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum MaskOp {
    Xor,
    Nand,
    OnePt,
    Uniform,
    And,
    Or,
}

lazy_static! {
    /* TODO read from config file */
    pub static ref CROSSOVER_MASK_COMBINER: MaskOp = MaskOp::And;
}

lazy_static! {
    /* TODO read */
    pub static ref CROSSOVER_MASK_INHERITANCE: MaskOp = MaskOp::Uniform;
} 

lazy_static! {
    /* TODO read */
    pub static ref CROSSOVER_MASK_MUT_RATE: f32 = 0.2;
}
