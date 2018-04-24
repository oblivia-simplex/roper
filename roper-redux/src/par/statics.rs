extern crate rand;
extern crate goblin;

use std::fs::File;
use std::sync::{Arc,RwLock,Mutex};
use std::io::Read;
use std::path::Path;
use std::env;

use self::goblin::{Object,elf};
use self::rand::{Rng,SeedableRng};
use self::rand::isaac::Isaac64Rng;

use emu::loader;
use emu::loader::{PROT_READ,PROT_WRITE,PROT_EXEC};

pub const STACK_SIZE: usize = 0x1000;

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

lazy_static! {
    pub static ref CODE_BUFFER: Vec<u8>
        = {
            /* first, read the config */
            let bp = read_conf("binary_path.txt");
            //println!("[*] Read binary path as {:?}",bp);
            let path = Path::new(&bp);
            let mut fd = File::open(path).unwrap();
            let mut buffer = Vec::new();
            fd.read_to_end(&mut buffer).unwrap();
            buffer
        };
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
    pub static ref MEM_IMAGE: loader::MemImage
        = {
            let obj = Object::parse(&CODE_BUFFER).unwrap();
            let mut image: loader::MemImage = loader::MemImage::new();
            match obj {
                /* FIXME: Don't map directly from CODE_BUFFER. Use the Section
                 * Headers for reference to get the virtual addresses right.
                 */
                Object::Elf(e) => {
                    let shdrs = &e.section_headers;

                    let phdrs = &e.program_headers;
                    for phdr in phdrs {
                        let seg = loader::Seg::from_phdr(&phdr);
                        if seg.loadable() {
                            let start = seg.aligned_start() as usize;
                            let end = seg.aligned_end() as usize;
                            image.push((seg.aligned_start(), 
                                        seg.perm,
                                        seg.aligned_size(),
                                        Vec::new()));
                        }
                    }
                    /* Low memory */
                    image.push((0, loader::PROT_READ, 0x1000, Vec::new()));

                    for shdr in shdrs {
                        let (i,j) = (shdr.sh_offset as usize, 
                                     (shdr.sh_offset+shdr.sh_size) as usize);
                        let aj = usize::min(j, CODE_BUFFER.len());
                        let sdata = CODE_BUFFER[i..aj].to_vec();
                        /* find the appropriate segment */
                        let mut s = 0;
                        for row in image.iter_mut() {
                            if shdr.sh_addr >= row.0 
                                && shdr.sh_addr < (row.0 + row.2 as u64) {
                                /* then we found a fit */
                                row.3 = sdata.clone();
                                break;
                            }
                            s += 1;
                        }
                    }
                    /* now allocate the stack */
                    let mut bottom = 0;
                    for row in &image {
                        let b = row.0 + row.2 as u64;
                        if b > bottom { bottom = b };
                    }
                    image.push((bottom, PROT_READ|PROT_WRITE, STACK_SIZE, vec![0; STACK_SIZE]));
                },
                _ => panic!("Not yet implemented."),
            }
            image
        };
}

#[test]
fn test_init_emulator_with_MEM_IMAGE() {
    loader::init_emulator_with_code_buffer(&loader::ARM_ARM).unwrap();
}
