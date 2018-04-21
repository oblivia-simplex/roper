extern crate unicorn;
extern crate rand;



use std::thread::{spawn,sleep,JoinHandle,Thread};
use std::sync::mpsc::{channel,Sender,Receiver};
use std::sync::{Arc,RwLock,MutexGuard,Mutex};
use std::cell::{RefCell};
use std::fs::File;
use std::ops::Deref;
use std::io::Read;
use std::path::Path;
use std::time::Duration;
use self::rand::{Rng,thread_rng};

use emu::loader;
use emu::loader::{ARM_ARM,ArchMode,Mode,Emu};

/*
 * what we want here is a function that spawns a listener loop and returns
 * the sending end of a channel to it. 
 * when the loop receives a message -- a serialized chain -- it executes 
 * it in its local emulator, and sends the results back on the channel. 
 */

const OK: u32 = 0;

pub struct Params {pub foo:usize} /*placeholder */ 

#[derive(Eq,PartialEq,Debug,Clone,Copy)]
pub struct HatchError (u32);

unsafe impl Send for HatchError {}

impl Default for HatchError { 
    fn default() -> Self { HatchError(0) }
}

#[derive(Eq,PartialEq,Clone,Debug,Default)]
pub struct HatchResult {
    pub regs: Vec<u32>,
    pub mem:  Vec<u8>,
    pub visited: Vec<u32>,
    pub status: HatchError,
}

impl HatchResult {
    fn new () -> Self {
        HatchResult {
            regs: Vec::new(),
            mem: Vec::new(),
            visited: Vec::new(),
            status: HatchError(OK),
        }
    }
}

unsafe impl Send for HatchResult {}

#[derive(Clone,Debug,PartialEq,Eq)]
pub struct Egg {
    pub packed: Vec<u8>, /* later, we can stick more control info in here */
}

unsafe impl Send for Egg {}

#[derive(Clone,Debug,PartialEq,Eq)]
pub enum HatchMsg {
    ToHatch(Egg),
    Hatched(HatchResult),
}

unsafe impl Send for HatchMsg {}

#[derive(Clone,Debug,PartialEq,Eq)]
pub struct Pod (Vec<u32>); /* placeholder */
impl Pod {
    pub fn new (i: Vec<u32>) -> Self {
        Pod(i)
    }
}
unsafe impl Send for Pod {}

pub fn pack_word32le_vec (v: &Vec<u32>) -> Vec<u8> {
    let mut p : Vec<u8> = Vec::new();
    for word in v {
        p.extend_from_slice(&[(word & 0xFF) as u8,
                              ((word & 0xFF00) >> 0x08) as u8,
                              ((word & 0xFF0000) >> 0x10) as u8,
                              ((word & 0xFF000000) >> 0x18) as u8]);
    }
    p
}

pub fn hatch (pod: &mut Pod, emu: &mut Emu) -> bool {
    /** a very simple version of hatch_chain **/
    let payload = pack_word32le_vec(&pod.0);
    let start_addr = pod.0[0] as u64;
    let (stack_addr, stack_size) = emu.find_stack();
    let stack_entry = stack_addr + (stack_size/2) as u64;
    /** save writeable regions **/
    let mut saved_regions: Vec<(u64,Vec<u8>)> = emu.writeable_memory();

    /** load payload **/
    emu.mem_write(stack_entry, &payload).expect("mem_write fail in hatch");
    let risc_width = emu.risc_width();
    emu.set_sp(stack_entry + risc_width);
    
    /** Hatch! **/
    let x = emu.start(start_addr, 0, 0, 1024); /* FIXME don't hardcode these params */

    true
}

// make Pod type as Sendable, interior-mutable encasement for Chain
//
pub fn spawn_hatchery (path: &'static str, params: &Params) 
    -> (Sender<Pod>, Receiver<Pod>, JoinHandle<()>) {

    let (alice_tx, bob_rx) = channel();
    let (bob_tx, alice_rx) = channel();
    lazy_static! {
        static ref CODE_BUFFER: Vec<u8>
            = {
                let path = Path::new("/home/vagrant/ROPER/data/openssl");
                let mut fd = File::open(path).unwrap();
                let mut buffer = Vec::new();
                fd.read_to_end(&mut buffer).unwrap();
                buffer
            };
    }
    /** THE MAIN HATCHERY THREAD **/
    let handle = spawn(move || {
        let mut inner_handles = Vec::new();
        let emu_pool = Arc::new((0..100)
            .map(|_| Mutex::new(loader::init_emulator(&CODE_BUFFER, ARM_ARM).unwrap()))
            .collect::<Vec<Mutex<Emu>>>());
        /** INNER HATCHERY THREAD: SPAWNS ONE PER INCOMING **/
        for mut incoming in alice_rx {
            let alice_tx_clone = alice_tx.clone();
            let emu_pool = emu_pool.clone();
            inner_handles.push(spawn(move || {
                let mut i = 0;
                let mut emulator = None;
                sleep(Duration::from_millis(thread_rng().gen::<u64>() % 500));
                'waiting_for_emu: loop {
                    'trying_emus: for emu in emu_pool.iter() {
                        match emu.try_lock() {
                            Ok(x) => { 
                                println!("Got emu {} {:?}", i, x); 
                                emulator = Some(x);
                                break 'waiting_for_emu; 
                            },
                            Err(_) => { println!("emu {} is busy", i); },
                        }
                        i += 1;
                    }
                }
                let mut emu = emulator.unwrap();
                let mut x : Pod = incoming;
                x.0.push(0xdeadbeef);
                /******* Where the magic happens *******/
                let res = hatch(&mut x, &mut emu);
                /******* Now, send back the result ******/
                alice_tx_clone.send(x).unwrap();
            }));
        }
        let mut jcount = 0;
        for h in inner_handles {
            jcount += 1;
            h.join().unwrap();
            println!("[+] joined {}",jcount);
        }
    });

    (bob_tx, bob_rx, handle)
}

