extern crate unicorn;
extern crate hexdump;
extern crate rand;
extern crate rayon;



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
use self::rayon::prelude::*;

use emu::loader;
use emu::loader::{ARM_ARM,ArchMode,Mode,Emu};
use gen;


const OK: u32 = 0;

/* The gen::Pod data structure will be implemented in the gen::genotype
 * module. It will contain (a) a genotype, and (b) any information
 * required in order to evaluate that genotype on the emulator --
 * input registers, problem specification, etc., perhaps a reference
 * to a ketos script that will perform the fitness evaluation on 
 * the phenotype.
 */
pub fn hatch (pod: &mut gen::Pod, emu: &mut Emu) -> bool {
    /** a very simple version of hatch_chain **/
    let payload = pod.chain.pack();
    hexdump::hexdump(&payload); /* NB: debugging only */
    let start_addr = pod.chain.entry();
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
   
    /* Now, get the resulting CPU context (the "phenotype"), and
     * attach it to the mutable pod
     */
    let registers = emu.read_general_registers().unwrap();
    let memory = emu.writeable_memory();
    /* print registers, for debugging */
    for reg in &registers {
        print!("{:08x} ", reg);
    }
    println!("");
    pod.registers = registers;
    pod.memory = memory;
    true
}

// make gen::Pod type as Sendable, interior-mutable encasement for Chain
//
pub fn spawn_hatchery (path: &'static str, num_engines: usize)
    -> (Sender<gen::Pod>, Receiver<gen::Pod>, JoinHandle<()>) {

    let (alice_tx, bob_rx) = channel();
    let (bob_tx, alice_rx) = channel();
    /* Initialize the code buffer once, and never again! */
    /** THE MAIN HATCHERY THREAD **/
    let handle = spawn(move || {
        let mut inner_handles = Vec::new();
        let emu_pool = Arc::new((0..num_engines)
            .map(|_| ARM_ARM)
            .collect::<Vec<ArchMode>>()
            .par_iter()
            .map(|ref x| Mutex::new(loader::init_emulator_with_code_buffer(x)
                                       .unwrap()))
            .collect::<Vec<Mutex<Emu>>>());
        /** INNER HATCHERY THREAD: SPAWNS ONE PER INCOMING **/
        for mut incoming in alice_rx {
            let alice_tx_clone = alice_tx.clone();
            let emu_pool = emu_pool.clone();
            inner_handles.push(spawn(move || {
                let mut i = 0;
                let mut emulator = None;
                'waiting_for_emu: loop {
                    'trying_emus: for emu in emu_pool.iter() {
                        match emu.try_lock() {
                            Ok(x) => { 
                                println!("Got emu {} {:?}", i, x); 
                                emulator = Some(x);
                                break 'waiting_for_emu; 
                            },
                            Err(_) => { /* println!("emu {} is busy", i); */ },
                        }
                        i += 1;
                    }
                }
                /* Assuming an average runtime in the emulator of 0.1 seconds,
                 * which is roughly what we see in the best specimens of ROPER
                 * 1, and which we can use as a tentative approximate upper
                 * bound, here, I'm finding that, over 10000 evaluations in a
                 * batch, the highest number we hit in the "emu # is busy"
                 * messages is 203. We can probably set the number of emulators
                 * to 256, in most purposes, even if we are using comparatively
                 * large batches of evaluations (in fitness-proportionate
                 * selection, for example). 
                 */
                let mut emu = emulator.unwrap();
                let mut x : gen::Pod = incoming;
                /******* Where the magic happens *******/
                let res = hatch(&mut x, &mut emu);
                sleep(Duration::from_millis(thread_rng().gen::<u64>() % 100));
                /******* Now, send back the result ******/
                alice_tx_clone.send(x).unwrap();
            }));
        }
        let mut jcount = 0;
        for h in inner_handles {
            jcount += 1;
            h.join().unwrap();
            //println!("[+] joined {}",jcount);
        }
    });

    (bob_tx, bob_rx, handle)
}

