extern crate unicorn;
extern crate hexdump;
extern crate rand;
extern crate rayon;
extern crate capstone;


use std::thread::{spawn,sleep,JoinHandle};
use std::sync::mpsc::{sync_channel,channel,SyncSender,Sender,Receiver};
use std::sync::{Arc,RwLock,MutexGuard,Mutex};
use std::rc::Rc;
use std::cell::{RefMut,RefCell};
use std::ops::Deref;
use std::time::Duration;
use self::rand::{SeedableRng,Rng,thread_rng};
use self::rand::isaac::Isaac64Rng;
use self::rayon::prelude::*;

use emu::loader;
use emu::loader::{ARM_ARM,ArchMode,Mode,Emu};
use gen;
use log;


//const OK: u32 = 0;

/* The gen::Pod data structure will be implemented in the gen::genotype
 * module. It will contain (a) a genotype, and (b) any information
 * required in order to evaluate that genotype on the emulator --
 * input registers, problem specification, etc., perhaps a reference
 * to a ketos script that will perform the fitness evaluation on 
 * the phenotype.
 */
pub fn hatch (creature: &mut gen::Creature, emu: &mut Emu) -> bool {
    /* a very simple version of hatch_chain **/
    let payload = creature.genome.pack();
    //hexdump::hexdump(&payload); /* NB: debugging only */
    let start_addr = creature.genome.entry();
    let (stack_addr, stack_size) = emu.find_stack();
    let stack_entry = stack_addr + (stack_size/2) as u64;
    /* save writeable regions **/
    let saved_regions: Vec<(u64,Vec<u8>)> = emu.writeable_memory();

    /* load payload **/
    emu.mem_write(stack_entry, &payload).expect("mem_write fail in hatch");
    let risc_width = emu.risc_width();
    emu.set_sp(stack_entry + risc_width);
    
    let visitor: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let hook;
    /* Set hooks **/
    {
        let visitor = visitor.clone();
        let callback = move|uc: &unicorn::Unicorn, addr: u64, size: u32| {
            let mut vmut = visitor.lock().unwrap();
            vmut.push(addr); /* maybe track mode here too */
            /* debugging */
            let inst: Vec<u8> = uc.mem_read(addr, size as usize).unwrap();
            let mode = if size == 4 { ArchMode::Arm(Mode::Arm) } else { ArchMode::Arm(Mode::Thumb) };
            let dis = log::disas(&inst, &mode);
            println!("{:08x}\t{}",addr, dis);

        };
        hook = emu.hook_exec_mem(callback);
        //println!("{:?}",hook);
/* Okay, we're getting segfaults now.
 * And when we don't the runtime has gone from 1.5 seconds to 5s.
 * Maybe there's a lighter way than hooking everything. 
 */
    }
    /* Hatch! **/ /* FIXME don't hardcode these params */
    let x = emu.start(start_addr, 0, 0, 1024);
    match hook {
        Ok(h)  => { emu.remove_hook(h).unwrap(); },
        Err(_) => { },
    }

   
    /* Now, get the resulting CPU context (the "phenotype"), and
     * attach it to the mutable pod
     */
    let registers = emu.read_general_registers().unwrap();
    let memory = emu.writeable_memory();
    let vtmp = visitor.clone();
    let visited = vtmp.lock().unwrap().clone().to_vec();
    /* print registers, for debugging */
    //for reg in &registers {
    //    print!("{:08x} ", reg);
   // }
    //println!("");
    let pod = gen::Pod::new(registers,memory,visited);
    creature.phenome = Some(pod);
    true
}


fn spawn_subhatchery (rx: Receiver<gen::Creature>, tx: Sender<gen::Creature>) -> () {
    /* a thread-local emulator */
    let mut emu = loader::init_emulator_with_code_buffer(ARM_ARM);
    for incoming in rx {
        let mut creature = incoming;
        let _ = hatch(&mut creature, &mut emu);
        tx.send(creature);
    }
}

// make gen::Pod type as Sendable, interior-mutable encasement for Chain
//
pub fn spawn_hatchery (num_engines: usize)
    -> (SyncSender<gen::Creature>, Receiver<gen::Creature>, JoinHandle<()>) {

    let (alice_tx, bob_rx) = sync_channel(20000);
    let (bob_tx, alice_rx) = sync_channel(20000);
    /* Initialize the code buffer once, and never again! */
    /* THE MAIN HATCHERY THREAD **/
    let handle = spawn(move || {
        let mut inner_handles = Vec::new();
        let emu_pool = Arc::new((0..num_engines)
            .map(|_| ARM_ARM)
            .collect::<Vec<ArchMode>>()
            .par_iter()
            .map(|ref x| Mutex::new(loader::init_emulator_with_code_buffer(x)
                                       .unwrap()))
            .collect::<Vec<Mutex<Emu>>>());
        /* INNER HATCHERY THREAD: SPAWNS ONE PER INCOMING **/
        for mut incoming in alice_rx {
            let alice_tx_clone = alice_tx.clone();
            let emu_pool = emu_pool.clone();
            inner_handles.push(spawn(move || {
                let emulator;
                'waiting_for_emu: loop {
                    'trying_emus: for emu in emu_pool.iter() {
                        match emu.try_lock() {
                            Ok(x) => { 
                                //println!("Got emu {} {:?}", i, x); 
                                emulator = x;
                                break 'waiting_for_emu; 
                            },
                            Err(_) => { /* println!("emu {} is busy", i); */ },
                        }
                    }
                    sleep(Duration::from_millis(1u64)); /* to avoid hogging CPU */
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
                let mut emu = emulator;
                let mut x : gen::Creature = incoming;
                /****** Where the magic happens *******/
                let res = hatch(&mut x, &mut emu);
                //sleep(Duration::from_millis(thread_rng().gen::<u64>() % 100));
                /****** Now, send back the result ******/
                alice_tx_clone.send(x).unwrap();
            }));
        }
        for h in inner_handles {
            h.join().unwrap();
        }
    });

    (bob_tx, bob_rx, handle)
}

