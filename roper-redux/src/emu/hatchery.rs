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
            if false && cfg!(debug_assertions) {
                let inst: Vec<u8> = uc.mem_read(addr, size as usize).unwrap();
                let mode = if size == 4 { ArchMode::Arm(Mode::Arm) } else { ArchMode::Arm(Mode::Thumb) };
                let dis = log::disas(&inst, &mode);
                println!("{:08x}\t{}",addr, dis);
            }

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


fn spawn_coop (rx: Receiver<gen::Creature>, tx: SyncSender<gen::Creature>) -> () {
    /* a thread-local emulator */
    let mut emu = loader::init_emulator_with_code_buffer(&ARM_ARM).unwrap();
    for incoming in rx {
        let mut creature = incoming;
        let _ = hatch(&mut creature, &mut emu);
        tx.send(creature); /* goes back to the thread that called spawn_hatchery */
    }
}

// make gen::Pod type as Sendable, interior-mutable encasement for Chain
//
pub fn spawn_hatchery (num_engines: usize, expect: usize)
    -> (SyncSender<gen::Creature>, Receiver<gen::Creature>, JoinHandle<()>) {

    let (alice_tx, bob_rx) = sync_channel(20000);
    let (bob_tx, alice_rx) = sync_channel(20000);

    /* think of ways to dynamically scale the workload, using a more
     * sophisticated data structure than a circular buffer for carousel */
    let handle = spawn(move || {
        let mut carousel = Vec::new();
        
        for i in 0..num_engines {
            let (eve_tx,eve_rx) = channel();
            let alice_tx = alice_tx.clone();
            let h = spawn(move || { spawn_coop(eve_rx, alice_tx); } );        
            carousel.push((eve_tx, h));
        }

        let mut coop = 0;
        let mut counter = 0;
        for incoming in alice_rx {
            let &(ref tx, _) = &carousel[coop];
            let tx = tx.clone();
            tx.send(incoming);
            coop = (coop + 1) % carousel.len();
            counter +=1;
            if counter == expect { break };
        }

        /* clean up the carousel */
        while carousel.len() > 0 {
            if let Some((tx, h)) = carousel.pop() {
                drop(tx); /* there we go. that stops the hanging */
                h.join();
            };
        }
        println!("");
    });

    /* clean up threads? */

    (bob_tx, bob_rx, handle)
}

