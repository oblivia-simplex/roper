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
use emu::loader::{ARM_ARM,Arch,Mode,Emu};
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

/* I think some of this data cloning could be optimized away. FIXME */
pub fn hatch_cases (creature: &mut gen::Creature, emu: &mut Emu) -> bool {
    let mut map = gen::Phenome::new();
    {
        let mut inputs: Vec<gen::Input> = creature.phenome
                                                  .keys()
                                                  .map(|x| x.clone())
                                                  .collect();
        while inputs.len() > 0 {
            let input = inputs.pop().unwrap(); 
        /* This can't really be threaded, due to the unsendability of emu */
            let pod = hatch(creature, &input, emu);
            map.insert(input.to_vec(),Some(pod));
        }
    }
    creature.phenome = map;
    true
}

pub fn hatch (creature: &mut gen::Creature, input: &gen::Input, emu: &mut Emu) -> gen::Pod {
    /* a very simple version of hatch_chain **/

    let payload = creature.genome.pack(input);
    //hexdump::hexdump(&payload); /* NB: debugging only */
    let start_addr = creature.genome.entry();
    let (stack_addr, stack_size) = emu.find_stack();
    let stack_entry = stack_addr + (stack_size/2) as u64;
    /* save writeable regions **/
    let saved_regions: loader::MemImage = emu.writeable_memory();

    /* load payload **/
    emu.mem_write(stack_entry, &payload).expect("mem_write fail in hatch");
    let risc_width = emu.risc_width();
    emu.set_sp(stack_entry + risc_width);
    
    let visitor: Rc<RefCell<Vec<(u64,Mode)>>> = Rc::new(RefCell::new(Vec::new()));
    let writelog = Rc::new(RefCell::new(Vec::new()));

    let mem_write_hook = {
        let writelog = writelog.clone();
        let callback = move |uc: &unicorn::Unicorn, 
                             _memtype: unicorn::MemType,
                             addr: u64, 
                             size: usize, 
                             val: i64| {
            let mut wmut = writelog.borrow_mut();
            wmut.push((addr, val as u64));
            /*
            let pc = uc.reg_read(11).unwrap(); /* FIXME KLUDGE ARM id for PC */
            let inst = uc.mem_read(pc, 4);
            let mode = loader::get_uc_mode(&uc);
            
            let dis = match inst {
                Err(_) => "out of bounds".to_string(),
                Ok(v)  => log::disas(&v, mode),
            };
            //println!("WRITE with PC {:x} ({}): addr: {:x}, size: {:x}, val: {:x}", pc, dis, addr, size, val);
            */
            true
        };
        emu.hook_writeable_mem(callback)
    };

    let visit_hook = {
        let visitor = visitor.clone();
        let callback = move |uc: &unicorn::Unicorn, addr: u64, size: u32| {
            let mut vmut = visitor.borrow_mut();
            let mode = loader::get_uc_mode(uc);
            //let dis1 = log::disas_static(addr, mode);
            //let size = if mode == Mode::Thumb {2} else {4};
            //let inst = uc.mem_read(addr, size).unwrap();
            //let dis2 = log::disas(&inst, mode);
            //println!("STATIC: {}\nLIVE:   {} {:?}\n", dis1, dis2, inst);
            vmut.push((addr,mode)); /* maybe track mode here too */
            /* debugging */

        };
        emu.hook_exec_mem(callback)
    };
    /* Hatch! **/ /* FIXME don't hardcode these params */
    let x = emu.start(start_addr, 0, 0, 1024);
    /* for debugging */
    /*
     * for seg in &emu.writeable_memory() {
        println!("{}, #bytes: 0x{:x}",seg, seg.data.len());
    }
    */
    match visit_hook {
        Ok(h)  => { emu.remove_hook(h).unwrap(); },
        Err(_) => { },
    }

   
    /* Now, get the resulting CPU context (the "phenotype"), and
     * attach it to the mutable pod
     */
    let registers = emu.read_general_registers().unwrap();
    //let memory = emu.writeable_memory();
    let vtmp = visitor.clone();
    let visited = vtmp.borrow().to_vec();
    let wtmp = writelog.clone();
    let writelog = wtmp.borrow().to_vec();
    //print!("writelog (len: 0x{:x}): ", writelog.len());
    //for &(addr, data) in &writelog {
    //    print!(" {:08x} -> {:x};", addr, data);
   // }
    //println!("");
    /* print registers, for debugging */
    //for reg in &registers {
    //    print!("{:08x} ", reg);
   // }
    //println!("");
    /* Now, restore the state of writeable memory */
    for seg in &saved_regions {
        emu.mem_write(seg.aligned_start(), &seg.data);
    }
    let pod = gen::Pod::new(registers,visited,writelog);
    pod
}


fn spawn_coop (rx: Receiver<gen::Creature>, tx: SyncSender<gen::Creature>) -> () {
    /* a thread-local emulator */
    let mut emu = loader::init_emulator_with_code_buffer(&ARM_ARM).unwrap();

    /* The syscall hooks will remain in place for the duration of the
     * emulator's life, since they're not phenome-specific, but will be
     * used to terminate execution. We'll install them here. 
     */
    let hook;
    {
        let cb = move |uc: &unicorn::Unicorn, what: u32| {
            //if cfg!(debug_assertions) {
                //let inst: Vec<u8> = uc.mem_read(addr, size as usize).unwrap();
                //let mode = loader::get_uc_mode(&uc);
                //let dis = log::disas(&inst, &mode);
                //println!("INTERRUPT: {:08x}\t{}",addr, dis);
            //}
            let pc = uc.reg_read(11).unwrap(); /* FIXME don't hardcode this arch-specific regid
                                         and don't leave it as a read-unfriendly i32.
                                         */
            //println!("INTERRUPT at PC {:08x}! {:x}", pc,what);
            uc.emu_stop().unwrap();
        };
        hook = emu.hook_interrupts(cb);
    }

    /* Hatch each incoming creature as it arrives, and send the creature
     * back to the caller of spawn_hatchery. */
    for incoming in rx {
        let mut creature = incoming;
        let _ = hatch_cases(&mut creature, &mut emu);
        tx.send(creature); /* goes back to the thread that called spawn_hatchery */
    }
    
    /* Cleanup */
    match hook {
        Ok(h) => { emu.remove_hook(h).unwrap(); },
        Err(_) => { },
    }
}

// make gen::Pod type as Sendable, interior-mutable encasement for Chain
//
// the segfauls appear to be resulting from a stack overflow, when the
// number of simultaneous threads (and therefore channels) is very high. 
// Perhaps boxing the channels would help?
pub fn spawn_hatchery (num_engines: usize, expect: usize)
    -> (SyncSender<gen::Creature>, Receiver<gen::Creature>, JoinHandle<()>) {

    let (alice_tx, bob_rx) = sync_channel(num_engines);
    let (bob_tx, alice_rx) = sync_channel(num_engines);

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
    });

    /* clean up threads? */

    (bob_tx, bob_rx, handle)
}

