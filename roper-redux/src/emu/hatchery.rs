// #![feature(fnbox)]
extern crate unicorn;
extern crate hexdump;
extern crate rand;
extern crate rayon;
extern crate capstone;


//use std::boxed::FnBox;
use std::thread::{spawn,sleep,JoinHandle};
use std::sync::mpsc::{sync_channel,channel,SyncSender,Sender,Receiver};
use std::sync::{Arc,RwLock,MutexGuard,Mutex};
use std::rc::Rc;
use std::cell::{RefMut,RefCell};
use std::ops::Deref;
use std::time::Duration;
use self::rand::{SeedableRng,Rng,thread_rng};
use self::rand::isaac::Isaac64Rng;
//use self::rayon::prelude::*;

use emu::loader;
use emu::loader::{ARM_ARM,Arch,Mode,Engine,get_mode,read_pc,uc_general_registers};
use par::statics::*;
use gen;
use gen::phenotype::{VisitRecord,WriteRecord};
use log;

fn snooze (millis: u64) {
    sleep(Duration::from_millis(millis))
}
//const OK: u32 = 0;

/* The gen::Pod data structure will be implemented in the gen::genotype
 * module. It will contain (a) a genotype, and (b) any information
 * required in order to evaluate that genotype on the emulator --
 * input registers, problem specification, etc., perhaps a reference
 * to a ketos script that will perform the fitness evaluation on 
 * the phenotype.
 */

/* I think some of this data cloning could be optimized away. FIXME */
#[inline]
pub fn hatch_cases (creature: &mut gen::Creature, emu: &mut Engine) -> gen::Phenome {
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
    map
}



#[inline]
pub fn hatch (creature: &mut gen::Creature, 
              input: &gen::Input, 
              emu: &mut Engine) -> gen::Pod {
    /* a very simple version of hatch_chain **/
    /* FIXME out of desperation, let's see if we get the crash if we create a new
     * emulator for every fucking hatch. */
    /* END KLUDGE */

    let payload = creature.genome.pack(input);
    //hexdump::hexdump(&payload); /* NB: debugging only */
    let start_addr = creature.genome.entry();
    let (stack_addr, stack_size) = emu.find_stack();
    let stack_entry = stack_addr + (stack_size/2) as u64;
    /* save writeable regions **/
    let saved_regions: loader::MemImage = emu.writeable_memory();

    /* load payload **/
    emu.uc.mem_write(stack_entry, &payload).expect("mem_write fail in hatch");
    emu.set_sp(stack_entry + *ADDR_WIDTH as u64);
    //emu.reset_registers(); /* TODO */
    // this will need to iterate through *ALL* the registers, not just the 
    // general purpose ones we're watching.
    // also the general_registers method is a misnomer. rename it.
    // eventually, we can replace this with a context restore.
    
    let visitor: Rc<RefCell<Vec<VisitRecord>>> 
        = Rc::new(RefCell::new(Vec::new()));
    let writelog = Rc::new(RefCell::new(Vec::new()));
    
    let mem_write_hook = {
        let writelog = writelog.clone();
        let callback = move |uc: &unicorn::Unicorn, 
                             _memtype: unicorn::MemType,
                             addr: u64, 
                             size: usize, 
                             val: i64| {
            let mut wmut = writelog.borrow_mut();
            let pc = read_pc(uc).unwrap();
            /* let's verify some things 
            if cfg!(debug_assertions) {
                let insts = uc.mem_read(pc, 15).unwrap();
                let dis = log::disas(&insts, get_mode(&uc), 1);
                println!("[*] pc: {} -- at {}, wrote {}, size {}", wf(pc), wf(addr), wf(val),size);
                println!("    {}", dis);

            };
            */
            /* TODO: record size of writes as well. */
            let write_record = WriteRecord {
                pc: pc,
                dest_addr: addr,
                value: val as u64,
                size: size,
            };
            wmut.push(write_record);
            true
        };
        emu.hook_writeable_mem(callback)
    };

    let visit_hook = {
        let visitor = visitor.clone();
        let callback = move |uc: &unicorn::Unicorn, addr: u64, size: u32| {
            let mut vmut = visitor.borrow_mut();
            let mode = get_mode(&uc);
            let size: usize = (size & 0xF) as usize;
            let registers = uc_general_registers(&uc).unwrap();
            let visit_record = VisitRecord {
                pc: addr,
                mode: mode,
                inst_size: size,
                registers: registers,
            };
            vmut.push(visit_record); 

        };
        emu.hook_exec_mem(callback)
    };
    
    /* Hatch! **/ /* FIXME don't hardcode these params */
    let x = emu.start(start_addr, 0, 0, 1024);
    match visit_hook {
        Ok(h)  => { emu.remove_hook(h).unwrap(); },
        Err(_) => { println!("visit_hook didn't take"); },
    }
    match mem_write_hook {
        Ok(h) =>  { emu.remove_hook(h).unwrap(); },
        Err(_) => { println!("mem_write_hook didn't take"); },
    }
    

   
    /* Now, get the resulting CPU context (the "phenotype"), and
     * attach it to the mutable pod
     */
    let registers = emu.read_general_registers().unwrap();
    //let memory = emu.writeable_memory();
    let vtmp = visitor.clone();
    let visited = vtmp.borrow().to_vec().clone();
    let wtmp = writelog.clone();
    let writelog = wtmp.borrow().to_vec().clone();
    drop(vtmp);
    drop(wtmp);
    
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
        emu.uc.mem_write(seg.aligned_start(), &seg.data);
    }
    let pod = gen::Pod::new(registers,visited,writelog);
    pod
}


fn spawn_coop (rx: Receiver<gen::Creature>, tx: Sender<gen::Creature>) -> () {
    /* a thread-local emulator */
    let mut emu = Engine::new(*ARCHITECTURE);

    /* Hatch each incoming creature as it arrives, and send the creature
     * back to the caller of spawn_hatchery. */
    //let mut best_before = 500; /* hideous, awful kludge, for which i deserve the gallows */
    let init_best_before = 1;
    let mut best_before = init_best_before;
    for incoming in rx {
        best_before -= 1;
        if best_before == 0 {
//            println!("[+] This is not called execution. It is called 'retirement.'");
            //emu.reset();  

            best_before = init_best_before;
        }
        let mut creature = incoming;
        let phenome = hatch_cases(&mut creature, &mut emu);
        creature.phenome = phenome;
        tx.send(creature); /* goes back to the thread that called spawn_hatchery */
    }
    
    //drop(emu)
}

pub fn spawn_hatchery (num_engines: usize, expect: usize)
    -> (Sender<gen::Creature>, Receiver<gen::Creature>, JoinHandle<()>) {

    let (alice_tx, bob_rx) = channel(); //sync_channel(num_engines);
    let (bob_tx, alice_rx) = channel(); //sync_channel(num_engines);

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

