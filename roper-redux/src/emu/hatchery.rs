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
    let mut payload = creature.genome.pack(input);
    let start_addr = creature.genome.entry().unwrap();
    /* A missing entry point should be considered an error,
     * since we try to guard against this in our generation
     * functions.
     */
    let (stack_addr, stack_size) = emu.find_stack();
    payload.truncate(stack_size / 2);
    let payload_len = payload.len();
    let stack_entry = stack_addr + (stack_size/2) as u64;
    /* save writeable regions **/

    /* load payload **/
    emu.restore_state();
    emu.mem_write(stack_entry, &payload).expect("mem_write fail in hatch");
    emu.set_sp(stack_entry + *ADDR_WIDTH as u64);
    //emu.reset_registers(); /* TODO */
    // this will need to iterate through *ALL* the registers, not just the 
    // general purpose ones we're watching.
    // also the general_registers method is a misnomer. rename it.
    // eventually, we can replace this with a context restore.
    
    let visitor: Rc<RefCell<Vec<VisitRecord>>> 
        = Rc::new(RefCell::new(Vec::new()));
    let writelog = Rc::new(RefCell::new(Vec::new()));
    let retlog = Rc::new(RefCell::new(Vec::new()));
    let jmplog = Rc::new(RefCell::new(Vec::new()));

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

    let ret_hook = {
        let retlog = retlog.clone();
        let callback = move |uc: &unicorn::Unicorn, addr: u64, size: u32| {
            let mut retlog = retlog.borrow_mut();
            let pc = addr;
            let dis = log::disas_static(pc, size as usize, ARCHITECTURE.mode(), 1);
            //println!("RET HOOK: {}", dis);
            retlog.push(pc);
        };
        emu.hook_rets(callback)
    };

    let indirect_jump_hook = {
        let jmplog = jmplog.clone();
        let callback = move |uc: &unicorn::Unicorn, addr: u64, size: u32| {
            let mut jmplog = jmplog.borrow_mut();
            let dis = log::disas_static(addr, size as usize, ARCHITECTURE.mode(), 1);
            //println!("JMP HOOK: {}", dis);
            jmplog.push(addr);
        };
        emu.hook_indirect_jumps(callback)
    };

    
    /* Hatch! **/ /* FIXME don't hardcode these params */
    let x = emu.start(start_addr, 0, 0, 1024);

    if retlog.borrow().len() > 2 {
        //println!("PAYLOAD: 0x{:x} bytes, {} INSTS, {} RETS: {} IND.JMPS: {}", visitor.borrow().len(), payload_len, retlog.borrow().len(), retlog.borrow().iter().map(|x| format!("{:08x}",x)).collect::<Vec<String>>().join(" "), jmplog.borrow().len());
    };
    
    /* Now, clean up the hooks */
    match visit_hook {
        Ok(h)  => { emu.remove_hook(h).unwrap(); },
        Err(e) => { println!("visit_hook didn't take {:?}",e); },
    }
    match mem_write_hook {
        Ok(h) =>  { emu.remove_hook(h).unwrap(); },
        Err(e) => { println!("mem_write_hook didn't take {:?}",e); },
    }
    match ret_hook {
        Ok(h) =>  { emu.remove_hook(h).unwrap(); },
        Err(e) => { println!("ret_hook didn't take: {:?}",e); },
    }
    match indirect_jump_hook {
        Ok(h) =>  { emu.remove_hook(h).unwrap(); }
        Err(e) => { println!("indirect_jmp_hook didn't take: {:?}", e); },
    }
    

   
    /* Now, get the resulting CPU context (the "phenotype"), and
     * attach it to the mutable pod
     */
    let registers = emu.read_general_registers().unwrap();
    let vtmp = visitor.clone();
    let visited = vtmp.borrow().to_vec().clone();
    let wtmp = writelog.clone();
    let writelog = wtmp.borrow().to_vec().clone();
    let rtmp = retlog.clone();
    let retlog = rtmp.borrow().to_vec().clone();
    drop(vtmp);
    drop(wtmp);
    
    let pod = gen::Pod::new(registers,visited,writelog,retlog);
    pod
}


fn spawn_coop (rx: Receiver<gen::Creature>, tx: Sender<gen::Creature>) -> () {
    /* a thread-local emulator */
    let mut emu = Engine::new(*ARCHITECTURE);

    /* place a halt hook on syscalls, for all evaluations 
    let syscall_hook = {
        let callback = move |uc: &unicorn::Unicorn| {
            let pc = read_pc(&uc).unwrap();
            let dis = log::disas_static(pc, 15, ARCHITECTURE.mode(), 1);
            println!("*** SYSCALL: {}", dis); 
        };
        let (exec_start, exec_stop) = emu.exec_mem_range();
        emu.uc.add_insn_sys_hook(unicorn::InsnSysX86::SYSCALL,
                                 exec_start.unwrap(),
                                 exec_stop.unwrap(),
                                 callback)
    };

    
    let interrupt_hook = {
        let callback = move |uc: &unicorn::Unicorn, num: u32| {
            let pc = read_pc(&uc).unwrap();
            let dis = log::disas_static(pc, 15, ARCHITECTURE.mode(), 1);
            println!("*** INTERRUPT 0x{:x}: {}", num, dis);
        };
        emu.uc.add_intr_hook(callback)
    };
    */

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
    
    /*
    match syscall_hook {
        Ok(h) =>  { emu.remove_hook(h).unwrap(); },
        Err(_) => { println!("syscall_hook didn't take"); },
    }
    
    match interrupt_hook {
        Ok(h) =>  { emu.remove_hook(h).unwrap(); },
        Err(_) => { println!("interrupt_hook didn't take"); },
    }
    */
    //drop(emu)
}

/* An expect of 0 will cause this loop to run indefinitely */
pub fn spawn_hatchery (num_engines: usize, expect: usize)
    -> (Sender<gen::Creature>, Receiver<gen::Creature>, JoinHandle<()>) {

    let (from_hatch_tx, from_hatch_rx) = channel(); //sync_channel(num_engines);
    let (into_hatch_tx, into_hatch_rx) = channel(); //sync_channel(num_engines);

    /* think of ways to dynamically scale the workload, using a more
     * sophisticated data structure than a circular buffer for carousel */
    let handle = spawn(move || {
        let mut carousel = Vec::new();
        
        for i in 0..num_engines {
            let (eve_tx,eve_rx) = channel();
            let from_hatch_tx = from_hatch_tx.clone();
            let h = spawn(move || { spawn_coop(eve_rx, from_hatch_tx); } );        
            carousel.push((eve_tx, h));
        }

        let mut coop = 0;
        let mut counter = 0;
        for incoming in into_hatch_rx {
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

    (into_hatch_tx, from_hatch_rx, handle)
}

