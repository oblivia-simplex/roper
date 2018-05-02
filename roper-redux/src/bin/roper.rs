extern crate libroper;
extern crate rand;


use std::env;
use std::time::Instant;
use std::collections::HashMap;
use std::thread::sleep;
use std::time::Duration;
use std::sync::mpsc::{channel,Sender,Receiver};
use std::thread::{spawn,JoinHandle};

use libroper::emu::*;
use libroper::gen::*;
use libroper::emu::loader::Mode;
use rand::{SeedableRng,Rng};
use rand::isaac::{Isaac64Rng};
use libroper::par::statics::*;

use libroper::{emu,gen,log};
/* The optimal combination, so far, seems to be something like:
 * batch of 1024, channels throttled to 512, number of engines: 4-6
 * 0.09 seconds to evaluate 1024 specimens!
 */

fn do_the_thing (engines: usize, 
                 expect: usize, 
                 rng: &mut Isaac64Rng, 
                 counter: usize,
                 log_tx: &Sender<Creature>) 
{
    let (tx,rx,handle) = spawn_hatchery(engines, expect);

    let (exec_seg, addr_range) = {
        let mut size = 0;
        let mut eseg: Option<&Seg> = None;
        for seg in &*MEM_IMAGE {
            if seg.is_executable() {
                if seg.aligned_size() > size {
                    size = seg.aligned_size();
                    eseg = Some(&seg);
                }
            }
        }
        (eseg.unwrap(), size as u64) /* should be *some* exec seg */
    };
    let lower_addr = exec_seg.aligned_start();
    let start = Instant::now();
    for i in 0..expect { /* 100000 is too much to handle. but unlikely */
        let i = i as u64;
        let length = rng.gen::<usize>() % 64 + 2;
        let mut gads = Vec::new();
        for i in 0..length {
            gads.push(Gadget {
                            entry: lower_addr + rng.gen::<u64>() % addr_range,
                            ret_addr: 0, /* not using this yet */
                            sp_delta: rng.gen::<usize>() % 16,
                            mode: Mode::Bits64,
                      });
        }
        let chain = Chain {
            gads: gads,
            pads: vec![Pad::Const(i), 
                       Pad::Const(i+0xdeadbeef), 
                       Pad::Input(0),
                       Pad::Input(9),
                       Pad::Const(i+0xbaadf00d),
                       Pad::Input(2),
                       Pad::Const(i+0xcafebabe)],
            metadata: Metadata::new(),
        };
        let mut creature = Creature::new(chain,0);
        creature.pose_problem(&vec![1,2,3,4]);
        tx.send(creature).unwrap();
    }

    for i in 0..expect {
        let creature = rx.recv().unwrap();
        log_tx.send(creature.clone()).unwrap();
    }
    
    drop(tx);
    drop(rx);
    handle.join().unwrap();
    let elapsed = start.elapsed();
    println!("{} {} {} {}", expect, engines, elapsed.as_secs() as f64 +  elapsed.subsec_nanos() as f64 / 1000000000.0, counter);
}


fn pipeline(rx: Receiver<Creature>, txs: Vec<Sender<Creature>>) 
    -> JoinHandle<()> 
{
    let h = spawn(move || {
        println!("Hello from pipeline");
        let mut i = 1;
        for x in rx {
            i += 1;
            for tx in &txs {
                /* make a copy, unless we're on the last */
                let x = x.clone(); //if i == txs.len() { x } else { x.clone() };
                tx.send(x).unwrap();
            }
        }
    });
    h
}

fn seeder_hatchery_pipeline(engines: usize, expect: usize) {
    let start = Instant::now();
    let (seed_rx, seed_hdl) = gen::spawn_seeder(expect, 
                                                (2,32),
                                                &vec![vec![1,2,3]]);
    let (hatch_tx, hatch_rx, hatch_hdl) 
        = emu::spawn_hatchery(engines, expect);
    let (logger_tx, logger_hdl) = log::spawn_logger(512);
    let pipe_hdl_1 = pipeline(seed_rx, vec![hatch_tx]);
    let pipe_hdl_2 = pipeline(hatch_rx, vec![logger_tx]);
    
   
    
    seed_hdl.join();   println!("seed_hdl joined");
    hatch_hdl.join();  println!("hatch_hdl joined");
    pipe_hdl_1.join(); println!("pipe_hdl_1 joined.");
    logger_hdl.join(); println!("logger_hdl joined");
    pipe_hdl_2.join(); println!("pipe_hdl_2 joined");
    let elapsed = start.elapsed();
    println!("{} {} {}", expect, engines, elapsed.as_secs() as f64 +  elapsed.subsec_nanos() as f64 / 1000000000.0);
}

fn main() {
    let mem_image = MEM_IMAGE.clone();
    let mut engines = match env::var("ROPER_ENGINES") {
        Err(_) => if cfg!(debug_assertions) {1} else {4},
        Ok(n)  => n.parse::<usize>().expect("Failed to parse ROPER_ENGINES env var"),
    };
    let expect = match env::var("ROPER_STRESS_LOAD") {
        Err(_) => 1024,
        Ok(n) => n.parse::<usize>().expect("Failed to parse ROPER_STRESS_EXPECT"),
    };
    let loops = match env::var("ROPER_LOOPS") {
        Err(_) => 1024,
        Ok(n) => n.parse::<usize>().expect("Failed to parse ROPER_LOOPS"),
    };
    //let mut rng = Isaac64Rng::from_seed(&RNG_SEED);
    
    //let (log_tx,log_handle) = log::spawn_logger(0x1000);
    /*
    for counter in 0..loops {
        do_the_thing(engines, expect, &mut rng, counter, &log_tx);
    }
    */
    //drop(log_tx);
    //log_handle.join();
    seeder_hatchery_pipeline(engines, expect);
}
