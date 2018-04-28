extern crate libroper;
extern crate rand;


use std::env;
use std::time::Instant;
use std::collections::HashMap;
use std::thread::sleep;
use std::time::Duration;
use std::sync::mpsc::{channel,Sender,Receiver};

use libroper::emu::*;
use libroper::gen::*;
use libroper::emu::loader::Mode;
use rand::{SeedableRng,Rng};
use rand::isaac::{Isaac64Rng};
use libroper::par::statics::*;
use libroper::log;

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
        let chain = Chain {
            gads: vec![Gadget {
                            entry: lower_addr + rng.gen::<u64>() % addr_range,
                            ret_addr: 0, /* not using this yet */
                            sp_delta: rng.gen::<usize>() % 16,
                            mode: Mode::Bits64,
                        },
                        Gadget {
                            entry: lower_addr + rng.gen::<u64>() % addr_range,
                            ret_addr: 0,
                            sp_delta: rng.gen::<usize>() % 16,
                            mode: Mode::Bits64,
                        }],
            pads: vec![Pad::Const(i), 
                       Pad::Const(i+0xdeadbeef), 
                       Pad::Input(0),
                       Pad::Input(9),
                       Pad::Const(i+0xbaadf00d),
                       Pad::Input(2),
                       Pad::Const(i+0xcafebabe)],
            wordsize: 4,
            endian: Endian::Little,
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
    let engine_period = 4;
    let mut counter = engine_period;
    let mut rng = Isaac64Rng::from_seed(&RNG_SEED);
    
    let (log_tx,log_handle) = log::spawn_logger(0x1000);
    for counter in 0..loops {
        do_the_thing(engines, expect, &mut rng, counter, &log_tx);
    }
    drop(log_tx);
    log_handle.join();
}
