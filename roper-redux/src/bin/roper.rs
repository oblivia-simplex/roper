extern crate libroper;
extern crate rand;


use std::env;
use std::time::Instant;
use std::collections::HashMap;

use libroper::emu::*;
use libroper::gen::*;
use libroper::emu::loader::Mode;
use rand::{SeedableRng,Rng};
use rand::isaac::{Isaac64Rng};
use libroper::par::statics::*;

/* The optimal combination, so far, seems to be something like:
 * batch of 1024, channels throttled to 512, number of engines: 4-6
 * 0.09 seconds to evaluate 1024 specimens!
 */
fn main() {
    let mem_image = MEM_IMAGE.clone();
    let mut engines = match env::var("ROPER_ENGINES") {
        Err(_) => 4,
        Ok(n)  => n.parse::<usize>().expect("Failed to parse ROPER_ENGINES env var"),
    };
    let expect = match env::var("ROPER_STRESS_EXPECT") {
        Err(_) => 1024,
        Ok(n) => n.parse::<usize>().expect("Failed to parse ROPER_STRESS_EXPECT"),
    };
    let engine_period = 4;
    let mut counter = engine_period;
    loop {
        if engines == 0 { break };
        let (tx,rx,handle) = spawn_hatchery(engines, expect);
        let mut rng = Isaac64Rng::from_seed(&RNG_SEED);
        let start = Instant::now();
        for i in 0..expect { /* 100000 is too much to handle. but unlikely */
            let i = i as u64;
            let chain = Chain {
                gads: vec![Gadget {
                                entry: 0x8000 + (rng.gen::<u32>() as u64 % 0x30000),
                                ret_addr: 0, /* not using this yet */
                                sp_delta: rng.gen::<usize>() % 16,
                                mode: Mode::Arm,
                            },
                            Gadget {
                                entry: 0x8000 + (rng.gen::<u32>() as u64 % 0x30000),
                                ret_addr: 0,
                                sp_delta: rng.gen::<usize>() % 16,
                                mode: Mode::Thumb,
                            }],
                pads: vec![Pad::Const(i), 
                           Pad::Const(i+0xdeadbeef), 
                           Pad::Const(i+0xbaadf00d),
                           Pad::Const(i+0xcafebabe)],
                wordsize: 4,
                endian: Endian::Little,
                metadata: Metadata::new(),
            };
            let creature = Creature::new(chain,0);

            tx.send(creature).unwrap();
        }

        for i in 0..expect {
            let creature = rx.recv().unwrap();
            for pod in creature.phenome.values() {
                println!("VISITED BY {}:\n\t{}", 
                         &creature.name,
                         pod.disas_visited().join("\n\t"));
            }
            //println!("{:?}", &creature.phenome.unwrap().visited);
        }
        
        drop(tx);
        handle.join().unwrap();
        let elapsed = start.elapsed();
        println!("{} {} {}", expect, engines, elapsed.as_secs() as f64 +  elapsed.subsec_nanos() as f64 / 1000000000.0);
        counter -= 1;
        if counter == 0 {
            counter = engine_period;
            //engines -= 1;
        };
    } 
}
