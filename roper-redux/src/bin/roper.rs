extern crate libroper;
extern crate rand;


use std::env;
use std::time::Instant;
use libroper::emu::*;
use libroper::gen::*;
use rand::{SeedableRng,Rng};
use rand::isaac::{Isaac64Rng};
use libroper::par::statics::RNG_SEED;


fn main() {
    let mut engines = match env::var("ROPER_ENGINES") {
        Err(_) => 256,
        Ok(n)  => n.parse::<usize>().expect("Failed to parse ROPER_ENGINES env var"),
    };
    let engine_period = 16;
    let mut counter = engine_period;
    loop {
        if engines == 0 { break };
        let (tx,rx,handle) = spawn_hatchery(engines);
        let mut rng = Isaac64Rng::from_seed(&RNG_SEED);
        let start = Instant::now();
        for i in 0..20000 { /* 100000 is too much to handle. but unlikely */
            let chain = Chain {
                gads: vec![Gadget {
                                entry: rng.gen::<u32>() as u64,
                                ret_addr: 0, /* not using this yet */
                                sp_delta: rng.gen::<usize>() % 16,
                            },
                            Gadget {
                                entry: rng.gen::<u32>() as u64,
                                ret_addr: 0,
                                sp_delta: rng.gen::<usize>() % 16,
                            }],
                pads: vec![i, i+0xdeadbeef, i+0xbaadf00d, i+0xcafebabe],
                wordsize: 4,
                endian: Endian::Little,
                metadata: Metadata::new(),
            };
            let creature = Creature::new(chain,0);

            tx.send(creature).unwrap();
        }

        for i in 0..20000 {
            let pod = rx.recv().unwrap();
        }
        
        drop(tx);
        handle.join().unwrap();
        let elapsed = start.elapsed();
        println!("{} {}", engines, elapsed.as_secs() as f64 +  elapsed.subsec_nanos() as f64 / 1000000000.0);
        counter -= 1;
        if counter == 0 {
            counter = engine_period;
            engines -= 1;
        };
    } 
}
