extern crate libroper;
extern crate rand;

use std::time::Instant;
use libroper::emu::*;
use libroper::gen::*;
use rand::{thread_rng,Rng};

fn main() {
    loop {
        let (tx,rx,handle) = spawn_hatchery(256);
        let mut rng = rand::thread_rng();
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
            let pod = Pod::new(chain); /* pod gets ownership of chain */

            //println!("Forth: {:?}", pod);
            tx.send(pod).unwrap();
        }

        for i in 0..20000 {
            let pod = rx.recv().unwrap();
        }
        
        drop(tx);
        handle.join().unwrap();
        let elapsed = start.elapsed();
        println!("20000 cycles in {}s", elapsed.as_secs() as f64 +  elapsed.subsec_nanos() as f64 / 1000000000.0);
    } 
}
