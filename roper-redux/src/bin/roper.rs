extern crate libroper;

use libroper::emu::*;
use libroper::gen::*;

fn main() {
    let path = "/home/vagrant/ROPER/data/openssl";
    let (tx,rx,handle) = spawn_hatchery(&path, 256);

    for i in 0..10000 {
        let chain = Chain {
            gads: vec![Gadget {
                            entry: 0x0001da94,
                            ret_addr: 0, /* not using this yet */
                            sp_delta: 8,
                        },
                        Gadget {
                            entry: 0x00016ee4,
                            ret_addr: 0,
                            sp_delta: 7,
                        }],
            pads: vec![i, i+0xdeadbeef, i+0xbaadf00d, i+0xcafebabe],
            wordsize: 4,
            endian: Endian::Little,
            metadata: Metadata::new(),
        };
        let pod = Pod::new(chain); /* pod gets ownership of chain */

        println!("Forth: {:?}", pod);
        tx.send(pod).unwrap();
    }

    for i in 0..10000 {
        let pod = rx.recv().unwrap();
    }
    
    drop(tx);
    handle.join().unwrap();
    
}
