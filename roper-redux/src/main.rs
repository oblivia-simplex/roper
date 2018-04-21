pub mod emu;
pub mod dbg;

use self::emu::{init_emulator,ARM_ARM,spawn_hatchery,Pod, Params};

fn main() {
    let path = "/home/vagrant/ROPER/data/openssl";
    let (tx,rx,handle) = spawn_hatchery(&path, &Params{foo:1});

    for i in 0..10000 {
        let pod = Pod::new(vec![i]);
        println!("Forth: {:?}", pod);
        tx.send(pod).unwrap();
    }

    for i in 0..10000 {
        let pod = rx.recv().unwrap();
        println!("Back: {:?}", pod);
    }
    
    drop(tx);
    handle.join().unwrap();
    
}
