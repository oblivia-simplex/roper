pub mod emu;
pub mod dbg;

use self::emu::{init_emulator,ARM_ARM,spawn_hatchery,Pod, Params};

fn main() {
    let path = "/home/vagrant/ROPER/data/openssl";
    let (tx,rx) = spawn_hatchery(&path, &Params{foo:1});

    for i in 0..100 {
        let pod = Pod::new(i);
        println!("Forth: {:?}", pod);
        tx.send(pod).unwrap();
        let pod = rx.recv().unwrap();
        println!("Back: {:?}", pod);
    }
    
}
