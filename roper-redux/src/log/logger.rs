use std::thread::{spawn, JoinHandle};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, RwLock};

use gen::Creature;
use fit::CircBuf;

/* the statistical functions can be defined as methods on
 * CircBuf
 */

/// The logger sits at the receiving end of a one-way channel.
/// It's best to send cloned data to it, since you won't get it back.
pub fn spawn_logger(circbuf_size: usize, log_freq: usize) -> (Sender<Creature>, JoinHandle<()>) {
    println!("Logger spawned. Send clones!");
    let (log_tx, log_rx) = channel();

    let circbuf = Arc::new(RwLock::new(CircBuf::new(circbuf_size)));

    let (analyse_tx, analyse_rx) = channel();

    let window = circbuf.clone();
    let _stat_handle = spawn(move || {
        for _ in analyse_rx {
            let window = window.read().unwrap();
            /* TODO here is where the analyses will be dispatched from */
            println!("circbuf holds {}", window.buf.len());
            for creature in window.buf.iter() {
                println!("LOGGER:\n{}", creature);
            }
            //sleep(Duration::from_millis(1000));
        }
    });

    let analysis_period = log_freq as u64;
    let received = circbuf.clone();
    let handle = spawn(move || {
        let mut count: u64 = 0;
        for incoming in log_rx {
            let mut received = received.write().unwrap();
            received.push(incoming);
            if count % analysis_period == 0 {
                analyse_tx.send(true);
            };
            count += 1;
        }
        drop(analyse_tx);
    });

    (log_tx, handle)
}
