use std::thread::{spawn, JoinHandle};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, RwLock};

use gen::*;
use circbuf::CircBuf;

// use ketos::{Interpreter,FromValueRef};

/* Instead of using the entire population as a reference point when
 * calculating things like shared fitness, we'll just keep reference
 * to a CircBuf that preserves the most recent N specimens that have
 * passed through the evaluator. This should let us do away with the
 * "Seasons" mechanism, to a large extent, and dispense with the
 * patch_io mechanism as well, since we have convenient reference to
 * a sliding window of specimens.
 */
pub fn spawn_evaluator(
    num_evaluators: usize,
    circbuf_size: usize,
) -> (Sender<Creature>, Receiver<Creature>, JoinHandle<()>) {
    let (from_eval_tx, from_eval_rx) = channel();
    let (into_eval_tx, into_eval_rx) = channel();

    let circbuf = Arc::new(RwLock::new(CircBuf::new(circbuf_size)));

    let eval_handle = spawn(move || {
        /* Here, we use the same pattern that we did in spawn_hatchery */
        let mut carousel = Vec::new();
        let reading_window = circbuf.clone();
        for _ in 0..num_evaluators {
            let (eval_tx, eval_rx) = channel();
            let tx = from_eval_tx.clone();
            let window = reading_window.clone();
            /* Pass the slave_eval the sender received by this function, so
             * that it can send its results directly back to the caller of
             * spawn_evaluator.
             */
            let h = spawn(move || {
                slave_eval(eval_rx, tx, window);
            });
            carousel.push((eval_tx, h));
        }

        let mut slave_idx = 0;
        let sliding_window = circbuf.clone();
        for creature in into_eval_rx {
            let mut creature: Creature = creature;
            //eval_fitness(&mut creature, &sliding_window.read().unwrap());
            let &(ref slave_tx, _) = &carousel[slave_idx];
            slave_idx = (slave_idx + 1) % carousel.len();
            let mut sliding_window = sliding_window.write().unwrap();
            sliding_window.push(creature.clone());
            slave_tx.send(creature);
        }

        while carousel.len() > 0 {
            if let Some((slave_tx, h)) = carousel.pop() {
                drop(slave_tx);
                h.join();
            }
        }
    });

    (into_eval_tx, from_eval_rx, eval_handle)
}

fn slave_eval(
    eval_rx: Receiver<Creature>,
    eval_tx: Sender<Creature>,
    _sliding_window: Arc<RwLock<CircBuf>>,
) -> () {
    /*
    let interp = Interpreter::new();    
    interp.scope().register_struct_value::<Creature>();
    interp.scope().register_struct_value::<Pod>();
    interp.run_code(r#"
    ;; Some fitness evaluation script here.    
    (define (eval-fitness creature)
        0.5)
    "#, None).unwrap();
    */
    /* Load the evaluation script and run it, taking
     * the Creature as argument. Return a fitness value
     * of an appropriate type.
     */
    for creature in eval_rx {
        let mut creature = creature;
        //let f = interp.call("eval-fitness",
        //                    (creature).into()).unwrap();
        //let fit = f32::from_value_ref(&f).unwrap();
        let fit = 0.5; /* FIXME Placeholder */
        creature.fitness = Some(vec![fit]);
        eval_tx.send(creature);
    }
}

/***
 * Various fitness functions, that can dispatches from slave_eval.
 */
