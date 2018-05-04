extern crate rand;

use std::thread::{spawn, JoinHandle};
use std::sync::mpsc::{Receiver, Sender};

use emu;
use fit;
use gen;
use gen::Creature;
use log;
use par::statics::*;
use breeders::*;

/* The genotype->phenotype pipeline */
/* -- spawns hatchery
 * -- receives new genotypes from initialization and/or breeding
 * -- sends new genotypes to hatchery, receives phenotypes
 * -- sends phenotypes to selection routine
 * -- selection sends some genotypes of those phenotypes to reproduction routine
 * -- reproduction routine sends them back here, to go on to hatchery
 */

pub fn pipeline(rx: Receiver<Creature>, txs: Vec<Sender<Creature>>) -> JoinHandle<()> {
    assert!(txs.len() > 0);
    let h = spawn(move || {
        for x in rx {
            if txs.len() > 1 {
                for tx in txs[1..].iter() {
                    let xc = x.clone();
                    tx.send(xc).unwrap();
                }
            };
            txs[0].send(x).unwrap();
        }
    });
    h
}

pub fn evolution_pipeline(num_engines: usize, num_evaluators: usize) -> () {
    let expect = 0; /* indefinite hatchery loop */
    /* FIXME: expect here is just a placeholder. Not sure what to do with it yet. */
    let sel_meth = SelectionMethod::Tournament;
    let population_size = 4096;

    let (from_seeder_rx, seed_handle) = gen::spawn_seeder(
        population_size,
        (2, 32),              /* length range */
        &vec![vec![1, 2, 3]], /* fake problem set */
        *RNG_SEED,            /* but FIXME: refresh seed! */
    );
    let (into_hatch_tx, from_hatch_rx, hatch_handle) = emu::spawn_hatchery(num_engines, expect);
    let (into_eval_tx, from_eval_rx, eval_handle) = fit::spawn_evaluator(num_evaluators, 4096);
    let (into_breed_tx, from_breed_rx, breed_handle) = spawn_breeder(sel_meth);
    let (into_log_tx, log_handle) = log::spawn_logger(4096, 4096);

    /* now weld the pipelines together */
    let mut pipehandles = Vec::new();
    pipehandles.push(pipeline(from_seeder_rx, vec![into_hatch_tx.clone()]));
    pipehandles.push(pipeline(from_hatch_rx, vec![into_eval_tx]));
    pipehandles.push(pipeline(from_eval_rx, vec![into_breed_tx, into_log_tx]));
    pipehandles.push(pipeline(from_breed_rx, vec![into_hatch_tx]));
    /* FIXME: as it stands, sending back to the into_hatch_tx will cause a send
     * error. one of the channels is probably getting prematurely dropped.
     * look into this. it would be nice to get a good, infinite "circle of life"
     * going, all in one pipeline.
     */
    /* the circle is now complete. */

    seed_handle.join().unwrap();
    hatch_handle.join().unwrap();
    eval_handle.join().unwrap();
    breed_handle.join().unwrap();
    log_handle.join().unwrap();

    for ph in pipehandles {
        ph.join().unwrap();
    }
}

/* The phenotype->genotype pipeline */
