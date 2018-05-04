extern crate rand;

use std::sync::Arc;
use std::sync::mpsc::{channel, Receiver};
use std::thread::{spawn, JoinHandle};

use self::rand::SeedableRng;
use self::rand::isaac::Isaac64Rng;

use genotype::*;
use phenotype::*;
use par::statics::RngSeed;

pub fn spawn_seeder(
    population_size: usize,
    len_range: (usize, usize),
    problem_set: &Vec<Vec<u64>>,
    seed: RngSeed,
) -> (Receiver<Creature>, JoinHandle<()>) {
    let (from_seeder_tx, from_seeder_rx) = channel();
    //    let (into_seeder_tx, into_seeder_rx) = channel();
    let problem_set = Arc::new(problem_set.clone());
    let seeder_handle = spawn(move || {
        let problem_set = problem_set.clone();
        let mut rng = Isaac64Rng::from_seed(seed);
        for i in 0..population_size {
            let genome = Chain::from_seed(&mut rng, len_range);
            let mut creature = Creature::new(genome, i);
            for problem in problem_set.iter() {
                creature.pose_problem(&problem);
            }
            let _ = from_seeder_tx.send(creature).unwrap();
        }
    });
    (from_seeder_rx, seeder_handle)
}
