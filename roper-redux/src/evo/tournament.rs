extern crate rand;

use rand::{SeedableRng,Isaac64Rng,Rng,thread_rng}; /* this time, do it with seeds */
use super::emu;
use super::gen;
use super::par::statics::*;


pub fn dispatch(populaton: &mut Population) -> () {
    let mut rng = Isaac64Rng::from_seed(&RNG_SEED);
}
