extern crate elf;
extern crate unicorn;
extern crate rand;
extern crate capstone;

use rand::{Rng,ThreadRng};
use unicorn::*;
use roper::ontostructs::*;
use roper::phylostructs::*;
use roper::population::*;
use roper::util::*;
use roper::hatchery::*;


/*
pub fn evolve (population: &Population,
               machinery: &mut Machinery)
              -> bool {
  let mut rng = &mut machinery.rng;
  let mut uc  = &mut machinery.uc;


}
*/
