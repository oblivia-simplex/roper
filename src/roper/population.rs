// Implement something like stackvec to make a copiable vec
// like structure to contain your shit.
use std::cell::*;
use std::io::{BufReader,BufRead};
use std::fs::File;
use std::path::Path;
use std::sync::{RwLock,RwLockReadGuard};

use rand::distributions::*;
use rand::Rng;
use rand::ThreadRng;
use unicorn::{CpuARM};
 
use std::cmp::*;

use roper::params::*;
use roper::phylostructs::*;
use roper::hatchery::{hatch_chain};
use roper::util::{pack_word32le,
                  pack_word32le_vec,
                  u8s_to_u16s,
                  u8s_to_u32s,
                  distance,
                  mang,
                  Indexable,
                  deref_mang};

use roper::thumb::{reap_thumb_gadgets};
use roper::arm::{reap_arm_gadgets};

/* A struct to bundle together mutable machinery 
 * Each thread should have its own instance.
 */
pub struct Machinery {
  rng: ThreadRng,
  uc:  CpuARM,
}

fn calc_link_fit (p_fit: i32, c_fit: i32, alpha: i32) -> i32 {
  (p_fit * alpha) + (c_fit * (MAX_FIT - alpha))
}

fn crossover (parents:    &Vec<&Chain>, 
              brood_size: usize,
              rng:        &mut ThreadRng) -> Vec<Chain> {
  let mut brood : Vec<Chain> = Vec::new();
  for s in 0..brood_size {
    let m_idx  : usize  = rng.gen::<usize>() % 2;
    let mother : &Chain = &(parents[m_idx]);
    let father : &Chain = &(parents[(m_idx+1) % 2]);
    let m_i : usize = splice_point(&mother, rng);
    let m_n : usize = mother.size() - m_i;
    let f_i : usize = splice_point(&father, rng);
    let mut child_clumps : Vec<Clump> = Vec::with_capacity(f_i+m_n);
    // let f_n : usize = father.size() - f_i;
    for f in 0..f_i {
      child_clumps.push(father.clumps[f].clone());
      child_clumps[f].link_age += 1;
    }
    child_clumps.push(father.clumps[f_i].clone());
    child_clumps[f_i].link_age = 0;
    for m in (m_i+1)..m_n {
      child_clumps.push(mother.clumps[m].clone());
      child_clumps[m-m_i].link_age += 1;
      /* adjust link_fit later, obviously */
    }
    let child : Chain = Chain::new(child_clumps);
    brood.push(child);
  }
  brood
}



fn mutate(chain: &mut Chain, params: &Params, rng: &mut ThreadRng) {
  /* mutations will only affect the immediate part of the clump */
  /* we'll let crossover handle the rest. */
  if rng.gen::<f32>() > params.mutation_rate { return };
  /* Add permutation operation, shuffling immeds */
  let cl_idx     = rng.gen::<usize>() % chain.size();
  let clump      = &mut (chain.clumps[cl_idx]);
  let idx        = 1 + (rng.gen::<usize>() % (clump.size() - 1));
  let mut_kind : u8 = rng.gen::<u8>() % 3;
  match mut_kind {
    0 => clump.words[idx] = mang(clump.words[idx].clone(), rng),
    1 => clump.words[idx] = deref_mang(clump.words[idx], 
                                  &(params.ro_data_32), 
                                  params.ro_data_addr),
    2 => { /* permutation */
      let other_idx = 1 + (rng.gen::<usize>() % (clump.size() - 1));
      let tmp = clump.words[idx];
      clump.words[idx] = clump.words[other_idx];
      clump.words[other_idx] = tmp;
    },
  };
}

fn mate (parents: &Vec<&Chain>, 
         params:  &Params, 
         rng:     &mut ThreadRng) -> Vec<Chain> {
  let mut brood = crossover(parents, params.brood_size, rng);
  for s in brood.iter_mut() {
    mutate(s, params, rng)
  }
  cull_brood(&mut brood, 2);
  brood
}

pub fn evaluate_fitness (uc: &mut CpuARM,
                         chain: &mut Chain, 
                         io_targets: &Vec<(Vec<i32>,Vec<i32>)>) {
  let mut fit_vec : Vec<Option<i32>> = Vec::new();
  let mut i : usize = 0;
  for (input,target) in io_targets {
                           /* stub */  
    let output = hatch_chain(uc, &chain.packed, &input);
    /* add checks for error codes, etc */
    fit_vec.push(distance(&res, &output));
    i += 1;
  }
}




fn tournement (population: &Population, 
               machinery: &mut Machinery) {
  /* randomly select contestants */
  let mut rng = machinery.rng;
  let mut uc  = machinery.uc;
  let t_size  = population.params.t_size;
  let targets = population.params.targets; // set of i/o pairs
  //  let mut rng = &mut population.rng;
  let mut contestants : Vec<& RwLock<Chain>> = {
    let mut tmp_vec = Vec::new();
    let mut i = 0;
    let mut c : usize = 0;
    let mut used : Vec<usize> = vec![0];
    while i < t_size {
      i += 1;
      /* Ensure that we pick *unique* contestants */
      /* This matters more from a memory management point of 
       * view than an evolutionary point of view. */
      while used.contains(&c) {
        c = rng.gen::<usize>() % population.size();
      } 
      let mut cell = & population.deme[c];
      /* fill in the hole from the end of the population */
//      let last = population.chains.pop().unwrap();
//      population.deme[c].set(last);
      /* ontogenesis step */
      evaluate_fitness(&mut uc, 
                       &mut (cell.write().unwrap())
                       &targets);
      tmp_vec.push(cell); // inefficient. can we fix? 
    }
    tmp_vec
  };
  /* This sort will crash at runtime if any of the contestants
   * are still being held by a write lock. But I think that
   * those should have all fallen out of scope by now. 
   */
  contestants.sort_by(|a,b| a.read().unwrap()
                             .cmp(&b.read().unwrap()));
  // I need to make sure that the parents are non-identical. 
  let mother = contestants[0].read().unwrap();
  let father = contestants[1].read().unwrap();
  let parents : Vec<&Chain> = vec![&*mother,&*father];
  let offspring = mate(&parents,
                       &population.params,
                       rng);
  let mut grave1 = contestants[t_size-1].write().unwrap();
  let mut grave2 = contestants[t_size-2].write().unwrap();    

  *grave1 = offspring[1].clone();
  *grave2 = offspring[2].clone();
}

fn cull_brood (brood: &mut Vec<Chain>, n: usize) {
  /* Sort by fitness - most to least */
  brood.sort();
  /* Now eliminate the least fit */
  while brood.len() > n {
    brood.pop();
  }
}
  
fn set_viscosity (clump: &mut Clump) -> i32 {
  clump.viscosity = clump.link_fit * 
    (min(clump.link_age * RIPENING_FACTOR, MAX_VISC));
  clump.viscosity
}

fn splice_point (chain: &Chain, rng: &mut ThreadRng) -> usize {
  let mut wheel : Vec<Weighted<usize>> = Vec::new();
  let mut i : usize = 0;
  for clump in &chain.clumps {
    i += 1;
    assert!(clump.visc() <= MAX_VISC);
    let vw : u32 = (MAX_VISC - clump.visc()) as u32;
    wheel.push(Weighted { weight: vw,
                          item: i });
  }
  let mut spin = WeightedChoice::new(&mut wheel);
  spin.sample(rng)
}

pub fn saturate_clumps <'a,I> (unsat: &mut Vec<Clump>,
                               pool:  &mut I)  //Vec<u32>,
    where I: Iterator <Item=u32> {
  let mut u : usize = 0;
  //let mut sat: Vec<Clump> = Vec::new();
  while u < unsat.len() {
    let mut c = &mut unsat[u];
    let needs = (c.sp_delta-1) as usize;
    // slow way. optimize later:
    for i in 0..needs {
      match pool.next() {
        Some(x) => c.push(x),
        _       => break 
      }
    }
    println!("c.sp_delta == {}, cp.words.len() == {}",
      c.sp_delta, c.words.len());
    u += 1;
  }
  
}


// replace mode str with mode enum at some point
pub fn reap_gadgets (code: &Vec<u8>, 
                     start_addr: u32, 
                     mode: MachineMode) 
                    -> Vec<Clump> {
  match mode {
    MachineMode::THUMB => reap_thumb_gadgets(code, start_addr),
    MachineMode::ARM   => reap_arm_gadgets(code, start_addr),
  }
}


/*
pub fn reap_arm_gadgets (code: &Vec<u8>,
                         start_addr: u32)
                         -> Vec<Clump>
{
  let mut gads : Vec<Clump> = Vec::new();
  // TODO: COMPLETE THIS STUB, and write an ARM lib.
  panic!("Unimplemented.");
  gads
}

*/


/*
 * Mutation algorithm:
 *
 * 1/n chance of imm gad mutation
 * 1-1/n chance of reg gad mutation
 *
 * imm gads can be a perturbation of the immediate value
 * two kinds of perturbation:
 * (a) logico-arithmetical perturbation
 *     (the idea being that they would complement ALU ops)
 * (b) indirection
 *
 * indirection can only be used in some cases:
 * - scan rodata and text for a value equal to, or close
 *   to, the value being mutated
 * - replace the value being mutated with a pointer to
 *   its counterpart in rodata/text
 *
 *   if indirection is unavailable -- if there are no candidate
 *   values in rodata/text to dereference to -- fall back on
 *   arithmetical mutation.
 *
 * reg gad mutations:
 * - these have to operate at the level of clumps, not
 *   individual gadget, where a clump is defined as a 
 *   regular gadget, followed by a number of immgads equal
 *   to its sp_delta.
 *
 * ----
 *
 * it would be handy to maintain a struct that holds bits
 * of relatively global information -- params, data, text,
 * etc.
 *
 */

/* Note:
 * BX can switch between ARM and THUMB mode, depending on
 * the LSB of the address.
 *
 * bit 0 = ARM
 * bit 1 = THUMB
 *
 * the ret scraper should also return an instruction type flag
 * in the tuple. if it's BX, then we need this information so
 * that we can control the machine mode
 */

/* Refactor scan_for_gadgets 
 * Build a clump struct right away, and then enrich it with
 * successive passes.
 */

