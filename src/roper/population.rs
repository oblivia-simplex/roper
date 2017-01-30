// Implement something like stackvec to make a copiable vec
// like structure to contain your shit.
extern crate unicorn; 

use std::cell::*;
use std::io::{BufReader,BufRead};
use std::fs::File;
use std::path::Path;
use std::sync::{RwLock,RwLockReadGuard};

use rand::distributions::*;
use rand::Rng;
use rand::ThreadRng;
use unicorn::*;
 
use std::cmp::*;

use roper::params::*;
use roper::phylostructs::*;
use roper::hatchery::hatch_chain;
use roper::hatchery::HatchResult;
use roper::util::{pack_word32le,
                  pack_word32le_vec,
                  u8s_to_u16s,
                  u8s_to_u32s,
                  distance,
                  mang,
                  Mangler,
                  Indexable,
                  deref_mang};
use roper::hooks::*;
use roper::thumb::{reap_thumb_gadgets};
use roper::arm::{reap_arm_gadgets};
use roper::ontostructs::*;


fn calc_link_fit (p_fit: i32, c_fit: i32, alpha: i32) -> i32 {
  (p_fit * alpha) + (c_fit * (MAX_FIT - alpha))
}
/* Try dropping the splice-point clump. This will do two things:
 * 1. provide a mechanism for ridding ourselves of bad clumps
 * 2. offset bloat (or encourage bloat! we'll see...)
 */

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
   /* 1 => clump.words[idx] = deref_mang(clump.words[idx], 
                                  &(params.ro_data_32), 
                                  params.ro_data_addr),
   
                                  */
    _ => { /* permutation */
      let other_idx = 1 + (rng.gen::<usize>() % (clump.size() - 1));
      let tmp = clump.words[idx];
      clump.words[idx] = clump.words[other_idx];
      clump.words[other_idx] = tmp;
    },
  };
}

pub fn mate (parents: &Vec<&Chain>, 
             params:  &Params, 
             rng:     &mut ThreadRng,
             uc:      &mut CpuARM) -> Vec<Chain> {
  let mut brood = crossover(parents, params.brood_size, rng);
  for s in brood.iter_mut() {
    mutate(s, params, rng)
  }
  cull_brood(&mut brood, 2, uc, &params.io_targets);
  brood
}

pub fn evaluate_fitness (uc: &mut CpuARM,
                         chain: &mut Chain, 
                         io_targets: &Vec<(Vec<i32>,Vec<i32>)>) {
  /* Empty chains can be discarded immediately */
  if chain.size() == 0 {
    chain.set_fitness(WORST_FITNESS);
    return;
  }

  /* Set hooks at return addresses */
  let mut hooks : Vec<uc_hook> = Vec::new();
  for clump in &chain.clumps {
    let r = uc.add_code_hook(CodeHookType::CODE,
                     clump.ret_addr as u64 ,
                     clump.ret_addr as u64,
                     counter_hook)
      .expect("Error adding ret_addr hook.");
    hooks.push(r);
  }
  let mut i : usize = 0;
  let mut fit_vec : Vec<f32> = Vec::new();
  let mut counter_sum = 0;
  for &(ref input, ref target) in io_targets {
                           /* stub */  
    reset_counter(uc);
    let result : HatchResult = hatch_chain(uc, &chain.packed, &input);
    let counter : usize = read_counter(uc);
    println!("COUNTER >> {}", counter);
    println!("RESULT  >> {:?}", result);

    if (result.error != None && counter < chain.size()) {
      /* If the chain didn't execute to the end, we know where
       * the weak link is. Drop its viscosity to zero.
       */
      counter_sum += counter;
      chain[counter].sicken();
    }

    let output = result.registers;
    //let error  = result.error;
    /* add checks for error codes, etc */
    fit_vec.push(distance(&output, &target));
    i += 1;
  };
  let counter_avg = counter_sum as f32 / io_targets.len() as f32;
  for hook in &hooks { uc.remove_hook(*hook); }

  //** improve the fitness calculation. take into consideration:
  //** counter_avg
  //** error code
  //** and normalize somehow.
  //** also: assign link fitnesses for clumps < counter?
  chain.fitness = Some((fit_vec.iter().map(|&x| x).sum::<f32>() 
                   / io_targets.len() as f32) as i32);
  println!("chain.fitness = {:?}", chain.fitness);
}

pub fn tournement (population: &Population, 
                   machinery: &mut Machinery) {
  /* randomly select contestants */
  let mut rng = &mut machinery.rng;
  let mut uc  = &mut machinery.uc;
  let t_size  = population.params.t_size;
  let targets = &population.params.io_targets; // set of i/o pairs
  let mut contestants : Vec<& Pod<Chain>> = {
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
        println!("RANDOM # c == {}", c);
      } 
      let mut egg = &population.deme[c];
      /* ontogenesis step */
      let mut larva = egg.write().unwrap();
      evaluate_fitness(uc, 
                       &mut larva,
                       &targets);
      tmp_vec.push(egg); // inefficient. can we fix? 
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
                       rng,
                       uc);
  let mut grave1 = contestants[t_size-1].write().unwrap();
  let mut grave2 = contestants[t_size-2].write().unwrap();    

  *grave1 = offspring[1].clone();
  *grave2 = offspring[2].clone();
}

fn cull_brood (brood: &mut Vec<Chain>, 
               n: usize,
               uc: &mut CpuARM,
               io_targets: &IoTargets) {
  /* Sort by fitness - most to least */
  let mut i = 0;
  for spawn in brood.iter_mut() {
    println!("[*] Evaluating spawn #{}...", i);
    i += 1;
    evaluate_fitness(uc, &mut *spawn, io_targets); 
  }
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
    assert!(clump.visc() <= MAX_VISC);
    let vw : u32 = 1 + (MAX_VISC - clump.visc()) as u32;
    wheel.push(Weighted { weight: vw,
                          item: i });
    i += 1;
  }
  let mut spin = WeightedChoice::new(&mut wheel);
  spin.sample(rng)
}

fn crossover (parents:    &Vec<&Chain>, 
              brood_size: usize,
              rng:        &mut ThreadRng) -> Vec<Chain> {
  let mut brood : Vec<Chain> = Vec::new();
  for _ in 0..brood_size {
    let m_idx  : usize  = rng.gen::<usize>() % 2;
    let mother : &Chain = &(parents[m_idx]);
    let father : &Chain = &(parents[(m_idx+1) % 2]);
    let m_i : usize = splice_point(&mother, rng);
    let m_n : usize = mother.size() - m_i;
    let f_i : usize = splice_point(&father, rng);
    println!("[*] mother.size() = {}, father.size() = {}",
      mother.size(), father.size());
    println!("[*] Splicing father at {}, mother at {}", f_i, m_i);
    let mut child_clumps : Vec<Clump> = Vec::new();
    let mut i = 0;
    // let f_n : usize = father.size() - f_i;
    for f in 0..f_i {
      //println!("[+] f = {}",f);
      child_clumps.push(father.clumps[f].clone());
      child_clumps[i].link_age += 1;
      i += 1;
    }
    /* By omitting the following lines, we drop the splicepoint */
    if father.clumps[f_i].visc() >= VISC_DROP_THRESH {
      //println!("[+] splice point over VISC_DROP_THRESH. copying.");
      child_clumps.push(father.clumps[f_i].clone());
      child_clumps[i].link_age = 0;
      i += 1;
    }
    /***********************************************************/
    for m in m_n..mother.size() {
      //println!("[+] m = {}",m);
      child_clumps.push(mother.clumps[m].clone());
      //println!("[+] child_clumps.len() = {}",child_clumps.len());
      child_clumps[i].link_age += 1;
      i += 1;
      /* adjust link_fit later, obviously */
    }
    let child : Chain = Chain::new(child_clumps);
    brood.push(child);
  }
  brood
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
    for _ in 0..needs {
      match pool.next() {
        Some(x) => c.push(x),
        _       => break 
      }
    }
   // println!("c.sp_delta == {}, cp.words.len() == {}",
   //   c.sp_delta, c.words.len());
    u += 1;
  }
  
}

pub fn saturate_clump <'a,I> (unsat: &mut Clump,
                              pool:  &mut I)  //Vec<u32>,
    where I: Iterator <Item=u32> {
  let needs = (unsat.sp_delta-1) as usize;
  for _ in 0..needs {
    match pool.next() {
      Some(x) => unsat.push(x),
      _       => break 
    }
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
  } // .iter().filter(|c| c.size() >= 2).collect()
}

pub fn random_chain (clumps:  &Vec<Clump>,
                     min_len: usize,
                     max_len: usize,
                     pool:    &mut Mangler,
                     rng:     &mut ThreadRng) -> Chain {
  let rlen  = rng.gen::<usize>() % (max_len - min_len) + min_len;
  let mut genes : Vec<Clump> = Vec::new();
  for _ in 0..rlen {
    let mut c = clumps[rng.gen::<usize>() % clumps.len()].clone();
    saturate_clump(&mut c, pool);
    genes.push(c);
  }
  Chain::new(genes)
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

