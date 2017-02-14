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
use roper::hatchery::*;
use roper::util::{pack_word32le,
                  pack_word32le_vec,
                  u8s_to_u16s,
                  u8s_to_u32s,
                  distance,
                  mang,
                  Mangler,
                  Indexable,
                  deref_mang};
//use roper::hooks::*;
use roper::thumb::{reap_thumb_gadgets};
use roper::arm::{reap_arm_gadgets};
use roper::ontostructs::*;


fn calc_link_fit (p_fit: u32, c_fit: u32, alpha: u32) -> u32 {
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
  if chain.size() == 0 {
    panic!("chain.size() == 0. Why?");
  }
  let mut cl_idx : usize = rng.gen::<usize>() % chain.size();
  let mut tries = 3;
  while chain[cl_idx].size() == 1 {
    if tries == 0 { return } else { tries -= 1 };
    cl_idx = rng.gen::<usize>() % chain.size();
  }
  let mut clump = chain[cl_idx].clone();
  if clump.size() == 0 {
    panic!("Hit an empty clump! Why is that?");
  }
  let idx        = 1 + (rng.gen::<usize>() % (clump.size() - 1));
  let mut_kind : u8 = rng.gen::<u8>() % 3;
  match mut_kind {
    0 => clump.words[idx] = mang(clump.words[idx].clone(), rng),
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
  let mut brood = crossover(parents, 
                            2, //params.brood_size, 
                            params.max_len,
                            rng);
  for s in brood.iter_mut() {
    mutate(s, params, rng)
  }
  //cull_brood(&mut brood, 2, uc, &params.io_targets);
  brood
}

pub fn evaluate_fitness (uc: &mut CpuARM,
                         chain: &mut Chain, 
                         io_targets: &IoTargets)
                         -> Option<FIT_INT>
{
  /* Empty chains can be discarded immediately */
  if chain.size() == 0 {
    println!(">> EMPTY CHAIN");
    return None;
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
  let mut fit_vec : Vec<FIT_INT> = Vec::new();
  let mut counter_sum = 0;
  for &(ref input, ref target) in io_targets {
    let result : HatchResult = hatch_chain(uc, &chain.packed, &input);
    println!("\n{}", result);
    let counter = result.counter;
    //println!("\n{}", result);
    if (result.error != None && counter < chain.size()) {
      /* If the chain didn't execute to the end, we know where
       * the weak link is. Drop its viscosity to zero.
       */
      chain[counter].sicken();
    }
    counter_sum += counter;
    let output = &result.registers;
    let d = target.distance(output) as FIT_INT;
    let ft = match result.error {
      Some(_) => (d*2) - min(d, counter as FIT_INT), 
      None    => d as FIT_INT,
    };
    fit_vec.push(ft);
    i += 1;
  };
  let counter_avg = counter_sum as f32 / io_targets.len() as f32;
  for hook in &hooks { uc.remove_hook(*hook); }

  //** improve the fitness calculation. take into consideration:
  //** counter_avg
  //** error code
  //** and normalize somehow.
  //** also: assign link fitnesses for clumps < counter?
  let fitness = (fit_vec.iter().map(|&x| x).sum::<FIT_INT>() 
                   / io_targets.len() as FIT_INT) as FIT_INT;
  chain.set_fitness(fitness as FIT_INT);
  //println!("chain.fitness = {:x}", chain.fitness.unwrap());
  Some(fitness)
}

pub fn tournement (population: &mut Population,
                   machinery: &mut Machinery) {
  let mut lots : Vec<usize> = Vec::new();
  let mut contestants : Vec<(Chain,usize)> = Vec::new();
  let mut uc = &mut(machinery.uc);
  let mut rng = &mut(machinery.rng);
  if population.best == None {
    population.best = Some(population.deme[0].clone());
  }
  let t_size = population.params.t_size;
  let p_size = population.size();
//  let io_targets = &(population.params.io_targets);
  for _ in 0..t_size {
    let mut l: usize = rng.gen::<usize>() % p_size;
    while lots.contains(&l) {
      l = rng.gen::<usize>() % p_size;
    }
    lots.push(l);
    if (population.deme[l].fitness == None) {
      evaluate_fitness(&mut uc, 
                       &mut population.deme[l], 
                       &population.params.io_targets);
    }
    if population.best_fit() == None ||
      population.best_fit() > population.deme[l].fitness {
      println!(">> updating best. from: {:?}, to: {:?}",
               population.best_fit(), population.deme[l].fitness);
      if population.deme[l].fitness == None {
        panic!("fitness of population.deme[l] is None!");
      }
      population.set_best(l);
    }
    //println!(">> l = {}", l);
    contestants.push(((population.deme[l]).clone(),l));
  }
  contestants.sort();
  /*
  println!(">> t_size = {}; contestants.len() = {}",
           t_size, contestants.len());
  println!(">> BEST CONTESTANT FITNESS:  {:?}",
           &contestants[0].0.fitness);
  println!(">> WORST CONTESTANT FITNESS: {:?}",
           &contestants[3].0.fitness);
  */
  if (&contestants[3].0.clumps == &contestants[0].0.clumps) {
    println!(">> BEST == WORST!");
  }
  // i don't like these gratuitous clones
  // but let's get it working first, and optimise later
  let (mother,_) = contestants[0].clone();
  let (father,_) = contestants[1].clone();
  let (_,grave0) = contestants[2];
  let (_,grave1) = contestants[3];
  let parents : Vec<&Chain> = vec![&mother,&father];
  let offspring = mate(&parents,
                       &population.params,
                       rng,
                       uc);
  /*
  for i in 0..4 {
    println!(">> contestant {}\n{}", i, &contestants[i].0);
  }
  for i in 0..2 {
    println!(">> offspring {}\n{}", i, &offspring[i]);
  }
  */
  population.deme[grave0] = offspring[0].clone();
  population.deme[grave1] = offspring[1].clone();
}


fn cull_brood (brood: &mut Vec<Chain>, 
               n: usize,
               uc: &mut CpuARM,
               io_targets: &IoTargets) {
  /* Sort by fitness - most to least */
  let mut i = 0;
  for spawn in brood.iter_mut() {
    // println!("[*] Evaluating spawn #{}...", i);
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
  clump.viscosity = clump.link_fit as i32 * 
    (min(clump.link_age * RIPENING_FACTOR, MAX_VISC));
  clump.viscosity
}

fn splice_point (chain: &Chain, rng: &mut ThreadRng) -> usize {
  let mut wheel : Vec<Weighted<usize>> = Vec::new();
  let mut i : usize = 0;
  if chain.size() == 0 {
    panic!("Empty chain in splice_point(). Why?");
  }
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
              max_len:    usize,
              rng:        &mut ThreadRng) -> Vec<Chain> {
  let mut brood : Vec<Chain> = Vec::new();
  for i in 0..brood_size {
    let m_idx  : usize  = i % 2;
    let mother : &Chain = &(parents[m_idx]);
    let father : &Chain = &(parents[(m_idx+1) % 2]);
    let m_i : usize = splice_point(&mother, rng);
    let m_n : usize = mother.size() - (m_i+1);
    let f_i : usize = splice_point(&father, rng);

    /*
     * println!("==> m viscosity at splice point: {}",
             mother[m_i].viscosity);
             */
    assert!(m_i < mother.size());
    assert!(f_i < father.size());

    // println!("[*] mother.size() = {}, father.size() = {}",
    // mother.size(), father.size());
    //println!("[*] Splicing father at {}, mother at {}", f_i, m_i);
    //println!("[*] m_n = {}", m_n);
    
    let mut child_clumps : Vec<Clump> = Vec::new();
    let mut i = 0;
    // let f_n : usize = father.size() - f_i;
    for f in 0..f_i {
      // println!("[+] f = {}",f);
      child_clumps.push(father.clumps[f].clone());
      child_clumps[i].link_age += 1;
      i += 1;
    }
    /* By omitting the following lines, we drop the splicepoint */
    if false && father.clumps[f_i].viscosity >= VISC_DROP_THRESH {
      //println!("[+] splice point over VISC_DROP_THRESH. copying.");
      child_clumps.push(father.clumps[f_i].clone());
      i += 1;
    } 
    if i > 0 { child_clumps[i-1].link_age = 0 };
    /***********************************************************/
    for m in m_n..mother.size() {
      if i >= max_len { break };
      // println!("[+] m = {}",m);
      child_clumps.push(mother.clumps[m].clone());
      //println!("[+] child_clumps.len() = {}",child_clumps.len());
      child_clumps[i].link_age += 1;
      i += 1;
      /* adjust link_fit later, obviously */
    }
    //println!("%%% child_clumps.len() == {}", child_clumps.len());
    if (child_clumps.len() == 0) {
      panic!("child_clumps.len() == 0. Stopping.");
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

