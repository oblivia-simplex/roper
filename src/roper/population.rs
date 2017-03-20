// Implement something like stackvec to make a copiable vec
// like structure to contain your shit.
extern crate unicorn; 

use std::cell::*;
use std::io::{BufReader,BufRead};
use std::path::Path;
use std::sync::{RwLock,RwLockReadGuard};
use std::fs::{File,OpenOptions};
use std::io::prelude::*;


use rand::distributions::*;
use rand::Rng;
use rand::ThreadRng;
use rand::thread_rng;
use unicorn::*;
 
use std::cmp::*;

use roper::phylostructs::*;
use roper::hatchery::*;
use roper::util::{pack_word32le,
                  pack_word32le_vec,
                  u8s_to_u16s,
                  u8s_to_u32s,
                  max_bin,
                  mang,
                  Mangler,
                  Indexable,
                  deref_mang};
//use roper::hooks::*;
use roper::thumb::{reap_thumb_gadgets};
use roper::arm::{reap_arm_gadgets};
use roper::ontostructs::*;

const LINK_FIT_ALPHA : f32 = 0.4;

fn calc_link_fit (clump: &Clump, c_fit: f32) -> Option<f32>{
  Some(match clump.link_fit {
    Some(p_fit) => {
      let alpha = LINK_FIT_ALPHA;
      MAX_FIT * (p_fit * alpha) + (c_fit * (1.0 - alpha)) 
    },
    None => c_fit,
  })
}
/* Try dropping the splice-point clump. This will do two things:
 * 1. provide a mechanism for ridding ourselves of bad clumps
 * 2. offset bloat (or encourage bloat! we'll see...)
 */

fn mutate_addr (clump: &mut Clump, rng: &mut ThreadRng) {
  if (clump.ret_addr < clump.words[0]) {
    println!("[WARNING] clump.ret_addr = {:08x}\nclump.words[0] = {:08x}",
             clump.ret_addr, clump.words[0]);
    return;
  }

  let d = (clump.ret_addr - clump.words[0]);
  let inst_size = if clump.mode == MachineMode::ARM {
    4
  } else {
    2
  };
  if d > 1 || rng.gen::<bool>() {
    clump.words[0] += inst_size;
  } else {
    clump.words[0] -= inst_size;
  }
}

fn mutate(chain: &mut Chain, params: &Params, rng: &mut ThreadRng) {
  /* mutations will only affect the immediate part of the clump */
  /* we'll let shufflefuck handle the rest. */
  if rng.gen::<f32>() > params.mutation_rate { return };
//  println!("*** mutating ***");
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
  assert!(clump.size() > 0);
  let idx : usize   = 1 + (rng.gen::<usize>() % (clump.size() - 1));
  let mut_kind : u8 = rng.gen::<u8>() % 3;
  match mut_kind {
    0 => clump.words[idx] = mang(clump.words[idx].clone(), rng),
    1 => mutate_addr(&mut clump, rng),
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
  let mut brood = shufflefuck(parents, 
                              params,
                              rng);
  for s in brood.iter_mut() {
    mutate(s, params, rng)
  }
  cull_brood(&mut brood, 2, uc, &params.io_targets);
  brood
}

fn eval_case (uc: &mut CpuARM,
              chain: &Chain,
              input: &Vec<i32>, // may revise
              target: &Target,
              outregs: usize, // need a better system
              verbose: bool) -> (f32, usize, bool) {
  
  if verbose {
    print!("\n");
    for _ in 0..80 { print!("="); };
    println!("\n==> Evaluating {:?}", input);
  };

  let result : HatchResult = hatch_chain(uc, 
                                         &chain.packed, 
                                         &input);
  // need to let hatch_chain choose *which* registers to preload.
  // input should be a vec of ordered pairs: (reg,value)
  if verbose { print!("\n{}", result); }
  let counter = result.counter;
  let mut crash = false;
  let output   = &result.registers;
  let final_pc = result.registers[15];
  let d : f32 = match target {
    &Target::Exact(ref t) => t.distance(output),
    &Target::Vote(t)  => {
      let b = max_bin(&(output[4..outregs+4].to_vec()));
      if verbose {
        println!("==> Target: {}, Result: {}\t[{}]", t, b, t == b);
      };
      if t == b {
        0.0 
      } else {
        1.0
      }
    },
  } + if final_pc == 0 { 0.0 } else { 0.1 };
  let ratio_run = f32::min(1.0, counter as f32 / chain.size() as f32);
  let p = if ratio_run > 1.0 {1.0} else {ratio_run};
  let ft = match result.error {
    Some(e) => {
      crash = true;
      f32::min(1.0, (d + (1.0 - ratio_run)/2.0))
    },
    None    => {
      f32::min(1.0, d)
    },
  };
  (ft, counter, crash)
}

pub const VARIABLE_FITNESS : bool = false;
pub fn evaluate_fitness (uc: &mut CpuARM,
                         chain: &Chain, 
                         io_targets: &IoTargets,
                         verbose: bool)
                         -> (f32,Option<usize>)
{
//  if !VARIABLE_FITNESS && chain.fitness != None {
//    return chain.fitness;
//  }
  /* Empty chains can be discarded immediately */
  if chain.size() == 0 {
    println!(">> EMPTY CHAIN");
    return (1.0, None);
  }

  let verbose = verbose || chain.verbose_tag;
  let outregs = 3; // don't hardcode this! 

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
  
  let mut fit_vec : Vec<f32> = Vec::new();
  //let mut crashes = 0;
  /* This loop would probably be easy to parallelize */
  /* So long as each thread can be provided with its */
  /* own instance of the emulator.                   */
  let mut counter_sum = 0;
  let mut anycrash = false;
  for &(ref input, ref target) in io_targets.iter() {
    let (ft,counter,crash) = eval_case(uc,
                                       chain,
                                       &input,
                                       &target,
                                       outregs,
                                       verbose);
    let counter = min(counter, chain.size()-1);
    counter_sum += counter;
    anycrash = anycrash || crash;
    fit_vec.push(ft);
  };
  /* clean up hooks */
  for hook in &hooks { uc.remove_hook(*hook); }

  let fitness = (fit_vec.iter().map(|&x| x).sum::<f32>() 
                   / fit_vec.len() as f32) as f32;
  
  (fitness, if anycrash {
    Some(counter_sum / io_targets.len())
  } else {
    None
  })
}

fn append_to_csv(path: &str, iter: usize,
                 avg_gen: f32, 
                 avg_fit: f32,
                 best: &Chain) {
  if best.fitness == None {
    println!("*** best.fitness is None in append_to_csv?! ***");
    return;
  }
  let fit  = best.fitness.unwrap();
  let gen = best.generation;
  let len  = best.clumps.len();
  let crash = match best.crashes {
    None => 0,
    Some(false) => 0,
    Some(true)  => 1,
  };
  let row  = format!("{},{},{},{},{},{},{}\n", 
                     iter, 
                     avg_gen,
                     avg_fit,
                     gen,
                     fit,
                     crash,
                     len);
  let mut file = OpenOptions::new()
                            .append(true)
                            .create(true)
                            .open(path)
                            .unwrap();
  file.write(row.as_bytes());
  file.flush();
//  println!(">> {}",row);
}


#[derive(Debug,Clone)]
pub struct TournementResult {
  pub graves: Vec<usize>,
  pub spawn:  Vec<Chain>,
  pub best:   Chain,
  pub display: String,
  pub fit_updates: Vec<(usize,(Option<f32>,Option<bool>))>,
}
unsafe impl Send for TournementResult {}

pub fn patch_population (tr: TournementResult,
                         population: &mut Population) 
                        -> Option<Chain> {
  assert_eq!(tr.graves.len(), tr.spawn.len());
  population.generation += 1;
  for i in 0..tr.graves.len() {
//    println!(">> filling grave #{}",tr.graves[i]);
    population.deme[tr.graves[i]] = tr.spawn[i].clone();
  }
  for (i,(f,c)) in tr.fit_updates {
    if f != None {
      population.deme[i].fitness = f;
      population.deme[i].crashes = c;
    }
  }
  println!("{}",tr.display);
  if population.best == None || 
    tr.best.fitness < population.best_fit() {
    population.best = Some(tr.best.clone());
    population.log();
    Some(tr.best)
  } else {
    if population.params.verbose {
      population.log();
    }
    None
  }
}
// returns a clone of the best if the best is new

pub fn tournement (population: &Population,
                   engine: &mut Engine,
                   batch: Batch,
                   vdeme: usize)
                  -> TournementResult {
  let mut lots : Vec<usize> = Vec::new();
  let io_targets = match batch {
    Batch::TRAINING => &population.params.io_targets,
    Batch::TESTING  => &population.params.test_targets,
  };
  let mut contestants : Vec<(Chain,usize)> = Vec::new();
  let mut uc = engine.unwrap_mut(); //(machinery.cluster[0].unwrap_mut()); // bandaid
  let mut rng = thread_rng(); //&mut(machinery.rng);
  let mut t_size = population.params.t_size;
  let mut cflag = false;
//  let io_targets = &(population.params.io_targets);
  if rng.gen::<f32>() < population.params.cuck_rate {
    cflag = true;
    t_size -= 1;
  }

  let mut specimens = Vec::new();
  
  // Virtual demes: segment of the population from which specimens
  // will be drawn.
  /*let lotdraw = if rng.gen::<f32>() < population.params.migration {
    Box::new(|| rng.gen::<usize>() % 
             population.params.population_size)
  } else {
    Box::new(|| rng.gen::<usize>() % r + (r * vdeme))
  };
  */
  let r = population.params.population_size / population.params.num_demes;
  let migrating = rng.gen::<f32>() < population.params.migration;
  for _ in 0..t_size {
    let mut l: usize = if !migrating {
      rng.gen::<usize>() % r + (r * vdeme)
    } else {
      rng.gen::<usize>() % population.params.population_size
    };
    while lots.contains(&l) {
      l = if migrating {
        rng.gen::<usize>() % r + (r * vdeme)
      } else {
        rng.gen::<usize>() % population.params.population_size
      };
    }
    lots.push(l);
    specimens.push((population.deme[l].clone(),l));
  }

  let mut fit_vec = Vec::new();
  for &(ref specimen,_) in specimens.iter() {
    if (specimen.fitness == None || 
        VARIABLE_FITNESS) {
      let (fitness,crash) = evaluate_fitness(&mut uc, 
                                             &specimen,
                                             io_targets,
                                             false); // verbose
      fit_vec.push((fitness,crash));
    } else {
      fit_vec.push((specimen.fitness.unwrap(),None));
    }
  }
   
  for (&mut (ref mut specimen,lot), (fitness, crash)) 
    in specimens.iter_mut()
                .zip(fit_vec) {
    match crash {
      Some(counter) => {
        specimen.crashes = Some(true);
        //specimen[counter].sicken(); 
      },
      None => {
        specimen.crashes = Some(false);
      },
    } 
      /* Set link fitness values */
    for clump in &mut specimen.clumps {
      clump.link_fit  = calc_link_fit(clump, fitness);
      clump.viscosity = calc_viscosity(clump);
    }
    //println!("## Setting fitness for lot #{} to {}",lot,fitness);
    specimen.set_fitness(fitness);
  }
  
  specimens.sort();
  
  let (mother,m_idx) = specimens[0].clone();
  let (father,f_idx) = if cflag {
    // make this a separate method of population
    (population.random_spawn(), 0)
  } else { 
    specimens[1].clone()
  };
  let mut fit_updates = vec![(m_idx, (mother.fitness,mother.crashes))];
  if !cflag {
    fit_updates.push((f_idx, (father.fitness,father.crashes)));
  }

  /* This little print job should be factored out into a fn */
  let mut display : String = String::new();
  display.push_str(&format!("[{:05}:{:02}] ", 
                            population.generation,
                            vdeme));
  let mut i = 0;
  for &(ref specimen,_) in specimens.iter() {
    if i == 1 && cflag { 
      display.push_str(" ???????? ||");
    }
    if specimen.fitness == None {
      display.push_str(" ~~~~~~~~ ");
    } else {
      let f = specimen.fitness.unwrap();
      display.push_str(&format!(" {:01.6}{}", f,
                         if specimen.crashes == Some(true) {
                           '*'
                         } else {
                           ' '
                         }));
    }
    i += 1;
    if i < specimens.len() { display.push_str("|") };
    if !cflag && i == 2 { display.push_str("|") };
  }
  if population.best_fit() != None {
    display.push_str(&format!(" ({:01.6}{})", 
                              population.best_fit().unwrap(),
      if population.best_crashes() == Some(true) {"*"} else {""}));
  } else {
    display.push_str(" (----------)");
  }
  /* End of little print job */

  let (_,grave0) = specimens[t_size-2];
  let (_,grave1) = specimens[t_size-1];
  let parents : Vec<&Chain> = vec![&mother,&father];
  let offspring = mate(&parents,
                       &population.params,
                       &mut rng,
                       uc);
  let t_best = specimens[0].0.clone();
  if t_best.fitness == None {
    panic!("t_best.fitness is None!");
  }
  TournementResult {
    graves:      vec![grave0, grave1],
    spawn:       offspring,
    best:        t_best,
    display:     display,
    fit_updates: fit_updates,
  }
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
    evaluate_fitness(uc, &mut *spawn, io_targets, false); 
  }
  brood.sort();
  /* Now eliminate the least fit */
  while brood.len() > n {
    brood.pop();
  }
}
  
fn calc_viscosity (clump: &Clump) -> i32 {
  match clump.link_fit {
    Some(x) => {
      assert!(x <= 1.0);
      assert!(x >= 0.0);
      MAX_VISC - (MAX_VISC as f32 * x) as i32
    },
    None    => MAX_VISC/2,
  }
}

fn splice_point (chain: &Chain, 
                 rng: &mut ThreadRng,
                 use_viscosity: bool) -> usize {
  let mut wheel : Vec<Weighted<usize>> = Vec::new();
  let mut i : usize = 0;
  if chain.size() == 0 {
    panic!("Empty chain in splice_point(). Why?");
  }
  for clump in &chain.clumps {
    assert!(clump.visc() <= MAX_VISC);
    let vw : u32 = if use_viscosity {
      1 + (MAX_VISC - clump.visc()) as u32
    } else {
      50
    };
    wheel.push(Weighted { weight: vw,
                          item: i });
    i += 1;
  }
  let mut spin = WeightedChoice::new(&mut wheel);
  spin.sample(rng) 
}

fn shufflefuck (parents:    &Vec<&Chain>, 
                params:     &Params,
                rng:        &mut ThreadRng) -> Vec<Chain> {
  let brood_size = params.brood_size;
  let max_len    = params.max_len;
  let use_viscosity = params.use_viscosity;
  let mut brood : Vec<Chain> = Vec::new();
  for i in 0..brood_size {
    let m_idx  : usize  = i % 2;
    let mother : &Chain = &(parents[m_idx]);
    let father : &Chain = &(parents[(m_idx+1) % 2]);
    let m_i : usize = splice_point(&mother, rng, use_viscosity);
    let m_n : usize = mother.size() - (m_i+1);
    let f_i : usize = splice_point(&father, rng, use_viscosity);

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
    if i > 0 { 
      child_clumps[i-1].link_age = 0;
      child_clumps[i-1].link_fit = None;
    };
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
    let mut child : Chain = Chain::new(child_clumps);
    child.generation = max(mother.generation, father.generation)+1;
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

