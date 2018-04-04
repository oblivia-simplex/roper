// Implement something like stackvec to make a copiable vec
// like structure to contain your shit.
extern crate unicorn; 
extern crate bit_vec;
use std::cell::*;
use std::time::Instant;
use std::io::{BufReader,BufRead};
use std::path::Path;
use std::sync::{RwLock,RwLockReadGuard};
use std::fs::{File,OpenOptions};
use std::io::prelude::*;
use std::collections::{HashMap};
use rand::distributions::*;
use rand::Rng;
use rand::ThreadRng;
use rand::thread_rng;
use unicorn::*;
  
use std::cmp::*;

use roper::statistics::*;
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
        if clump.ret_addr < clump.words[0] {
            println!("[WARNING] clump.ret_addr = {:08x}\nclump.words[0] = {:08x}",
                              clump.ret_addr, clump.words[0]);
            return;
        }

        let d = clump.ret_addr - clump.words[0];
        let inst_size = if clump.mode == MachineMode::ARM {
            4
        } else {
            2
        };
        if d > inst_size || rng.gen::<bool>() {
            clump.words[0] += inst_size;
        } else if d < (inst_size * 8) {
            clump.words[0] -= inst_size;
        }
}

fn mutate(chain: &mut Chain, 
          params: &Params, 
          uc: &unicorn::CpuARM, 
          rng: &mut ThreadRng) {
        /* mutations will only affect the immediate part of the clump */
        /* we'll let shufflefuck handle the rest. */
        /* Add permutation operation, shuffling immeds */
        if chain.size() == 0 {
            panic!("chain.size() == 0. Why?");
        }
        let mut cl_idx : usize = rng.gen::<usize>() % chain.size();
        let mut tries = 3;
        /* if you do this, take viscosity, link age, and link fit into 
          * account. 
        if rng.gen::<bool>() {
            let cl_idx2 = rng.gen::<usize>() % chain.size();
            let tmp = chain[cl_idx];
            chain[cl_idx] = chain[cl_idx2];
            chain[cl_idx2] = tmp;
        }
        **/
        while chain[cl_idx].size() == 1 {
            if tries == 0 { return } else { tries -= 1 };
            cl_idx = rng.gen::<usize>() % chain.size();
        }
        let mut clump = chain[cl_idx].clone();
        assert!(clump.size() > 0);
        let idx : usize   = 1 + (rng.gen::<usize>() % (clump.size() - 1));
        let mut_kind : u8 = rng.gen::<u8>() % 5;
        match mut_kind {
            0 => clump.words[idx] = mang(clump.words[idx].clone(), rng),
            1 => mutate_addr(&mut clump, rng),
            2 => match deref(&(uc.emu()), clump.words[idx].clone()) {
                Some(x) => { println!("==> deref mutation: {:x} -> {:x}", clump.words[idx], x); clump.words[idx] = x; },
                None    => (),
            },
            3 => match uc_seek_word(clump.words[idx].clone(), uc) {
                Some(x) => {
                    chain.name = "child of indirection mutation".to_string();
                    println!("<== indirection mutation: {:x} -> {:x}", clump.words[idx], x);
                    clump.words[idx] = x as u32;
                },
                None    => (),
            },
            // 2 => /**** mutate the input_slots ****/
            _ => { /* permutation */
                let other_idx = 1 + (rng.gen::<usize>() % (clump.size() - 1));
                let tmp = clump.words[idx];
                clump.words[idx] = clump.words[other_idx];
                clump.words[other_idx] = tmp;
            },
        };
        /* oh christ, the mutated clumps were never entered back in the chain! */
        chain[cl_idx] = clump;
}

fn mutate_edi (chain: &mut Chain, params: &Params, rng: &mut ThreadRng) {
        for ref mut clump in &mut chain.clumps {
            if rng.gen::<f32>() < params.edi_toggle_rate {
                clump.enabled = !clump.enabled; 
            }
        }
}

fn clone_and_mutate (parents: &Vec<&Chain>,
                     params:  &Params,
                     uc:      &unicorn::CpuARM,
                     rng:     &mut ThreadRng) -> Vec<Chain> {
        let mut brood : Vec<Chain> = Vec::new();
        let n = params.brood_size;
        for i in 0..n {
            let spawnclumps = parents[i % 2].clumps.clone();
            let unmutated = spawnclumps.clone();
            let mut spawn = Chain::new(spawnclumps);
            mutate(&mut spawn, &params, uc, rng);
            let mutated = spawn.clumps.clone();
            if mutated == unmutated {
                println!("??? not mutated");
            } else {
                println!("!!! mutated");
            }
            if params.use_edis { mutate_edi(&mut spawn, &params, rng); };
            spawn.p_fitness = parents[i % 2].fitness;
            spawn.generation = parents[i % 2].generation + 1;
            brood.push(spawn);
        }
        brood
}

fn mate (parents: &Vec<&Chain>, 
         params:  &Params, 
         rng:     &mut ThreadRng,
         uc:      &mut CpuARM) -> Vec<Chain> {
        let mut brood = if rng.gen::<f32>() < params.crossover_rate {
            shufflefuck(parents, 
                        params,
                        rng)
        } else {
            let uc = &uc;
            clone_and_mutate(parents,
                             params,
                             uc,
                             rng)
        };
        cull_brood(&mut brood, 2, uc, &params);
        brood
}

#[derive(Debug,PartialEq)]
pub struct EvalCaseResult {
        pub fitness : f32,
        pub ab_fitness : f32,
        pub counter : usize,
        pub crashes : bool,
        pub visited : Vec<u32>,
        pub registers : Vec<u32>,
        pub reg_deref : Vec<Option<u32>>,
}
#[derive(Debug,PartialEq)]
pub struct EvalResult {
        pub fitness : f32,
        pub ab_fitness : f32,
        pub mean_ratio_run : f32,
        pub counter : usize,
        pub crashes : bool,
        pub visitation_diversity : f32,
        pub visited_map : HashMap<Problem, Vec<u32>>,
        pub register_map : HashMap<Problem, (Vec<u32>,Vec<Option<u32>>)>,
        pub difficulties : Option<HashMap<Problem, f32>>,
}

/* This is getting a bit convoluted, trying to cover too many
  * kinds of evaluation at once. due for a major rewrite. 
  * NB: dropped support for games. do that in another eval func, not this one.
  */
fn eval_case (uc: &mut CpuARM,
              chain: &Chain,
              problem: &Problem,
              params: &Params,
              verbose: bool) -> EvalCaseResult { 
    let inregs = &params.inregs;
    let outregs = &params.outregs;
    let target = &problem.target;
    let reset = true;
    let input  = &problem.input;
    let result = hatch_chain(uc, 
                             &chain,
                             input,
                             &inregs,
                             reset);
    let (af,rf) = problem.assess_output(&outregs, 
                                        &result.registers,
                                        &result.reg_deref, 
                                        uc);
    let counter = result.counter;
    let crash = result.error != None || result.isnull();
            
    EvalCaseResult {
        fitness: if params.fitness_sharing {rf} else {af},
        ab_fitness: af,
        counter: counter,
        crashes: crash,
        visited: result.visited,
        registers: result.registers,
        reg_deref: result.reg_deref,
    }
}
/*
fn adj_score_for_difficulty (score: f32, 
                                                              popsize: usize,
                                                              difficulty: f32) -> f32 {
        f32::max(0.0, score - (difficulty / popsize as f32))
}
*/
pub const VARIABLE_FITNESS : bool = true;
pub fn evaluate_fitness (uc: &mut CpuARM,
                         chain: &Chain, 
                         params: &Params,
                         batch: Batch,
                         verbose: bool)
                         -> EvalResult //(f32,Option<usize>)
{
        /* Empty chains can be discarded immediately */
        if chain.size() == 0 {
            panic!("EMPTY CHAIN IN evaluate_fitness");
        }
        let io = match batch {
            Batch::TRAINING => &params.io_targets,
            Batch::TESTING  => &params.test_targets,
        };
        let io2 : IoTargets;
        // NB: fingerprint mechanics won't work, as currrently implemented,
        // if the samples are shuffled, since it uses the order to id them
        // but this can be overcome at the cost of a bit more memory usage.
        // we'd just have to make fingerprints a vector of problem_id/bool
        // pairs. 
        /* could be optimized by skipping when sample_ratio == 1 */
        let sample_ratio = &params.sample_ratio;
        let (io_targets, io_targets2) = 
            io.split_at((io.len() as f32 * sample_ratio).ceil() as usize);
        
        let outregs    = &params.outregs;
        let inregs     = &params.inregs;
        let verbose = verbose || chain.verbose_tag;

        let mut fit_vec : Vec<f32> = Vec::new();
        let mut abfit_vec : Vec<f32> = Vec::new();
//  let mut fingerprint :Fingerprint = Fingerprint::new(); 
        /* This loop would probably be easy to parallelize */
        /* So long as each thread can be provided with its */
        /* own instance of the emulator.                   */
        let mut counter_sum = 0;
        let mut anycrash = false;
        let mut difficulties : HashMap<Problem,f32> = HashMap::new();
        let mut visited_map  : HashMap<Problem,Vec<u32>> = HashMap::new();
        let mut register_map : HashMap<Problem,(Vec<u32>,Vec<Option<u32>>)>
            = HashMap::new(); 
        let mut ratio_run_vec = Vec::new();
        for problem in io_targets.iter() {
            let res : EvalCaseResult = eval_case(uc,
                                                 chain,
                                                 problem,
                                                 &params,
                                                 verbose);
            let p = problem.clone();
            let dif = res.ab_fitness;
            //println!(">> dif = {}", dif);
            //let dif = if res.fingerprint[0] {1.0} else {0.0};
            difficulties.insert(p.clone(), dif);
            // we could make this more efficient by just taking a
            // unique identifier for each problem.
            visited_map.insert(p.clone(), res.visited);
            register_map.insert(p, (res.registers, res.reg_deref));
            /* crash tracking */ 
            let counter = res.counter;
            
            let upperbound = chain.effective_size() as f32 - 1.0;
            let cs = f32::max(upperbound, 1.0);
            let ratio_run = f32::min(1.0, counter as f32 / cs);
            ratio_run_vec.push(ratio_run);
            counter_sum += counter;
            anycrash = anycrash || res.crashes;
            /* adjust score if there was a crash */
            let crash_adjusted = if res.crashes {
                crash_override(res.fitness,
                               ratio_run,
                               params)
            } else {
                res.fitness
            };
            /* If crash_adjusted is better than the best currently on 
              * record, then evaluate the specimen against the remainder
              * of the problems (io_targets2). 
              */ //\\//\\ TODO //\\//\\
            fit_vec.push(crash_adjusted);
            abfit_vec.push(res.ab_fitness);
        };
        let ab_fitness = mean(&abfit_vec);
        let fitness =  mean(&fit_vec);
        let ab_fitness = f32::min(1.0, ab_fitness);
        let mut fitness = f32::min(1.0, fitness);
        let mut divers = 0.0; 
        if  io_targets.len() > 1 && params.reward_visitation_diversity {
            let mut visits : Vec<Vec<u32>> = visited_map.values()
                                                        .map(|x| x.clone())
                                                        .collect();
            let total : f32 = visits.len() as f32;
            visits.sort();
            visits.dedup();
            let uniq  : f32 = visits.len() as f32;
            divers = uniq / total;
            let nondivers = 1.0 - divers;
            let adjusted = fitness * nondivers; // because lower = better
            let w = params.visitation_diversity_weight;
            fitness = (w * adjusted) + ((1.0 - w) * fitness);
            /* oh ffs, this reduces fitness to zero when io_targets.len() == 1 !! */
        }
        let fitness = fitness;
        assert!(0.0 <= fitness && fitness <= 1.0);
        assert!(0.0 <= ab_fitness && ab_fitness <= 1.0);
        
        let ratio_run = mean(&ratio_run_vec);
        EvalResult {
            fitness      : fitness,
            ab_fitness   : ab_fitness,
            counter      : counter_sum / io_targets.len(),
            mean_ratio_run : ratio_run,
            visited_map  : visited_map,
            register_map : register_map,
            crashes      : anycrash,
            visitation_diversity : divers,
            difficulties : Some(difficulties),
        }
}


#[derive(Clone,Debug,PartialEq)]
pub struct FitUpdate {
        pub fitness     : Option<f32>,
        pub ab_fitness  : Option<f32>,
        pub p_fitness   : Option<f32>,
  // pub fingerprint : Fingerprint,
        pub crashes     : Option<bool>,
        pub ratio_run   : f32,
        pub runtime     : Option<f32>,
        pub visitation_diversity : f32,
        pub visited_map : HashMap<Problem, Vec<u32>>,
        pub register_map : HashMap<Problem, (Vec<u32>,Vec<Option<u32>>)>,
}

#[derive(Debug,Clone)]
pub struct TournamentResult {
        pub graves            : Vec<usize>,
        pub spawn             : Vec<Chain>,
        pub best              : Chain,
        pub fit_updates       : Vec<(usize,FitUpdate)>,
        pub difficulty_update : HashMap <Problem, Vec<f32>>, // or avg f32
}
unsafe impl Send for TournamentResult {}


pub fn patch_io_targets (tr: &TournamentResult,
                                                      params: &mut Params,
                                                      iteration: usize) 
{
        let mut io_targets = &mut params.io_targets;
        for ref mut problem in io_targets.iter_mut() {
            if let Some(d_vec) = tr.difficulty_update.get(&problem) {
                //println!("(*) found problem {:?}", problem);
                problem.inc_predifficulty(d_vec); // += d_vec.iter().sum::<f32>();
                //println!(">> d_vec: {:?}", d_vec);
            } else {
                //println!("(x) couldn't find problem {:?}", problem);
            }
        }
}

pub fn update_difficulties (params: &mut Params,
                                                            iteration: usize) -> usize {
        let season_length = params.calc_season_length(iteration);
        let mut io_targets = &mut params.io_targets;
        let reset = iteration > params.threads 
                                && iteration % season_length == 0;
        if reset {
            let divisor = (season_length * params.t_size) as f32
                                        * (1.0 - params.cuck_rate);
            let sum_diff = io_targets.iter()
                                                              .map(|p| p.predifficulty())
                                                              .sum::<f32>();
            println!("==[ RESETTING PROBLEM DIFFICULTIES ]==");
            for ref mut problem in io_targets.iter_mut() {
                problem.rotate_difficulty(divisor);
            }
            1
        } else {
            0
        }
}


pub fn patch_population (tr: &TournamentResult,
                         population: &mut Population,
                         verbose: bool,
                         heatmap: &mut HashMap<u32,usize>) 
                         -> (Option<Chain>, Vec<f32>) 
{
        assert_eq!(tr.graves.len(), tr.spawn.len());
        population.iteration += 1;
        let season = population.season;
        // Insert the new children into the slots of the dead
        for i in 0..tr.graves.len() {
            // update heatmap for the offspring
            mark_heatmap(heatmap, &tr.spawn[i].dedup_visits());
            population.deme[tr.graves[i]] = tr.spawn[i].clone();
            population.deme[tr.graves[i]].season = season;
        }
        // Update fitness, etc. on survivors
        let mut fitness_deltas = Vec::new();
        for &(i, ref fit_up) in tr.fit_updates.iter() {
            if let Some(f) = fit_up.fitness {
                mark_heatmap(heatmap, &population.deme[i].dedup_visits());
                population.deme[i].season  = season;
                population.deme[i].fitness = Some(f);
                population.deme[i].visited_map = fit_up.visited_map.clone();
                population.deme[i].visitation_diversity = fit_up.visitation_diversity;
                population.deme[i].register_map = fit_up.register_map.clone();
                population.deme[i].crashes = fit_up.crashes.clone();
                population.deme[i].ratio_run = fit_up.ratio_run;
                population.deme[i].ab_fitness = fit_up.ab_fitness.clone();
                population.deme[i].p_fitness = fit_up.p_fitness.clone();

                if let Some(pf) = population.deme[i].p_fitness {
                    fitness_deltas.push(f - pf);
                };
            }
        }
        if population.best == None 
            || (tr.best.crashes == Some(false) &&  // throw caution to the wind
                tr.best.ab_fitness < population.best_abfit()) {
            population.best = Some(tr.best.clone());
            println!("NEW BEST\n{}\n", &tr.best);
            (Some(tr.best.clone()), fitness_deltas)
        } else {
            (None, fitness_deltas)
        }
}

pub fn lexicase_rpat (population: &Population,
                      engine: &mut Engine,
                      batch: Batch,
                      vdeme: usize)
                      -> ()
{
        // for register patterns
        let p_size = population.params.population_size;
        let n_demes = population.params.num_demes;
        let d_size  = p_size / n_demes;
        let io_targets = &population.params.io_targets;
        
        let ref pproblem = io_targets.to_vec()[0]; // shortcut.
        
        let rpat : &RPattern = match pproblem.target {
            Target::Exact(ref rp) => rp,
            _   => panic!("Not that kind of lexicase, yet."),
        };

        let mut rng = thread_rng(); // switch to seedable
        let deme = rng.gen::<usize>() % n_demes;
        let mut lots : Vec<usize> = 
            ((deme * d_size)..(deme * (d_size+1))).collect();
        rng.shuffle(&mut lots);
        
        let rpvec = rpat.shuffle_vec();
        for (reg, val, dif) in rpvec {
            while lots.len() > 2 {
              // do the stuff 
            }
        }
}

pub fn tournament (population: &Population,
                   engine: &mut Engine,
                   batch: Batch,
                   vdeme: usize,
                   verbose: bool)
                   -> TournamentResult 
{
        let season = population.season;
        let mut lots : Vec<usize> = Vec::new();
        let mut contestants : Vec<(Chain,usize)> = Vec::new();
        let mut uc = engine.unwrap_mut(); //(machinery.cluster[0].unwrap_mut()); // bandaid
        let mut rng = thread_rng(); //&mut(machinery.rng);
        let mut t_size = population.params.t_size;
        let mut cflag = false;
        //  let io_targets = &(population.params.io_targets);
        if rng.gen::<f32>() < population.params.cuck_rate 
        {
            cflag = true;
            t_size -= 1;
        }

        let mut specimens = Vec::new();

        let migrating = rng.gen::<f32>() < population.params.migration;
        let vdeme = if migrating {vdeme / 2 + (vdeme % 2)} else {vdeme};
        let r = population.params.population_size / population.params.num_demes;
        let r = if migrating {r*2} else {r};
        for _ in 0..t_size 
        {
            let mut l: usize = rng.gen::<usize>() % r + (r * vdeme);
            while lots.contains(&l) {
                l = rng.gen::<usize>() % r + (r * vdeme);
            }
            l = l % population.params.population_size;
            lots.push(l);
            specimens.push((population.deme[l].clone(),l));
        }

        let mut fit_vec = Vec::new();
        let mut difficulty_update = HashMap::new();
        for &(ref specimen,_) in specimens.iter() 
        {
            let start = Instant::now();
            let res = evaluate_fitness(&mut uc, 
                                       &specimen,
                                       &population.params,
                                       batch,
                                       verbose); // verbose
            let ratio_run : f32 = res.mean_ratio_run;
            let crash   = Some(res.crashes);
            //println!("==> ratio_run = {:1.6}, crash? {:?}",ratio_run, crash);
            let e = start.elapsed();
            let elapsed = Some(e.as_secs() as f32 + (e.subsec_nanos() as f32 / 1000000000.0));
            let fitness = res.fitness;
            let ab_fitness = res.ab_fitness;
            for (input, difficulty) in &res.difficulties.unwrap() {
                match difficulty_update.get(input) {
                    None    => {
                        difficulty_update.insert(input.clone(), vec![*difficulty]);
                    },
                    Some(_) => {
                        difficulty_update.get_mut(input).unwrap().push(*difficulty);
                    }
                };
            }
            fit_vec.push(FitUpdate {
                fitness      : Some(fitness),
                ab_fitness   : Some(ab_fitness),
                p_fitness    : specimen.p_fitness.clone(),
                crashes      : crash,
                ratio_run    : ratio_run,
                visitation_diversity : res.visitation_diversity,
                runtime      : elapsed,
                visited_map  : res.visited_map,
                register_map : res.register_map,
                });
        } 
         
        /* does this have to be done here? seems extraneous... */
        /* oh, setting the viscosity is necessary for the mating */
        for (&mut (ref mut specimen,lot), ref fit_up) 
            in specimens.iter_mut().zip(fit_vec) 
        {
                specimen.crashes = fit_up.crashes;
                specimen.fitness = fit_up.fitness;
                specimen.runtime = fit_up.runtime;
                specimen.ratio_run = fit_up.ratio_run;
                specimen.ab_fitness = fit_up.ab_fitness;
                specimen.visited_map = fit_up.visited_map.clone();
                specimen.visitation_diversity = fit_up.visitation_diversity;
                specimen.register_map = fit_up.register_map.clone();
                /* Set link fitness values */
                for clump in &mut specimen.clumps {
                    clump.link_fit  = calc_link_fit(clump, fit_up.fitness.unwrap());
                    clump.viscosity = calc_viscosity(clump);
                }
                //println!("## Setting fitness for lot #{} to {}",lot,fitness);
        //    specimen.set_fitness(fitness);
            //  specimen.set_ab_fitness(ab_fitness);
        }

        select_mates(&mut specimens, true); //.sort();
        let (mother,m_idx) = specimens[0].clone();
        let (father,f_idx) = if cflag {
            (population.random_spawn(), 0)
        } else { 
            specimens[1].clone()
        };
        let mut fit_updates = vec![(m_idx, 
                                    FitUpdate {
                                                fitness     : mother.fitness,
                                                ab_fitness  : mother.ab_fitness,
                                                p_fitness   : mother.p_fitness,
                                                crashes     : mother.crashes,
                                                ratio_run   : mother.ratio_run,
                                                runtime     : mother.runtime,
                                                visited_map : mother.visited_map.clone(),
                                                visitation_diversity : mother.visitation_diversity,
                                                register_map : mother.register_map.clone(),
                                              })];
        if !cflag {
            fit_updates.push((f_idx, 
                              FitUpdate { 
                                          fitness     : father.fitness,
                                          ab_fitness  : father.ab_fitness,
                                          p_fitness   : father.p_fitness,
                                          crashes     : father.crashes,
                                          ratio_run   : father.ratio_run,
                                          runtime     : father.runtime,
                                          visited_map : father.visited_map.clone(),
                                          visitation_diversity : father.visitation_diversity,
                                          // this redundancy must be refactorable!
                                          register_map : father.register_map.clone(),
                                         })); // (father.fitness,father.crashes)));
        }


        let (_,grave0) = specimens[t_size-2];
        let (_,grave1) = specimens[t_size-1];
        let parents : Vec<&Chain> = vec![&mother,&father];
        let offspring = mate(&parents,
                             &population.params,
                             &mut rng,
                             &mut uc);
        let t_best = specimens[0].0.clone();
        if t_best.fitness == None {
            panic!("t_best.fitness is None!");
        }
        TournamentResult {
            graves:      vec![grave0, grave1],
            spawn:       offspring,
            best:        t_best,
            fit_updates: fit_updates,
            difficulty_update: difficulty_update,
        }  
}

fn select_mates(specimens: &mut Vec<(Chain,usize)>,
                                    select_for_diversity: bool)  {
        // easy way: sort by fitness. specimens.sort()
        // interesting way: sort, and then let the winner choose her mate
        specimens.sort();
        //let m0 = specimens[0].0.fingerprint.clone();
        /*
        println!(">> BEFORE FINGERPRINT SORT:");
        for s in specimens.iter() {
            println!("   {} [{}]", s.0.fingerprint, m0.distance(&s.0.fingerprint));
        }
        */
/*
        if select_for_diversity {
            specimens[1..]
                .sort_by(|y,x| m0.distance(&x.0.fingerprint)
                                                  .cmp(&m0.distance(&y.0.fingerprint)));
        }
        */
        /*
        println!(">> AFTER FINGERPRINT SORT:");
        for s in specimens.iter() {
            println!("{}[{}]", s.0.fingerprint, m0.distance(&s.0.fingerprint));
        }
        */
}

fn cull_brood (brood: &mut Vec<Chain>, 
                              n: usize,
                              uc: &mut CpuARM,
                              params: &Params) {
        /* Sort by fitness - most to least */
        let mut i = 0;
        if brood.len() <= n { return; };
        for spawn in brood.iter_mut() {
            // println!("[*] Evaluating spawn #{}...", i);
            i += 1;
            /* This doesn't make sense anymore. The fitness field
              * isn't mutated by evaluate_fitness, just returned. 
              * This whole function needs to be refactored.
              */
            evaluate_fitness(uc, 
                             &spawn, 
                             &params, 
                             Batch::TRAINING,
                             false); 
        }
        brood.sort();
        /* Now eliminate the least fit */
        while brood.len() > n {
            brood.pop();
        }
}

pub fn calc_mutrate (std_dev_difs: &Vec<f32>) -> f32 {
        let mean_std_dev_dif = mean(std_dev_difs);
        let rate = f32::max(0.01, 1.0 - (100.0 * mean_std_dev_dif));
        println!(">> mean_std_dev_dif at {}; setting mutation rate to {}",
                          mean_std_dev_dif, rate);
        rate
}

fn calc_viscosity (clump: &Clump) -> i32 {
match clump.link_fit {
        Some(x) => {
            assert!(x <= 1.0);
            //let x = f32::max(0.0,x);
            MAX_VISC - (MAX_VISC as f32 * f32::min(x,1.0)) as i32
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
            
            let mut child_clumps : Vec<Clump> = Vec::new();
            let mut i = 0;
            for f in 0..f_i {
                child_clumps.push(father.clumps[f].clone());
                child_clumps[i].link_age += 1;
                i += 1;
            }
            /* By omitting the following lines, we drop the splicepoint */
            if false && father.clumps[f_i].viscosity >= VISC_DROP_THRESH {
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
                child_clumps.push(mother.clumps[m].clone());
                child_clumps[i].link_age += 1;
                i += 1;
                /* adjust link_fit later, obviously */
            }
            if child_clumps.len() == 0 {
                panic!("child_clumps.len() == 0. Stopping.");
            }
            let mut child : Chain = Chain::new(child_clumps);
            child.generation = max(mother.generation, father.generation)+1;
            child.p_fitness = {
                let mut f = Vec::new();
                if let Some(x) = mother.fitness {f.push(x)};
                if let Some(x) = father.fitness {f.push(x)};
                if f.len() == 0 {None} else {Some(mean(&f))}
            };
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

/* TODO: try holding crash penalty constant */
pub fn compute_crash_penalty(crash_rate: f32) -> f32 {
        crash_rate / 2.0
}

fn crash_override(score: f32,
                  ratio_run: f32,
                  params: &Params) -> f32 {
        if params.fatal_crash {
            1.0
        } else {
            1.0 - (1.0 - score) * params.crash_penalty * ratio_run
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

