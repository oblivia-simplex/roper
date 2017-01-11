
use std::io::{BufReader,BufRead};
use std::fs::File;
use std::path::Path;

use rand::distributions::*;
use rand::Rng;
use rand::ThreadRng;
 
use std::cmp::*;

use roper::params::*;

use roper::util::{pack_word32le,
                  pack_word32le_vec,
                  u8s_to_u16s,
                  mang,
                  deref_mang};

use roper::thumb::{reap_thumb_gadgets};

/*
#[derive(PartialEq,Debug)]
pub enum GadKind {
  imm,
  reg,
}

fn str_gadkind (s: &str) -> GadKind {
  match s {
    "imm" => GadKind::imm,
    "reg" => GadKind::reg,
    _     => panic!("Couldn't match GadKind to {}",s),
  }
}
*/

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct Chain {
  pub clumps: Vec<Clump>, 
  pub packed: Vec<u8>,
  pub fitness: Option<i32>,
  pub generation: u32,
  pub ancestral_fitness: Vec<i32>,
  // space-consuming, but it'll give us some useful data on
  // the destructiveness of the crossover operator
}
impl Default for Chain {
  fn default () -> Chain {
    Chain {
      clumps: Vec::new(),
      packed: Vec::new(),
      fitness: None,
      generation: 0,
      ancestral_fitness: Vec::new(),
    }
  } 
}
impl Chain {
  fn new () -> Chain {
    Chain {..Default::default()}
  }
  fn size (&self) -> usize {
    self.clumps.len()
  }
}
impl PartialOrd for Chain {
  fn partial_cmp (&self, other: &Chain) -> Option<Ordering> {
    match (self.fitness, other.fitness) {
      (Some(a), Some(b)) => Some(b.cmp(&a)), // Note reversal
      _                  => None,
    }
  }
}
impl Ord for Chain {
  fn cmp (&self, other: &Chain) -> Ordering {
    self.partial_cmp(other).unwrap_or(Ordering::Equal)
  }
}
// tmp
#[derive(Eq,PartialEq,Debug,Clone)]
pub struct Clump {
  // pub kind:        GadKind,
  pub sp_delta:    i32, // how much does the sp change by?
  pub ret_offset:  i32, // how far down is the next address?
  pub exchange:    bool, // BX instruction? can we change mode?
  pub mode:        MachineMode,
  pub words:       Vec<u32>,
  pub viscosity:   i32,
  pub link_age:    i32,
  pub link_fit:    i32,
  // pub size:        usize,
  // consider adding operation field
}
impl Default for Clump {
  fn default () -> Clump {
    Clump {
      sp_delta:   1,
      ret_offset: 1,
      exchange:   false,
      mode:       MachineMode::THUMB,
      words:      Vec::new(),
      viscosity:  (MAX_VISC - MIN_VISC) / 2 + MIN_VISC,
      link_age:   0,
      link_fit:   (MAX_FIT/2),
    }
  }
}
impl Clump {
  fn new () -> Clump {
    Clump {..Default::default()}
  }
  fn size (&self) -> usize {
    self.words.len()
  }
}


/* Viscosity measures the likelihood of a clump to "stick" to its
 * successor in the chain. (We could look at a 2dim matrix of visc-
 * osity measures, since the flow of execution in a chain is not
 * necessarily one-dimensional, but this would complicate things.)
 * That is, it is proportional to the likelihood for the link between
 * the clump and its successor to be selected as a slice point for
 * crossover. 
 *
 * There are a few different ways of parameterizing viscosity, but
 * one interesting candidate is as follows: 
 *
 * viscosity := link_fit * link_age * C 
 *
 * where 
 * link_fit = (a * max(parents' link_fit) + ((1-a) * chain fitness)
 * if the link is inherited, and
 * link_fit = N
 * if the link is new, where N is some "neutral" value. We'll 
 * probably set N to 0.5. 
 *
 * This is similar to the calculation of RTT in TCP, and is, of course
 * open to other approaches.
 *
 * See section 6.5.5 of Banzhaf et al., Genetic Programming: An
 * Introduction, for a discussion of similar strategies.
 */
pub trait Gadget {
  fn addr (&self) -> u32; 
  fn pack (&self) -> Vec<u8>;
}

impl Gadget for Clump {
  fn addr (&self) -> u32 {
    self.words[0]
  }
  fn pack (&self) -> Vec<u8> {
    let mut p : Vec<u8> = Vec::new();
    for ref w in &(self.words) {
      p.extend(pack_word32le(**w).iter())
    }
    p
  }
}
// nb: ret_offset is not always going to equal sp_delta
// e.g. pop {r1,r2,r3,r4,r5}; bxr r3
// has an sp_delta of +5, and a ret_offset of +3

 /* then in each child, all clumps at index < i have:
 * fitness of their parent * alpha + child fitness * (1-alpha)
 * similarly for all clumps at index > i. clump at index i
 * is given a neutral fitness value. 
 */
fn calc_link_fit (p_fit: i32, c_fit: i32, alpha: i32) -> i32 {
  (p_fit * alpha) + (c_fit * (MAX_FIT - alpha))
}

/* link age = parental link age + 1, or 0 if at splice index
 */



fn crossover (parents:    &Vec<Chain>, 
              brood_size: usize,
              rng:        &mut ThreadRng) -> Vec<Chain> {
  let mut brood : Vec<Chain> = Vec::new();
  for s in 0..brood_size {
    let m_idx  : usize  = rng.gen::<usize>() % 2;
    let mother : &Chain = &(parents[m_idx]);
    let father : &Chain = &(parents[(m_idx+1) % 2]);
    let mut child : Chain = Chain::new();
    let m_i : usize = splice_point(&mother, rng);
    let m_n : usize = mother.size() - m_i;
    let f_i : usize = splice_point(&father, rng);
    let f_n : usize = father.size() - f_i;
    child.clumps = Vec::with_capacity(f_i+m_n);
    for f in 0..f_i {
      child.clumps.push(father.clumps[f].clone());
      child.clumps[f].link_age += 1;
    }
    child.clumps.push(father.clumps[f_i].clone());
    child.clumps[f_i].link_age = 0;
    for m in (m_i+1)..m_n {
      child.clumps.push(mother.clumps[m].clone());
      child.clumps[m-m_i].link_age += 1;
      /* adjust link_fit later, obviously */
    }
    brood.push(child);
  }
  brood
}



fn mutate(chain: &mut Chain, params: &Params, rng: &mut ThreadRng) {
  /* mutations will only affect the immediate part of the clump */
  /* we'll let crossover handle the rest. */
  if rng.gen::<f32>() > params.mutation_rate { return };

  let cl_idx     = rng.gen::<usize>() % chain.size();
  let clump      = &mut (chain.clumps[cl_idx]);
  let idx        = 1 + (rng.gen::<usize>() % (clump.size() - 1));
  if rng.gen::<bool>() {
    clump.words[idx] = mang(clump.words[idx].clone(), rng);
  } else {
    clump.words[idx] = deref_mang(clump.words[idx], 
                                  &(params.ro_data_32), 
                                  params.ro_data_addr);
  }
}

fn mate (parents: &Vec<Chain>, 
         params:  &Params, 
         rng:     &mut ThreadRng) -> Vec<Chain> {
  let mut brood = crossover(parents, params.brood_size, rng);
  cull_brood(&mut brood, 2);
  for s in brood.iter_mut() {
    mutate(s, params, rng)
  }
  brood
}

fn evaluate_fitness (chain: &mut Chain) {
 /* stub */  
}




fn tournement (population: &mut Population) {
  /* randomly select contestants */
  let t_size = population.params.t_size;
  let mut rng = &mut population.rng;
//  let p_chains = &(population.chains);
  let mut contestants : Vec<Chain> = {
    let mut tmp_vec = Vec::new();
    let mut i = 0;
    while i < t_size {
      i += 1;
      let c = rng.gen::<usize>() % population.chains.len();
      let mut p = population.chains[c].clone();
      /* fill in the hole from the end of the population */
      let last = population.chains.pop().unwrap();
      population.chains[c] = last;
      /* ontogenesis step */
      evaluate_fitness(&mut p);
      tmp_vec.push(p); // inefficient. can we fix? 
    }
    tmp_vec
  };
  contestants.sort();
  while contestants.len() > 2 {
    contestants.pop();
  };
  let offspring = mate(&contestants,
                       &population.params,
                       rng);
  contestants.extend_from_slice(&offspring);
  population.chains.extend_from_slice(&contestants);
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
  for clump in &(chain.clumps) {
    i += 1;
    assert!(clump.viscosity <= MAX_VISC);
    let vw : u32 = (MAX_VISC - clump.viscosity) as u32;
    wheel.push(Weighted { weight: vw,
                          item: i });
  }
  let mut spin = WeightedChoice::new(&mut wheel);
  spin.sample(rng)
}

fn saturated (gad: &Clump) -> bool {
  gad.words.len() as i32 == gad.sp_delta
}

fn concatenate (clumps: &Vec<Clump>) -> Vec<u32> {
  let s : usize = clumps.iter()
                        .map(|ref x| x.words.len())
                        .sum();
  let mut c = vec![0; s];
  println!("s = {}; c.len() = {}", s, c.len());
  let mut spd = 0;
  let mut rto = 0 as usize;
  let mut exchange = false;
  for ref gad in clumps {
    /* for debugging */
    println!("[{}] ==> {:?}",rto,gad);
    /*****************/
    if !saturated(gad) {
      panic!("Attempting to concatenate unsaturated clumps");
    }
    assert!(gad.sp_delta >= 0);
    let t : usize = rto + gad.sp_delta as usize;
    &c[rto..t].clone_from_slice(&(gad.words));
    if exchange && (gad.mode == MachineMode::THUMB) {
      /* If we BX, the LSB of the addr decides machine mode */
      c[rto] |= 1;
      println!("*** exchange: adding 1 mask ***");
    }
    rto += gad.ret_offset as usize;
    spd += gad.sp_delta as usize;
    exchange = gad.exchange;
  }
  c
}



pub fn mk_chain (clumps: &Vec<Clump>) -> Chain {
  let conc = concatenate(clumps);
  let pack = pack_word32le_vec(&conc);
  Chain {
    clumps: (*clumps).clone(),
    packed: pack,
    fitness: None,
    generation: 0,
    ..Default::default()
  }
}

pub struct Population  {
  pub chains: Vec<Chain>,
  pub params: Params,
  pub rng: ThreadRng,
}


fn read_popfile (path: &str) -> Vec<Vec<Clump>> {
  let f = File::open(path).expect("Failed to read file");
  let mut file = BufReader::new(&f);
  file.lines()
      .map(|x| deserialize_chain(&(x.unwrap())))
      .collect()
}

// have a separate file format and function to read 
// parameters. no reason not to keep these distinct.

// let the format for each gadget be:
// sp_delta;ret_offset;addr,pad,pad...
fn deserialize_clump(gad: &str) -> Clump {
  let fields : Vec<&str> = gad.split(';').collect();
  let words : Vec<u32> = fields[4].split(',')
                                  .map(|x| x.parse::<u32>()
                                             .unwrap())
                                  .collect();
  
  let mode : MachineMode = match fields[0] {
    "THUMB" => MachineMode::THUMB,
    "ARM"   => MachineMode::ARM,
    _       => panic!("Failed to parse MachineMode"),
  };

  let exchange : bool = match fields[1] {
    "X" => true,
    _   => false,
  };
  //let a = fields[2].parse::<u32>().unwrap();
  Clump {
    mode       : mode,
    exchange   : exchange,
    sp_delta   : fields[0].parse::<i32>().unwrap(),
    ret_offset : fields[1].parse::<i32>().unwrap(),
    words      : words,
    ..Default::default()
  } 
  
}

fn deserialize_chain (row: &str) -> Vec<Clump> {
  row.split(' ').map(deserialize_clump).collect()
}

pub fn saturate_clumps <'a,I> (unsat: &Vec<Clump>,
                               pool:  &mut I,//Vec<u32>,
                               desired: usize) 
                              -> Vec<Clump> 
    where I: Iterator <Item=u32> {
  let mut u : usize = 0;
  let mut d : usize = 0;
  let mut sat: Vec<Clump> = Vec::new();
  while d < desired {
    let mut w = unsat[u].words.clone();
    let taken = (unsat[u].sp_delta-1) as usize;
    // slow way. optimize later:
    for i in 0..taken {
      match pool.next() {
        Some(x) => w.push(x),
        _       => return sat,
      }
    }
    //w.extend((poo).take(taken).clone()); //pool[p..taken]);
    sat.push(Clump {
      sp_delta   : unsat[u].sp_delta,
      ret_offset : unsat[u].ret_offset,
      exchange   : unsat[u].exchange,
      mode       : unsat[u].mode,
      words      : w,
      ..Default::default()
    });
    d += 1;
    u = d % unsat.len();
  }
  sat
}


// replace mode str with mode enum at some point
pub fn reap_gadgets (code: &Vec<u8>, 
                     start_addr: u32, 
                     mode: MachineMode) 
                    -> Vec<Clump> {
  match mode {
    MachineMode::THUMB => reap_thumb_gadgets(code, start_addr),
    MachineMode::ARM   => panic!("unimplemented"),
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

