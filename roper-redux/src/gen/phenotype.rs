extern crate rand;
extern crate evmap;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::sync::{Arc,Mutex,RwLock,MutexGuard};
use std::hash::{Hash,Hasher};
use self::rand::{Rng,SeedableRng};
use self::rand::isaac::Isaac64Rng;

use genotype::*;
use emu::loader::{Mode,MemImage};
use par::statics::*;
use log;

#[derive(Clone,Debug,PartialEq)]
pub struct Pod {
    pub registers: Vec<u64>,
    //pub memory: MemImage,
    pub visited: Vec<(u64,Mode)>,
    pub writelog: Vec<(u64,u64)>,
}

impl Pod {
    pub fn new(registers: Vec<u64>, 
              // memory:    MemImage,
               visited:   Vec<(u64,Mode)>,
               writelog:  Vec<(u64,u64)>) -> Self {
        Pod {
            registers: registers,
            //memory: memory,
            visited: visited,
            writelog: writelog,
        }
    }
    /// Dump a vector of strings containing the disassembly
    /// of each address visited by the phenotype.
    pub fn disas_visited (&self) -> Vec<String> {
        let mut v = Vec::new();
        for &(addr, mode) in &self.visited {
            v.push(log::disas_static(addr, mode));
        }
        v
    }
}

unsafe impl Send for Pod {}

/* Retain the Pod after hatching. Initialized genomes in an otherwise
 * empty Pod. Or with an Option<Pod>. We only ever need to hatch a
 * genome /once/ -- even with fitness sharing, we can just re-evaluate
 * the hatched phenome with different parameters. But that part of the
 * evaluation is a one-shot deal. ROPER I made the mistake of tightly
 * coupling the hatching procedure with the "eval_case" procedure. This
 * doesn't need to be done that way. 
 */

pub type Input = Vec<u64>; /* a static reference would be better FIXME */
pub type Phenome = HashMap<Input,Option<Pod>>;

#[derive(Debug,Clone)]
pub struct Creature {
    pub genome: Chain,
    pub phenome: Phenome,
    pub index: usize,
    pub metadata: Metadata,
    pub name: String,
}
impl PartialEq for Creature {
    fn eq(&self, other: &Creature) -> bool {
        self.name == other.name
    }
}

impl Eq for Creature {}

fn baptise_chain (chain: &Chain) -> String {
    let syllables = 8;
    let p = chain.pack(&Vec::new());
    let mut hasher = DefaultHasher::new();
    p.hash(&mut hasher);
    let hash: u64 = hasher.finish();
    /* now, convert that hash to a pronounceable name */
    let consonants = vec!['b','c','d','f','g',
                          'h','j','k','l','m',
                          'n','v','w','x','z','y'];
    let vowels = vec!['a','e','i','o','u'];
    let hbytes = pack_word64le(hash);
    let mut letters = Vec::new();
    assert!(syllables <= hbytes.len());
    for i in 0..syllables {
        letters.push(consonants[(hbytes[i] as usize) % consonants.len()]);
        letters.push(vowels[(hbytes[i] as usize) % vowels.len()]);
        letters.push(consonants[(hbytes[i] as usize) % consonants.len()]);
        if i % 2 == 1 && i < syllables-1 { letters.push('-') };
    }
    letters.iter().collect::<String>()
}

impl Creature {
    pub fn new(genome: Chain, index: usize) -> Self {
        let name = baptise_chain(&genome);
        Creature {
            genome: genome,
            phenome: Phenome::new(),
            index: index,
            metadata: Metadata::new(),
            name: name,
        }
    }

    pub fn ab_fit(&self) -> Option<f32> {
        match self.metadata.get("ab_fit") {
            None => None,
            Some(&x) => Some(x),
        }
    }

    pub fn set_ab_fit(&mut self, ab_fit: f32) -> () {
        self.metadata.insert("ab_fit", ab_fit);
    }

    pub fn pose_problem(&mut self, input: &Input) -> () {
        self.phenome.insert(input.clone(), None);
    }

    pub fn disas_visited(&self) -> Vec<String> {
        let mut dump = Vec::new();
        for (input,pod) in &self.phenome {
            if pod == &None { continue };
            dump.push(format!("ON INPUT {:?}\n\t{}",
                              input,
                              pod.as_ref()
                                 .unwrap()
                                 .disas_visited()
                                 .join("\n\t")));
        }
        dump
    }
}

unsafe impl Send for Creature {}

type Larva = Mutex<Creature>;

fn larvalise (creature: Creature) -> Larva {
    Mutex::new(creature) 
}

/* ok, evmap won't work. */
#[derive(Debug,Clone)]
pub struct Population {
    pub hive: Arc<Vec<Mutex<Arc<RefCell<Creature>>>>>,
}

impl Population {
    /// What we want to do here is to create an indexable
    /// collection of creatures that can be individually
    /// and mutably accessed by arbitrary threads. 
    pub fn new(creatures: Vec<Creature>) -> Self {
        let mut mutexed_creatures = Vec::new();
        let mut creatures = creatures;
        while creatures.len() > 0 {
            mutexed_creatures.push(Mutex::new(
                                     Arc::new(
                                       RefCell::new(
                                         creatures.pop()
                                                  .unwrap()))))
        }
            
        Population {
            hive: Arc::new(mutexed_creatures),
        }
    }


    /// Selects num individuals at random, using the RngSeed, and
    /// ensures that the chosen are all internally mutable, wrt their
    /// RwLocks.
    pub fn choose(&self, seed: RngSeed, num: usize) -> Vec<Arc<RefCell<Creature>>> {
        let mut rng = Isaac64Rng::from_seed(&seed);
        //sample(&mut rng, self.hive, num)       
        // choose unlocked
        let mut chosen = Vec::new();
        /* Careful here. Could this cause hold-and-wait deadlocks?
         * Maybe have a mutex on the hive to guard against that.
         */
        while chosen.len() < num {
            let i = rng.gen::<usize>() % self.hive.len();
            match self.hive[i].try_lock() {
                Err(_) => continue,
                Ok(x)  => chosen.push(x.clone()),
            }
            /* if you observe a lot of busy waiting here, try adding a very
             * short sleep() (especially in small populations)  */
        }
        chosen
    }
}
