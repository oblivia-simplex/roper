
use std::cell::*;
#[derive(Eq,PartialEq,Debug,Clone)]
pub struct Clump {
  pub sp_delta:    i32, // how much does the sp change by?
  pub ret_offset:  i32, // how far down is the next address?
  pub exchange:    bool, // BX instruction? can we change mode?
  pub mode:        MachineMode,
  pub words:       Vec<u32>,
  pub viscosity:   i32,
  pub link_age:    i32,
  pub link_fit:    i32,
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
impl Indexable<u32> for Clump {
  fn index (&self, t: u32) -> usize {
    self.index_opt(t).unwrap()
  }
  fn index_opt (&self, t: u32) -> Option<usize> {
    self.words.iter().position(|x| x == &t)
  }
  fn fetch (&self, i: usize) -> u32 {
    self.words[i]
  }
}
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct Chain {
  pub clumps: Vec<Clump>, //[Clump; MAX_CHAIN_LENGTH], 
  pub packed: Vec<u8>, //[u8; MAX_CHAIN_LENGTH * 4], //Vec<u8>,
  pub fitness: Option<i32>,
  pub generation: u32,
//  pub ancestral_fitness: Vec<i32>,
  // space-consuming, but it'll give us some useful data on
  // the destructiveness of the crossover operator
}
impl Default for Chain {
  fn default () -> Chain {
    Chain {
      fitness: None,
      generation: 0,
    //  ancestral_fitness: Vec::new(),
    }
  } 
}
impl Indexable<Clump> for Chain {
  fn index (&self, t: Clump) -> usize {
    self.index_opt(t).unwrap()
  }
  fn index_opt (&self, t: Clump) -> Option<usize> {
    self.clumps.iter().position(|x| x == &t)
  }
  fn fetch (&self, i: usize) -> Clump {
    self.clumps[i]
  }
}

impl Chain {
  /* NB: a Chain::new(c) takes ownership of its clump vec */
  fn new (clumps: Vec<Clump>) -> Chain {
    let conc = concatenate(&clumps);
    let pack = pack_word32le_vec(&conc);
    Chain {
      clumps: clumps,
      packed: pack,
      ..Default::default()
    }
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
