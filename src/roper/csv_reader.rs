use std::collections::HashMap;
use std::io::{self,BufReader};
use std::io::prelude::*;
use std::fs::File;
use roper::util::{Indexable};
use roper::params::*;


pub fn process_data (path: &str, numfields: usize) -> HashMap<Vec<i32>,usize> {
  let file = File::open(path).unwrap();
  let mut rdr = BufReader::new(file);
  let mut ids : Vec<String> = Vec::new();
  let mut ht : HashMap<Vec<i32>,usize> = HashMap::new();
  for line in rdr.lines() {
    let line = match line {
      Ok(l)  => l,
      Err(_) => break,
    };
    if line == "" { break };
    let sp   = line.split(",");
    let v    = sp.last()
                 .expect("Failed to get last element")
                 .to_string();
    let sp   = line.split(",");
    // ugly, stupid hack. shouldn't have to rebuild iterator.
    let key : Vec<i32> = 
      sp.take(numfields)
        .map(|s| (s.parse::<f32>()
                   .expect("Error parsing CSV.") 
                   * 100.0) as i32)
        .collect::<Vec<i32>>();
    if !ids.contains(&v) {
      ids.push(v.clone()); 
    }
    let val = ids.index_of(v);
    ht.insert(key.clone(),val);
    println!("Inserted {:?} -> {:?}", key, val);
  }
  ht
}

pub fn process_data2 (path: &str, 
                      numfields: usize) 
                      -> IoTargets {
  let file = File::open(path).unwrap();
  let mut rdr = BufReader::new(file);
  let mut ids : Vec<String> = Vec::new();
  let mut io_targets : IoTargets = IoTargets::new();
  for line in rdr.lines() {
    let line = match line {
      Ok(l)  => l,
      Err(_) => break,
    };
    if line == "" { break };
    let sp   = line.split(",");
    let v    = sp.last()
                 .expect("Failed to get last element")
                 .to_string();
    let sp   = line.split(",");
    // ugly, stupid hack. shouldn't have to rebuild iterator.
    let key : Vec<i32> = 
      sp.take(numfields)
        .map(|s| (s.parse::<f32>()
                   .expect("Error parsing CSV.") 
                   * 100.0) as i32)
        .collect::<Vec<i32>>();
    if !ids.contains(&v) {
      ids.push(v.clone()); 
    }
    let val = ids.index_of(v);
    io_targets.push((key.clone(), Target::Vote(val)));
    println!("Inserted {:?} -> {:?}", key, val);
  }
  io_targets
}
