use std::io::{BufReader};
use std::io::prelude::*;
use std::fs::File;
use roper::util::{Indexable};
use roper::phylostructs::*;



pub fn process_data2 (path: &str, 
                      num_attrs: usize,
                      num_classes: usize) 
                      -> IoTargets {
        let file = File::open(path).unwrap();
        let rdr = BufReader::new(file);
        let class_masks = class_masks_randomized(num_classes);
        let mut ids : Vec<String> = Vec::new();
        let mut io_targets : IoTargets = IoTargets::new(TargetKind::Classification);
        for line in rdr.lines() {
            let line = match line {
                Ok(l)  => l,
                Err(_) => break,
            };
            if line.chars().nth(0).unwrap() == '%' { continue };
            if line == "" { break };
            let sp   = line.split(",");
            let v    = sp.last()
                         .expect("Failed to get last element")
                         .to_string();
            let sp   = line.split(",");
            // ugly, stupid hack. shouldn't have to rebuild iterator.
            let key : Vec<i32> = 
                sp.take(num_attrs)
                    .map(|s| (s.parse::<f32>()
                               .expect("Error parsing CSV.") 
                               * 100.0) as i32)
                    .collect::<Vec<i32>>();
            if !ids.contains(&v) {
                ids.push(v.clone()); 
            }
            let val = ids.index_of(v);
            io_targets.push(Problem::new(key.clone(), mk_class(val, num_classes, &class_masks)))
                                                            

//    io_targets.push((Problem::new(key.clone()), 
//                     Target::Vote(Classification::new(val))));
            //println!("Inserted {:?} -> {:?}", key, val);
        }
        io_targets.num_classes = ids.len();
        assert!(io_targets.num_classes == num_classes);
        io_targets
}

// add function to shuffle and split io_targets

