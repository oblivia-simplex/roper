#[allow(dead_code)]
extern crate elf;
extern crate unicorn;
extern crate capstone;
extern crate rand;
extern crate getopts;
extern crate scoped_threadpool;

extern crate ctrlc;
extern crate backtrace;

use scoped_threadpool::Pool;
use std::sync::mpsc::channel;
use getopts::*;
use std::env;

use std::fs::{File,OpenOptions};
use std::io::prelude::*;
use std::io;
use std::process;
mod roper;

use rand::{thread_rng,Rng};

use std::path::{Path,PathBuf};
use std::sync::{Arc,RwLock};
use std::cmp::Ordering;
use unicorn::*;
// use std::io;
//use roper::dis::{disas_sec,Inst};
use roper::statistics::*;
use roper::thumb::*;
use roper::util::*;
use roper::population::*;
use roper::hatchery::*;
use roper::phylostructs::*;
use roper::ontostructs::*;
use roper::csv_reader::*;

fn print_usage (program: &str, opts: Options) {
  let brief = format!("Usage: {} [options]", program);
  print!("{}", opts.usage(&brief));
}



fn get_elf_addr_data (path: &str, 
                      secs: &Vec<&str>) 
                      -> Vec<Sec> {
  let path = PathBuf::from(path);
  let file = match elf::File::open_path(&path) {
    Ok(f) => f,
    Err(e) => panic!("Error: {:?}",e),
  };
  let mut sections : Vec<Sec> = Vec::new();
  for sec_name in secs.iter() {
    let sec = file.get_section(sec_name)
                  .expect("Unable to fetch section from elf");
    sections.push(Sec {
      name: sec_name.to_string(),
      addr: sec.shdr.addr,
      data: sec.data.clone(),
      perm: PROT_ALL, // Placeholder. Need to convert from elf
    });
  }
  sections
}

/*
fn get_gba_addr_data (path: &str) -> Vec<(u64, Vec<u8>)> {
  let addr = GBA_CARTRIDGE_ROM_START;
  let data = load_file(path);
  vec![(addr,data)]
}
  */                  

//const GBA_CARTRIDGE_ROM_START : u64 = 0x08000000;

#[derive(PartialEq,Eq,Clone,Debug)]
enum Challenge {
  Data,
  Pattern,
  Game,
  Undecided,
}

/* Just a debugging stub */
fn main() {
  let verbose = false;
  let args: Vec<String> = env::args().collect();
  let program = args[0].clone();
    
  

  ctrlc::set_handler(move || {

    /*
    backtrace::trace(|frame| {
      let ip = frame.ip();
      let sym_addr = frame.symbol_address();
      /* Resolve this instruction pointer to a symbol name */
      backtrace::resolve(ip, |sym| {
        if let Some(name) = sym.name() {
          if let Some(filename) = sym.filename() {
            println!("=> {:?} in {:?}", name, filename);
          } else {
            println!("=> {:?}", name);
          }
        }
      });
      true // keep going to next frame
    });
    */  
    println!("Goodbye!\n");
    std::process::exit(1);
  }).expect("Error setting ctrlc handler");
  

  let mut opts = Options::new();
  opts.parsing_style(ParsingStyle::FloatingFrees);
  opts.optopt("b", "binary", "select binary file to search for gadgets", "<path to binary file>");
  opts.optopt("p", "pattern", "set target pattern", "<register pattern>");
  opts.optopt("d", "data", "set data path", "<path to data file>");
  opts.optopt("a", "address", "address and port of a game server to interact with", "<address:port>");
  opts.optopt("n", "game_seeds", "number of unique random seeds to use for game", "<integer>");
  opts.optopt("g", "goal", "set fitness goal (default 0)", "<float between 0.0 and 1.0>");
  opts.optopt("o", "logs", "set log directory", "<directory>");
  opts.optopt("t", "threads", "set number of threads", "<positive integer>");
  opts.optopt("T", "tsize", "set tournament size", "<positive integer>");
  opts.optopt("P", "population", "set population size", "<positive integer>");
  opts.optopt("D", "demes", "set number of subpopulations", "<positive integer>");
  opts.optopt("L", "label", "set a label for the trial", "<string>");
  opts.optopt("l", "init_length", "set initial length for snek", "<integer>");
  opts.optopt("m", "migration", "set migration rate", "<float between 0.0 and 1.0>");
  opts.optopt("s", "sample_ratio", "set ratio of samples to evaluate on per training cycle", "<float > 0.0 and <= 1.0>");
  opts.optflag("S", "fitness_sharing", "enable fitness sharing to encourage niching, where applicable");
  opts.optopt("c", "crossover", "set crossover (vs. clone+mutate) rate", "<float between 0.0 and 1.0>");
  opts.optopt("r", "radius", "game board radius, used for snek", "<integer of 3 or greater>");
  opts.optopt("A", "apples", "number of apples, used for snek", "<integer>");
  opts.optopt("C", "cacti", "number of cacti, used for snek", "<integer>");
  opts.optflag("O", "random_override", "override random seeds sent to game with fresh seed from ROPER's rng");
  opts.optflag("R", "norethook", "remove the counting hooks on the return instructions");
  opts.optflag("V", "noviscosity", "do not use viscosity modulations to encourage gene linkage");
  opts.optflag("h", "help", "print this help menu");
  let matches = match opts.parse(&args[1..]) {
    Ok(m)  => { m },
    Err(f) => { panic!(f.to_string()) },
  };
  println!("[+] Command line parameters read: {:?}", &matches.free);

  if matches.opt_present("h") {
    print_usage(&program, opts);
    return;
  }

  let mut challenge : Challenge = Challenge::Undecided;

  let use_viscosity = ! matches.opt_present("V");

  let random_override = matches.opt_present("O");
   
  let ret_hooks = ! matches.opt_present("R");

  let game_seeds = match matches.opt_str("n") {
    None => 9,
    Some(n) => n.parse::<i32>().expect("Failed to parse game_seeds parameter (-n)"),
  };

  let radius = match matches.opt_str("r") {
    None => 6,
    Some(n) => n.parse::<i32>().expect("Failed to parse radius parameter (-r)"),
  };
  
  let init_length = match matches.opt_str("l") {
    None => 3,
    Some(n) => n.parse::<i32>().expect("Failed to parse init_length parameter (-l)"),
  };

  let cacti = match matches.opt_str("C") {
    None => 1,
    Some(n) => n.parse::<i32>().expect("Failed to parse cacti parameter (-C)"),
  };
  
  let apples = match matches.opt_str("A") {
    None => 1,
    Some(n) => n.parse::<i32>().expect("Failed to parse cacti parameter (-A)"),
  };

  let host_port = match matches.opt_str("a") {
    None    => "".to_string(),
    Some(s) => {
      challenge = Challenge::Game;
      s.to_string()
    },
  };
  
  let crossover_rate = match matches.opt_str("c") {
    None => 0.5,
    Some(n) => n.parse::<f32>().unwrap(),
  };
  let sample_ratio = match matches.opt_str("s") {
    None => 1.0,
    Some(n) => n.parse::<f32>().unwrap(),
  };
  let popsize = match matches.opt_str("P") {
    None => 2000,
    Some(n) => n.parse::<usize>().unwrap(),
  };
  let migration = match matches.opt_str("m") {
    None => 0.1,
    Some(n) => n.parse::<f32>().unwrap(),
  };
  let num_demes = match matches.opt_str("D") {
    None => 4,
    Some(n) => n.parse::<usize>().unwrap(),
  };
  let label = match matches.opt_str("L") {
    None => "roper".to_string(),
    Some(n) => n.to_string(),
  };
  let rpattern_str = matches.opt_str("p");
  if rpattern_str != None {challenge = Challenge::Pattern};

  let fitness_sharing = matches.opt_present("S") && rpattern_str == None;
  let data_path    = matches.opt_str("d");
  if data_path != None {challenge = Challenge::Data};

  let threads : usize = match matches.opt_str("t") {
    None => 8,
    Some(n) => n.parse::<usize>().unwrap(),
  };
  let log_dir      = match matches.opt_str("o") {
    None    => {
      let p = Path::new("./logs/");
      if p.is_dir() { 
        p.to_str().unwrap().to_string() 
      } else { 
      "./".to_string()
      }
    },
    Some(p) => p,
  };
  let t_size = match matches.opt_str("T") {
    None => 4,
    Some(p) => p.parse::<usize>()
                .expect("Couldn't parse t_size parameter."),
  };
  let goal : f32 = match matches.opt_str("g") {
    None => 0.11,
    Some(s) => s.parse::<f32>()
                .expect("Error parsing fitness goal"),
  };
  // ugly kludge here
 
  let mut params : Params = Params::new(&label);
  let io_targets = match challenge {
    Challenge::Data => {
      let num_attrs = 4; // TODO: Figure out how not to hardcode this
      let io = process_data2(&data_path.unwrap(), num_attrs).shuffle();
      params.inregs  = (0..num_attrs).collect::<Vec<usize>>();
      params.outregs = (num_attrs..(num_attrs+io.num_classes)).collect::<Vec<usize>>();
      println!(">> inregs: {:?}\n>> outregs: {:?}", 
               &params.inregs, &params.outregs);
      assert!(io.len() > 0);
      io
    },
    Challenge::Pattern => {
      params.outregs = vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14];
      IoTargets::from_vec(TargetKind::PatternMatch,
        vec![Problem::new(vec![1;16], mk_pattern(&rpattern_str.unwrap()))],
        1)
    },
    Challenge::Game => {
      /* This should be read from a per-game config file */
      params.inregs = vec![3,4,5,6,7,8,9,10];
      params.outregs= vec![0,1,2];
      let mut gs = Vec::new();
      let mut num_classes = 0;
      for i in 0..game_seeds {
        gs.push(Problem::new(vec![0,0,0],
                             Target::Game(GameData {
                               addr: host_port.clone(),
                               params: vec![i, radius, radius * 8 +1, 0, apples, cacti, init_length]
                             })));
        num_classes += 1;
      }
      IoTargets::from_vec(TargetKind::Game, gs, num_classes)
    },
    Challenge::Undecided => panic!("Challenge type undecided. Specify one."),
  };

  let (testing,training) = io_targets.split_at(io_targets.len()/3);
  println!(">> testing.len() = {}; training.len() = {}", testing.len(), training.len());

  //let debug_samples = training.clone();
  /*
  let sample1 = "tomato-RT-AC3200-ARM-132-AIO-httpd";
  let sample2 = "tomato-RT-N18U-httpd";
  let sample3 = "openssl";
  let sample4 = "ldconfig.real";
  let sample_gba = "megaman_zero_4.gba";
  let sample_root = "/home/oblivia/Projects/roper/data/"
    .to_string();
  let elf_path = sample_root.clone() + sample4;
  let gba_path = sample_root.clone() + sample_gba;
 */ 
  
  
  let elf_path = match matches.opt_str("b") {
    None    => { print_usage(&program, opts); return; },
    Some(p) => p,
  };
 
  /* TODO: REFACTOR AWAY THIS OLD elf_addr_data CRUFT. 
   * IT DUPLICATES STUFF THAT's BEING HANDLED MORE ELEGANTLY
   * OVER IN ONTOSTRUCTS, but is still relied upon.
   */
  
  let elf_addr_data = get_elf_addr_data(&elf_path,
                                        &vec![".text",".rodata"]);
  println!("****************** ELF {} **********************",
           elf_path);
  
  let text_addr = elf_addr_data[0].addr;
  let text_data = &elf_addr_data[0].data;
  let rodata_addr = elf_addr_data[1].addr;
  let rodata_data = &elf_addr_data[1].data;
  
  let mode = MachineMode::ARM;

  let constants = suggest_constants(&io_targets);
  params.ret_hooks = ret_hooks;
  params.code = text_data.clone();
  params.code_addr = text_addr as u32;
  params.data = vec![rodata_data.clone()];
  params.data_addrs   = vec![rodata_addr as u32];
  params.constants    = constants.iter().map(|&x| x as u32).collect();
  params.t_size       = t_size;
  params.fitness_sharing = fitness_sharing;
  params.io_targets   = training;
  params.test_targets = testing;
  params.fit_goal     = goal;
  params.migration    = migration;
  params.verbose      = verbose;
  params.threads      = threads;
  params.num_demes    = num_demes;
  params.use_viscosity = use_viscosity;
  params.crossover_rate = crossover_rate;
  params.sample_ratio = sample_ratio;
  params.set_log_dir(&log_dir);
  params.population_size = popsize;
  params.binary_path = elf_path.clone();
  params.host_port = host_port; 
  params.season_divisor = 1;
  params.random_override = random_override;
  params.set_init_difficulties();

  //params.io_targets.num_classes = params.outregs.len();
  // add string search function
  // find string addresses in rodata
  // pass these addresses to the mangler in population building
  //println!("params: {:?}",params); 
  println!("PARAMETERS:\n{}", params);

  let mut machinery : Machinery
    = Machinery::new(&elf_path,
                     mode,
                     threads,
                     false);
  
  let population = Population::new(&params, &mut machinery.cluster[0]);

  for chain in population.deme.iter() {
    println!("\n{}",chain);
  }

  let mut debug_machinery : Machinery 
    = Machinery::new(&elf_path,
                     mode,
                     1,
                     true);
  add_debug_hooks(debug_machinery.cluster[0].unwrap_mut());
  let printevery = 1;
  let mut champion : Option<Chain> = None;
  let mut season = 0;
  let max_iterations = params.max_iterations;
  let pop_rw  = RwLock::new(population);
  let pop_arc = Arc::new(pop_rw); 
  let pop_local = pop_arc.clone();
  let mut first_log = true;
  let mut i = 0; 
  let mut crash_rate : f32 = 0.5;
  let mut fitness_deltas : CircBuffer<f32> = CircBuffer::new(100);
  let mut improvement_ratio = None;
  
  let peek_path = format!("/tmp/roper/{}.peek", label);
  let peek_path = Path::new(&peek_path);
  println!("io_targets: {:?}", &params.io_targets);

  /***************************
   * The Main Evolution Loop *
   ***************************/
  while i < max_iterations
    && (champion == None 
        || champion.as_ref().expect("Failed to unwrap champion reference (1)").crashes == Some(true)
        || champion.as_ref().expect("Failed to unwrap champion reference (2)").ab_fitness > Some(params.fit_goal))
  {
    let mut iteration = pop_local.read()
                                 .expect("Failed to open read lock on pop_local")
                                 .iteration;
    let (tx, rx)  = channel();
    let n_workers = threads as u32;
    let n_jobs    = machinery.cluster.len();
    let mut pool  = Pool::new(n_workers);
    pool.scoped(|scope| {
      let mut vdeme = thread_rng().gen::<usize>() % num_demes;
      for e in machinery.cluster.iter_mut() {
        let tx = tx.clone();
        let p = pop_arc.clone();
        let verbose = false; //vdeme == 0 && season > 1 && iteration % show_every == show_every % threads;
        scope.execute(move || {
          let t = tournament(&p.read().expect("Failed to open read lock on tournament"),
                             e,
                             Batch::TRAINING,
                             vdeme,
                             verbose);
          tx.send(t).expect("Failed to sent tournament result down channel");
        });
        vdeme = (vdeme + 1) % num_demes;
      }
      let mut trs : Vec<TournementResult> = rx.iter()
                                              .take(n_jobs)
                                              .collect();
      trs.sort_by(|a,b| b.best.ab_fitness
                         .partial_cmp(&a.best.ab_fitness)
                         .unwrap_or(Ordering::Equal));
      let season_change;
      let class_stddev_difficulties;
      /* Update a bunch of relatively global parameters & population */
      { // block to enclose write lock
        let mut mut_pop = &mut pop_local.write().expect("Failed to open write lock on population");
        iteration = mut_pop.iteration.clone();
        for tr in trs {
          println!("[*] about to call patch_io_targets()");
          patch_io_targets(&tr, &mut mut_pop.params, iteration);
          let (updated, f_deltas) = patch_population(&tr,
                                                     mut_pop,
                                                     true);
          fitness_deltas.push_all(f_deltas);
          if updated != None {
            champion = updated.clone();
          };
          //let mean_fit_deltas = mean(&fit_deltas);
          if updated != None || (peek_path.exists() && champion != None) {
            let champion = champion.clone();
            println!("[*] Verbosely evaluating new champion:\n{}",
                     champion.as_ref()
                             .expect("Failed to unwrap champion"));
            evaluate_fitness(debug_machinery.cluster[0]
                                             .unwrap_mut(),
                             &champion.expect("Failed to unwrap champion clone for peeking"),
                             &params,
                             Batch::TESTING,
                             true);
          }
          mut_pop.params.crash_penalty = compute_crash_penalty(crash_rate);
        }
        season_change = update_difficulties(&mut mut_pop.params, 
                                            iteration);
        mut_pop.season += season_change;
        season = mut_pop.season.clone();
        class_stddev_difficulties = mut_pop.params
                                           .io_targets
                                           .class_stddev_difficulties();
        /* Update variation operators according to 1:5 rule:
         * if fewer than 1 in 5 offspring is as fit as the parent(s),
         * then the algorithm should be more exploitative; if more
         * than 1 in 5 is fitter, the algorithm should be more exploratory.
         */
        if fitness_deltas.primed() {
          improvement_ratio = Some(fitness_deltas.as_vec()
                                                 .iter()
                                                 .filter(|x| **x < 0.0)
                                                 .count() as f32 / fitness_deltas.cap() as f32);
        }

      } // end mut block
     
      if champion != None && (season_change > 0 || iteration % printevery == 0) {
        println!("[+] in champion block of main loop");
        /**************************************************
         * Pretty-print some information for the viewers  *
         * huddled around the terminal, in hushed antici- *
         * pation.                                        *
         **************************************************/
        let pop_read = pop_local.read().expect("Failed to open read lock on pop_local");
        first_log = pop_read.log(first_log);
        println!("");
        let avg_pop_gen = pop_read.avg_gen();
        let avg_pop_fit = pop_read.avg_fit(season);
        let avg_pop_abfit = pop_read.avg_abfit();
        crash_rate = pop_read.crash_rate();
        let min_fit = pop_read.min_fit(season);
        let min_abfit = pop_read.min_abfit();
        let stddev_abfit = pop_read.stddev_abfit();
        let champ = champion.clone().expect("Failed to unwrap champion");
        let dprof = pop_read.params
                            .io_targets
                            .difficulty_profile();
        println!("[*] ITERATION {}, SEASON {}", iteration, season);
        print!  ("[+] CRASH RATE:  {:1.6}    ", crash_rate);
        println!("[+] AVG GEN:     {:1.6}", avg_pop_gen);
        print!  ("[+] AVG FIT:     {:1.6}    ", avg_pop_fit);
        println!("[+] AVG AB_FIT:  {:1.6}", avg_pop_abfit);
        print!  ("[+] MIN FIT:     {:1.6}    ", min_fit);
        println!("[+] MIN AB_FIT:  {:1.6}", min_abfit);
        print!  ("[+] BEST FIT:    {:1.6}    ", champ.fitness
                                                 .unwrap());
        println!("[+] BEST AB_FIT: {:1.6}  ", champ.ab_fitness
                                                 .unwrap());
        print!  ("[+] AVG LEN:     {:3.5}    ", pop_read.avg_len());     
        println!("[+] IMPROVEMENT: {:1.6}  ", improvement_ratio.unwrap_or(0.0));
        //println!("[+] SEASONS ELAPSED: {}", season);
        println!("[+] STANDARD DEVIATION OF DIFFICULTY: {}",  
                 standard_deviation(&dprof));
        println!("[+] MEAN DIFFICULTIES BY CLASS:");
        
        let mut c = 0;
        for d in pop_local.read()
                          .expect("Failed to open read lock on pop_local")
                          .params
                          .io_targets
                          .class_mean_difficulties() {
          println!("    {} -> {:1.6}", c, d);
          c += 1;
        }
        
        println!("[+] STDDEV DIFFICULTIES BY CLASS:");
        let mut c = 0;
        for d in class_stddev_difficulties {
          println!("    {} -> {:1.6}", c, d);
          c += 1;
        }
        
        println!("[+] STANDARD DEVIATION OF AB_FIT: {}", stddev_abfit);
      } else {
        print!("\r[{}]                 ",iteration);
        io::stdout().flush().ok().expect("Could not flush stdout");
      }
      pop_local.read().expect("Failed to open read lock on pop_local for periodic_save").periodic_save();
      println!("------------------------------------------------");
    }); // END POOL SCOPE
    i += 1;
  } // END OF MAIN LOOP
  println!("=> {} ITERATIONS",
           pop_local.read()
                    .expect("Failed to open read lock on pop_local")
                    .iteration);
  println!("=> BEST (ABSOLUTE) FIT: {:?}", pop_local.read()
                                                    .unwrap().best_abfit());
  println!("=> RUNNING BEST:\n");
  if champion == None {
    panic!("Champion is none!");
  }
  let testing_res =
    evaluate_fitness(debug_machinery.cluster[0].unwrap_mut(),
                   &mut champion.unwrap(),
                   &pop_local.read().unwrap().params,
                   Batch::TRAINING, // there's a bug right now causing the testing set to be empty. fix it. 
                   true);
  println!("\n{}", pop_local.read().unwrap().best.clone().unwrap());
  println!("[*] Absolute fitness of champion on testing run: {:1.6}",
           testing_res.ab_fitness);
  println!("[*] Crash on testing run: {}", testing_res.crashes);
  println!("[*] Logged at {}", pop_local.read().unwrap().params.csv_path);
}
