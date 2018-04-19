#[allow(dead_code)]
extern crate elf;
extern crate ansi_term;
extern crate unicorn;
extern crate capstone;
extern crate rand;
extern crate getopts;
extern crate scoped_threadpool;

extern crate ctrlc;
extern crate backtrace;
extern crate chrono;

use self::chrono::prelude::*;
use self::ansi_term::Colour::*;

use scoped_threadpool::Pool;
use std::sync::mpsc::channel;
use getopts::*;
use std::env;

use std::collections::HashMap;
use std::fs::{File,OpenOptions};
use std::io::prelude::*;
use std::io;
use std::process;
use std::process::{Command,exit};
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
use roper::evolve::*;
use roper::hatchery::*;
use roper::phylostructs::*;
use roper::ontostructs::*;
use roper::csv_reader::*;

fn print_usage (program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
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
    Data(String),
    Pattern(String),
    Game(String),
    Kafka,
    Undecided,
}

/* Just a debugging stub */
fn main() {
    let verbose = false;
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let script_dir = "/home/vagrant/ROPER/scripts/";
        
    
/*
    ctrlc::set_handler(move || {
        println!("Goodbye!\n");
        std::process::exit(1);
    }).expect("Error setting ctrlc handler");
    
*/
    let mut opts = Options::new();
    opts.parsing_style(ParsingStyle::FloatingFrees);

    opts.optflag("B", "use_buckets", "use register buckets for classification task, instead of bitmasks");
    opts.optflag("E", "use_edis", "use explicitly defined introns (set rate with -e)");
    opts.optflag("K", "kafka", "use an arbitrary and inscrutable fitness function");
    opts.optflag("O", "random_override", "override random seeds sent to game with fresh seed from ROPER's rng");
    opts.optflag("S", "fitness_sharing", "enable fitness sharing to encourage niching, where applicable");
    opts.optflag("V", "noviscosity", "do not use viscosity modulations to encourage gene linkage");
    opts.optflag("h", "help", "print this help menu");
    opts.optflag("H", "homo", "enable homologous crossover");
    opts.optflag("y", "dynamic_crash_penalty", "dynamically adjust the crash penalty in response to the population's crash rate");

    opts.optopt("0", "crash_penalty", "penalty to additively apply to crashing chains", "<float>");
    opts.optopt("A", "apples", "number of apples, used for snek", "<integer>");
    opts.optopt("C", "cacti", "number of cacti, used for snek", "<integer>");
    opts.optopt("D", "demes", "set number of subpopulations", "<positive integer>");
    opts.optopt("I", "stack_input_sampling", "set proportion of stack slots used to carry input data", "<float>");
    opts.optopt("L", "label", "set a label for the trial", "<string>");
    opts.optopt("M", "class_masks", "comma-separated list of hex integers to use as classification bitmasks", "<string>");
    opts.optopt("N", "num_attrs", "number of attributes in dataset", "<integer>");
    opts.optopt("X", "comment", "a comment to write into the logs and repeat on the screen", "<string>");
    opts.optopt("Z", "num_classes", "number of classes in dataset", "<integer>");
    opts.optopt("P", "population", "set population size", "<positive integer>");
    opts.optopt("T", "tsize", "set tournament size", "<positive integer>");
    opts.optopt("a", "address", "address and port of a game server to interact with", "<address:port>");
    opts.optopt("b", "binary", "select binary file to search for gadgets", "<path to binary file>");
    opts.optopt("c", "crossover", "set crossover (vs. clone+mutate) rate", "<float between 0.0 and 1.0>");
    opts.optopt("d", "data", "set data path", "<path to data file>");
    opts.optopt("e", "edirate", "set initial explicitly defined introns rate", "<float between 0.0 and 1.0>");
    opts.optopt("+", "edi_toggle_rate", "set likelihood of an edi toggle in mutation", "<float between 0.0 and 1.0>");
    opts.optopt("g", "goal", "set fitness goal (default 0)", "<float between 0.0 and 1.0>");
    opts.optopt("l", "init_length", "set initial length for snek", "<integer>");
    opts.optopt("m", "migration", "set migration rate", "<float between 0.0 and 1.0>");
    opts.optopt("n", "game_seeds", "number of unique random seeds to use for game", "<integer>");
    opts.optopt("o", "logs", "set log directory", "<directory>");
    opts.optopt("p", "pattern", "set target pattern", "<register pattern>");
    opts.optopt("r", "radius", "game board radius, used for snek", "<integer of 3 or greater>");
    opts.optopt("s", "sample_ratio", "set ratio of samples to evaluate on per training cycle", "<float > 0.0 and <= 1.0>");
    opts.optopt("t", "threads", "set number of threads", "<positive integer>");
    opts.optopt("v", "ttl", "set initial clump TTL", "<positive integer>");
    opts.optopt("w", "visitation_diversity_weight", "set weight for visitation diversity wrt population", "<float between 0.0 and 1.0>");

    let matches = match opts.parse(&args[1..]) {
        Ok(m)  => { m },
        Err(f) => { panic!(f.to_string()) },
    };

    println!("[+] Command line parameters read: {:?}", &matches.free);

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }
    
    let use_buckets = matches.opt_present("B");

    let visitation_diversity_weight = match matches.opt_str("w") {
        None => 0.2,
        Some(n) => n.parse::<f32>().expect("failed to parse visit visitation_diversity_weight")
    };
    
    let homologous_crossover = matches.opt_present("H");

    let class_masks : Vec<(u32,usize)> = match matches.opt_str("M") {
        None => Vec::new(),
        Some(s) => s.split(",")
                    .map(|x| u32::from_str_radix(x, 16)
                                 .expect("Failed to parse class_mask"))
                    .enumerate()
                    .map(|(a,b)| (b,a))
                    .collect(),
    };

    let ttl = match matches.opt_str("v") {
        None => 65536,
        Some(n) => n.parse::<usize>().expect("Failed to parse ttl"),
    };

    let stack_input_sampling = match matches.opt_str("I") {
        None => 0.0,
        Some(n) => n.parse::<f32>().expect("Failed to parse stack_input_sampling"),
    };
    
    let comment = match matches.opt_str("X") {
        None => "".to_string(),
        Some(s) => s.to_string(),
    };

    let num_attrs = match matches.opt_str("N") {
        None => 4,
        Some(n) => n.parse::<usize>().expect("Failed to parse num_attrs"),
    };

    let num_classes = match matches.opt_str("Z") {
        None => 3,
        Some(n) => n.parse::<usize>().expect("Failed to parse num_classes"),
    };
    
    let mut challenge : Challenge = Challenge::Undecided;

    if matches.opt_present("K") {
        challenge = Challenge::Kafka;
    }

    let use_viscosity = ! matches.opt_present("V");
    
    let use_edis = matches.opt_present("E");

    let edirate = match matches.opt_str("e") {
        None => 0.10,
        Some(n) => n.parse::<f32>().expect("Failed to parse edirate (-e)"),
    };

    let edi_toggle_rate = match matches.opt_str("+") {
        None => 0.01,
        Some(n) => n.parse::<f32>().expect("Failed to parse edi_toggle_rate (-+)"),
    };

    let crash_penalty = match matches.opt_str("0") {
        None => 0.2,
        Some(n) => n.parse::<f32>().expect("Failed to parse crash_penalty"),
    };

    let use_dynamic_crash_penalty = matches.opt_present("y");

    let random_override = matches.opt_present("O");
      
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
            challenge = Challenge::Game(s.to_string());
            s.to_string()
        },
    };
    
    let crossover_rate = match matches.opt_str("c") {
        None => 0.5,
        Some(n) => n.parse::<f32>().expect("Failed to parse crossover rate"),
    };
    let sample_ratio = match matches.opt_str("s") {
        None => 1.0,
        Some(n) => n.parse::<f32>().expect("Failed to parse sample ratio"),
    };
    let popsize = match matches.opt_str("P") {
        None => 2000,
        Some(n) => n.parse::<usize>().expect("Failed to parse population size"),
    };
    let migration = match matches.opt_str("m") {
        None => 0.1,
        Some(n) => n.parse::<f32>().expect("Failed to parse migration rate"),
    };
    let num_demes = match matches.opt_str("D") {
        None => 4,
        Some(n) => n.parse::<usize>().expect("Failed to parse number of demes"),
    };
    let label = match matches.opt_str("L") {
        None => "roper".to_string(),
        Some(n) => n.to_string(),
    };
    if let Some(rp) = matches.opt_str("p") {
        challenge = Challenge::Pattern(rp.to_string())
    };

    let fitness_sharing = matches.opt_present("S");

    match matches.opt_str("d") {
        None => (),
        Some(d) => challenge = Challenge::Data(d.clone()),
    };


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
    params.use_buckets  = use_buckets;
    // params.data = vec![rodata_data.clone()];
    // params.data_addrs   = vec![rodata_addr as u32];
    params.comment      = comment.clone();
    params.t_size       = t_size;
    params.fitness_sharing = fitness_sharing;
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
    params.host_port = host_port; 
    params.homologous_crossover = homologous_crossover;
    params.season_divisor = 1;
    params.random_override = random_override;
    params.set_init_difficulties();
    params.use_edis = use_edis;
    params.edi_toggle_rate = edi_toggle_rate;
    params.initial_edi_rate = edirate;
    params.crash_penalty = crash_penalty;
    params.use_dynamic_crash_penalty = use_dynamic_crash_penalty;
    params.stack_input_sampling = stack_input_sampling;
    params.ttl = ttl;
    params.visitation_diversity_weight = visitation_diversity_weight;
    if !use_edis {
        params.initial_edi_rate = 0.0;
        params.edi_toggle_rate  = 0.0;
    };
    let io_targets = match &challenge {
        &Challenge::Data(ref dp) => {
            let io = process_data2(&dp, num_attrs, num_classes, &mut params).shuffle();
            params.outregs = (0..(num_classes)).collect(); //vec![5,6,7];
            params.inregs  = (num_classes..(num_classes+num_attrs)).collect(); //vec![1,2,3,4];
            println!(">> inregs: {:?}\n>> outregs: {:?}", 
                              &params.inregs, &params.outregs);
            assert!(io.len() > 0);
            io
        },
        &Challenge::Pattern(ref pat) => {
            // outregs are actually ignored now, when dealing with RPattern tasks
            params.outregs = vec![0,1,2,3,4,5,6,7,8,9,10,11,12,13,14];
            IoTargets::from_vec(TargetKind::PatternMatch,
                vec![Problem::new(vec![0;16], mk_pattern(&pat))],
                1)
        },
        &Challenge::Game(ref hostport) => {
            /* This should be read from a per-game config file */
            params.inregs = vec![3,4,5,6,7,8,9,10];
            params.outregs= vec![0,1,2];
            let mut gs = Vec::new();
            let mut num_classes = 0;
            for i in 0..game_seeds {
                gs.push(Problem::new(vec![0,0,0],
                        Target::Game(GameData {
                            addr: hostport.clone(),
                            params: vec![i, radius, radius * 8 +1, 0, apples, cacti, init_length]
                        })));
                num_classes += 1;
            }
            IoTargets::from_vec(TargetKind::Game, gs, num_classes)
        },
        &Challenge::Kafka => {
            params.inregs = (0..16).collect();
            params.outregs = (0..16).collect();
            IoTargets::from_vec(TargetKind::Kafka,
                                vec![Problem::new_kafkaesque()],
                                1)
        },
        &Challenge::Undecided => panic!("Challenge type undecided. Specify one."),
    };

    let (testing,training) = (io_targets.clone(), io_targets.clone()); //io_targets.split_at(io_targets.len()/3);
    println!(">> testing.len() = {}; training.len() = {}", testing.len(), training.len());

    params.io_targets   = training;
    params.test_targets = testing;
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
  
    params.binary_path = elf_path.clone();
    
    let (secs,segs) = get_elf_addr_data(&elf_path);
    println!("****************** ELF {} **********************", elf_path);
    let exec_secs : Vec<&Sec> = secs.iter()
                                    .filter(|&s| sec_is_exec(s, &segs))
                                    .collect();

    let text_sec : &Sec = secs.iter()
                              .find(|s| &(s.name) == ".text" )
                              .expect("Couldn't find .text section...");
    /* do this the smart way now */
   
    /* that's better. later try extracting gadgets from other exec-mapped
     * sections as well, and see what happens. */
    let text_addr = text_sec.addr;
    let text_data = &text_sec.data;
    //let rodata_addr = elf_addr_data[1].addr;
    //let rodata_data = &elf_addr_data[1].data;
    
    let mode = MachineMode::ARM;

    /* FIXME make sure that all of the params are actually passed and set here.
     * I don't think they currently are. 
     */
    let constants = suggest_constants(&io_targets);
    
    params.constants    = constants.iter().map(|&x| x as u32).collect();
    params.code = text_data.clone();
    params.code_addr = text_addr as u32;
    

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

    let mut debug_machinery : Machinery 
        = Machinery::new(&elf_path,
                         mode,
                         1,
                         true);
    add_debug_hooks(&mut debug_machinery.cluster[0].unwrap_mut());
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
    
    let peek_path = format!("/tmp/roper/{}.peek", label);
    let peek_path = Path::new(&peek_path);
    println!("io_targets: {:?}", &params.io_targets);

    /***************************
      * The Main Evolution Loop *
      ***************************/
    let heatmap = HashMap::new();
    let heatmap = RwLock::new(heatmap);
    let heatmap : Arc<RwLock<HashMap<u32,usize>>> = Arc::new(heatmap);
    let mut all_heatmaps : Vec<HashMap<u32,usize>> = Vec::new();
    while i < max_iterations
        && (champion == None 
        || champion.as_ref()
                   .expect("Failed to unwrap champion reference (1)")
                   .crashes.len() > 0
        || champion.as_ref()
                   .expect("Failed to unwrap champion reference (2)")
                   .ab_fitness > Some(params.fit_goal))
    {
        let mut iteration = pop_local.read()
                                     .expect("Failed to open lock on pop_local")
                                     .iteration;
        let (tx, rx)  = channel();
        let n_workers = threads as u32;
        let n_jobs    = machinery.cluster.len();
        let mut pool  = Pool::new(n_workers);
        let challenge = challenge.clone();
        pool.scoped(|scope| {
            let mut vdeme = thread_rng().gen::<usize>() % num_demes;
            for e in machinery.cluster.iter_mut() {
                let tx = tx.clone();
                let p = pop_arc.clone();
                let hm = heatmap.clone();
                let verbose = false; //vdeme == 0 && season > 1 && iteration % show_every == show_every % threads;
                scope.execute(move || {
                    let t = tournament(&p.read()
                                         .expect("Failed to open read lock on population for tournament"),
                                        e,
                                        Batch::TRAINING,
                                        vdeme,
                                        verbose,
                                        &hm.read()
                                           .expect("Failed to open read lock on heatmap for tournament"));
                    tx.send(t).expect("Failed to sent tournament result down channel");
                });
                vdeme = (vdeme + 1) % num_demes;
            }
            let hm = heatmap.clone();
            let mut trs : Vec<TournamentResult> = rx.iter()
                                                    .take(n_jobs)
                                                    .collect();
            trs.sort_by(|a,b| b.best.ab_fitness
                               .partial_cmp(&a.best.ab_fitness)
                               .unwrap_or(Ordering::Equal));
            let season_change;
            let class_stddev_difficulties;
            /* Update a bunch of relatively global parameters & population */
            { // block to enclose write lock
                let mut mut_pop = &mut pop_local.write()
                                                .expect(
                                    "Failed to open write lock on population");
                iteration = mut_pop.iteration.clone();
                for tr in trs {
                    patch_io_targets(&tr, &mut mut_pop.params, iteration);
                    let (updated, f_deltas) = patch_population(&tr,
                                                               mut_pop,
                                                               true,
                                                               &mut hm.write().expect("failed to open write lock on heatmap for updating in patch_population"));
                    if updated != None {
                        champion = updated.clone();
                    };
                    //let mean_fit_deltas = mean(&fit_deltas);
                    if updated != None || (peek_path.exists() && champion != None) {
                        let champion = champion.clone();
                        /* dump the champion's visited_map */
                        let path = format!("{}/{}_champion_{}_{}_visited.txt",
                                           params.log_dir,
                                           label, 
                                           &params.timestamp,
                                           iteration);
                        champion.as_ref()
                                .expect("failed to unwrap champ to dump")
                                .dump_visited_map(&path, 
                                                  &debug_machinery.cluster[0].unwrap(),
                                                  &params);

                        println!("[*] Verbosely evaluating new champion:\n{}",
                                champion.as_ref()
                                .expect("Failed to unwrap champion"));
                        evaluate_fitness(&mut (debug_machinery.cluster[0]
                                                              .unwrap_mut()),
                                         &champion.expect(
                                             "Failed to unwrap champion"),
                                         &params,
                                         Batch::TESTING,
                                         true,
                                         &hm.read()
                                            .expect("failed to open read
                                                    lock on heatmap for 
                                                    debug run")
                                            );
                    }
                    /* TODO: try commenting out the next line to hold crash penalty constant */
                    if mut_pop.params.use_dynamic_crash_penalty {
                      mut_pop.params.crash_penalty = compute_crash_penalty(crash_rate);
                    };
                }
                season_change = update_difficulties(&mut mut_pop.params, 
                                                    iteration);
                mut_pop.season += season_change;
                season = mut_pop.season.clone();
                if season_change > 0 && season % 4 == 0 {
                    println!("--- SEASONAL POPULATION DATA DUMP ---");
                    let dir = &mut_pop.dump_all(&debug_machinery.cluster[0]
                                                                .unwrap());  
                    let hm_path = format!("{}/{}_S{}_heatmap.sexp", 
                                          dir,
                                          &params.label,
                                          season);
                    println!("--- DUMPING HEATMAP ---");
                    /* cumulative heatmap dump */
                    dump_heatmap(&hm.read().unwrap(), &params.binary_path, &hm_path);
                    let out = Command::new(&format!("{}/visitplot.lisp", script_dir))
                                      .args(&["-H", &hm_path])
                                      .output()
                                      .expect("Failed to run visitplot.lisp on heatmap");
                    println!("> {:?}",out);
                    //all_heatmaps.push(heatmap.clone());
                    //heatmap = HashMap::new();

                };
                class_stddev_difficulties = mut_pop.params
                                                   .io_targets
                                                   .class_stddev_difficulties();
                /* Update variation operators according to 1:5 rule:
                  * if fewer than 1 in 5 offspring is as fit as the parent(s),
                  * then the algorithm should be more exploitative; if more
                  * than 1 in 5 is fitter, the algorithm should be more exploratory.
                  */

            } // end mut block
          
            if champion != None && (season_change > 0 || iteration % printevery == 0) {
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
                print!  ("[+] CRASH RATE:  {:6.6}    ", crash_rate);
                println!("[+] AVG GEN:     {:6.6}", avg_pop_gen);
                print!  ("[+] AVG FIT:     {:6.6}    ", avg_pop_fit);
                println!("[+] AVG AB_FIT:  {:6.6}", avg_pop_abfit);
                print!  ("[+] MIN FIT:     {:6.6}    ", min_fit);
                println!("[+] MIN AB_FIT:  {:6.6}", min_abfit);
                print!  ("[+] BEST FIT:    {:6.6}    ", champ.fitness
                                                                                                  .unwrap());
                println!("[+] BEST AB_FIT: {:6.6}  ", champ.ab_fitness
                                                                                                  .unwrap());
                print!  ("[+] AVG LEN:       {:3.5}  ", pop_read.avg_len());     

                println!  ("[+] STRAY RATE:    {:6.6}  ",pop_read.avg_stray_addr_rate());
                print!("[+] XOVER DELTA:   {:6.6}  ", pop_read.avg_crossover_delta());
                println!("[+] MUT. DELTA:    {:6.6}  ", pop_read.avg_mutation_delta());
                print!("[+] RATIO RUN:     {:6.6}  ",pop_read.avg_ratio_run());
                println!("[+] VISIT DIVERS:  {:6.6}  ",pop_read.avg_visitation_diversity());

                println!("[+] EDI RATE:      {:6.6}  ",pop_read.avg_edi_rate());
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
                    println!("    {} -> {:6.6}", c, d);
                    c += 1;
                }
                
                println!("[+] STDDEV DIFFICULTIES BY CLASS:");
                let mut c = 0;
                for d in class_stddev_difficulties {
                    println!("    {} -> {:6.6}", c, d);
                    c += 1;
                }
                
                println!("[+] STANDARD DEVIATION OF AB_FIT: {}", stddev_abfit);
            } else {
                print!("\r[{}]                 ",iteration);
                io::stdout().flush().ok().expect("Could not flush stdout");
            }
            println!("TASK: {:?}\n{} ({}) on {} at {}\nREM: {}",
                     &challenge,
                     Red.bold().paint(label.clone()), 
                     &params.population_size,
                     &params.binary_path,
                     Local::now().format("%H:%M:%S"), 
                     comment);
            //println!("------------------------------------------------");
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
    {
        let r = evaluate_fitness(&mut(debug_machinery.cluster[0]
                                                     .unwrap_mut()),
                                 &mut champion.as_mut()
                                              .unwrap(),
                                 &pop_local.read()
                                           .unwrap().params,
                                 Batch::TRAINING, // FIXME Testing empty
                                 true,
                                 &HashMap::new());
    //champion.unwrap().dump("stdout", 
    //                       &params.binary_path, 
    //                       debug_machinery.cluster[0].unwrap(),
    //                       &params);

        println!("-=-=-=-=- CHAMPION -=-=-=-=-\n{}\n",
                 &champion.as_ref()
                          .unwrap()
                          .dump_visited_map_to_string(&debug_machinery.cluster[0]
                                                                      .unwrap(),
                                                      &params));
        r
    };
             

    println!("\n{}", pop_local.read().unwrap().best.clone().unwrap());
    println!("[*] Absolute fitness of champion on testing run: {:6.6}",
                      testing_res.ab_fitness);
    println!("[*] Crash on testing run: {:?}", testing_res.crashes);
    println!("[*] Logged at {}", pop_local.read().unwrap().params.csv_path);
}
