// Implement something like stackvec to make a copiable vec
// like structure to contain your shit.
extern crate unicorn; 
extern crate bit_vec;
use std::cell::*;
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
use roper::population::*;

use std::net::{TcpListener, TcpStream};


fn handle_stream_and_eval (stream: TcpStream,
                           chain:  &Chain,
                           params: &Params) -> Option<EvalResult> {
  

  None
}

pub fn listen_and_eval (chain: &Chain,
                        params: &Params) -> Vec<EvalResult> {

  let listener = TcpListener::bind(&(params.host_port.as_str()))
                            .expect(&format!("Could not bind to {}", 
                                             &params.host_port));
  let mut results : Vec<EvalResult> = Vec::new();
  for stream in listener.incoming() {
    let res = match stream {
      Ok(stream) => handle_stream_and_eval(stream, chain, params),
      Err(e) => None,
    };
    if res != None {
      results.push(res.unwrap());
    };
  }
  results
}
