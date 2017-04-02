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
use roper::util::{get_word32le,
                  pack_word32le,
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

#[derive(Debug,PartialEq)]
enum GameState {
  Hello,
  Input (Vec<i32>),
  Score (f32), // we'll use fixed point numbers to keep it simple
}

const hello : u8 = 0x00;
const input : u8 = 0x10;
const score : u8 = 0x20;
const output: u8 = 0x30;

fn decode_packet (packet: &Vec<u8>) -> GameState {
  let header = packet[0].clone();
  let off = 1;
  match header & 0xF0 {
    hello => GameState::Hello,
    input => {
      let wordsize = 4;
      let len = (header & 0xF) as usize;
      let mut i = off;
      let mut words : Vec<i32> = Vec::new();
      while i < (off + (len * 4)) {
        words.push(get_word32le(&packet, i) as i32);
        i += wordsize;
      }
      GameState::Input(words)
    },
    score => GameState::Score(1.0/get_word32le(&packet, off) as f32),
    _     => panic!("Packet header not recognized."),
  }
}

fn encode_packet (regs: &Vec<u32>) -> Vec<u8> {
  let mut pkt : Vec<u8> = Vec::new();
  pkt.push(output | (0x0F & regs.len() as u8));
  pkt.extend_from_slice(&pack_word32le_vec(&regs));
  pkt
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
