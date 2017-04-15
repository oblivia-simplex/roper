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
use roper::util::*;
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
pub enum GameState {
    Okay (usize),
    Input (Vec<i32>),
    Output (Vec<i32>),
    Param (Vec<i32>),
    Score (i32), // we'll use fixed point numbers to keep it simple
}

const okay: u8 = 0x00;
const input: u8 = 0x10;
const score: u8 = 0x20;
// outgoing packet headers
const output: u8 = 0x30;
const param: u8 = 0x40; 

fn encode_packet (gamestate: &GameState) -> Vec<u8> {
  let mut pkt : Vec<u8> = Vec::new();
  let (hdr,bdy) = match gamestate {
    &GameState::Param(ref xs)  => ((param  | xs.len() as u8), xs),
    &GameState::Output(ref xs) => ((output | xs.len() as u8), xs),
    _ => panic!("Unimplemented packet encoding for GameState"),
  };
  pkt.push(hdr);
  pkt.extend_from_slice(&pack_wordi32le_vec(&bdy));
  print!("<-- pkt: ");
  for byte in pkt.iter() {
    print!("{:02x} ", byte);
  }
  println!("");
  pkt 
}

pub fn send_controls (gamestate: &GameState,
                      addr: &str) -> GameState {
  let pkt = encode_packet(&gamestate);
  let mut stream = TcpStream::connect(&addr)
                            .expect("Failed to open TCP stream.");
  let _ = stream.write(&pkt);
  recv_packet(&mut stream) 
}

pub fn init_game<'a> (game_params: &'a Vec<i32>,
                      addr: &'a str) -> Vec<i32> {
  let gs = GameState::Param(game_params.clone());
  let rs = send_controls(&gs, &addr);
  match rs {
    GameState::Input(x) => x,
    _ => panic!("Is that all there is?"),
  }
}

pub fn play_game <'a> (out: &Vec<i32>,
                  addr: &'a str) -> (Option<i32>, Vec<i32>) {
  
  let gs = GameState::Output(out.clone());
  let rs = send_controls(&gs, &addr);
  match rs {
    GameState::Input(x) => (None, x),
    GameState::Score(x) => (Some(x), Vec::new()),
    _ => panic!("Unexpected GameState."),
  }
}

pub fn recv_packet (stream: &mut TcpStream) -> GameState {
  let mut hdr = [0];
  stream.read(&mut hdr)
        .expect("Failed to read header from TCP stream.");
  let typ = hdr[0] & 0xF0;
  let len = if typ == input {
    (hdr[0] & 0x0F) as usize
  } else {
    1
  };
  let mut body = vec![0; len * 4];
  stream.read(&mut body)
        .expect(&format!("Failed to read packet body of length {} from TCP stream.", len));
  print!("--> pkt: {:02x} ", &hdr[0]);
  for byte in body.iter() {
    print!("{:02x} ", byte);
  }
  println!("");
  match typ {
    input => {
      let wordsize = 4;
      let mut i = 0;
      let mut words : Vec<i32> = Vec::new();
      while i < (len * wordsize) {
        words.push(get_word32le(&body, i) as i32);
        i += wordsize;
      }
      GameState::Input(words)
    },
    score => {
      GameState::Score(get_word32le(&body, 0) as i32)
    },
    _ => panic!(format!("Unrecognized packet header: {:02x}", hdr[0])),
  }
}


