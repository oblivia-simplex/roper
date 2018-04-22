use genotype::*;
use emu::loader::MemImage;

#[derive(Clone,Debug,PartialEq)]
pub struct Pod {
    pub chain: Chain, /* consider boxing or cowing */
    pub memory: MemImage,
    pub registers: Vec<u64>,
    pub visited: Vec<u64>,
}

impl Pod {
    pub fn new(chain: Chain) -> Self {
        Pod {
            chain: chain,
            memory: Vec::new(),
            registers: Vec::new(),
            visited: Vec::new(),
        }
    }
}

unsafe impl Send for Pod {}

