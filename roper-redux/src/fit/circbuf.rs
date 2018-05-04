use std::collections::VecDeque;
use gen::Creature;

pub struct CircBuf {
    pub buf: VecDeque<Creature>,
    pub capacity: usize,
}

impl CircBuf {
    pub fn new(capacity: usize) -> Self {
        CircBuf {
            buf: VecDeque::with_capacity(capacity),
            capacity: capacity,
        }
    }

    pub fn push(&mut self, item: Creature) {
        self.buf.push_back(item);
        if self.buf.len() > self.capacity {
            self.buf.pop_front();
        };
    }
}
