use std::thread::{spawn,JoinHandle};
use std::sync::mpsc::{Sender,Receiver,channel};

use gen::*;


#[derive(Debug,Clone,Copy)]
pub enum SelectionMethod {
    Tournament,
    Roulette,
}



fn pareto_ordering (creatures: &mut Vec<Creature>) -> () {
}

pub fn spawn_breeder(selection_method: SelectionMethod)
    -> (Sender<Creature>, Receiver<Creature>, JoinHandle<()>)
{
    let (from_breed_tx, from_breed_rx) = channel();
    let (into_breed_tx, into_breed_rx) = channel();

    let breed_handle = spawn(move || {
        /*TODO STUB */
    });

    (into_breed_tx, from_breed_rx, breed_handle)

}


