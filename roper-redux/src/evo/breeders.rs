use std::thread::{spawn, JoinHandle};
use std::sync::mpsc::{channel, Receiver, Sender};

use gen::*;

#[derive(Debug, Clone, Copy)]
pub enum SelectionMethod {
    Tournament,
    Roulette,
}

/*
fn pareto_ordering (creatures: &mut Vec<Creature>) -> () {
}
*/
pub fn spawn_breeder(
    _selection_method: SelectionMethod,
) -> (Sender<Creature>, Receiver<Creature>, JoinHandle<()>) {
    let (_from_breed_tx, from_breed_rx) = channel();
    let (into_breed_tx, _into_breed_rx) = channel();

    let breed_handle = spawn(move || { /*TODO STUB */ });

    (into_breed_tx, from_breed_rx, breed_handle)
}
