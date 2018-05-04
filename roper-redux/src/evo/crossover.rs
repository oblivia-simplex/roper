extern crate rand;
use self::rand::{Rng};
use gen::*;
use par::statics::*;

/// One-point crossover, between two u64s, as bitvectors.
fn onept_bits<R: Rng>(a: u64, b: u64, rng: &mut R) -> u64 {
    let i = rng.gen::<u64>() % 64;
    let mut mask = ((!0) >> i) << i;
    if rng.gen::<bool>() {
        mask ^= !0
    };
    (mask & a) | (!mask & b)
}

/// Uniform crossover between two u64s, as bitvectors.
fn uniform_bits<R: Rng>(a: u64, b: u64, rng: &mut R) -> u64 {
    let mask = rng.gen::<u64>();
    (mask & a) | (!mask & b)
}

/// A simple mutation operator to use on the crossover mask,
/// prior to passing it on to the offspring.
fn random_bit_flip<R: Rng>(u: u64, rng: &mut R) -> u64 {
  if rng.gen::<f32>() < *CROSSOVER_MASK_MUT_RATE {
      u ^ (1u64 << (rng.gen::<u64>() % 64)) 
  } else {
      u
  }
}

fn combine_xbits<R: Rng>(m_bits: u64,
                         p_bits: u64,
                         combiner: MaskOp,
                         mut rng: &mut R) -> u64 {
    match combiner {
        MaskOp::Xor => m_bits ^ p_bits,
        MaskOp::Nand => !(m_bits & p_bits),
        MaskOp::OnePt => onept_bits(m_bits, p_bits, &mut rng),
        MaskOp::Uniform => uniform_bits(m_bits, p_bits, &mut rng),
        MaskOp::And => m_bits & p_bits,
        MaskOp::Or => m_bits | p_bits,
    }
}
fn xbits_sites<R: Rng>(
    xbits: u64,
    bound: usize,
    crossover_degree: f32,
    mut rng: &mut R,
) -> Vec<usize> {
    let mut potential_sites = (0..bound)
        .filter(|x| (1u64.rotate_left(*x as u32) & xbits != 0) == *CROSSOVER_XBIT)
        .collect::<Vec<usize>>();
    potential_sites.sort();
    potential_sites.dedup();
    let num = (potential_sites.len() as f32 * crossover_degree).ceil() as usize;
    if cfg!(debug_assertions) {
        println!("{:064b}: potential sites: {:?}", xbits, &potential_sites);
    }

    let mut actual_sites = rand::seq::sample_iter(&mut rng,
                                                  potential_sites.into_iter(), 
                                                  num).unwrap();
    if cfg!(debug_assertions) {
        println!("actual sites: {:?}", &actual_sites);
    }
    actual_sites
}
pub fn homologous_crossover<R>(mother: &Creature,
                               father: &Creature,
                               mut rng: &mut R) -> Vec<Creature>
where R: Rng, {
    let crossover_degree = *CROSSOVER_DEGREE;
    let bound = usize::min(mother.genome.alleles.len(), 
                           father.genome.alleles.len());
    let xbits = combine_xbits(mother.genome.xbits, 
                              father.genome.xbits, 
                              *CROSSOVER_MASK_COMBINER, rng);
    let child_xbits = combine_xbits(mother.genome.xbits, 
                                    father.genome.xbits, 
                                    *CROSSOVER_MASK_INHERITANCE, rng);
    let sites = xbits_sites(xbits,
                            bound, 
                            crossover_degree, 
                            &mut rng,
    );
    let mut offspring = Vec::new();
    let parents = vec![mother, father];
    let mut i = 0;
    /* Like any respectable couple, the mother and father take
     * turns inseminating one another...
     */
    while offspring.len() < 2 {
        let p0: &Creature = parents[i % 2];
        let p1: &Creature = parents[(i + 1) % 2];
        i += 1;
        let mut egg = p0.genome.alleles.clone();
        let mut sem = &p1.genome.alleles;
        for site in sites.iter() {
            egg[*site] = sem[*site];
        }
        let zygote = Chain {
            alleles: egg,
            metadata: Metadata::new(),
            xbits: random_bit_flip(child_xbits, &mut rng),
        };
        /* The index will be filled in later, prior to filling
         * the graves of the fallen
         */
        if zygote.entry() != None {
            offspring.push(Creature::new(zygote, 0));
        };
        if cfg!(debug_assertions) {
            println!("WITH XBITS {:064b}, SITES: {:?}, MATED\n{}\nAND\n{}\nPRODUCING\n{}",
                     xbits,
                     &sites.iter().map(|x| x % bound).collect::<Vec<usize>>(),
                     p0, p1, &offspring[offspring.len()-1]);
            println!("************************************************************");
        }
    }
    offspring
}
