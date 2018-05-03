use genotype::*;

/* This module reads text files of gadget listings,
 * and constructs Gadget data structures, to be used
 * in the genotype. 
 *
 * ROPER I handled gadget extraction on its own, but
 * not with any particular skill -- just a standard 
 * linear scan. I figured that I might as well just
 * outsource this task to external tools, which gives
 * me a wider margin of flexibility, and a bit less
 * work. It also lets me compare the results of using
 * different gadget extraction techniques on the fly.
 */

/* File format for gadget dumps is:
 * ARCH entry ret_addr sp_delta
 * tab separated. ARCH is either 'ARM' or 'ARMTHUMB'.
 */

parse_gadget_dump(path: &str) -> Vec<Gadget> {
/* TODO: this */
}
