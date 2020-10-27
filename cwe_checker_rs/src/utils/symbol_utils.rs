use std::collections::HashMap;

use crate::intermediate_representation::{Jmp, Program, Sub, Term, Tid};

/// Find the extern symbol object for a symbol name and return the symbol tid and name.
pub fn find_symbol<'a>(prog: &'a Term<Program>, name: &str) -> Option<(&'a Tid, &'a str)> {
    let mut symbol: Option<(&'a Tid, &'a str)> = None;
    prog.term.extern_symbols.iter().for_each(|sym| {
        if name == sym.name {
            symbol = Some((&sym.tid, &sym.name));
        }
    });

    symbol
}

/// Match direct calls' target tids in the program's subroutines with
/// with the tids of the external symbols given to the function.
/// When a match was found, add a triple of (caller name, callsite tid, callee name)
/// to a vector. Lastly, return the vector with all callsites of all given external symbols.
pub fn get_calls_to_symbols<'a, 'b>(
    sub: &'a Term<Sub>,
    symbols: &'b HashMap<&'a Tid, &'a str>,
) -> Vec<(&'a str, &'a Tid, &'a str)> {
    let mut calls: Vec<(&'a str, &'a Tid, &'a str)> = Vec::new();
    for blk in sub.term.blocks.iter() {
        for jmp in blk.term.jmps.iter() {
            if let Jmp::Call { target: dst, .. } = &jmp.term {
                if symbols.contains_key(dst) {
                    calls.push((
                        sub.term.name.as_str(),
                        &jmp.tid,
                        symbols.get(dst).clone().unwrap(),
                    ));
                }
            }
        }
    }
    calls
}
