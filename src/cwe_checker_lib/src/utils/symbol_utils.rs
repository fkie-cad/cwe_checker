//! Helper functions for common tasks utilizing extern symbols,
//! e.g. searching for calls to a specific extern symbol.

use std::collections::HashMap;

use crate::intermediate_representation::*;

/// Find the extern symbol object for a symbol name and return the symbol tid and name.
pub fn find_symbol<'a>(prog: &'a Term<Program>, name: &str) -> Option<(&'a Tid, &'a str)> {
    let mut symbol: Option<(&'a Tid, &'a str)> = None;
    prog.term.extern_symbols.iter().find(|(_tid, sym)| {
        if name == sym.name {
            symbol = Some((&sym.tid, &sym.name));
            true
        } else {
            false
        }
    });

    symbol
}

/// Match direct calls' target tids in the program's subroutines
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
                    calls.push((sub.term.name.as_str(), &jmp.tid, symbols.get(dst).unwrap()));
                }
            }
        }
    }
    calls
}

/// Get a map from TIDs to the corresponding extern symbol struct.
/// Only symbols with names contained in `symbols_to_find` are contained in the map.
pub fn get_symbol_map<'a>(
    project: &'a Project,
    symbols_to_find: &[String],
) -> HashMap<Tid, &'a ExternSymbol> {
    let mut tid_map = HashMap::new();
    for symbol_name in symbols_to_find {
        if let Some((tid, symbol)) =
            project
                .program
                .term
                .extern_symbols
                .iter()
                .find_map(|(_tid, symbol)| {
                    if symbol.name == *symbol_name {
                        Some((symbol.tid.clone(), symbol))
                    } else {
                        None
                    }
                })
        {
            tid_map.insert(tid, symbol);
        }
    }
    tid_map
}

/// Find calls to TIDs contained as keys in the given symbol map.
/// For each match return the block containing the call,
/// the jump term representing the call itself and the symbol corresponding to the TID from the symbol map.
pub fn get_callsites<'a>(
    sub: &'a Term<Sub>,
    symbol_map: &HashMap<Tid, &'a ExternSymbol>,
) -> Vec<(&'a Term<Blk>, &'a Term<Jmp>, &'a ExternSymbol)> {
    let mut callsites = Vec::new();
    for blk in sub.term.blocks.iter() {
        for jmp in blk.term.jmps.iter() {
            if let Jmp::Call { target: dst, .. } = &jmp.term {
                if let Some(symbol) = symbol_map.get(dst) {
                    callsites.push((blk, jmp, *symbol));
                }
            }
        }
    }
    callsites
}
