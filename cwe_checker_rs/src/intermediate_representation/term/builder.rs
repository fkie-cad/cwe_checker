use crate::intermediate_representation::{Expression, Variable};

use super::{Def, Jmp, Term, Tid};

/// ## Helper functions for building defs
impl Def {
    // Shortcut for creating a assign def
    pub fn assign(tid: &str, var: Variable, value: Expression) -> Term<Def> {
        Term {
            tid: Tid::new(tid),
            term: Def::Assign { var, value },
        }
    }

    // Shortcut for creating a load def
    pub fn load(tid: &str, var: Variable, address: Expression) -> Term<Def> {
        Term {
            tid: Tid::new(tid),
            term: Def::Load { var, address },
        }
    }

    // Shortcut for creating a store def
    pub fn store(tid: &str, address: Expression, value: Expression) -> Term<Def> {
        Term {
            tid: Tid::new(tid),
            term: Def::Store { address, value },
        }
    }
}

/// ## Helper functions for building jmps
impl Jmp {
    // Shortcut for creating a call
    pub fn call(tid: &str, target_tid: &str, return_tid: Option<&str>) -> Term<Jmp> {
        if let Some(return_) = return_tid {
            return Term {
                tid: Tid::new(tid),
                term: Jmp::Call {
                    target: Tid::new(target_tid),
                    return_: Some(Tid::new(return_)),
                },
            };
        }
        Term {
            tid: Tid::new(tid),
            term: Jmp::Call {
                target: Tid::new(target_tid),
                return_: None,
            },
        }
    }

    // Shortcut for creating a branch
    pub fn branch(tid: &str, target_tid: &str) -> Term<Jmp> {
        Term {
            tid: Tid::new(tid),
            term: Jmp::Branch(Tid::new(target_tid)),
        }
    }
}
