use crate::analysis::graph::Graph;
use crate::intermediate_representation::*;
use std::collections::BTreeSet;

/// Given the variables that are alive after execution of the given `Def` term,
/// modify the set of variables to the ones that are alive before the execution of the `Def` term.
pub fn update_alive_vars_by_def(alive_variables: &mut BTreeSet<Variable>, def: &Term<Def>) {
    match &def.term {
        Def::Assign { var, value } => {
            if alive_variables.contains(var) {
                alive_variables.remove(var);
                for input_var in value.input_vars() {
                    alive_variables.insert(input_var.clone());
                }
            } // The else-case is a dead store whose inputs do not change the set of alive variables.
        }
        Def::Load { var, address } => {
            alive_variables.remove(var);
            for input_var in address.input_vars() {
                alive_variables.insert(input_var.clone());
            }
        }
        Def::Store { address, value } => {
            for input_var in address.input_vars() {
                alive_variables.insert(input_var.clone());
            }
            for input_var in value.input_vars() {
                alive_variables.insert(input_var.clone());
            }
        }
    }
}

/// The context struct for the alive variables fixpoint computation.
///
/// The computation is a intraprocedural backwards fixpoint calculation
/// that stores at each node the set of all registers that are assumed to be alive.
/// A register is alive if its content is (assumed to be) read before it is overwritten by another value assignment.
pub struct Context<'a> {
    /// The reversed control flow graph of the program.
    graph: &'a Graph<'a>,
    /// The set of all physical base registers (i.e. no sub registers).
    /// This is the set of registers that are assumed to be alive at call/return instructions
    /// and all other places in the control flow graph,
    /// where the next instruction to be executed may not be known.
    pub all_physical_registers: &'a BTreeSet<Variable>,
}

impl<'a> Context<'a> {
    /// Create a new context object for the given project and reversed control flow graph.
    pub fn new(project: &'a Project, graph: &'a Graph) -> Context<'a> {
        Context {
            graph,
            all_physical_registers: &project.register_set,
        }
    }
}

impl<'a> crate::analysis::backward_interprocedural_fixpoint::Context<'a> for Context<'a> {
    /// The value at each node is the set of variables that are known to be alive.
    type Value = BTreeSet<Variable>;

    /// Get the reversed control flow graph on which the fixpoint computation operates.
    fn get_graph(&self) -> &Graph<'a> {
        self.graph
    }

    /// Merge by taking the union of the two sets of alive registers.
    fn merge(&self, var_set_1: &Self::Value, var_set_2: &Self::Value) -> Self::Value {
        var_set_1.union(var_set_2).cloned().collect()
    }

    /// Update the set of alive registers according to the effect of the given `Def` term.
    fn update_def(&self, alive_variables: &Self::Value, def: &Term<Def>) -> Option<Self::Value> {
        let mut alive_variables = alive_variables.clone();
        update_alive_vars_by_def(&mut alive_variables, def);
        Some(alive_variables)
    }

    /// Update the set of alive registers according to the effect of the given jump term.
    /// Adds input variables of jump conditions or jump target computations to the set of alive variables.
    fn update_jumpsite(
        &self,
        alive_vars_after_jump: &Self::Value,
        jump: &Term<Jmp>,
        untaken_conditional: Option<&Term<Jmp>>,
        _jumpsite: &Term<Blk>,
    ) -> Option<Self::Value> {
        let mut alive_variables = alive_vars_after_jump.clone();
        match &jump.term {
            Jmp::CBranch {
                condition: expression,
                ..
            }
            | Jmp::BranchInd(expression) => {
                for input_var in expression.input_vars() {
                    alive_variables.insert(input_var.clone());
                }
            }
            _ => (),
        }
        if let Some(Term {
            tid: _,
            term: Jmp::CBranch { condition, .. },
        }) = untaken_conditional
        {
            for input_var in condition.input_vars() {
                alive_variables.insert(input_var.clone());
            }
        }
        Some(alive_variables)
    }

    /// At a call instruction we assume all physical registers to be alive.
    /// Also adds inputs for the call target computation to the set of alive registers.
    fn update_callsite(
        &self,
        _target_value: Option<&Self::Value>,
        _return_value: Option<&Self::Value>,
        _caller_sub: &Term<Sub>,
        call: &Term<Jmp>,
        _return_: &Term<Jmp>,
    ) -> Option<Self::Value> {
        let mut alive_variables = self.all_physical_registers.clone();
        if let Jmp::CallInd { target, .. } = &call.term {
            for input_var in target.input_vars() {
                alive_variables.insert(input_var.clone());
            }
        }
        Some(alive_variables)
    }

    /// Interprocedural edge that is ignored by the fixpoint computation.
    fn split_call_stub(&self, _combined_value: &Self::Value) -> Option<Self::Value> {
        None
    }

    /// At a return instruction we assume all physical registers to be alive.
    fn split_return_stub(
        &self,
        _combined_value: &Self::Value,
        _returned_from_sub: &Term<Sub>,
    ) -> Option<Self::Value> {
        Some(self.all_physical_registers.clone())
    }

    /// At a call instruction we assume all physical registers to be alive.
    /// Also adds inputs for the call target computation to the set of alive registers.
    fn update_call_stub(
        &self,
        _value_after_call: &Self::Value,
        call: &Term<Jmp>,
    ) -> Option<Self::Value> {
        let mut alive_variables = self.all_physical_registers.clone();
        if let Jmp::CallInd { target, .. } = &call.term {
            for input_var in target.input_vars() {
                alive_variables.insert(input_var.clone());
            }
        }
        Some(alive_variables)
    }

    /// This function just clones its input as it is not used by the fixpoint computation.
    fn specialize_conditional(
        &self,
        alive_vars_after_jump: &Self::Value,
        _condition: &Expression,
        _is_true: bool,
    ) -> Option<Self::Value> {
        Some(alive_vars_after_jump.clone())
    }
}
