use super::{Def, Jmp};
use crate::prelude::*;
use crate::utils::log::LogMessage;
use std::collections::HashSet;

/// A basic block is a sequence of `Def` instructions followed by up to two `Jmp` instructions.
///
/// The `Def` instructions represent side-effectful operations that are executed in order when the block is entered.
/// `Def` instructions do not affect the control flow of a program.
///
/// The `Jmp` instructions represent control flow affecting operations.
/// There can only be zero, one or two `Jmp`s:
/// - Zero `Jmp`s indicate that the next execution to be executed could not be discerned.
/// This should only happen on disassembler errors or on dead ends in the control flow graph that were deliberately inserted by the user.
/// - If there is exactly one `Jmp`, it is required to be an unconditional jump.
/// - For two jumps, the first one has to be a conditional jump,
/// where the second unconditional jump is only taken if the condition of the first jump evaluates to false.
///
/// If one of the `Jmp` instructions is an indirect jump,
/// then the `indirect_jmp_targets` is a list of possible jump target addresses for that jump.
/// The list may not be complete and the entries are not guaranteed to be correct.
///
/// Basic blocks are *single entry, single exit*, i.e. a basic block is only entered at the beginning
/// and is only exited by the jump instructions at the end of the block.
/// If a new control flow edge is discovered that would jump to the middle of a basic block,
/// the block structure needs to be updated accordingly.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Blk {
    /// The `Def` instructions of the basic block in order of execution.
    pub defs: Vec<Term<Def>>,
    /// The `Jmp` instructions of the basic block
    pub jmps: Vec<Term<Jmp>>,
    /// If the basic block contains an indirect jump,
    /// this field contains possible jump target addresses for the jump.
    ///
    /// Note that possible targets of indirect calls are *not* contained,
    /// since the [`Project::make_block_to_sub_mapping_unique`] normalization pass assumes
    /// that only intraprocedural jump targets are contained in this field.
    pub indirect_jmp_targets: Vec<Tid>,
}

impl Term<Blk> {
    /// Return a clone of `self` where the given suffix is appended to
    /// the TIDs of all contained terms (the block itself and all `Jmp`s and `Def`s).
    ///
    /// Note that all TIDs of jump targets (direct, indirect and return targets) are left unchanged.
    fn clone_with_tid_suffix(&self, suffix: &str) -> Self {
        let mut cloned_block = self.clone();
        cloned_block.tid = cloned_block.tid.with_id_suffix(suffix);
        for def in cloned_block.term.defs.iter_mut() {
            def.tid = def.tid.clone().with_id_suffix(suffix);
        }
        for jmp in cloned_block.term.jmps.iter_mut() {
            jmp.tid = jmp.tid.clone().with_id_suffix(suffix);
        }
        cloned_block
    }

    /// Remove indirect jump target addresses for which no corresponding target block exists.
    /// Return an error message for each removed address.
    pub fn remove_nonexisting_indirect_jump_targets(
        &mut self,
        known_block_tids: &HashSet<Tid>,
    ) -> Result<(), Vec<LogMessage>> {
        let mut logs = Vec::new();
        self.term.indirect_jmp_targets = self
            .term
            .indirect_jmp_targets
            .iter()
            .filter_map(|target| {
                if known_block_tids.get(&target).is_some() {
                    Some(target.clone())
                } else {
                    let error_msg =
                        format!("Indirect jump target at {} does not exist", target.address);
                    logs.push(LogMessage::new_error(error_msg).location(self.tid.clone()));
                    None
                }
            })
            .collect();
        if logs.is_empty() {
            Ok(())
        } else {
            Err(logs)
        }
    }

    /// Wherever possible, substitute input variables of expressions
    /// with the input expression that defines the input variable.
    ///
    /// Note that substitution is only possible
    /// if the input variables of the input expression itself did not change since the definition of said variable.
    ///
    /// The expression propagation allows the [`Project::substitute_trivial_expressions`] normalization pass
    /// to further simplify the generated expressions
    /// and allows more dead stores to be removed during [dead variable elimination](`crate::analysis::dead_variable_elimination`).
    pub fn propagate_input_expressions(&mut self) {
        let mut insertable_expressions = Vec::new();
        for def in self.term.defs.iter_mut() {
            match &mut def.term {
                Def::Assign {
                    var,
                    value: expression,
                } => {
                    // insert known input expressions
                    for (input_var, input_expr) in insertable_expressions.iter() {
                        expression.substitute_input_var(input_var, input_expr);
                    }
                    // expressions dependent on the assigned variable are no longer insertable
                    insertable_expressions.retain(|(input_var, input_expr)| {
                        input_var != var && !input_expr.input_vars().into_iter().any(|x| x == var)
                    });
                    // If the value of the assigned variable does not depend on the former value of the variable,
                    // then it is insertable for future expressions.
                    if !expression.input_vars().into_iter().any(|x| x == var) {
                        insertable_expressions.push((var.clone(), expression.clone()));
                    }
                }
                Def::Load {
                    var,
                    address: expression,
                } => {
                    // insert known input expressions
                    for (input_var, input_expr) in insertable_expressions.iter() {
                        expression.substitute_input_var(input_var, input_expr);
                    }
                    // expressions dependent on the assigned variable are no longer insertable
                    insertable_expressions.retain(|(input_var, input_expr)| {
                        input_var != var && !input_expr.input_vars().into_iter().any(|x| x == var)
                    });
                }
                Def::Store { address, value } => {
                    // insert known input expressions
                    for (input_var, input_expr) in insertable_expressions.iter() {
                        address.substitute_input_var(input_var, input_expr);
                        value.substitute_input_var(input_var, input_expr);
                    }
                }
            }
        }
        for jump in self.term.jmps.iter_mut() {
            match &mut jump.term {
                Jmp::Branch(_) | Jmp::Call { .. } | Jmp::CallOther { .. } => (),
                Jmp::BranchInd(expr)
                | Jmp::CBranch {
                    condition: expr, ..
                }
                | Jmp::CallInd { target: expr, .. }
                | Jmp::Return(expr) => {
                    // insert known input expressions
                    for (input_var, input_expr) in insertable_expressions.iter() {
                        expr.substitute_input_var(input_var, input_expr);
                    }
                }
            }
        }
    }

    /// Merge subsequent assignments to the same variable to a single assignment to that variable.
    ///
    /// The value expressions of merged assignments can often be simplified later on
    /// in the [`Project::substitute_trivial_expressions`] normalization pass.
    pub fn merge_def_assignments_to_same_var(&mut self) {
        let mut new_defs = Vec::new();
        let mut last_def_opt = None;
        for def in self.term.defs.iter() {
            if let Def::Assign {
                var: current_var, ..
            } = &def.term
            {
                if let Some(Term {
                    term:
                        Def::Assign {
                            var: last_var,
                            value: last_value,
                        },
                    ..
                }) = &last_def_opt
                {
                    if current_var == last_var {
                        let mut substituted_def = def.clone();
                        substituted_def.substitute_input_var(last_var, last_value);
                        last_def_opt = Some(substituted_def);
                    } else {
                        new_defs.push(last_def_opt.unwrap());
                        last_def_opt = Some(def.clone());
                    }
                } else if last_def_opt.is_some() {
                    panic!(); // Only assign-defs should be saved in last_def.
                } else {
                    last_def_opt = Some(def.clone());
                }
            } else {
                if let Some(last_def) = last_def_opt {
                    new_defs.push(last_def);
                }
                new_defs.push(def.clone());
                last_def_opt = None;
            }
        }
        if let Some(last_def) = last_def_opt {
            new_defs.push(last_def);
        }
        self.term.defs = new_defs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intermediate_representation::{Def, Expression, Variable};

    impl Blk {
        pub fn mock() -> Term<Blk> {
            Term {
                tid: Tid::new("block"),
                term: Blk {
                    defs: Vec::new(),
                    jmps: Vec::new(),
                    indirect_jmp_targets: Vec::new(),
                },
            }
        }

        pub fn mock_with_tid(tid: &str) -> Term<Blk> {
            Term {
                tid: Tid::new(tid),
                term: Blk {
                    defs: Vec::new(),
                    jmps: Vec::new(),
                    indirect_jmp_targets: Vec::new(),
                },
            }
        }
    }

    #[test]
    fn expression_propagation() {
        use crate::intermediate_representation::UnOpType;
        let defs = vec![
            Def::assign(
                "tid_1",
                Variable::mock("X", 8),
                Expression::var("Y", 8).un_op(UnOpType::IntNegate),
            ),
            Def::assign(
                "tid_2",
                Variable::mock("Y", 8),
                Expression::var("X", 8).plus(Expression::var("Y", 8)),
            ),
            Def::assign(
                "tid_3",
                Variable::mock("X", 8),
                Expression::var("X", 8).un_op(UnOpType::IntNegate),
            ),
            Def::assign(
                "tid_4",
                Variable::mock("Y", 8),
                Expression::var("Y", 8).un_op(UnOpType::IntNegate),
            ),
            Def::assign(
                "tid_5",
                Variable::mock("Y", 8),
                Expression::var("X", 8).plus(Expression::var("Y", 8)),
            ),
        ];
        let mut block = Term {
            tid: Tid::new("block"),
            term: Blk {
                defs,
                jmps: Vec::new(),
                indirect_jmp_targets: Vec::new(),
            },
        };
        block.merge_def_assignments_to_same_var();
        block.propagate_input_expressions();
        let result_defs = vec![
            Def::assign(
                "tid_1",
                Variable::mock("X", 8),
                Expression::var("Y", 8).un_op(UnOpType::IntNegate),
            ),
            Def::assign(
                "tid_2",
                Variable::mock("Y", 8),
                Expression::var("Y", 8)
                    .un_op(UnOpType::IntNegate)
                    .plus(Expression::var("Y", 8)),
            ),
            Def::assign(
                "tid_3",
                Variable::mock("X", 8),
                Expression::var("X", 8).un_op(UnOpType::IntNegate),
            ),
            Def::assign(
                "tid_5",
                Variable::mock("Y", 8),
                Expression::var("X", 8).plus(Expression::var("Y", 8).un_op(UnOpType::IntNegate)),
            ),
        ];
        assert_eq!(block.term.defs, result_defs);
    }
}
