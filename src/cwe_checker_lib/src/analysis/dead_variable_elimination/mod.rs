//! This module contains a fixpoint computation to compute alive (resp. dead) variables
//! and a function to remove dead assignments from a project.

use crate::analysis::backward_interprocedural_fixpoint::create_computation;
use crate::analysis::graph::Node;
use crate::analysis::interprocedural_fixpoint_generic::NodeValue;
use crate::intermediate_representation::*;
use std::collections::{BTreeSet, HashMap};

mod alive_vars_computation;
use alive_vars_computation::*;

/// Compute alive variables by means of an intraprocedural fixpoint computation.
/// Returns a map that assigns to each basic block `Tid` the set of all variables
/// that are alive at the end of the basic block.
pub fn compute_alive_vars(project: &Project) -> HashMap<Tid, BTreeSet<Variable>> {
    let extern_subs = project
        .program
        .term
        .extern_symbols
        .keys()
        .cloned()
        .collect();
    let mut graph = crate::analysis::graph::get_program_cfg(&project.program, extern_subs);
    graph.reverse();
    let context = Context::new(project, &graph);
    let all_physical_registers = context.all_physical_registers.clone();
    let mut computation = create_computation(context, None);
    for node in graph.node_indices() {
        match graph[node] {
            Node::BlkStart(_, _) => (),
            Node::BlkEnd(blk, _sub) => {
                if graph
                    .neighbors_directed(node, petgraph::Incoming)
                    .next()
                    .is_none()
                {
                    // A dead end in the CFG has no incoming edges in the reversed CFG.
                    // Since dead ends are mostly due to cases where the control flow graph is incomplete,
                    // we assume that all registers are alive at the end of the block.
                    let mut alive_vars = all_physical_registers.clone();
                    for jmp in blk.term.jmps.iter() {
                        match &jmp.term {
                            Jmp::CallInd {
                                target: expression, ..
                            }
                            | Jmp::BranchInd(expression)
                            | Jmp::CBranch {
                                condition: expression,
                                ..
                            } => {
                                // The expressions may contain virtual registers
                                for input_var in expression.input_vars() {
                                    alive_vars.insert(input_var.clone());
                                }
                            }
                            _ => (),
                        }
                    }
                    computation.set_node_value(node, NodeValue::Value(alive_vars));
                } else {
                    computation.set_node_value(node, NodeValue::Value(BTreeSet::new()))
                }
            }
            Node::CallReturn { .. } => {
                computation.set_node_value(node, NodeValue::Value(BTreeSet::new()));
            }
            Node::CallSource { .. } => {
                computation.set_node_value(
                    node,
                    NodeValue::CallFlowCombinator {
                        call_stub: Some(BTreeSet::new()),
                        interprocedural_flow: Some(BTreeSet::new()),
                    },
                );
            }
        }
    }
    computation.compute_with_max_steps(100);
    if !computation.has_stabilized() {
        panic!("Fixpoint for dead register assignment removal did not stabilize.");
    }

    let mut results = HashMap::new();
    for node in graph.node_indices() {
        if let Node::BlkEnd(blk, _sub) = graph[node] {
            if let Some(NodeValue::Value(alive_vars)) = computation.get_node_value(node) {
                results.insert(blk.tid.clone(), alive_vars.clone());
            } else {
                panic!("Error during dead variable elimination computation.")
            }
        }
    }
    results
}

/// For the given `block` look up the variables alive at the end of the block via the given `alive_vars_map`
/// and then remove those register assignment `Def` terms from the block
/// that represent dead assignments.
/// An assignment is considered dead if the register is not read before its value is overwritten by another assignment.
fn remove_dead_var_assignments_of_block(
    block: &mut Term<Blk>,
    alive_vars_map: &HashMap<Tid, BTreeSet<Variable>>,
) {
    let mut alive_vars = alive_vars_map.get(&block.tid).unwrap().clone();
    let mut cleaned_defs = Vec::new();
    for def in block.term.defs.iter().rev() {
        match &def.term {
            Def::Assign { var, .. } if alive_vars.get(var).is_none() => (), // Dead Assignment
            _ => cleaned_defs.push(def.clone()),
        }
        alive_vars_computation::update_alive_vars_by_def(&mut alive_vars, def);
    }
    block.term.defs = cleaned_defs.into_iter().rev().collect();
}

/// Remove all dead assignments from all basic blocks in the given `project`.
pub fn remove_dead_var_assignments(project: &mut Project) {
    let alive_vars_map = compute_alive_vars(project);
    for sub in project.program.term.subs.values_mut() {
        for block in sub.term.blocks.iter_mut() {
            remove_dead_var_assignments_of_block(block, &alive_vars_map);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def_assign_term(term_index: u64, input: &str, output: &str) -> Term<Def> {
        Def::assign(
            &format!("def_{}", term_index),
            Variable::mock(output, 8),
            Expression::Var(Variable::mock(input, 8)),
        )
    }

    #[test]
    fn dead_assignment_removal() {
        let defs = vec![
            def_assign_term(1, "A", "B"),
            def_assign_term(2, "B", "C"),
            def_assign_term(3, "C", "RAX"), // dead assignment
            def_assign_term(4, "B", "RAX"),
            def_assign_term(5, "C", "RBX"),
            def_assign_term(6, "A", "B"), // dead assignment, since the next assignment is dead
            def_assign_term(7, "B", "C"), // dead assignment, since C is not a physical register
        ];
        let block = Term {
            tid: Tid::new("block"),
            term: Blk {
                defs: defs,
                jmps: Vec::new(),
                indirect_jmp_targets: Vec::new(),
            },
        };
        let sub = Term {
            tid: Tid::new("sub"),
            term: Sub {
                name: "sub".to_string(),
                blocks: vec![block],
                calling_convention: None,
            },
        };
        let mut project = Project::mock_empty();
        project.program.term.subs.insert(sub.tid.clone(), sub);
        remove_dead_var_assignments(&mut project);

        let cleaned_defs = vec![
            def_assign_term(1, "A", "B"),
            def_assign_term(2, "B", "C"),
            def_assign_term(4, "B", "RAX"),
            def_assign_term(5, "C", "RBX"),
        ];
        assert_eq!(
            &project.program.term.subs[&Tid::new("sub")].term.blocks[0]
                .term
                .defs,
            &cleaned_defs
        );
    }
}
