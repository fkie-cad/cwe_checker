use crate::analysis::graph::{Edge, Graph, Node};
use crate::intermediate_representation::*;
use itertools::Itertools;
use petgraph::graph::NodeIndex;
use petgraph::Direction::Incoming;
use std::collections::{BTreeSet, HashMap, HashSet};

/// The `propagate_control_flow` normalization pass tries to simplify the representation of
/// sequences of if-else blocks that all have the same condition
/// so that they are either all executed or none of the blocks are executed.
/// Such sequences are often generated by sequences of conditional assignment assembly instructions.
///
/// To simplify the generated control flow graph
/// (and thus propagate the knowledge that either all or none of these blocks are executed to the control flow graph)
/// we look for sequences of (conditional) jumps where the final jump target is determined by the source of the first jump
/// (because we know that the conditionals for all jumps evaluate to the same value along the sequence).
/// For such a sequence we then retarget the destination of the first jump to the final jump destination of the sequence.
/// Lastly, the newly bypassed blocks are considered dead code and are removed.
pub fn propagate_control_flow(project: &mut Project) {
    let extern_subs: HashSet<Tid> = project
        .program
        .term
        .extern_symbols
        .keys()
        .cloned()
        .collect();
    let cfg = crate::analysis::graph::get_program_cfg(&project.program, extern_subs.clone());
    let nodes_without_incomming_edges_at_beginning = get_nodes_without_incomming_edge(&cfg);

    let mut jmps_to_retarget = HashMap::new();
    for node in cfg.node_indices() {
        if let Node::BlkStart(block, sub) = cfg[node] {
            // Check whether we already know the result of a conditional at the end of the block
            let known_conditional_result = get_known_conditional_at_end_of_block(&cfg, node);
            // Check whether we can propagate the control flow for outgoing jumps
            match &block.term.jmps[..] {
                [Term {
                    term: Jmp::Branch(target),
                    tid: jump_tid,
                }] => {
                    if let Some(true_condition) = &known_conditional_result {
                        if let Some(new_target) =
                            find_target_for_retargetable_jump(target, &sub.term, true_condition)
                        {
                            jmps_to_retarget.insert(jump_tid.clone(), new_target);
                        }
                    }
                }
                [Term {
                    term:
                        Jmp::CBranch {
                            condition,
                            target: if_target,
                        },
                    tid: jump_tid_if,
                }, Term {
                    term: Jmp::Branch(else_target),
                    tid: jump_tid_else,
                }] => {
                    if let Some(new_target) =
                        find_target_for_retargetable_jump(if_target, &sub.term, condition)
                    {
                        jmps_to_retarget.insert(jump_tid_if.clone(), new_target);
                    }
                    if let Some(new_target) = find_target_for_retargetable_jump(
                        else_target,
                        &sub.term,
                        &negate_condition(condition.clone()),
                    ) {
                        jmps_to_retarget.insert(jump_tid_else.clone(), new_target);
                    }
                }
                _ => (),
            }
        }
    }
    retarget_jumps(project, jmps_to_retarget);

    let cfg = crate::analysis::graph::get_program_cfg(&project.program, extern_subs);
    let nodes_without_incomming_edges_at_end = get_nodes_without_incomming_edge(&cfg);

    remove_new_orphaned_blocks(
        project,
        nodes_without_incomming_edges_at_beginning,
        nodes_without_incomming_edges_at_end,
    );
}

/// Insert the new target TIDs into jump instructions for which a new target was computed.
fn retarget_jumps(project: &mut Project, mut jmps_to_retarget: HashMap<Tid, Tid>) {
    for sub in project.program.term.subs.values_mut() {
        for blk in sub.term.blocks.iter_mut() {
            for jmp in blk.term.jmps.iter_mut() {
                if let Some(new_target) = jmps_to_retarget.remove(&jmp.tid) {
                    println!("block: {}: {} ---> {}", blk.tid, jmp.term, new_target);
                    match &mut jmp.term {
                        Jmp::Branch(target) | Jmp::CBranch { target, .. } => *target = new_target,
                        _ => panic!("Unexpected type of jump encountered."),
                    }
                }
            }
        }
    }
}

/// Under the assumption that the given `true_condition` expression evaluates to `true`,
/// check whether we can retarget jumps to the given target to another final jump target.
/// I.e. we follow sequences of jumps that are not interrupted by [`Def`] instructions to their final jump target
/// using the `true_condition` to resolve the targets of conditional jumps if possible.
fn find_target_for_retargetable_jump(
    target: &Tid,
    sub: &Sub,
    true_condition: &Expression,
) -> Option<Tid> {
    let mut visited_tids = BTreeSet::from([target.clone()]);
    let mut new_target = target;
    while let Some(block) = sub.blocks.iter().find(|blk| blk.tid == *new_target) {
        if let Some(retarget) = check_for_retargetable_block(block, true_condition) {
            if !visited_tids.insert(retarget.clone()) {
                // The target was already visited, so we abort the search to avoid infinite loops.
                break;
            }
            new_target = retarget;
        } else {
            break;
        }
    }
    if new_target != target {
        Some(new_target.clone())
    } else {
        None
    }
}

/// Check whether the given block does not contain any [`Def`] instructions.
/// If yes, check whether the target of the jump at the end of the block is predictable
/// under the assumption that the given `true_condition` expression evaluates to true.
/// If it can be predicted, return the target of the jump.
fn check_for_retargetable_block<'a>(
    block: &'a Term<Blk>,
    true_condition: &Expression,
) -> Option<&'a Tid> {
    if !block.term.defs.is_empty() {
        return None;
    }
    match &block.term.jmps[..] {
        [Term {
            term: Jmp::Branch(target),
            ..
        }] => Some(target),
        [Term {
            term:
                Jmp::CBranch {
                    target: if_target,
                    condition,
                },
            ..
        }, Term {
            term: Jmp::Branch(else_target),
            ..
        }] => {
            if condition == true_condition {
                Some(if_target)
            } else if *condition == negate_condition(true_condition.clone()) {
                Some(else_target)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Check whether the given node in the control flow graph has exactly on incoming edge
/// and if that edge stems from a conditional jump.
/// If both are true, return the condition expression that needs to evaluate to true whenever this edge is taken.
fn check_if_single_conditional_incoming(graph: &Graph, node: NodeIndex) -> Option<Expression> {
    let incoming_edges: Vec<_> = graph
        .edges_directed(node, petgraph::Direction::Incoming)
        .collect();
    if incoming_edges.len() == 1 {
        match incoming_edges[0].weight() {
            Edge::Jump(
                Term {
                    term: Jmp::CBranch { condition, .. },
                    ..
                },
                None,
            ) => Some(condition.clone()),
            Edge::Jump(
                Term {
                    term: Jmp::Branch(_),
                    ..
                },
                Some(Term {
                    term: Jmp::CBranch { condition, .. },
                    ..
                }),
            ) => Some(negate_condition(condition.clone())),
            _ => None,
        }
    } else {
        None
    }
}

/// Check if the block at the given `BlkStart` node only has one input edge stemming from a conditional jump.
/// If yes, check whether the conditional expression for that jump will still evaluate to true at the end of the block.
/// If yes, return the conditional expression.
fn get_known_conditional_at_end_of_block(cfg: &Graph, node: NodeIndex) -> Option<Expression> {
    if let Node::BlkStart(block, sub) = cfg[node] {
        // Check whether we know the result of a conditional at the start of the block
        let mut known_conditional_result: Option<Expression> =
            if block.tid != sub.term.blocks[0].tid {
                check_if_single_conditional_incoming(cfg, node)
            } else {
                // Function start blocks always have incoming caller edges
                // even if these edges are missing in the CFG because we do not know the callers.
                None
            };
        // If we have a known conditional result at the start of the block,
        // check whether it will still hold true at the end of the block.
        if let Some(conditional) = &known_conditional_result {
            let input_vars = conditional.input_vars();
            for def in block.term.defs.iter() {
                match &def.term {
                    Def::Assign { var, .. } | Def::Load { var, .. } => {
                        if input_vars.contains(&var) {
                            known_conditional_result = None;
                            break;
                        }
                    }
                    Def::Store { .. } => (),
                }
            }
        }
        known_conditional_result
    } else {
        None
    }
}

/// Negate the given boolean condition expression, removing double negations in the process.
fn negate_condition(expr: Expression) -> Expression {
    if let Expression::UnOp {
        op: UnOpType::BoolNegate,
        arg,
    } = expr
    {
        *arg
    } else {
        Expression::UnOp {
            op: UnOpType::BoolNegate,
            arg: Box::new(expr),
        }
    }
}

/// Iterates the CFG and returns all node's blocks, that do not have an incoming edge.
fn get_nodes_without_incomming_edge(cfg: &Graph) -> HashSet<Tid> {
    let mut nodes_without_incomming_edges = HashSet::new();
    for node in cfg.node_indices() {
        if cfg.neighbors_directed(node, Incoming).next().is_none() {
            println!("{}", cfg[node].get_block().tid.clone());
            nodes_without_incomming_edges.insert(cfg[node].get_block().tid.clone());
        }
    }
    nodes_without_incomming_edges
}

/// Calculates the difference of the orphaned blocks and removes them from the project.
fn remove_new_orphaned_blocks(
    project: &mut Project,
    orphaned_blocks_before: HashSet<Tid>,
    orphaned_blocks_after: HashSet<Tid>,
) {
    let new_orphan_blocks = orphaned_blocks_after
        .difference(&orphaned_blocks_before)
        .collect_vec();
    for sub in project.program.term.subs.values_mut() {
        sub.term
            .blocks
            .retain(|blk| !new_orphan_blocks.contains(&&blk.tid));
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{def, expr};
    use std::collections::BTreeMap;

    fn mock_condition_block(name: &str, if_target: &str, else_target: &str) -> Term<Blk> {
        let if_jmp = Jmp::CBranch {
            target: Tid::new(if_target),
            condition: expr!("ZF:1"),
        };
        let if_jmp = Term {
            tid: Tid::new(name.to_string() + "_jmp_if"),
            term: if_jmp,
        };
        let else_jmp = Jmp::Branch(Tid::new(else_target));
        let else_jmp = Term {
            tid: Tid::new(name.to_string() + "_jmp_else"),
            term: else_jmp,
        };
        let blk = Blk {
            defs: Vec::new(),
            jmps: Vec::from([if_jmp, else_jmp]),
            indirect_jmp_targets: Vec::new(),
        };
        Term {
            tid: Tid::new(name),
            term: blk,
        }
    }

    fn mock_block_with_defs(name: &str, return_target: &str) -> Term<Blk> {
        let def = def![format!("{name}_def: r0:4 = r1:4")];
        let jmp = Jmp::Branch(Tid::new(return_target));
        let jmp = Term {
            tid: Tid::new(name.to_string() + "_jmp"),
            term: jmp,
        };
        let blk = Blk {
            defs: vec![def],
            jmps: vec![jmp],
            indirect_jmp_targets: Vec::new(),
        };
        Term {
            tid: Tid::new(name),
            term: blk,
        }
    }

    #[test]
    fn test_propagate_control_flow() {
        let sub = Sub {
            name: "sub".to_string(),
            calling_convention: None,
            blocks: vec![
                mock_condition_block("cond_blk_1", "def_blk_1", "cond_blk_2"),
                mock_block_with_defs("def_blk_1", "cond_blk_2"),
                mock_condition_block("cond_blk_2", "def_blk_2", "cond_blk_3"),
                mock_block_with_defs("def_blk_2", "cond_blk_3"),
                mock_condition_block("cond_blk_3", "def_blk_3", "end_blk"),
                mock_block_with_defs("def_blk_3", "end_blk"),
                mock_block_with_defs("end_blk", "end_blk"),
            ],
        };
        let sub = Term {
            tid: Tid::new("sub"),
            term: sub,
        };
        let mut project = Project::mock_arm32();
        project.program.term.subs = BTreeMap::from([(Tid::new("sub"), sub)]);

        propagate_control_flow(&mut project);
        let expected_blocks = vec![
            mock_condition_block("cond_blk_1", "def_blk_1", "end_blk"),
            mock_block_with_defs("def_blk_1", "def_blk_2"),
            // cond_blk_2 removed, since no incomming edge anymore
            mock_block_with_defs("def_blk_2", "def_blk_3"),
            // cond_blk_3 removed, since no incomming edge anymore
            mock_block_with_defs("def_blk_3", "end_blk"),
            mock_block_with_defs("end_blk", "end_blk"),
        ];
        assert_eq!(
            &project.program.term.subs[&Tid::new("sub")].term.blocks[..],
            &expected_blocks[..]
        );
    }
}
