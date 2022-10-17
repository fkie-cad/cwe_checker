//! This module contains a fixpoint computation for intra-functional expression propagation of variables
//! and contains a functions for inserting such expressions.

use super::fixpoint::Computation;
use super::forward_interprocedural_fixpoint::GeneralizedContext;
use crate::analysis::forward_interprocedural_fixpoint::create_computation;
use crate::analysis::graph::Graph;
use crate::analysis::graph::Node;
use crate::analysis::interprocedural_fixpoint_generic::NodeValue;
use crate::intermediate_representation::*;
use std::collections::HashMap;

/// The context struct for the expression propagation fixpoint computation.
///
/// The computation is a intra procedural forward fixpoint calculation
/// that stores at each node the set of registers with their propagated expressions.
/// This expressions can be used for expression specification among basic blocks.
pub struct Context<'a> {
    graph: &'a Graph<'a>,

    /// Variable-expression lookup table primitive.
    pub insertable_expressions: HashMap<Variable, Expression>,
}

impl<'a> Context<'a> {
    /// Create a new context object for the given project and control flow graph.
    pub fn new(_project: &'a Project, graph: &'a Graph) -> Context<'a> {
        Context {
            graph,
            insertable_expressions: HashMap::new(),
        }
    }
}

impl<'a> crate::analysis::forward_interprocedural_fixpoint::Context<'a> for Context<'a> {
    type Value = HashMap<Variable, Expression>;
    fn get_graph(&self) -> &Graph<'a> {
        self.graph
    }
    /// Merges two values by intersecting their variable-expression pairs.
    fn merge(&self, value1: &Self::Value, value2: &Self::Value) -> Self::Value {
        value1
            .iter()
            .filter(|x| value2.iter().any(|y| y == *x))
            .map(|(var, expr)| (var.clone(), expr.clone()))
            .collect()
    }

    /// Adds the expression for the assigned variable to the table.
    ///
    /// Invalid pairs are removed and new expressions are supplemented if possible.
    fn update_def(&self, value: &Self::Value, def: &Term<Def>) -> Option<Self::Value> {
        let mut insertable_expressions = value.clone();

        match &def.term {
            Def::Assign {
                var,
                value: expression,
            } => {
                // Extend the considered expression with already known expressions.
                let mut extended_expression = expression.clone();
                for input_var in expression.input_vars().into_iter() {
                    if let Some(expr) = insertable_expressions.get(input_var) {
                        extended_expression.substitute_input_var(input_var, expr)
                    }
                }
                insertable_expressions.insert(var.clone(), extended_expression.clone());

                // Expressions dependent on the assigned variable are no longer insertable.
                // Except, if the assigned variable depends on itself.
                insertable_expressions.retain(|input_var, input_expr| {
                    !(input_var != var && input_expr.input_vars().into_iter().any(|x| x == var))
                });

                Some(insertable_expressions)
            }
            Def::Load {
                var,
                address: _expression,
            } => {
                // Expressions dependent on the assigned variable are no longer insertable
                insertable_expressions.retain(|input_var, input_expr| {
                    input_var != var && !input_expr.input_vars().into_iter().any(|x| x == var)
                });
                Some(insertable_expressions)
            }
            Def::Store { .. } => Some(insertable_expressions),
        }
    }

    fn update_call_stub(
        &self,
        value_after_call: &Self::Value,
        _call: &Term<Jmp>,
    ) -> Option<Self::Value> {
        Some(value_after_call.clone())
    }

    fn update_jump(
        &self,
        value: &Self::Value,
        _jump: &Term<Jmp>,
        _untaken_conditional: Option<&Term<Jmp>>,
        _target: &Term<Blk>,
    ) -> Option<Self::Value> {
        Some(value.clone())
    }

    fn update_call(
        &self,
        _value: &Self::Value,
        _call: &Term<Jmp>,
        _target: &Node,
        _calling_convention: &Option<String>,
    ) -> Option<Self::Value> {
        None // This propagation is intra-functional
    }

    fn update_return(
        &self,
        _value: Option<&Self::Value>,
        _value_before_call: Option<&Self::Value>,
        _call_term: &Term<Jmp>,
        _return_term: &Term<Jmp>,
        _calling_convention: &Option<String>,
    ) -> Option<Self::Value> {
        Some(HashMap::new()) // Start with no prior knowledge
    }

    fn specialize_conditional(
        &self,
        value: &Self::Value,
        _condition: &Expression,
        _block_before_condition: &Term<Blk>,
        _is_true: bool,
    ) -> Option<Self::Value> {
        Some(value.clone())
    }
}

/// Performs the fixpoint algorithm and returns the computation.
///
/// Panics, if the computation does not stabilizes.
fn compute_expression_propagation<'a>(
    project: &'a Project,
    graph: &'a Graph,
) -> Computation<GeneralizedContext<'a, Context<'a>>> {
    let context = Context::new(project, graph);
    let mut computation = create_computation(context, None);

    for node in graph.node_indices() {
        if let Node::BlkStart(_blk, _sub) = graph[node] {
            // A start in the CFG has no incoming edges in the CFG and
            // are mostly due to cases where the control flow graph is incomplete.
            // We assume that no expressions are insertable at such starting nodes.
            if graph
                .neighbors_directed(node, petgraph::Incoming)
                .next()
                .is_none()
            {
                computation.set_node_value(node, NodeValue::Value(HashMap::new()));
            }
        }
    }

    computation.compute_with_max_steps(100);

    if !computation.has_stabilized() {
        panic!("Fixpoint for expression propagation did not stabilize.");
    }
    computation
}

/// Returns the computed result for every basic block.
fn extract_results<'a>(
    graph: &Graph,
    computation: Computation<GeneralizedContext<'a, Context<'a>>>,
) -> HashMap<Tid, HashMap<Variable, Expression>> {
    let mut results = HashMap::new();
    for node in graph.node_indices() {
        if let Node::BlkEnd(blk, _sub) = graph[node] {
            if let Some(NodeValue::Value(insertables)) = computation.get_node_value(node) {
                results.insert(blk.tid.clone(), insertables.clone());
            }
        }
    }
    results
}

/// Replaces for every basic block all propagated expressions.
///
/// This uses the expression propagation of basic blocks, thus performs intra-basic-block insertion of expressions.
fn insert_expressions(
    inseratables: HashMap<Tid, HashMap<Variable, Expression>>,
    program: &mut Program,
) {
    for sub in program.subs.values_mut() {
        let mut blocks = sub.term.blocks.iter_mut();
        // First blocks of functions should not insert any expressions, extracted by the fixpoint computation.
        if let Some(first_block) = blocks.next() {
            first_block.merge_def_assignments_to_same_var();
            first_block.propagate_input_expressions(None);
        }
        for block in blocks {
            block.merge_def_assignments_to_same_var();
            if let Some(insertable_for_block) = inseratables.get(&block.tid) {
                block.propagate_input_expressions(Some(insertable_for_block.clone()));
            }
        }
    }
}

/// Replaces variables by expressions that can be propagated within functions.
///
/// This is performed by a fixpoint computation and might panic, if it does not stabilize.
pub fn propagate_input_expression(project: &mut Project) {
    let extern_subs = project
        .program
        .term
        .extern_symbols
        .keys()
        .cloned()
        .collect();

    let graph = crate::analysis::graph::get_program_cfg(&project.program, extern_subs);
    let computation = compute_expression_propagation(project, &graph);
    let results = extract_results(&graph, computation);
    insert_expressions(results, &mut project.program.term);
}

#[cfg(test)]
mod tests;
