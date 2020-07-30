/*!
This module defines a trait for interprocedural fixpoint problems.

## Basic usage

Define a *Context* struct containing all information that does not change during the fixpoint computation.
In particular, this includes the graph on which the fixpoint computation is run.
Then implement the *Problem* trait for the *Context* struct.
The fixpoint computation can now be run as follows:
```
let context = MyContext::new(); // MyContext needs to implement Problem
let mut computation = Computation::new(context, None);
// add starting node values here with
computation.compute();
// computation is done, get solution node values here
```
*/

// TODO: When indirect jumps are sufficiently supported, the update_jump methods need access to
// target (and maybe source) nodes/TIDs, to determine which target the current edge points to.
// Alternatively, this could be achieved through usage of the specialize_conditional function.
// Currently unclear, which way is better.

use super::fixpoint::Problem as GeneralFPProblem;
use super::graph::*;
use crate::bil::Expression;
use crate::prelude::*;
use crate::term::*;
use fnv::FnvHashMap;
use petgraph::graph::{EdgeIndex, NodeIndex};
use std::marker::PhantomData;

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeValue<T: PartialEq + Eq> {
    Value(T),
    CallReturnCombinator { call: Option<T>, return_: Option<T> },
}

impl<T: PartialEq + Eq> NodeValue<T> {
    pub fn unwrap_value(&self) -> &T {
        match self {
            NodeValue::Value(value) => value,
            _ => panic!("Unexpected node value type"),
        }
    }
}

/// An interprocedural fixpoint problem defines the context for a fixpoint computation.
///
/// All trait methods have access to the FixpointProblem structure, so that context informations are accessible through it.
pub trait Problem<'a> {
    type Value: PartialEq + Eq + Clone;

    fn get_graph(&self) -> &Graph<'a>;

    fn merge(&self, value1: &Self::Value, value2: &Self::Value) -> Self::Value;

    fn update_def(&self, value: &Self::Value, def: &Term<Def>) -> Self::Value;
    fn update_jump(
        &self,
        value: &Self::Value,
        jump: &Term<Jmp>,
        untaken_conditional: Option<&Term<Jmp>>,
    ) -> Option<Self::Value>;
    fn update_call(&self, value: &Self::Value, call: &Term<Jmp>, target: &Node) -> Self::Value;
    fn update_return(
        &self,
        value: &Self::Value,
        value_before_call: Option<&Self::Value>,
        call_term: &Term<Jmp>,
    ) -> Option<Self::Value>;
    fn update_call_stub(&self, value: &Self::Value, call: &Term<Jmp>) -> Option<Self::Value>;
    fn specialize_conditional(
        &self,
        value: &Self::Value,
        condition: &Expression,
        is_true: bool,
    ) -> Option<Self::Value>;
}

/// This struct is a wrapper to create a general fixpoint problem out of an interprocedural fixpoint problem.
struct GeneralizedProblem<'a, T: Problem<'a>> {
    problem: T,
    _phantom_graph_reference: PhantomData<Graph<'a>>,
}

impl<'a, T: Problem<'a>> GeneralizedProblem<'a, T> {
    pub fn new(problem: T) -> Self {
        GeneralizedProblem {
            problem,
            _phantom_graph_reference: PhantomData,
        }
    }
}

impl<'a, T: Problem<'a>> GeneralFPProblem for GeneralizedProblem<'a, T> {
    type EdgeLabel = Edge<'a>;
    type NodeLabel = Node<'a>;
    type NodeValue = NodeValue<T::Value>;

    fn get_graph(&self) -> &Graph<'a> {
        self.problem.get_graph()
    }

    fn merge(&self, val1: &Self::NodeValue, val2: &Self::NodeValue) -> Self::NodeValue {
        use NodeValue::*;
        match (val1, val2) {
            (Value(value1), Value(value2)) => Value(self.problem.merge(value1, value2)),
            (
                CallReturnCombinator {
                    call: call1,
                    return_: return1,
                },
                CallReturnCombinator {
                    call: call2,
                    return_: return2,
                },
            ) => CallReturnCombinator {
                call: merge_option(call1, call2, |v1, v2| self.problem.merge(v1, v2)),
                return_: merge_option(return1, return2, |v1, v2| self.problem.merge(v1, v2)),
            },
            _ => panic!("Malformed CFG in fixpoint computation"),
        }
    }

    fn update_edge(
        &self,
        node_value: &Self::NodeValue,
        edge: EdgeIndex,
    ) -> Option<Self::NodeValue> {
        let graph = self.problem.get_graph();
        let (start_node, end_node) = graph.edge_endpoints(edge).unwrap();
        let block_term = graph.node_weight(start_node).unwrap().get_block();
        match graph.edge_weight(edge).unwrap() {
            Edge::Block => {
                let value = node_value.unwrap_value();
                let defs = &block_term.term.defs;
                let end_val = defs.iter().fold(value.clone(), |accum, def| {
                    self.problem.update_def(&accum, def)
                });
                Some(NodeValue::Value(end_val))
            }
            Edge::Call(call) => Some(NodeValue::Value(self.problem.update_call(
                node_value.unwrap_value(),
                call,
                &graph[end_node],
            ))),
            Edge::CRCallStub => Some(NodeValue::CallReturnCombinator {
                call: Some(node_value.unwrap_value().clone()),
                return_: None,
            }),
            Edge::CRReturnStub => Some(NodeValue::CallReturnCombinator {
                call: None,
                return_: Some(node_value.unwrap_value().clone()),
            }),
            Edge::CRCombine(call_term) => match node_value {
                NodeValue::Value(_) => panic!("Unexpected interprocedural fixpoint graph state"),
                NodeValue::CallReturnCombinator { call, return_ } => {
                    if let Some(return_value) = return_ {
                        match self
                            .problem
                            .update_return(return_value, call.as_ref(), call_term)
                        {
                            Some(val) => Some(NodeValue::Value(val)),
                            None => None,
                        }
                    } else {
                        None
                    }
                }
            },
            Edge::ExternCallStub(call) => self
                .problem
                .update_call_stub(node_value.unwrap_value(), call)
                .map(NodeValue::Value),
            Edge::Jump(jump, untaken_conditional) => self
                .problem
                .update_jump(node_value.unwrap_value(), jump, *untaken_conditional)
                .map(NodeValue::Value),
        }
    }
}

/// This struct contains an intermediate result of an interprocedural fixpoint cumputation.
pub struct Computation<'a, T: Problem<'a>> {
    generalized_computation: super::fixpoint::Computation<GeneralizedProblem<'a, T>>,
}

impl<'a, T: Problem<'a>> Computation<'a, T> {
    /// Generate a new computation from the corresponding problem and a default value for nodes.
    pub fn new(problem: T, default_value: Option<T::Value>) -> Self {
        let generalized_problem = GeneralizedProblem::new(problem);
        let computation = super::fixpoint::Computation::new(
            generalized_problem,
            default_value.map(NodeValue::Value),
        );
        Computation {
            generalized_computation: computation,
        }
    }

    /// Compute the fixpoint.
    /// Note that this function does not terminate if the fixpoint algorithm does not stabilize
    pub fn compute(&mut self) {
        self.generalized_computation.compute()
    }

    /// Compute the fixpoint while updating each node at most max_steps times.
    /// Note that the result may not be a stabilized fixpoint, but only an intermediate result of a fixpoint computation.
    pub fn compute_with_max_steps(&mut self, max_steps: u64) {
        self.generalized_computation
            .compute_with_max_steps(max_steps)
    }

    /// Get the value of a node.
    pub fn get_node_value(&self, node: NodeIndex) -> Option<&NodeValue<T::Value>> {
        self.generalized_computation.get_node_value(node)
    }

    /// Set the value of a node and mark the node as not yet stabilized
    pub fn set_node_value(&mut self, node: NodeIndex, value: NodeValue<T::Value>) {
        self.generalized_computation.set_node_value(node, value)
    }

    /// Get a reference to the internal map where one can look up the current values of all nodes
    pub fn node_values(&self) -> &FnvHashMap<NodeIndex, NodeValue<T::Value>> {
        self.generalized_computation.node_values()
    }

    /// Get a reference to the underlying graph
    pub fn get_graph(&self) -> &Graph {
        self.generalized_computation.get_graph()
    }
}

fn merge_option<T: Clone, F>(opt1: &Option<T>, opt2: &Option<T>, merge: F) -> Option<T>
where
    F: Fn(&T, &T) -> T,
{
    match (opt1, opt2) {
        (Some(value1), Some(value2)) => Some(merge(value1, value2)),
        (Some(value), None) | (None, Some(value)) => Some(value.clone()),
        (None, None) => None,
    }
}
