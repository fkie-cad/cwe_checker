use super::fixpoint::Problem as GeneralFPProblem;
use super::graph::*;
use crate::bil::Expression;
use crate::term::*;
use petgraph::graph::EdgeIndex;
use std::marker::PhantomData;

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
    fn update_call(&self, value: &Self::Value, call: &Call) -> Self::Value;
    fn update_return(
        &self,
        value: &Self::Value,
        value_before_call: Option<&Self::Value>,
    ) -> Self::Value;
    fn update_call_stub(&self, value: &Self::Value, call: &Call) -> Option<Self::Value>;
    fn specialize_conditional(
        &self,
        value: &Self::Value,
        condition: &Expression,
        is_true: bool,
    ) -> Option<Self::Value>;
}

struct GeneralizedProblem<'a, T: Problem<'a>> {
    problem: T,
    _phantom_graph_reference: PhantomData<Graph<'a>>,
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
        let (start_node, _end_node) = graph.edge_endpoints(edge).unwrap();
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
            Edge::Call(call) => Some(NodeValue::Value(
                self.problem.update_call(node_value.unwrap_value(), call),
            )),
            Edge::CRCallStub => Some(NodeValue::CallReturnCombinator {
                call: Some(node_value.unwrap_value().clone()),
                return_: None,
            }),
            Edge::CRReturnStub => Some(NodeValue::CallReturnCombinator {
                call: None,
                return_: Some(node_value.unwrap_value().clone()),
            }),
            Edge::CRCombine => match node_value {
                NodeValue::Value(_) => panic!("Unexpected interprocedural fixpoint graph state"),
                NodeValue::CallReturnCombinator { call, return_ } => {
                    if let Some(return_value) = return_ {
                        Some(NodeValue::Value(
                            self.problem.update_return(return_value, call.as_ref()),
                        ))
                    } else {
                        None
                    }
                }
            },
            Edge::ExternCallStub(call) => self
                .problem
                .update_call_stub(node_value.unwrap_value(), call)
                .map(|val| NodeValue::Value(val)),
            Edge::Jump(jump, untaken_conditional) => self
                .problem
                .update_jump(node_value.unwrap_value(), jump, *untaken_conditional)
                .map(|val| NodeValue::Value(val)),
        }
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
