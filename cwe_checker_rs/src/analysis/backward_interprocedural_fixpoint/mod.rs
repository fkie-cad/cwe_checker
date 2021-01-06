use super::fixpoint::Context as GeneralFPContext;
use super::graph::*;
use super::interprocedural_fixpoint_generic::*;
use crate::intermediate_representation::*;
use fnv::FnvHashMap;
use petgraph::graph::{EdgeIndex, NodeIndex};
use std::marker::PhantomData;

/// The context for an backward interprocedural fixpoint computation.
///
/// Basically, a `Context` object needs to contain a reference to the actual graph,
/// a method for merging node values,
/// and methods for computing the edge transitions for each different edge type.
///
/// All trait methods have access to the FixpointProblem structure, so that context informations are accessible through it.
///
/// All edge transition functions can return `None` to indicate that no information flows through the edge.
/// For example, this can be used to indicate edges that can never been taken.
pub trait Context<'a> {
    type Value: PartialEq + Eq + Clone;

    /// Get a reference to the graph that the fixpoint is computed on.
    fn get_graph(&self) -> &Graph<'a>;

    /// Merge two node values.
    fn merge(&self, value1: &Self::Value, value2: &Self::Value) -> Self::Value;

    /// Transition function for `Def` terms.
    /// The transition function for a basic block is computed
    /// by iteratively applying this function to the starting value for each `Def` term in the basic block.
    /// The iteration short-circuits and returns `None` if `update_def` returns `None` at any point.
    fn update_def(&self, value: &Self::Value, def: &Term<Def>) -> Option<Self::Value>;

    /// Transition function for (conditional and unconditional) `Jmp` terms.
    fn update_jumpsite(
        &self,
        value_after_jump: &Self::Value,
        jump: &Term<Jmp>,
        untaken_conditional: Option<&Term<Jmp>>,
        jumpsite: &Term<Blk>,
    ) -> Option<Self::Value>;

    /// Transition function for in-program calls.
    fn update_callsite(
        &self,
        value_after_call: Option<&Self::Value>,
        fallthrough_value: Option<&Self::Value>,
        call: &Term<Jmp>,
        return_: &Term<Jmp>,
    ) -> Option<Self::Value>;

    /// Transition function for call stub split.
    /// Has access to the value at the ReturnCombine node and
    /// decides which data is transferred along the Call Stub Edge.
    fn split_call_stub(&self, combined_value: &Self::Value) -> Option<Self::Value>;

    /// Transition function for return stub split.
    /// Has access to the value at the ReturnCombine node and
    /// decides which data is transferred along the Return Stub Edge.
    fn split_return_stub(&self, combined_value: &Self::Value) -> Option<Self::Value>;

    /// Transition function for calls to functions not contained in the binary.
    /// The corresponding edge goes from the callsite to the returned-to block.
    fn update_call_stub(
        &self,
        value_after_call: &Self::Value,
        call: &Term<Jmp>,
    ) -> Option<Self::Value>;

    /// This function is used to refine the value using the information on which branch was taken on a conditional jump.
    fn specialize_conditional(
        &self,
        value_after_jump: &Self::Value,
        condition: &Expression,
        is_true: bool,
    ) -> Option<Self::Value>;
}

impl<'a, T: Context<'a>> GeneralFPContext for GeneralizedContext<'a, T> {
    type EdgeLabel = Edge<'a>;
    type NodeLabel = Node<'a>;
    type NodeValue = NodeValue<T::Value>;

    /// Get a reference to the underlying graph.
    fn get_graph(&self) -> &Graph<'a> {
        self.context.get_graph()
    }

    /// Merge two values using the merge function from the interprocedural context object.
    fn merge(&self, val1: &Self::NodeValue, val2: &Self::NodeValue) -> Self::NodeValue {
        use NodeValue::*;
        match (val1, val2) {
            (Value(value1), Value(value2)) => Value(self.context.merge(value1, value2)),
            (
                CallFlowCombinator {
                    call_stub: call1,
                    interprocedural_flow: target1,
                },
                CallFlowCombinator {
                    call_stub: call2,
                    interprocedural_flow: target2,
                },
            ) => CallFlowCombinator {
                call_stub: merge_option(call1, call2, |v1, v2| self.context.merge(v1, v2)),
                interprocedural_flow: merge_option(target1, target2, |v1, v2| {
                    self.context.merge(v1, v2)
                }),
            },
            _ => panic!("Malformed CFG in fixpoint computation"),
        }
    }

    /// Backward edge transition function.
    /// Applies the transition functions from the interprocedural context object
    /// corresponding to the type of the provided edge.
    fn update_edge(
        &self,
        node_value: &Self::NodeValue,
        edge: EdgeIndex,
    ) -> Option<Self::NodeValue> {
        let graph = self.context.get_graph();
        let (start_node, end_node) = graph.edge_endpoints(edge).unwrap();

        match graph.edge_weight(edge).unwrap() {
            // Added rev() function to iterator to iterate backwards over the definitions
            Edge::Block => {
                let block_term = graph.node_weight(start_node).unwrap().get_block();
                let value = node_value.unwrap_value();
                let defs = &block_term.term.defs;
                let end_val = defs.iter().rev().try_fold(value.clone(), |accum, def| {
                    self.context.update_def(&accum, def)
                });
                end_val.map(NodeValue::Value)
            }
            Edge::ReturnCombine(_) => {
                Some(Self::NodeValue::Value(node_value.unwrap_value().clone()))
            }
            // The Call Edge value is added to the CallSourceCombinator.
            // The end node will be the callsite node and the node_value parameter is the value at the
            // called subroutine's BlkStart node
            Edge::Call(_) => Some(NodeValue::CallFlowCombinator {
                call_stub: None,
                interprocedural_flow: Some(node_value.unwrap_value().clone()),
            }),
            // The CallStub Edge value is added to the CallSourceCombinator
            // The user has the ability to split the node value at the BlkStart return to node
            // to only send specific data along the CallStub Edge to the callsite
            Edge::CRCallStub => Some(NodeValue::CallFlowCombinator {
                call_stub: self.context.split_call_stub(node_value.unwrap_value()),
                interprocedural_flow: None,
            }),
            // The user has the ability to split the node value at the BlkStart return node
            // to only send specific data along the ReturnStub Edge to the last BlkEnd node called subroutine
            Edge::CRReturnStub => self
                .context
                .split_return_stub(node_value.unwrap_value())
                .map(NodeValue::Value),

            // The CallCombine Edge merges the values coming in from the CallStub Edge and Call Edge
            // It also gives the user access to the call and return term.
            Edge::CallCombine(return_term) => match node_value {
                NodeValue::Value(_) => panic!("Unexpected interprocedural fixpoint graph state"),
                NodeValue::CallFlowCombinator {
                    call_stub,
                    interprocedural_flow,
                } => {
                    let call_block = match graph.node_weight(start_node) {
                        Some(Node::CallSource {
                            source: (call_block, ..),
                            target: _,
                        }) => call_block,
                        _ => panic!("Malformed Control flow graph"),
                    };
                    let call_term = &call_block.term.jmps[0];
                    match self.context.update_callsite(
                        interprocedural_flow.as_ref(),
                        call_stub.as_ref(),
                        call_term,
                        return_term,
                    ) {
                        Some(val) => Some(NodeValue::Value(val)),
                        None => None,
                    }
                }
            },
            Edge::ExternCallStub(call) => self
                .context
                .update_call_stub(node_value.unwrap_value(), call)
                .map(NodeValue::Value),
            Edge::Jump(jump, untaken_conditional) => self
                .context
                .update_jumpsite(
                    node_value.unwrap_value(),
                    jump,
                    *untaken_conditional,
                    graph[end_node].get_block(),
                )
                .map(NodeValue::Value),
        }
    }
}

/// This struct is a wrapper to create a general fixpoint context out of an interprocedural fixpoint context.
pub struct GeneralizedContext<'a, T: Context<'a>> {
    context: T,
    _phantom_graph_reference: PhantomData<Graph<'a>>,
}

impl<'a, T: Context<'a>> GeneralizedContext<'a, T> {
    /// Create a new generalized context out of an interprocedural context object.
    pub fn new(context: T) -> Self {
        GeneralizedContext {
            context,
            _phantom_graph_reference: PhantomData,
        }
    }
}

/// An intermediate result of an interprocedural fixpoint computation.
///
/// The usage instructions are identical to the usage of the general fixpoint computation object,
/// except that you need to provide an interprocedural context object instead of a general one.
pub struct Computation<'a, T: Context<'a>> {
    generalized_computation: super::fixpoint::Computation<GeneralizedContext<'a, T>>,
}

impl<'a, T: Context<'a>> Computation<'a, T> {
    /// Generate a new computation from the corresponding context and an optional default value for nodes.
    pub fn new(problem: T, default_value: Option<T::Value>) -> Self {
        let generalized_problem = GeneralizedContext::new(problem);
        let computation = super::fixpoint::Computation::new(
            generalized_problem,
            default_value.map(NodeValue::Value),
        );
        Computation {
            generalized_computation: computation,
        }
    }

    /// Compute the fixpoint.
    /// Note that this function does not terminate if the fixpoint algorithm does not stabilize.
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

    /// Get a reference to the underlying context object
    pub fn get_context(&self) -> &T {
        &self.generalized_computation.get_context().context
    }

    /// Returns `True` if the computation has stabilized, i.e. the internal worklist is empty.
    pub fn has_stabilized(&self) -> bool {
        self.generalized_computation.has_stabilized()
    }

    /// Return a list of all nodes which are marked as not-stabilized
    pub fn get_worklist(&self) -> Vec<NodeIndex> {
        self.generalized_computation.get_worklist()
    }
}

pub mod mock_context;
#[cfg(test)]
pub mod tests;
