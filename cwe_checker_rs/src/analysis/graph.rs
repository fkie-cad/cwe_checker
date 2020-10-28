//! Generate control flow graphs out of a program term.
//!
//! The generated graphs follow some basic principles:
//! * **Nodes** denote specific (abstract) points in time during program execution,
//! i.e. information does not change on a node.
//! So a basic block itself is not a node,
//! but the points in time before and after execution of the basic block can be nodes.
//! * **Edges** denote either transitions between the points in time of their start and end nodes during program execution
//! or they denote (artificial) information flow between nodes. See the `CRCallStub` edges of interprocedural control flow graphs
//! for an example of an edge that is only meant for information flow and not actual control flow.
//!
//! # General assumptions
//!
//! The graph construction algorithm assumes
//! that each basic block of the program term ends with zero, one or two jump instructions.
//! In the case of two jump instructions the first one is a conditional jump
//! and the second one is an unconditional jump.
//! Conditional calls are not supported.
//! Missing jump instructions are supported to indicate incomplete information about the control flow,
//! i.e. points where the control flow reconstruction failed.
//! These points are converted to dead ends in the control flow graphs.
//!
//! # Interprocedural control flow graph
//!
//! The function [`get_program_cfg`](fn.get_program_cfg.html) builds an interprocedural control flow graph out of a program term as follows:
//! * Each basic block ([`image`](../../../../../doc/images/node_edge.png)) is converted into two nodes, *BlkStart* and *BlkEnd*,
//! and a *block* edge from *BlkStart* to *BlkEnd*.
//! * Jumps and calls inside the program are converted to *Jump* or *Call* edges from the *BlkEnd* node of their source
//! to the *BlkStart* node of their target (which is the first block of the target function in case of calls).
//! * Calls to library functions ([`image`](../../../../../doc/images/extern_calls.png)) outside the program are converted to *ExternCallStub* edges
//! from the *BlkEnd* node of the callsite to the *BlkStart* node of the basic block the call returns to
//! (if the call returns at all).
//! * For each in-program call ([`image`](../../../../../doc/images/internal_function_call.png)) and corresponding return jump one node and three edges are generated:
//!   * An artificial node *CallReturn*
//!   * A *CRCallStub* edge from the *BlkEnd* node of the callsite to *CallReturn*
//!   * A *CRReturnStub* edge from the *BlkEnd* node of the returning from block to *CallReturn*
//!   * A *CRCombine* edge from *CallReturn* to the *BlkStart* node of the returned to block.
//!
//! The artificial *CallReturn* nodes enable enriching the information flowing through a return edge
//! with information recovered from the corresponding callsite during a fixpoint computation.

use crate::intermediate_representation::*;
use crate::prelude::*;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{HashMap, HashSet};

/// The graph type of an interprocedural control flow graph
pub type Graph<'a> = DiGraph<Node<'a>, Edge<'a>>;

/// The node type of an interprocedural control flow graph
///
/// Each node carries a pointer to its associated block with it.
/// For `CallReturn`nodes the associated blocks are both the callsite block (containing the call instruction)
/// and the returning-from block (containing the return instruction).
///
/// Basic blocks are allowed to be contained in more than one `Sub`.
/// In the control flow graph such basic blocks occur once per subroutine they are contained in.
/// For this reason, the nodes also carry a pointer to the corresponding subroutine with them
/// to allow unambigous node identification.
#[derive(Serialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Node<'a> {
    BlkStart(&'a Term<Blk>, &'a Term<Sub>),
    BlkEnd(&'a Term<Blk>, &'a Term<Sub>),
    CallReturn {
        call: (&'a Term<Blk>, &'a Term<Sub>),
        return_: (&'a Term<Blk>, &'a Term<Sub>),
    },
}

impl<'a> Node<'a> {
    /// Get the block corresponding to the node for `BlkStart` and `BlkEnd` nodes.
    /// panics if called on a `CallReturn` node.
    pub fn get_block(&self) -> &'a Term<Blk> {
        use Node::*;
        match self {
            BlkStart(blk, _sub) | BlkEnd(blk, _sub) => blk,
            CallReturn { .. } => panic!("get_block() is undefined for CallReturn nodes"),
        }
    }
}

impl<'a> std::fmt::Display for Node<'a> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::BlkStart(block, sub) => {
                write!(formatter, "BlkStart @ {} (sub {})", block.tid, sub.tid)
            }
            Self::BlkEnd(block, sub) => {
                write!(formatter, "BlkEnd @ {} (sub {})", block.tid, sub.tid)
            }
            Self::CallReturn { call, return_ } => write!(
                formatter,
                "CallReturn @ {} (sub {}) (caller @ {} (sub {}))",
                return_.0.tid, return_.1.tid, call.0.tid, call.1.tid
            ),
        }
    }
}

/// The edge type of an interprocedural fixpoint graph.
///
/// Where applicable the edge carries a reference to the corresponding jump instruction.
/// For `CRCombine` edges the corresponding jump is the call and not the return jump.
/// Intraprocedural jumps carry a second optional reference,
/// which is only set if the jump directly follows an conditional jump,
/// i.e. it represents the "conditional jump not taken" branch.
/// In this case the other jump reference points to the untaken conditional jump.
#[derive(Serialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Edge<'a> {
    Block,
    Jump(&'a Term<Jmp>, Option<&'a Term<Jmp>>),
    Call(&'a Term<Jmp>),
    ExternCallStub(&'a Term<Jmp>),
    CRCallStub,
    CRReturnStub,
    CRCombine(&'a Term<Jmp>),
}

/// A builder struct for building graphs
struct GraphBuilder<'a> {
    program: &'a Term<Program>,
    extern_subs: HashSet<Tid>,
    graph: Graph<'a>,
    /// Denotes the NodeIndices of possible call targets
    call_targets: HashMap<Tid, (NodeIndex, NodeIndex)>,
    /// Denotes the NodeIndices of possible intraprocedural jump targets.
    /// The keys are of the form (block_tid, sub_tid).
    /// The values are of the form (BlkStart-node-index, BlkEnd-node-index).
    jump_targets: HashMap<(Tid, Tid), (NodeIndex, NodeIndex)>,
    /// for each function the list of return addresses of the corresponding call sites
    return_addresses: HashMap<Tid, Vec<(NodeIndex, NodeIndex)>>,
    /// A list of `BlkEnd` nodes for which outgoing edges still have to be added to the graph.
    block_worklist: Vec<NodeIndex>,
}

impl<'a> GraphBuilder<'a> {
    /// create a new builder with an emtpy graph
    pub fn new(program: &'a Term<Program>, extern_subs: HashSet<Tid>) -> GraphBuilder<'a> {
        GraphBuilder {
            program,
            extern_subs,
            graph: Graph::new(),
            call_targets: HashMap::new(),
            jump_targets: HashMap::new(),
            return_addresses: HashMap::new(),
            block_worklist: Vec::new(),
        }
    }

    /// Add start and end nodes of a block and the connecting edge.
    /// Also add the end node to the `block_worklist`.
    fn add_block(&mut self, block: &'a Term<Blk>, sub: &'a Term<Sub>) -> (NodeIndex, NodeIndex) {
        let start = self.graph.add_node(Node::BlkStart(block, sub));
        let end = self.graph.add_node(Node::BlkEnd(block, sub));
        self.jump_targets
            .insert((block.tid.clone(), sub.tid.clone()), (start, end));
        self.graph.add_edge(start, end, Edge::Block);
        self.block_worklist.push(end);
        (start, end)
    }

    /// Add all blocks of the program to the graph.
    ///
    /// Each block is only added once,
    /// i.e. for blocks contained in more than one function the extra nodes have to be added separately later.
    /// The `sub` a block is associated with is the `sub` that the block is contained in in the `program` struct.
    fn add_program_blocks(&mut self) {
        let subs = self.program.term.subs.iter();
        for sub in subs {
            for block in sub.term.blocks.iter() {
                self.add_block(block, sub);
            }
        }
    }

    /// add all subs to the call targets so that call instructions can be linked to the starting block of the corresponding sub.
    fn add_subs_to_jump_targets(&mut self) {
        for sub in self.program.term.subs.iter() {
            if !sub.term.blocks.is_empty() {
                let start_block = &sub.term.blocks[0];
                let target_index = self.jump_targets[&(start_block.tid.clone(), sub.tid.clone())];
                self.call_targets.insert(sub.tid.clone(), target_index);
            }
            // TODO: Generate Log-Message for Subs without blocks.
        }
    }

    /// add call edges and interprocedural jump edges for a specific jump term to the graph
    fn add_jump_edge(
        &mut self,
        source: NodeIndex,
        jump: &'a Term<Jmp>,
        untaken_conditional: Option<&'a Term<Jmp>>,
    ) {
        let sub_term = match self.graph[source] {
            Node::BlkEnd(_source_block, sub_term) => sub_term,
            _ => panic!(),
        };
        match &jump.term {
            Jmp::Branch(tid)
            | Jmp::CBranch {
                target: tid,
                condition: _,
            } => {
                if let Some((target_node, _)) =
                    self.jump_targets.get(&(tid.clone(), sub_term.tid.clone()))
                {
                    self.graph.add_edge(
                        source,
                        *target_node,
                        Edge::Jump(jump, untaken_conditional),
                    );
                } else {
                    let target_block = self.program.term.find_block(tid).unwrap();
                    let (target_node, _) = self.add_block(target_block, sub_term);
                    self.graph
                        .add_edge(source, target_node, Edge::Jump(jump, untaken_conditional));
                }
            }
            Jmp::BranchInd(_) => (), // TODO: add handling of indirect edges!
            Jmp::Call { target, return_ } => {
                // first make sure that the return block exists
                let return_to_node_option = if let Some(return_tid) = return_ {
                    if let Some((return_to_node, _)) = self
                        .jump_targets
                        .get(&(return_tid.clone(), sub_term.tid.clone()))
                    {
                        Some(*return_to_node)
                    } else {
                        let return_block = self.program.term.find_block(return_tid).unwrap();
                        Some(self.add_block(return_block, sub_term).0)
                    }
                } else {
                    None
                };
                // now add the call edge
                if self.extern_subs.contains(target) {
                    if let Some(return_to_node) = return_to_node_option {
                        self.graph
                            .add_edge(source, return_to_node, Edge::ExternCallStub(jump));
                    }
                } else {
                    if let Some((target_node, _)) = self.call_targets.get(&target) {
                        self.graph.add_edge(source, *target_node, Edge::Call(jump));
                    } // TODO: Log message for the else-case?
                    if let Some(return_node) = return_to_node_option {
                        self.return_addresses
                            .entry(target.clone())
                            .and_modify(|vec| vec.push((source, return_node)))
                            .or_insert_with(|| vec![(source, return_node)]);
                    }
                }
            }
            Jmp::CallInd {
                target: _,
                return_: _,
            } => {
                // TODO: add handling of indirect calls!
            }
            Jmp::CallOther {
                description: _,
                return_: _,
            } => {
                // TODO: Decide how to represent CallOther edges.
                // Right now they are dead ends in the control flow graph.
            }
            Jmp::Return(_) => {} // return edges are handled in a different function
        }
    }

    /// Add all outgoing edges generated by calls and intraprocedural jumps for a specific block to the graph.
    /// Return edges are *not* added by this function.
    fn add_outgoing_edges(&mut self, node: NodeIndex, block: &'a Term<Blk>) {
        let jumps = block.term.jmps.as_slice();
        match jumps {
            [] => (), // Blocks without jumps are dead ends corresponding to control flow reconstruction errors or user-inserted dead ends.
            [jump] => self.add_jump_edge(node, jump, None),
            [if_jump, else_jump] => {
                self.add_jump_edge(node, if_jump, None);
                self.add_jump_edge(node, else_jump, Some(if_jump));
            }
            _ => panic!("Basic block with more than 2 jumps encountered"),
        }
    }

    /// For each return instruction and each corresponding call, add the following to the graph:
    /// - a CallReturn node.
    /// - edges from the callsite and from the returning-from site to the CallReturn node
    /// - an edge from the CallReturn node to the return-to site
    fn add_call_return_node_and_edges(
        &mut self,
        return_from_sub: &'a Term<Sub>,
        return_source: NodeIndex,
    ) {
        if self.return_addresses.get(&return_from_sub.tid).is_none() {
            return;
        }
        for (call_node, return_to_node) in self.return_addresses[&return_from_sub.tid].iter() {
            let (call_block, caller_sub) = match self.graph[*call_node] {
                Node::BlkEnd(block, sub) => (block, sub),
                _ => panic!(),
            };
            let return_from_block = self.graph[return_source].get_block();
            let call_term = call_block
                .term
                .jmps
                .iter()
                .find(|jump| matches!(jump.term, Jmp::Call{..}))
                .unwrap();
            let cr_combine_node = self.graph.add_node(Node::CallReturn {
                call: (call_block, caller_sub),
                return_: (return_from_block, return_from_sub),
            });
            self.graph
                .add_edge(*call_node, cr_combine_node, Edge::CRCallStub);
            self.graph
                .add_edge(return_source, cr_combine_node, Edge::CRReturnStub);
            self.graph
                .add_edge(cr_combine_node, *return_to_node, Edge::CRCombine(call_term));
        }
    }

    /// Add all return instruction related edges and nodes to the graph (for all return instructions).
    fn add_return_edges(&mut self) {
        let mut return_from_vec = Vec::new();
        for node in self.graph.node_indices() {
            if let Node::BlkEnd(block, sub) = self.graph[node] {
                if block
                    .term
                    .jmps
                    .iter()
                    .any(|jmp| matches!(jmp.term, Jmp::Return(_)))
                {
                    return_from_vec.push((node, sub));
                }
            }
        }
        for (return_from_node, return_from_sub) in return_from_vec {
            self.add_call_return_node_and_edges(return_from_sub, return_from_node);
        }
    }

    /// Add all non-return-instruction-related jump edges to the graph.
    fn add_jump_and_call_edges(&mut self) {
        while !self.block_worklist.is_empty() {
            let node = self.block_worklist.pop().unwrap();
            match self.graph[node] {
                Node::BlkEnd(block, _) => self.add_outgoing_edges(node, block),
                _ => panic!(),
            }
        }
    }

    /// Build the interprocedural control flow graph.
    pub fn build(mut self) -> Graph<'a> {
        self.add_program_blocks();
        self.add_subs_to_jump_targets();
        self.add_jump_and_call_edges();
        self.add_return_edges();
        self.graph
    }
}

/// Build the interprocedural control flow graph for a program term.
pub fn get_program_cfg(program: &Term<Program>, extern_subs: HashSet<Tid>) -> Graph {
    let builder = GraphBuilder::new(program, extern_subs);
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_program() -> Term<Program> {
        let call_term = Term {
            tid: Tid::new("call".to_string()),
            term: Jmp::Call {
                target: Tid::new("sub2"),
                return_: Some(Tid::new("sub1_blk2")),
            },
        };
        let return_term = Term {
            tid: Tid::new("return".to_string()),
            term: Jmp::Return(Expression::Const(Bitvector::zero(64.into()))), // The return term does not matter
        };
        let jmp = Jmp::Branch(Tid::new("sub1_blk1"));
        let jmp_term = Term {
            tid: Tid::new("jump"),
            term: jmp,
        };
        let sub1_blk1 = Term {
            tid: Tid::new("sub1_blk1"),
            term: Blk {
                defs: Vec::new(),
                jmps: vec![call_term],
            },
        };
        let sub1_blk2 = Term {
            tid: Tid::new("sub1_blk2"),
            term: Blk {
                defs: Vec::new(),
                jmps: vec![jmp_term],
            },
        };
        let sub1 = Term {
            tid: Tid::new("sub1"),
            term: Sub {
                name: "sub1".to_string(),
                blocks: vec![sub1_blk1, sub1_blk2],
            },
        };
        let cond_jump = Jmp::CBranch {
            target: Tid::new("sub1_blk1"),
            condition: Expression::Const(Bitvector::from_u8(0)),
        };
        let cond_jump_term = Term {
            tid: Tid::new("cond_jump"),
            term: cond_jump,
        };
        let jump_term_2 = Term {
            tid: Tid::new("jump2"),
            term: Jmp::Branch(Tid::new("sub2_blk2")),
        };
        let sub2_blk1 = Term {
            tid: Tid::new("sub2_blk1"),
            term: Blk {
                defs: Vec::new(),
                jmps: vec![cond_jump_term, jump_term_2],
            },
        };
        let sub2_blk2 = Term {
            tid: Tid::new("sub2_blk2"),
            term: Blk {
                defs: Vec::new(),
                jmps: vec![return_term],
            },
        };
        let sub2 = Term {
            tid: Tid::new("sub2"),
            term: Sub {
                name: "sub2".to_string(),
                blocks: vec![sub2_blk1, sub2_blk2],
            },
        };
        let program = Term {
            tid: Tid::new("program"),
            term: Program {
                subs: vec![sub1, sub2],
                extern_symbols: Vec::new(),
                entry_points: Vec::new(),
            },
        };
        program
    }

    #[test]
    fn create_program_cfg() {
        let program = mock_program();
        let graph = get_program_cfg(&program, HashSet::new());
        println!("{}", serde_json::to_string_pretty(&graph).unwrap());
        assert_eq!(graph.node_count(), 14);
        assert_eq!(graph.edge_count(), 18);
    }
}
