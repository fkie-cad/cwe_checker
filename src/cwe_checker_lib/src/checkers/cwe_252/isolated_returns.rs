//! Analyse Isolated Return Sites.
//!
//! Taint that reaches a return site implies that there is some path from the
//! call to a fallible function to the return instruction where the return value
//! is not checked. If additionally, the taint is not returned to the caller
//! we have a bug, since with the return of the function all information about
//! success or failure of the function call is lost.
//!
//! For each function that is called at least once, we catch those cases during
//! the FP computation. However, for functions that are never called, e.g.,
//! exported functions in shared libraries or functions that are only ever
//! called indirectly, we need an additional pass once we have the result of
//! the FP computation.

use crate::abstract_domain::AbstractDomain;
use crate::analysis::graph::{Graph, Node, NodeIndex};
use crate::intermediate_representation::{Jmp, Project, Tid};
use crate::utils::log::CweWarning;

use std::collections::HashSet;
use std::sync::Arc;

use super::context;
use super::{generate_cwe_warning, MustUseCall};

/// Represents a return site of a function.
#[derive(Hash, Eq, PartialEq, Debug)]
pub struct ReturnSite<'a> {
    /// CFG node of the end of the block containing the return instruction.
    ret_node: NodeIndex,
    /// Calling convention of the function that returns.
    calling_convention: &'a Option<String>,
    /// Identifier of the return instruction.
    ret_insn_tid: &'a Tid,
}

impl<'a> ReturnSite<'a> {
    /// Create a new `ReturnSite`.
    fn new(
        ret_node: NodeIndex,
        calling_convention: &'a Option<String>,
        ret_insn_tid: &'a Tid,
    ) -> Self {
        Self {
            ret_node,
            calling_convention,
            ret_insn_tid,
        }
    }
}

/// The set of all isolated return sites of a binary.
pub type IsolatedReturns<'a> = HashSet<ReturnSite<'a>>;

/// Represents the post-fixpoint-computation pass that checks isolated return
/// sites for taint.
pub struct IsolatedReturnAnalysis<'a> {
    call: MustUseCall<'a>,
    isolated_returns: Arc<IsolatedReturns<'a>>,
    project: &'a Project,
    cwe_sender: crossbeam_channel::Sender<CweWarning>,
}

impl<'a> IsolatedReturnAnalysis<'a> {
    /// Create a new `IsolatedReturnAnalysis`.
    pub fn new(
        call: MustUseCall<'a>,
        isolated_returns: Arc<IsolatedReturns<'a>>,
        project: &'a Project,
        cwe_sender: crossbeam_channel::Sender<CweWarning>,
    ) -> Self {
        Self {
            call,
            isolated_returns,
            project,
            cwe_sender,
        }
    }

    /// Checks isolated return sites for taint with the results of the given
    /// `computation`.
    ///
    /// Generates CWE warnings when non-returned taint is found. We have no
    /// caller context, i.e., no aID renaming map, so we can not tell if memory
    /// taint is returned or not. Currently we always assume that memory taint
    /// will *not* be reachable for the caller (generates FPs).
    pub fn analyze(&self, computation: &context::FpComputation<'_, '_>) {
        for (taint_state, calling_convention, ret_insn_tid) in
            // Filter isolated returns with a taint state.
            self.isolated_returns.iter().filter_map(
                    |ReturnSite {
                         ret_node,
                         calling_convention,
                         ret_insn_tid,
                     }| {
                        computation
                            .node_values()
                            .get(ret_node)
                            .map(|state| (state.unwrap_value(), calling_convention, ret_insn_tid))
                    },
                )
        {
            if !taint_state.has_register_taint() {
                // Emit a warning since we do not consider cases where memory
                // taint may be returned.
                generate_cwe_warning(
                    &self.cwe_sender,
                    &self.call,
                    ret_insn_tid,
                    "isolated_returns_no_reg_taint",
                );
            } else if let Some(calling_convention) = self
                .project
                .get_specific_calling_convention(calling_convention)
            {
                // If no taint is returned we emit a warning.
                if calling_convention
                    .get_all_return_register()
                    .iter()
                    .all(|return_register| taint_state.get_register_taint(return_register).is_top())
                {
                    generate_cwe_warning(
                        &self.cwe_sender,
                        &self.call,
                        ret_insn_tid,
                        "isolated_returns_no_reg_taint_returned",
                    );
                }
            }
        }
    }
}

/// Get the set of all isolated return sites in the given interprocedural CFG.
pub fn get_isolated_returns<'a>(cfg: &Graph<'a>) -> IsolatedReturns<'a> {
    cfg.node_indices()
        .filter_map(|node| {
            if cfg.edges(node).next().is_some() {
                // By definition, a node with outgoing edges cannot be an
                // isolated return.
                None
            } else if let Node::BlkEnd(blk, sub) = cfg[node] {
                blk.term.jmps.iter().find_map(|jmp| {
                    if matches!(jmp.term, Jmp::Return(_)) {
                        Some(ReturnSite::new(
                            node,
                            &sub.term.calling_convention,
                            &jmp.tid,
                        ))
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        })
        .collect()
}
