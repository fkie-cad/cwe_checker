//! Modules necessary for graph-based and fixpoint-based analyses,
//! as well as analyses depending on these modules.

pub mod backward_interprocedural_fixpoint;
pub mod dead_variable_elimination;
pub mod fixpoint;
pub mod forward_interprocedural_fixpoint;
pub mod function_signature;
pub mod graph;
pub mod interprocedural_fixpoint_generic;
pub mod pointer_inference;
pub mod string_abstraction;
pub mod vsa_results;
