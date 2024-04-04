//! Taint Analysis.
//!
//! This module provides general-purpose infrastructure for performing inter- or
//! intraprocedural Taint Analyses. In general, a Taint Analysis is a special
//! case of a forward "may" data flow analysis, where "may" means that merging
//! of flows is performed by taking unions, i.e., a value is tainted at a point
//! P iff there is *some* flow to P where it is tainted.
//!
//! A user defines the specific *instance* of a Taint Analyses that they want to
//! perform by implementing the [`TaintAnalysis`] trait. See its documentation
//! for further information.

use crate::abstract_domain::{AbstractDomain, HasTop, RegisterDomain, SizedDomain};
use crate::analysis::graph::Node as CfgNode;
use crate::analysis::pointer_inference::Data as PiData;
use crate::analysis::{
    forward_interprocedural_fixpoint,
    graph::{Graph as Cfg, HasCfg},
    vsa_results::{HasVsaResult, VsaResult},
};
use crate::intermediate_representation::*;
use crate::prelude::*;
use crate::utils::debug::ToJsonCompact;
use std::convert::AsRef;
use std::fmt::Display;

pub mod state;

use state::State;

/// Trait representing the definition of a Taint Analysis.
///
/// Taken together, these callbacks define the transfer function of the Taint
/// Analysis. Individual callbacks define the transfer functions for the
/// different kinds of statements that can occur in the intermediate
/// representation.
///
/// The property space of this analysis is the [`State`] type, it represents the
/// taint information we have about a particular point in the program.
///
/// # Default Implementations
///
/// Many callbacks have default implementations that contain a behavior common
/// to many taint analyses. However, you almost certainly want to override some
/// of them to implement the custom logic of your analysis.
pub trait TaintAnalysis<'a>: HasCfg<'a> + HasVsaResult<PiData> + AsRef<Project> {
    /// Called when a transition function mapped the input state to the empty
    /// state.
    ///
    /// This function will be called every time a default transition function
    /// maps a (possibly empty) input state to the empty state. Its return value
    /// will override the `Some(empty_state)` return value of the transition
    /// function.
    ///
    /// # Default
    ///
    /// Just returns `None`. This is the desired behavior as long as it is
    /// impossible for transition functions to generate taint from an empty
    /// state.
    fn handle_empty_state_out(&self, _tid: &Tid) -> Option<State> {
        None
    }

    /// Update taint state on a function call without further target information.
    ///
    /// # Default
    ///
    /// Only remove taint from non-callee-saved registers.
    fn update_call_generic(
        &self,
        state: &State,
        call_tid: &Tid,
        calling_convention_hint: &Option<String>,
    ) -> Option<State> {
        let mut new_state = state.clone();

        if let Some(calling_conv) = <Self as AsRef<Project>>::as_ref(self)
            .get_specific_calling_convention(calling_convention_hint)
        {
            new_state.remove_non_callee_saved_taint(calling_conv);
        }

        if new_state.is_empty() {
            self.handle_empty_state_out(call_tid)
        } else {
            Some(new_state)
        }
    }

    /// Transition function for edges of type [`Call`].
    ///
    /// Corresponds to intra-program calls, i.e., the target function is
    /// defined in the same binary. Return `None` here to keep the
    /// analysis intraprocedural.
    ///
    /// [`Call`]: crate::analysis::graph::Edge::Call
    ///
    /// # Default
    ///
    /// Just returns `None` to keep the analysis intraprocedural.
    fn update_call(
        &self,
        _state: &State,
        _call: &Term<Jmp>,
        _target: &CfgNode,
        _calling_convention: &Option<String>,
    ) -> Option<State> {
        None
    }

    /// Transition function for calls to external functions.
    ///
    /// # Default
    ///
    /// Removes taint from non-callee-saved registers.
    fn update_extern_call(
        &self,
        state: &State,
        _call: &Term<Jmp>,
        project: &Project,
        extern_symbol: &ExternSymbol,
    ) -> Option<State> {
        let mut new_state = state.clone();

        new_state.remove_non_callee_saved_taint(project.get_calling_convention(extern_symbol));

        Some(new_state)
    }

    /// Transition function for edges of type [`ExternCallStub`].
    ///
    /// Corresponds to inter-program calls, i.e., calls to shared libraries.
    /// Currently, indirect calls also lead to edges of type [`ExternCallStub`].
    /// If you are only interested in handling calls to library functions
    /// consider implementing [`update_extern_call`] instead.
    ///
    /// [`update_extern_call`]: TaintAnalysis::update_extern_call
    /// [indirect calls]: crate::intermediate_representation::Jmp::CallInd
    /// [`ExternCallStub`]: crate::analysis::graph::Edge::ExternCallStub
    ///
    /// # Default
    ///
    /// Remove taint from non-callee-saved registers.
    fn update_call_stub(&self, state: &State, call: &Term<Jmp>) -> Option<State> {
        match &call.term {
            Jmp::Call { target, .. } => {
                let project = <Self as AsRef<Project>>::as_ref(self);
                let extern_symbol = project
                    .program
                    .term
                    .extern_symbols
                    .get(target)
                    .expect("TA: BUG: Unable to find extern symbol for call.");

                match self.update_extern_call(state, call, project, extern_symbol) {
                    Some(new_state) if new_state.is_empty() => {
                        self.handle_empty_state_out(&call.tid)
                    }
                    new_state_option => new_state_option,
                }
            }
            Jmp::CallInd { .. } => self.update_call_generic(state, &call.tid, &None),
            _ => panic!("TA: BUG: Malformed control flow graph encountered."),
        }
    }

    /// Returns the new taint state after a jump.
    ///
    /// # Default
    ///
    /// Clones the state before the jump.
    fn update_jump(
        &self,
        state: &State,
        jump: &Term<Jmp>,
        _untaken_conditional: Option<&Term<Jmp>>,
        _target: &Term<Blk>,
    ) -> Option<State> {
        if state.is_empty() {
            self.handle_empty_state_out(&jump.tid)
        } else {
            Some(state.clone())
        }
    }

    /// Corresponds to returns from calls to other functions within the program.
    ///
    /// Only invoked if we have information about the taint state in the called
    /// subroutine at the time it returns, i.e., we are in the first column of
    /// the table in [`update_return`]. The `state` parameter corresponds to
    /// the taint state at the return sites of the called subroutine.
    ///
    /// By implementing this method you can perform an interprocedural taint
    /// analysis:
    /// - If you return `Some(state)` you may influence the taint
    ///   state in the caller (see the documentation of [`update_return`] for
    ///   more information), by having it be [`merged`] into the state coming
    ///   from the call site.
    /// - If you return `None`, **no** information will be propagated through
    ///   this call. (This includes possible state information from the call
    ///   site!); thus, return the empty state if you want to keep the analysis
    ///   in the caller going.
    ///
    /// [`update_return`]: TaintAnalysis::update_return
    /// [`merged`]: State::merge
    ///
    /// # Default
    ///
    /// Returns an empty state, i.e., information is propagated through the call
    /// but the analysis stays intraprocedural.
    fn update_return_callee(
        &self,
        _state: &State,
        _call_term: &Term<Jmp>,
        _return_term: &Term<Jmp>,
        _calling_convention: &Option<String>,
    ) -> Option<State> {
        Some(State::new_empty())
    }

    /// Corresponds to returns from calls to other functions within the program.
    ///
    /// By implementing this method you can perform interprocedural taint
    /// analysis. See
    /// [`forward_interprocedural_fixpoint::Context::update_return`] for more
    /// information.
    ///
    /// # Default
    ///
    /// Depending on the availability of `state_before_call` and
    /// `state_before_return` the return value is computed according to the
    /// following scheme:
    ///
    /// ```table
    /// | state_before_call/    |                                                       |                     |
    /// |   state_before_return | Some                                                  | None                |
    /// |-----------------------|-------------------------------------------------------|---------------------|
    /// | Some                  | Some(update_call_generic.merge(update_return_callee)) | update_call_generic |
    /// |                       | IF both are Some ELSE None                            |                     |
    /// |-----------------------|-------------------------------------------------------|---------------------|
    /// | None                  | update_return_callee                                  | None                |
    /// ```
    fn update_return(
        &self,
        state_before_return: Option<&State>,
        state_before_call: Option<&State>,
        call_term: &Term<Jmp>,
        return_term: &Term<Jmp>,
        calling_convention: &Option<String>,
    ) -> Option<State> {
        let new_state = match (state_before_call, state_before_return) {
            (Some(state_before_call), Some(state_before_return)) => {
                let state_from_caller =
                    self.update_call_generic(state_before_call, &call_term.tid, calling_convention);
                let state_from_callee = self.update_return_callee(
                    state_before_return,
                    call_term,
                    return_term,
                    calling_convention,
                );

                match (state_from_caller, state_from_callee) {
                    (Some(mut state_caller), Some(state_callee)) => {
                        state_caller.merge_with_renaming(
                            &state_callee,
                            self.vsa_result().get_call_renaming_map(&call_term.tid),
                        );

                        Some(state_caller)
                    }
                    // If one implementation indicated that no information
                    // should be propagated by returning `None` we ignore what
                    // the other call returned.
                    _ => None,
                }
            }
            (Some(state_before_call), None) => {
                self.update_call_generic(state_before_call, &call_term.tid, calling_convention)
            }
            (None, Some(state_before_return)) => self
                .update_return_callee(
                    state_before_return,
                    call_term,
                    return_term,
                    calling_convention,
                )
                .map(|state_callee| {
                    let mut dummy_caller_state = State::new_empty();

                    dummy_caller_state.merge_with_renaming(
                        &state_callee,
                        self.vsa_result().get_call_renaming_map(&call_term.tid),
                    );

                    dummy_caller_state
                }),
            _ => None,
        };

        match new_state {
            Some(state) => {
                if state.is_empty() {
                    self.handle_empty_state_out(&return_term.tid)
                } else {
                    Some(state)
                }
            }
            None => None,
        }
    }

    /// Returns the new taint state after an assignment.
    ///
    /// # Default
    ///
    /// Taints the destination register if the value that is assigned to it is
    /// tainted.
    fn update_def_assign(
        &self,
        state: &State,
        _tid: &Tid,
        var: &Variable,
        value: &Expression,
    ) -> State {
        let mut new_state = state.clone();

        new_state.set_register_taint(var, state.eval(value));

        new_state
    }

    /// Returns the new taint state after a load from memory.
    ///
    /// # Default
    ///
    /// Taints the destination register if the memory location was tainted. In
    /// cases where the address is unknown the destination register is *not*
    /// tainted.
    fn update_def_load(
        &self,
        state: &State,
        tid: &Tid,
        var: &Variable,
        _address: &Expression,
    ) -> State {
        let mut new_state = state.clone();
        let vsa_result = self.vsa_result();

        let taint = if let Some(address_value) = vsa_result.eval_address_at_def(tid) {
            state.load_taint_from_memory(&address_value, var.size)
        } else {
            Taint::Top(var.size)
        };

        new_state.set_register_taint(var, taint);

        new_state
    }

    /// Returns the new taint state after a store to memory.
    ///
    /// # Default
    ///
    /// Taints the destination memory if the value that is being stored is
    /// tainted. If the destination is unknown, all memory taint is removed from
    /// the state.
    fn update_def_store(
        &self,
        state: &State,
        tid: &Tid,
        _address: &Expression,
        value: &Expression,
    ) -> State {
        let mut new_state = state.clone();
        let vsa_result = self.vsa_result();

        match vsa_result.eval_address_at_def(tid) {
            Some(address_value) => {
                let taint = state.eval(value);
                new_state.save_taint_to_memory(&address_value, taint);
            }
            None => {
                // We lost all knowledge about memory pointers.
                // We delete all memory taint to reduce false positives.
                new_state.remove_all_memory_taints();
            }
        }

        new_state
    }

    /// Returns the new taint state after processing a single Def term.
    ///
    /// Receives both, the taint state before processing the Def and after
    /// processing it. Has a chance to overrule the default processing in
    /// special cases, usually when this Def is a sink.
    ///
    /// # Default
    ///
    /// Just returns the proposed state.
    fn update_def_post(
        &self,
        _old_state: &State,
        new_state: State,
        def: &Term<Def>,
    ) -> Option<State> {
        if new_state.is_empty() {
            self.handle_empty_state_out(&def.tid)
        } else {
            Some(new_state)
        }
    }
}

impl<'a, T: TaintAnalysis<'a>> forward_interprocedural_fixpoint::Context<'a> for T {
    type Value = State;

    fn get_graph(&self) -> &Cfg<'a> {
        self.get_cfg()
    }

    fn merge(&self, state1: &Self::Value, state2: &Self::Value) -> Self::Value {
        state1.merge(state2)
    }

    fn specialize_conditional(
        &self,
        state: &Self::Value,
        _condition: &Expression,
        _block_before_condition: &Term<Blk>,
        _is_true: bool,
    ) -> Option<Self::Value> {
        Some(state.clone())
    }

    fn update_call(
        &self,
        state: &Self::Value,
        call: &Term<Jmp>,
        target: &CfgNode,
        calling_convention: &Option<String>,
    ) -> Option<Self::Value> {
        <Self as TaintAnalysis>::update_call(self, state, call, target, calling_convention)
    }

    fn update_call_stub(&self, state: &Self::Value, call: &Term<Jmp>) -> Option<Self::Value> {
        <Self as TaintAnalysis>::update_call_stub(self, state, call)
    }

    fn update_jump(
        &self,
        state: &Self::Value,
        jump: &Term<Jmp>,
        untaken_conditional: Option<&Term<Jmp>>,
        target: &Term<Blk>,
    ) -> Option<Self::Value> {
        <Self as TaintAnalysis>::update_jump(self, state, jump, untaken_conditional, target)
    }

    fn update_def(&self, state: &Self::Value, def: &Term<Def>) -> Option<Self::Value> {
        let new_state = match &def.term {
            Def::Assign { var, value } => self.update_def_assign(state, &def.tid, var, value),
            Def::Load { var, address } => self.update_def_load(state, &def.tid, var, address),
            Def::Store { address, value } => self.update_def_store(state, &def.tid, address, value),
        };

        self.update_def_post(state, new_state, def)
    }

    fn update_return(
        &self,
        state_before_return: Option<&State>,
        state_before_call: Option<&State>,
        call_term: &Term<Jmp>,
        return_term: &Term<Jmp>,
        calling_convention: &Option<String>,
    ) -> Option<State> {
        <Self as TaintAnalysis>::update_return(
            self,
            state_before_return,
            state_before_call,
            call_term,
            return_term,
            calling_convention,
        )
    }
}

/// An abstract domain representing a value that is either tainted or not.
///
/// Note that the [merge](Taint::merge)-function does not respect the partial
/// order that is implied by the naming scheme of the variants! In fact, the
/// whole analysis does not enforce any partial order for this domain. This
/// means that in theory the fixpoint computation may not actually converge to a
/// fixpoint, but in practice the analysis can make more precise decisions
/// whether a value should be tainted or not.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Taint {
    /// A tainted value of a particular bytesize.
    Tainted(ByteSize),
    /// An untainted value of a particular bytesize.
    Top(ByteSize),
}

impl Display for Taint {
    /// Print the value of a `Taint` object.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tainted(size) => write!(f, "Tainted:{size}"),
            Self::Top(size) => write!(f, "Top:{size}"),
        }
    }
}

impl AbstractDomain for Taint {
    /// The result of merging two `Taint` values is tainted if at least one input was tainted.
    fn merge(&self, other: &Self) -> Self {
        use Taint::*;
        match (self, other) {
            (Tainted(size), _) | (_, Tainted(size)) => Tainted(*size),
            _ => Top(self.bytesize()),
        }
    }

    /// Replaces `self` with `other` iff `self` is untainted and `other` is
    /// tainted.
    ///
    /// No change to `self` is required in the other cases.
    fn merge_with(&mut self, other: &Self) {
        use Taint::*;

        if let (Top(_), Tainted(_)) = (&self, other) {
            *self = *other;
        };
    }

    /// Checks whether the value is an untainted `Top`-value.
    fn is_top(&self) -> bool {
        matches!(self, Taint::Top(_))
    }
}

impl SizedDomain for Taint {
    /// The size in bytes of the `Taint` value.
    fn bytesize(&self) -> ByteSize {
        match self {
            Self::Tainted(size) | Self::Top(size) => *size,
        }
    }

    /// Get a new `Top`-value with the given bytesize.
    fn new_top(bytesize: ByteSize) -> Self {
        Self::Top(bytesize)
    }
}

impl HasTop for Taint {
    /// Get a new `Top`-value with the same bytesize as `self`.
    fn top(&self) -> Self {
        Self::Top(self.bytesize())
    }
}

impl RegisterDomain for Taint {
    /// The result of a binary operation is tainted if at least one input value
    /// was tainted.
    fn bin_op(&self, op: BinOpType, rhs: &Self) -> Self {
        match (self, rhs) {
            (Self::Tainted(_), _) | (_, Self::Tainted(_)) => {
                Self::Tainted(self.bin_op_bytesize(op, rhs))
            }
            _ => Self::Top(self.bin_op_bytesize(op, rhs)),
        }
    }

    /// The result of a unary operation is tainted if the input was tainted.
    fn un_op(&self, _op: UnOpType) -> Self {
        *self
    }

    /// A subpiece of a tainted value is again tainted.
    fn subpiece(&self, _low_byte: ByteSize, size: ByteSize) -> Self {
        if let Self::Tainted(_) = self {
            Self::Tainted(size)
        } else {
            Self::Top(size)
        }
    }

    /// The result of a cast operation is tainted if the input was tainted.
    fn cast(&self, _kind: CastOpType, width: ByteSize) -> Self {
        if let Self::Tainted(_) = self {
            Self::Tainted(width)
        } else {
            Self::Top(width)
        }
    }
}

impl ToJsonCompact for Taint {
    fn to_json_compact(&self) -> serde_json::Value {
        serde_json::json!(self.to_string())
    }
}

impl Taint {
    /// Checks whether the given value is in fact tainted.
    pub fn is_tainted(&self) -> bool {
        matches!(self, Taint::Tainted(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::pointer_inference::tests::MockVsaResult;
    use crate::{def, expr};

    #[test]
    fn abstract_domain() {
        let taint = Taint::Tainted(ByteSize::new(4));
        let top = Taint::Top(ByteSize::new(4));

        assert_eq!(taint.merge(&top), taint);
        assert_eq!(top.merge(&top), top);
        assert_eq!(taint.is_top(), false);
    }

    #[test]
    fn register_domain() {
        use crate::intermediate_representation::*;

        let taint = Taint::Tainted(ByteSize::new(4));
        let taint_8 = Taint::Tainted(ByteSize::new(8));
        let top = Taint::Top(ByteSize::new(4));

        assert_eq!(taint.bin_op(BinOpType::IntAdd, &top), taint);
        assert_eq!(top.bin_op(BinOpType::IntMult, &top), top);
        assert_eq!(taint.un_op(UnOpType::FloatFloor), taint);
        assert_eq!(taint.subpiece(ByteSize::new(0), ByteSize::new(4)), taint);
        assert_eq!(top.cast(CastOpType::IntZExt, ByteSize::new(4)), top);
        assert_eq!(taint.cast(CastOpType::LzCount, ByteSize::new(8)), taint_8);
        assert_eq!(taint.cast(CastOpType::LzCount, ByteSize::new(4)), taint);
    }

    struct TestContext<'a> {
        project: &'a Project,
        vsa_result: &'a MockVsaResult,
    }

    impl<'a> HasCfg<'a> for TestContext<'a> {
        fn get_cfg(&self) -> &Cfg<'a> {
            // Should not be called.
            panic!()
        }
    }

    impl<'a> HasVsaResult<PiData> for TestContext<'a> {
        fn vsa_result(&self) -> &impl VsaResult<ValueDomain = PiData> {
            self.vsa_result
        }
    }

    impl<'a> AsRef<Project> for TestContext<'a> {
        fn as_ref(&self) -> &Project {
            self.project
        }
    }

    impl<'a> TaintAnalysis<'a> for TestContext<'a> {
        fn update_call_stub(&self, state: &State, call: &Term<Jmp>) -> Option<State> {
            self.update_call_generic(state, &call.tid, &None)
        }
    }

    #[test]
    fn update_def() {
        let project = Project::mock_x64();
        let (state, pi_state) = State::mock_with_pi_state();
        let address_at_def = Some(pi_state.eval(&expr!("RSP:8")));
        let pi_results = MockVsaResult::new(pi_state, address_at_def, None, None);
        let context = TestContext {
            project: &project,
            vsa_result: &pi_results,
        };

        // Test that taint state is updated correctly on assignments.
        let assign_def = def!["def: RCX:8 = RAX:8"];
        let result = <TestContext as forward_interprocedural_fixpoint::Context>::update_def(
            &context,
            &state,
            &assign_def,
        )
        .unwrap();
        assert!(result.eval(&expr!("RCX:8")).is_tainted());
        assert!(result.eval(&expr!("RSP:8")).is_top());

        // Test that taint state is updated correctly on loads.
        let load_def = def!["def: RCX:8 := Load from RSP:8"];
        let result = <TestContext as forward_interprocedural_fixpoint::Context>::update_def(
            &context, &state, &load_def,
        )
        .unwrap();
        assert!(result.eval(&expr!("RCX:8")).is_tainted());
        assert!(result.eval(&expr!("RSP:8")).is_top());

        // Test that taint state is updated correctly on stores.
        let store_def = def!["def: Store at RSP:8 := RCX:8"];
        let result = <TestContext as forward_interprocedural_fixpoint::Context>::update_def(
            &context, &state, &store_def,
        )
        .unwrap();
        let result = <TestContext as forward_interprocedural_fixpoint::Context>::update_def(
            &context, &result, &load_def,
        )
        .unwrap();
        assert!(result.eval(&expr!("RCX:8")).is_top());
    }
}
