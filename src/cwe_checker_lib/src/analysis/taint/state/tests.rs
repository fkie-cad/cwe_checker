use super::*;

use crate::analysis::graph::NodeIndex;
use crate::analysis::pointer_inference::{tests::MockVsaResult, State as PiState, ValueDomain};
use crate::{abstract_domain::*, expr, variable};

use std::collections::BTreeSet;

impl State {
    pub fn mock() -> State {
        State {
            register_taint: RegisterTaint::new(),
            memory_taint: MemoryTaint::new(),
        }
    }

    pub fn mock_with_pi_state() -> (State, PiState) {
        let ret1 = Arg::Register {
            expr: expr!("RAX:8"),
            data_type: None,
        };
        let ret2 = Arg::Stack {
            address: expr!("RSP:8"),
            size: ByteSize::new(8),
            data_type: None,
        };
        let symbol = ExternSymbol {
            tid: Tid::new("extern_symbol".to_string()),
            addresses: vec![],
            name: "extern_symbol".into(),
            calling_convention: None,
            parameters: Vec::new(),
            return_values: vec![ret1, ret2],
            no_return: false,
            has_var_args: false,
        };

        let pi_state = PiState::new(&variable!("RSP:8"), Tid::new("func"), BTreeSet::new());
        let vsa_result = MockVsaResult::new(pi_state.clone(), None, None, None);

        let state = State::new_return(&symbol, &vsa_result, NodeIndex::new(42));

        (state, pi_state)
    }
}

fn bv(value: i64) -> ValueDomain {
    ValueDomain::from(Bitvector::from_i64(value))
}

fn new_id(name: &str) -> AbstractIdentifier {
    AbstractIdentifier::new(
        Tid::new("time0"),
        AbstractLocation::Register(variable!(format!("{}:8", name))),
    )
}

fn new_pointer(location: &str, offset: i64) -> DataDomain<ValueDomain> {
    let id = new_id(location);
    DataDomain::from_target(id, bv(offset))
}

#[test]
fn merge_state() {
    let taint = Taint::Tainted(ByteSize::new(8));
    let top = Taint::Top(ByteSize::new(8));

    let mut state = State::mock();
    state.set_register_taint(&variable!("RAX:8"), taint.clone());

    let mut other_state = State::mock();
    let address = new_pointer("mem", 10);
    other_state.save_taint_to_memory(&address, taint);

    let merged_state = state.merge(&other_state);
    assert_eq!(
        merged_state.register_taint.get(&variable!("RAX:8")),
        Some(&taint)
    );
    assert_eq!(merged_state.register_taint.get(&variable!("RBX:8")), None);
    assert_eq!(
        merged_state.load_taint_from_memory(&address, ByteSize::new(8)),
        taint.clone()
    );
    let other_address = new_pointer("mem", 18);
    assert_eq!(
        merged_state.load_taint_from_memory(&other_address, ByteSize::new(8)),
        top.clone()
    );
}

#[test]
fn new_state() {
    let (state, pi_state) = State::mock_with_pi_state();
    let taint = Taint::Tainted(ByteSize::new(8));

    assert_eq!(state.register_taint.get(&variable!("RAX:8")), Some(&taint));
    assert_eq!(state.register_taint.get(&variable!("RSP:8")), None);
    let address = Expression::Var(variable!("RSP:8"));
    assert_eq!(
        state.load_taint_from_memory(&pi_state.eval(&address), ByteSize::new(8)),
        taint
    );
}

#[test]
fn eval_expression() {
    let (state, _pi_state) = State::mock_with_pi_state();

    let expr = expr!("RAX:8 + RBX:8");
    assert!(state.eval(&expr).is_tainted());

    let expr = Expression::UnOp {
        op: UnOpType::Int2Comp,
        arg: Box::new(Expression::Var(variable!("RSP:8"))),
    };
    assert!(state.eval(&expr).is_top());
}

#[test]
fn check_register_list_for_taint() {
    let (mut state, mut pi_state) = State::mock_with_pi_state();
    let mut vsa_results = MockVsaResult::new(pi_state.clone(), None, None, None);
    let taint = Taint::Tainted(ByteSize::new(8));
    let untainted = Taint::Top(ByteSize::new(8));
    let (rdi, rsi, rdx) = (variable!("RDI:8"), variable!("RSI:8"), variable!("RDX:8"));
    let address = new_pointer("mem", 10);
    let tid = Tid::new("foo".to_string());

    state.save_taint_to_memory(&address, taint);
    state.set_register_taint(&rdi, untainted);
    state.set_register_taint(&rsi, untainted);
    state.set_register_taint(&rdx, untainted);
    let register_list = [rdi.clone(), rsi, rdx];

    assert_eq!(
        state.check_register_list_for_taint::<true>(&vsa_results, &tid, &register_list),
        false
    );
    assert_eq!(
        state.check_register_list_for_taint::<false>(&vsa_results, &tid, &register_list),
        false
    );

    state.set_register_taint(&rdi, taint);
    assert_eq!(
        state.check_register_list_for_taint::<true>(&vsa_results, &tid, &register_list),
        true
    );
    assert_eq!(
        state.check_register_list_for_taint::<false>(&vsa_results, &tid, &register_list),
        true
    );

    state.set_register_taint(&rdi, untainted);
    pi_state.set_register(&rdi, address);
    vsa_results.set_state(pi_state.clone());
    assert_eq!(
        state.check_register_list_for_taint::<true>(&vsa_results, &tid, &register_list),
        true
    );
    assert_eq!(
        state.check_register_list_for_taint::<false>(&vsa_results, &tid, &register_list),
        false
    );
}

#[test]
fn check_extern_parameter_for_taint() {
    let (mut state, mut pi_state) = State::mock_with_pi_state();
    let mut vsa_results = MockVsaResult::new(pi_state.clone(), None, None, None);

    assert_eq!(
        state.check_extern_parameters_for_taint::<true>(
            &vsa_results,
            &ExternSymbol::mock_x64("mock_symbol"),
            &Tid::new("call".to_string()),
        ),
        false
    );

    state.set_register_taint(&variable!("RDI:8"), Taint::Tainted(ByteSize::new(8)));
    assert_eq!(
        state.check_extern_parameters_for_taint::<true>(
            &vsa_results,
            &ExternSymbol::mock_x64("mock_symbol"),
            &Tid::new("call".to_string()),
        ),
        true
    );

    let taint = Taint::Tainted(ByteSize::new(8));
    let address = new_pointer("mem", 10);
    state.save_taint_to_memory(&address, taint);
    state.set_register_taint(&variable!("RDI:8"), Taint::Top(ByteSize::new(8)));
    assert_eq!(
        state.check_extern_parameters_for_taint::<true>(
            &vsa_results,
            &ExternSymbol::mock_x64("mock_symbol"),
            &Tid::new("call".to_string()),
        ),
        false
    );

    pi_state.set_register(&variable!("RDI:8"), address);
    vsa_results.set_state(pi_state.clone());
    assert_eq!(
        state.check_extern_parameters_for_taint::<true>(
            &vsa_results,
            &ExternSymbol::mock_x64("mock_symbol"),
            &Tid::new("call".to_string()),
        ),
        true
    );
    assert_eq!(
        state.check_extern_parameters_for_taint::<false>(
            &vsa_results,
            &ExternSymbol::mock_x64("mock_symbol"),
            &Tid::new("call".to_string()),
        ),
        false
    );
}

#[test]
fn has_memory_taint() {
    let (mut state, pi_state) = State::mock_with_pi_state();
    let untainted = Taint::Top(ByteSize::new(8));
    let rsp = pi_state.eval(&expr!("RSP:8"));

    assert!(state.has_memory_taint());
    assert!(!state.memory_taint.is_empty());

    state.save_taint_to_memory(&rsp, untainted);

    assert!(!state.has_memory_taint());
    assert!(!state.memory_taint.is_empty());
}
