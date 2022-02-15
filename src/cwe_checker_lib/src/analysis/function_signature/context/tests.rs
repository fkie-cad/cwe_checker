use super::*;
use std::collections::HashSet;

#[test]
fn test_compute_return_values_of_call() {
    let project = Project::mock_empty();
    let cconv = CallingConvention::mock_x64();
    let graph = crate::analysis::graph::get_program_cfg(&project.program, HashSet::new());

    let context = Context::new(&project, &graph);

    let mut caller_state = State::mock_x64("caller");
    let mut callee_state = State::mock_x64("callee");
    let call = Term {
        tid: Tid::new("call_tid"),
        term: Jmp::Call {
            target: Tid::new("callee"),
            return_: Some(Tid::new("return_tid")),
        },
    };
    // Test returning a value of unknown origin (since RAX does not contain a reference to the input register).
    let return_values =
        context.compute_return_values_of_call(&mut caller_state, &callee_state, &cconv, &call);
    let expected_val = DataDomain::from_target(
        AbstractIdentifier::from_var(Tid::new("call_tid"), &Variable::mock("RAX", 8)),
        Bitvector::from_i64(0).into(),
    );
    assert_eq!(return_values.iter().len(), 3);
    assert_eq!(return_values[0], (&Variable::mock("RAX", 8), expected_val));
    // Test returning a known value.
    let param_ref = DataDomain::from_target(
        AbstractIdentifier::from_var(Tid::new("callee"), &Variable::mock("RDI", 8)),
        Bitvector::from_i64(0).into(),
    );
    callee_state.set_register(&Variable::mock("RAX", 8), param_ref);
    let expected_val = DataDomain::from_target(
        AbstractIdentifier::from_var(Tid::new("caller"), &Variable::mock("RDI", 8)),
        Bitvector::from_i64(0).into(),
    );
    let return_values =
        context.compute_return_values_of_call(&mut caller_state, &callee_state, &cconv, &call);
    assert_eq!(return_values.iter().len(), 3);
    assert_eq!(return_values[0], (&Variable::mock("RAX", 8), expected_val));
}
