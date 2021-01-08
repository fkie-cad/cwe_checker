use crate::{bil::Bitvector, intermediate_representation::*};

use super::{create_computation, mock_context, NodeValue};

use mock_context::Context;
use mock_context::StartEnd;

fn mock_program() -> Term<Program> {
    let var = Variable {
        name: String::from("RAX"),
        size: ByteSize::new(8),
        is_temp: false,
    };
    let value = Expression::UnOp {
        op: UnOpType::IntNegate,
        arg: Box::new(Expression::Var(var.clone())),
    };
    let def_term1 = Term {
        tid: Tid::new("def1".to_string()),
        term: Def::Assign {
            var: var.clone(),
            value: value.clone(),
        },
    };
    let def_term2 = Term {
        tid: Tid::new("def2".to_string()),
        term: Def::Assign {
            var: var.clone(),
            value: value.clone(),
        },
    };
    let def_term3 = Term {
        tid: Tid::new("def3".to_string()),
        term: Def::Assign {
            var: var.clone(),
            value: value.clone(),
        },
    };
    let def_term4 = Term {
        tid: Tid::new("def4".to_string()),
        term: Def::Assign {
            var: var.clone(),
            value: value.clone(),
        },
    };
    let def_term5 = Term {
        tid: Tid::new("def5".to_string()),
        term: Def::Assign {
            var: var.clone(),
            value: value.clone(),
        },
    };
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
            defs: vec![def_term1],
            jmps: vec![call_term],
        },
    };
    let sub1_blk2 = Term {
        tid: Tid::new("sub1_blk2"),
        term: Blk {
            defs: vec![def_term5],
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
            defs: vec![def_term2, def_term3],
            jmps: vec![cond_jump_term, jump_term_2],
        },
    };
    let sub2_blk2 = Term {
        tid: Tid::new("sub2_blk2"),
        term: Blk {
            defs: vec![def_term4],
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
fn backward_fixpoint() {
    let project = Project {
        program: mock_program(),
        cpu_architecture: String::from("x86"),
        stack_pointer_register: Variable {
            name: String::from("RSP"),
            size: ByteSize::new(8),
            is_temp: false,
        },
        calling_conventions: Vec::new(),
    };

    let mock_con = Context::new(&project);
    let mut computation = create_computation(mock_con.clone(), None);
    computation.set_node_value(
        *mock_con
            .tid_to_node_index
            .get(&(Tid::new("sub1"), Tid::new("sub1_blk1"), StartEnd::Start))
            .unwrap(),
        NodeValue::Value(0),
    );
    computation.compute_with_max_steps(100);

    // The fixpoint values of all 12 BlockStart/BlockEnd nodes are compared with their expected value
    assert_eq!(
        *computation
            .get_node_value(
                *mock_con
                    .tid_to_node_index
                    .get(&(Tid::new("sub1"), Tid::new("sub1_blk1"), StartEnd::Start))
                    .unwrap()
            )
            .unwrap()
            .unwrap_value(),
        0 as u64
    );
    assert_eq!(
        *computation
            .get_node_value(
                *mock_con
                    .tid_to_node_index
                    .get(&(Tid::new("sub1"), Tid::new("sub1_blk1"), StartEnd::End))
                    .unwrap()
            )
            .unwrap()
            .unwrap_value(),
        1 as u64
    );
    assert_eq!(
        *computation
            .get_node_value(
                *mock_con
                    .tid_to_node_index
                    .get(&(Tid::new("sub1"), Tid::new("sub1_blk2"), StartEnd::Start))
                    .unwrap()
            )
            .unwrap()
            .unwrap_value(),
        1 as u64
    );
    assert_eq!(
        *computation
            .get_node_value(
                *mock_con
                    .tid_to_node_index
                    .get(&(Tid::new("sub1"), Tid::new("sub1_blk2"), StartEnd::End))
                    .unwrap()
            )
            .unwrap()
            .unwrap_value(),
        0 as u64
    );
    assert_eq!(
        *computation
            .get_node_value(
                *mock_con
                    .tid_to_node_index
                    .get(&(Tid::new("sub2"), Tid::new("sub2_blk1"), StartEnd::Start))
                    .unwrap()
            )
            .unwrap()
            .unwrap_value(),
        4 as u64
    );
    assert_eq!(
        *computation
            .get_node_value(
                *mock_con
                    .tid_to_node_index
                    .get(&(Tid::new("sub2"), Tid::new("sub2_blk1"), StartEnd::End))
                    .unwrap()
            )
            .unwrap()
            .unwrap_value(),
        2 as u64
    );
    assert_eq!(
        *computation
            .get_node_value(
                *mock_con
                    .tid_to_node_index
                    .get(&(Tid::new("sub2"), Tid::new("sub2_blk2"), StartEnd::Start))
                    .unwrap()
            )
            .unwrap()
            .unwrap_value(),
        2 as u64
    );
    assert_eq!(
        *computation
            .get_node_value(
                *mock_con
                    .tid_to_node_index
                    .get(&(Tid::new("sub2"), Tid::new("sub2_blk2"), StartEnd::End))
                    .unwrap()
            )
            .unwrap()
            .unwrap_value(),
        1 as u64
    );
    assert_eq!(
        *computation
            .get_node_value(
                *mock_con
                    .tid_to_node_index
                    .get(&(Tid::new("sub2"), Tid::new("sub1_blk1"), StartEnd::Start))
                    .unwrap()
            )
            .unwrap()
            .unwrap_value(),
        5 as u64
    );
    assert_eq!(
        *computation
            .get_node_value(
                *mock_con
                    .tid_to_node_index
                    .get(&(Tid::new("sub2"), Tid::new("sub1_blk1"), StartEnd::End))
                    .unwrap()
            )
            .unwrap()
            .unwrap_value(),
        4 as u64
    );
    assert_eq!(
        *computation
            .get_node_value(
                *mock_con
                    .tid_to_node_index
                    .get(&(Tid::new("sub2"), Tid::new("sub1_blk2"), StartEnd::Start))
                    .unwrap()
            )
            .unwrap()
            .unwrap_value(),
        6 as u64
    );
    assert_eq!(
        *computation
            .get_node_value(
                *mock_con
                    .tid_to_node_index
                    .get(&(Tid::new("sub2"), Tid::new("sub1_blk2"), StartEnd::End))
                    .unwrap()
            )
            .unwrap()
            .unwrap_value(),
        5 as u64
    );
}
