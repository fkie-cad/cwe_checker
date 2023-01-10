use super::{create_computation, mock_context, NodeValue};
use crate::def;
use crate::expr;
use crate::intermediate_representation::*;
use mock_context::Context;
use mock_context::StartEnd;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::iter::FromIterator;

fn mock_program() -> Term<Program> {
    let def_term1 = def!["def1: RAX:8 = -(RAX:8)"];
    let def_term2 = def!["def2: RAX:8 = -(RAX:8)"];
    let def_term3 = def!["def3: RAX:8 = -(RAX:8)"];
    let def_term4 = def!["def4: RAX:8 = -(RAX:8)"];
    let def_term5 = def!["def5: RAX:8 = -(RAX:8)"];

    let call_term = Term {
        tid: Tid::new("call".to_string()),
        term: Jmp::Call {
            target: Tid::new("sub2"),
            return_: Some(Tid::new("sub1_blk2")),
        },
    };
    let return_term = Term {
        tid: Tid::new("return".to_string()),
        term: Jmp::Return(expr!("0:8")), // The return term does not matter
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
            indirect_jmp_targets: Vec::new(),
        },
    };
    let sub1_blk2 = Term {
        tid: Tid::new("sub1_blk2"),
        term: Blk {
            defs: vec![def_term5],
            jmps: vec![jmp_term],
            indirect_jmp_targets: Vec::new(),
        },
    };
    let sub1 = Term {
        tid: Tid::new("sub1"),
        term: Sub {
            name: "sub1".to_string(),
            blocks: vec![sub1_blk1, sub1_blk2],
            calling_convention: None,
        },
    };
    let cond_jump = Jmp::CBranch {
        target: Tid::new("sub1_blk1"),
        condition: expr!("0:1"),
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
            indirect_jmp_targets: Vec::new(),
        },
    };
    let sub2_blk2 = Term {
        tid: Tid::new("sub2_blk2"),
        term: Blk {
            defs: vec![def_term4],
            jmps: vec![return_term],
            indirect_jmp_targets: Vec::new(),
        },
    };
    let sub2 = Term {
        tid: Tid::new("sub2"),
        term: Sub {
            name: "sub2".to_string(),
            blocks: vec![sub2_blk1, sub2_blk2],
            calling_convention: None,
        },
    };
    let program = Term {
        tid: Tid::new("program"),
        term: Program {
            subs: BTreeMap::from_iter([(sub1.tid.clone(), sub1), (sub2.tid.clone(), sub2)]),
            extern_symbols: BTreeMap::new(),
            entry_points: BTreeSet::new(),
            address_base_offset: 0,
        },
    };
    program
}

#[test]
fn backward_fixpoint() {
    let mut project = Project::mock_x64();
    project.program = mock_program();

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
