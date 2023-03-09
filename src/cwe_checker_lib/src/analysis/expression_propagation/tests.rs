use super::*;
use crate::{defs, expr, intermediate_representation::Def, variable};

/// Creates a specific project containing three blocks for expression propagation tests.
///
/// The program consisting of two functions and three blocks is build up bottom-up.
/// Function "main" consists of blocks "entry_block" and "entry_jmp_block", whereby
/// "entry_block" is the first reached block and contains a jump to "entry_jmp_block".
/// The latter contains a call to function "called_function", which contains only the
/// block "callee_block".
fn mock_project() -> Project {
    let callee_block = Term {
        tid: Tid::new("callee_block"),
        term: Blk {
            defs: defs!["callee_def_1: Y:8 = Z:8"],
            jmps: Vec::new(),
            indirect_jmp_targets: Vec::new(),
        },
    };

    let called_function = Term {
        tid: Tid::new("called_function"),
        term: Sub {
            name: "called_function".to_string(),
            blocks: vec![callee_block],
            calling_convention: Some("_stdcall".to_string()),
        },
    };

    let entry_jmp_block = Term {
        tid: Tid::new("entry_jmp_block"),
        term: Blk {
            defs: defs![
                "entry_jmp_def_1: X:8 = ¬(Z:8)",
                "entry_jmp_def_2: Z:8 = -(Z:8)"
            ],
            jmps: vec![Term {
                tid: Tid::new("call_to_called_function"),
                term: Jmp::Call {
                    target: called_function.tid.clone(),
                    return_: None,
                },
            }],
            indirect_jmp_targets: Vec::new(),
        },
    };

    let mut entry_block = get_mock_entry_block();
    entry_block.term.jmps = vec![Term {
        tid: Tid::new("jmp_to_entry_jmp_blk"),
        term: Jmp::Branch(entry_jmp_block.tid.clone()),
    }];

    let mut project = Project::mock_x64();
    let sub1 = Term {
        tid: Tid::new("main"),
        term: Sub {
            name: "main".to_string(),
            blocks: vec![entry_block, entry_jmp_block],
            calling_convention: Some("_stdcall".to_string()),
        },
    };

    project
        .program
        .term
        .subs
        .insert(sub1.tid.clone(), sub1.clone());
    project
        .program
        .term
        .subs
        .insert(called_function.tid.clone(), called_function.clone());

    project
}

/// Assembles a specific basic block for the mock project and other test cases.
fn get_mock_entry_block() -> Term<Blk> {
    Term {
        tid: Tid::new("entry_block"),
        term: Blk {
            defs: defs![
                "tid_1: Z:8 = -(42:4)",
                "tid_2: X:8 = -(Y:8)",
                "tid_3: Y:8 = X:8 + Y:8",
                "tid_4: X:8 = -(X:8)",
                "tid_5: Y:8 = -(Y:8)",
                "tid_6: Y:8 = X:8 + Y:8"
            ],
            jmps: Vec::new(),
            indirect_jmp_targets: Vec::new(),
        },
    }
}

#[test]
fn expression_propagation() {
    use super::*;

    let defs = defs![
        "tid_1: X:8 = -(Y:8)",
        "tid_2: Y:8 = X:8 + Y:8",
        "tid_3: X:8 = -(X:8)",
        "tid_4: Y:8 = -(Y:8)",
        "tid_5: Y:8 = X:8 + Y:8"
    ];

    let block = &mut Blk::mock();
    block.term.defs = defs;

    merge_def_assignments_to_same_var(block);
    propagate_input_expressions(block, None);
    let result_defs = defs![
        "tid_1: X:8 = -(Y:8)",
        "tid_2: Y:8 = -(Y:8) + Y:8",
        "tid_3: X:8 = -(X:8)",
        "tid_5: Y:8 = X:8 + -(Y:8)"
    ];
    assert_eq!(block.term.defs, result_defs);
}

#[test]
/// Tests the propagation of insertable expressions among basic blocks.
fn inter_block_propagation() {
    let mut project = mock_project();
    propagate_input_expression(&mut project);
    assert_eq!(
        project
            .program
            .term
            .subs
            .get(&Tid::new("main"))
            .unwrap()
            .term
            .blocks[1]
            .term
            .defs,
        vec![
            Def::assign(
                "entry_jmp_def_1",
                variable!("X:8"),
                expr!("-(42:4)").un_op(UnOpType::BoolNegate),
            ),
            Def::assign(
                "entry_jmp_def_2",
                variable!("Z:8"),
                expr!("-(42:4)").un_op(UnOpType::IntNegate),
            )
        ]
    )
}
#[test]
/// Tests if the propagation is intra-function only.
///
/// The expression of the callee_block is replaceable, but
/// within another function.
fn no_propagation_on_calls() {
    let mut project = mock_project();
    propagate_input_expression(&mut project);

    assert_eq!(
        project
            .program
            .term
            .find_block(&Tid::new("callee_block"))
            .unwrap()
            .term
            .defs,
        defs!["callee_def_1: Y:8 = Z:8"]
    )
}
#[test]
/// Tests if defs are handled correctly by: adding variable-expressions pairs,
/// checking supplementation with prior expressions and removing invalid
/// variable-expressions pairs.
fn insertion_table_update() {
    let project = &mock_project();
    let graph = crate::analysis::graph::get_program_cfg(&project.program);
    let context = Context::new(&graph);

    let blk = get_mock_entry_block().term;
    let update = crate::analysis::forward_interprocedural_fixpoint::Context::update_def(
        &context,
        &HashMap::new(),
        &blk.defs[0],
    );
    // Assignment is inserted into table, no other changes.
    assert_eq!(
        update.clone().unwrap(),
        HashMap::from([(variable!("Z:8"), expr!("-(42:4)"))])
    );

    let update = crate::analysis::forward_interprocedural_fixpoint::Context::update_def(
        &context,
        &update.unwrap(),
        &blk.defs[1],
    );
    // Assignment is inserted into table, no other changes.
    assert_eq!(
        update.clone().unwrap(),
        HashMap::from([
            (variable!("Z:8"), expr!("-(42:4)")),
            (variable!("X:8"), expr!("-(Y:8)"))
        ])
    );

    let update = crate::analysis::forward_interprocedural_fixpoint::Context::update_def(
        &context,
        &update.unwrap(),
        &blk.defs[2],
    );
    // Expression for X is removed and Assignment is not inserted.
    assert_eq!(
        update.clone().unwrap(),
        HashMap::from([(variable!("Z:8"), expr!("-(42:4)")),])
    );
    let update = crate::analysis::forward_interprocedural_fixpoint::Context::update_def(
        &context,
        &update.unwrap(),
        &blk.defs[3],
    );
    // Expression for Y is removed and Assignment is not inserted.
    assert_eq!(
        update.clone().unwrap(),
        HashMap::from([(variable!("Z:8"), expr!("-(42:4)")),])
    );

    let update = crate::analysis::forward_interprocedural_fixpoint::Context::update_def(
        &context,
        &update.unwrap(),
        &blk.defs[4],
    );
    // Assignment not inserted.
    assert_eq!(
        update.clone().unwrap(),
        HashMap::from([(variable!("Z:8"), expr!("-(42:4)")),])
    );

    let update = crate::analysis::forward_interprocedural_fixpoint::Context::update_def(
        &context,
        &update.unwrap(),
        &blk.defs[5],
    );
    // Assignment not inserted.
    assert_eq!(
        update.clone().unwrap(),
        HashMap::from([(variable!("Z:8"), expr!("-(42:4)")),])
    );
}
#[test]
/// Tests the correct insertion of propagational expressions.
fn expressions_inserted() {
    let mut project = mock_project();
    propagate_input_expression(&mut project);
    let result_def_entry_block = defs![
        "tid_1: Z:8 = -(42:4)",
        "tid_2: X:8 = -(Y:8)",
        "tid_3: Y:8 = -(Y:8) + Y:8",
        "tid_4: X:8 = -(X:8)",
        "tid_6: Y:8 = X:8 + -(Y:8)"
    ];
    assert_eq!(
        project
            .program
            .term
            .subs
            .get(&Tid::new("main"))
            .unwrap()
            .term
            .blocks[0]
            .term
            .defs,
        result_def_entry_block
    );
    assert_eq!(
        project
            .program
            .term
            .subs
            .get(&Tid::new("main"))
            .unwrap()
            .term
            .blocks[1]
            .term
            .defs,
        vec![
            Def::assign(
                "entry_jmp_def_1",
                variable!("X:8"),
                expr!("-(42:4)").un_op(UnOpType::BoolNegate),
            ),
            Def::assign(
                "entry_jmp_def_2",
                variable!("Z:8"),
                expr!("-(42:4)").un_op(UnOpType::IntNegate)
            )
        ]
    );
    assert_eq!(
        project
            .program
            .term
            .subs
            .get(&Tid::new("called_function"))
            .unwrap()
            .term
            .blocks[0]
            .term
            .defs,
        defs!["callee_def_1: Y:8 = Z:8"]
    );
}
