use crate::{def, defs, intermediate_representation::*};

fn mock_defs_for_sprintf(format_known: bool, blk_num: usize) -> Vec<Term<Def>> {
    /*
        r11 = INT_ADD sp, 4:4
        r12 = COPY 0x3002:4
        r0 = INT_SUB r11, 0x58:4   // Destination string pointer
        r1 = COPY 0x6000:4    // Constant format string
        OR
        r1 = INT_SUB r11, 0x62:4   // Variable format string
        r2 = INT_ADD sp, 24:4    // Variable input in register
        r3 = INT_ADD sp, 16:4      // Variable input in register
        $U1050:4 = INT_ADD sp, 0:4    // Constant string input 'Hello World' on stack
        STORE ram($U1050:4), r12
        r12 = INT_ADD r11, 0x66:4
        $U1050:4 = INT_ADD sp, 4:4 // Second variable input on stack
        STORE ram($U1050:4), r12
    */

    let mut defs = defs![
        format!("def_0_blk_{}: r11:4 = sp:4 + 0x4:4", blk_num),
        format!("def_1_blk_{}: r12:4 = 0x3002:4", blk_num),
        format!("def_2_blk_{}: r0:4 = r11:4 - 0x58:4", blk_num)
    ];

    if format_known {
        defs.append(defs![&format!("def_3_blk_{}: r1:4 = 0x6000:4", blk_num)].as_mut());
    } else {
        defs.append(defs![&format!("def_3_blk_{}: r1:4 = r11:4 - 0x62:4", blk_num)].as_mut());
    }

    defs.append(
        defs![
            &format!("def_4_blk_{}: r2:4 = sp:4 + 0x18:4", blk_num),
            &format!("def_5_blk_{}: r3:4 = sp:4 + 0x10:4", blk_num)
        ]
        .as_mut(),
    );

    defs.push(Def::pointer_plus_offset_to_temp_var(
        &format!("def_6_blk_{}", blk_num),
        "$U1050",
        "sp",
        0,
    ));
    defs.push(Def::store_var_content_at_temp_var(
        &format!("def_7_blk_{}", blk_num),
        "$U1050",
        "r12",
    ));

    defs.push(def![&format!(
        "def_8_blk_{}: r12:4 = r11:4 + 0x66:4",
        blk_num
    )]);

    defs.push(Def::pointer_plus_offset_to_temp_var(
        &format!("def_9_blk_{}", blk_num),
        "$U1050",
        "sp",
        4,
    ));
    defs.push(Def::store_var_content_at_temp_var(
        &format!("def_10_blk_{}", blk_num),
        "$U1050",
        "r12",
    ));

    defs
}

fn mock_defs_for_scanf(format_known: bool, blk_num: usize) -> Vec<Term<Def>> {
    /*
       r11 = INT_ADD sp, 4:4
       r0 = INT_SUB r11, 0x3c:4
       $U1050 = INT_ADD sp, 0:4
       STORE ram($U1050:4), r0  - variable output 4
       r3 = INT_SUB r11, 0x50:4 - variable output 3
       r2 = INT_SUB r11, 0x62:4 - variable output 2
       r1 = INT_SUB r11, 0x78:4 - variable output 1
       r0 = LOAD ram(0x6000)    - constant format string
       OR
       r0 = INT_SUB r11, 0x82:4 - variable format string
    */

    let mut defs = defs![
        format!("def_0_blk_{}: r11:4 = sp:4 + 4:4", blk_num),
        format!("def_1_blk_{}: r0:4 = r11:4 - 0x3c:4", blk_num)
    ];

    defs.push(Def::pointer_plus_offset_to_temp_var(
        &format!("def_2_blk_{}", blk_num),
        "$U1050",
        "sp",
        0,
    ));

    defs.push(Def::store_var_content_at_temp_var(
        &format!("def_3_blk_{}", blk_num),
        "$U1050",
        "r0",
    ));
    defs.append(
        defs![
            format!("def_4_blk_{}: r3:4 = r11:4 - 0x50:4", blk_num),
            format!("def_5_blk_{}: r2:4 = r11:4 - 0x62:4", blk_num),
            format!("def_6_blk_{}: r1:4 = r11:4 - 0x78:4", blk_num)
        ]
        .as_mut(),
    );

    if format_known {
        defs.push(def![format!("def_7_blk_{}: r0:4 = 0x6000:4", blk_num)]);
    } else {
        defs.push(def![format!(
            "def_7_blk_{}: r0:4 = r11:4 - 0x82:4",
            blk_num
        )]);
    }

    defs
}

fn mock_defs_for_sscanf(source_known: bool, format_known: bool, blk_num: usize) -> Vec<Term<Def>> {
    /*
       r11 = INT_ADD sp, 4:4
       r3 = INT_SUB r11, 0x96:4

       $U1050:4 = INT_ADD sp, 0:4
       STORE ram($U1050), r3       - variable string input 3

       r3 = INT_SUB r11, 0x88:4

       $U1050:4 = INT_ADD sp, 4:4
       STORE ram($U1050), r3       - variable string input 4

       r3 = INT_SUB r11, 0x6c:4    - variable string input 2

       r2 = INT_SUB r11, 0x80:4    - variable string input 1

       r1 = LOAD ram(0x6000)       - constant format string
       OR
       r1 = INT_SUB r11, 0x40:4    - variable format string

       r0 = LOAD ram(0x7000)       - constant source string
       OR
       r0 = INT_SUB r11, 048:4     - variable source string

    */
    let mut defs = defs![
        format!("def_0_blk_{}: r11:4 = sp:4 + 4:4", blk_num),
        format!("def_1_blk_{}: r3:4 = r11:4 - 0x96:4", blk_num)
    ];

    defs.push(Def::pointer_plus_offset_to_temp_var(
        &format!("def_2_blk_{}", blk_num),
        "$U1050",
        "sp",
        0,
    ));

    defs.push(Def::store_var_content_at_temp_var(
        &format!("def_3_blk_{}", blk_num),
        "$U1050",
        "r3",
    ));

    defs.push(def![format!(
        "def_4_blk_{}: r3:4 = r11:4 - 0x88:4",
        blk_num
    )]);

    defs.push(Def::pointer_plus_offset_to_temp_var(
        &format!("def_5_blk_{}", blk_num),
        "$U1050",
        "sp",
        4,
    ));
    defs.push(Def::store_var_content_at_temp_var(
        &format!("def_6_blk_{}", blk_num),
        "$U1050",
        "r3",
    ));

    defs.append(
        defs![
            format!("def_7_blk_{}: r3:4 = r11:4 - 0x6c:4", blk_num),
            format!("def_8_blk_{}: r2:4 = r11:4 - 0x80:4", blk_num)
        ]
        .as_mut(),
    );

    if format_known {
        defs.push(def![format!("def_9_blk_{}: r1:4 = 0x6000:4", blk_num)]);
    } else {
        defs.push(def![format!(
            "def_9_blk_{}: r1:4 = r11:4 - 0x40:4",
            blk_num
        )]);
    }

    if source_known {
        defs.push(def![format!("def_10_blk_{}: r0:4 = 0x7000:4", blk_num)]);
    } else {
        defs.push(def![format!(
            "def_10_blk_{}: r0:4 = r11:4 - 0x48:4",
            blk_num
        )]);
    }

    defs
}

fn mock_defs_for_strcat(second_input_known: bool, blk_num: usize) -> Vec<Term<Def>> {
    /*
        r11 = INT_ADD sp, 4:4
        r0 = INT_SUB r11, 40:4,
            r1 = LOAD ram(0x7000)

            OR

            r1 = INT_ADD r11, 0x24:4
    */
    let mut def = defs![
        format!("def_0_blk_{}: r11:4 = sp:4 + 4:4", blk_num),
        format!("def_1_blk_{}: r0:4 = r11:4 - 0x40:4", blk_num)
    ];

    if second_input_known {
        def.push(def![format!("def_2_blk_{}: r1:4 = 0x7000:4", blk_num)]);
    } else {
        def.push(def![format!(
            "def_3_blk_{}: r1:4 = r11:4 + 0x24:4",
            blk_num
        )]);
    }
    def
}

fn mock_defs_for_malloc(blk_num: usize) -> Vec<Term<Def>> {
    /*
        r0 = COPY 0xf
    */
    defs![format!("def_0_blk_{}: r0:4 = 0xf:4", blk_num)]
}

fn mock_defs_for_memcpy(copy_from_global: bool, blk_num: usize) -> Vec<Term<Def>> {
    /*
        r11 = INT_ADD sp, 4:4
        r0 = INT_SUB r11, 0x40:4,
            r1 = LOAD ram(0x7000)
            OR
            r1 = INT_ADD r11, 0x24:4
    */
    let mut def = defs![
        format!("def_0_blk_{}: r11:4 = sp:4 + 4:4", blk_num),
        format!("def_1_blk_{}: r0:4 = r11:4 - 0x40:4", blk_num)
    ];

    if copy_from_global {
        def.push(def![format!("def_2_blk_{}: r1:4 = 0x7000:4", blk_num)]);
    } else {
        def.push(def![format!(
            "def_3_blk_{}: r1:4 = r11:4 + 0x24:4",
            blk_num
        )])
    }
    def
}

impl ExternSymbol {
    pub fn mock_memcpy_symbol_arm() -> ExternSymbol {
        let mut ex = ExternSymbol::create_extern_symbol(
            "memcpy",
            CallingConvention::mock_arm32(),
            None,
            None,
        );
        ex.parameters = vec![
            Arg::mock_register("r0", 4),
            Arg::mock_register("r1", 4),
            Arg::mock_register("r2", 4),
        ];
        ex
    }

    pub fn mock_sprintf_symbol_arm() -> ExternSymbol {
        let mut ex = ExternSymbol::create_extern_symbol(
            "sprintf",
            CallingConvention::mock_arm32(),
            None,
            None,
        );
        ex.parameters = vec![Arg::mock_register("r0", 4), Arg::mock_register("r1", 4)];
        ex
    }

    pub fn mock_scanf_symbol_arm() -> ExternSymbol {
        ExternSymbol::create_extern_symbol(
            "scanf",
            CallingConvention::mock_arm32(),
            Some(Datatype::Pointer),
            Some(Datatype::Integer),
        )
    }

    pub fn mock_sscanf_symbol_arm() -> ExternSymbol {
        let mut ex = ExternSymbol::create_extern_symbol(
            "sscanf",
            CallingConvention::mock_arm32(),
            None,
            None,
        );
        ex.parameters = vec![Arg::mock_register("r0", 4), Arg::mock_register("r1", 4)];
        ex
    }

    pub fn mock_strcat_symbol_arm() -> ExternSymbol {
        let mut ex = ExternSymbol::create_extern_symbol(
            "strcat",
            CallingConvention::mock_arm32(),
            None,
            None,
        );
        ex.parameters = vec![Arg::mock_register("r0", 4), Arg::mock_register("r1", 4)];
        ex
    }

    pub fn mock_free_symbol_arm() -> ExternSymbol {
        ExternSymbol::create_extern_symbol(
            "free",
            CallingConvention::mock_arm32(),
            Some(Datatype::Pointer),
            None,
        )
    }

    pub fn mock_malloc_symbol_arm() -> ExternSymbol {
        ExternSymbol::create_extern_symbol(
            "malloc",
            CallingConvention::mock_arm32(),
            Some(Datatype::Integer),
            Some(Datatype::Pointer),
        )
    }
}

fn mock_abstract_string_call_to_external_function(
    sub_name: &str,
    symbol_name: &str,
    blk_num: usize,
) -> Term<Jmp> {
    let call_tid = format!("{}_{}_{}", sub_name, symbol_name, blk_num);
    Jmp::call(
        &call_tid,
        &symbol_name,
        Some(&format!("block{}", blk_num + 1)),
    )
}

fn mock_block_with_function_call(
    sub_name: &str,
    symbol_name: &str,
    config: &Vec<bool>,
    blk_num: usize,
) -> Term<Blk> {
    let mut blk = Blk::mock();
    blk.tid = Tid::new(format!("block{}", blk_num));
    let call = mock_abstract_string_call_to_external_function(sub_name, symbol_name, blk_num);
    let defs: Vec<Term<Def>> = match symbol_name {
        "sprintf" => mock_defs_for_sprintf(*config.get(0).unwrap(), blk_num),
        "scanf" => mock_defs_for_scanf(*config.get(0).unwrap(), blk_num),
        "sscanf" => mock_defs_for_sscanf(*config.get(0).unwrap(), *config.get(1).unwrap(), blk_num),
        "strcat" => mock_defs_for_strcat(*config.get(0).unwrap(), blk_num),
        "free" => vec![],
        "malloc" => mock_defs_for_malloc(blk_num),
        "memcpy" => mock_defs_for_memcpy(*config.get(0).unwrap(), blk_num),
        _ => panic!("Invalid symbol name for def mock"),
    };
    blk.term.defs = defs;
    blk.term.jmps.push(call);

    blk
}

fn mock_sub_with_name_and_symbol_calls(
    name: &str,
    symbols: Vec<(ExternSymbol, Vec<bool>)>,
) -> Term<Sub> {
    let mut sub = Sub::mock(name);
    let mut last_blk_num = 0;

    for (blk_num, (symbol, config)) in symbols.iter().enumerate() {
        sub.term.blocks.push(mock_block_with_function_call(
            &sub.term.name,
            &symbol.name,
            config,
            blk_num,
        ));

        last_blk_num = blk_num;
    }

    let mut empty_blk = Blk::mock();
    empty_blk.tid = Tid::new(format!("block{}", last_blk_num + 1));
    sub.term.blocks.push(empty_blk);

    sub
}

pub fn mock_project_with_intraprocedural_control_flow(
    symbol_call_config: Vec<(ExternSymbol, Vec<bool>)>,
    sub_name: &str,
) -> Project {
    let mut program = Program::mock_arm32();
    let mocked_sub = mock_sub_with_name_and_symbol_calls(sub_name, symbol_call_config);

    program.subs.insert(mocked_sub.tid.clone(), mocked_sub);
    let memcpy = ExternSymbol::mock_memcpy_symbol_arm();
    program.extern_symbols.insert(memcpy.tid.clone(), memcpy);
    let sprintf = ExternSymbol::mock_sprintf_symbol_arm();
    program.extern_symbols.insert(sprintf.tid.clone(), sprintf);
    let scanf = ExternSymbol::mock_scanf_symbol_arm();
    program.extern_symbols.insert(scanf.tid.clone(), scanf);
    let sscanf = ExternSymbol::mock_sscanf_symbol_arm();
    program.extern_symbols.insert(sscanf.tid.clone(), sscanf);
    let strcat = ExternSymbol::mock_strcat_symbol_arm();
    program.extern_symbols.insert(strcat.tid.clone(), strcat);
    let free = ExternSymbol::mock_free_symbol_arm();
    program.extern_symbols.insert(free.tid.clone(), free);
    let malloc = ExternSymbol::mock_malloc_symbol_arm();
    program.extern_symbols.insert(malloc.tid.clone(), malloc);
    program.entry_points.insert(Tid::new(sub_name));

    let mut project = Project::mock_arm32();
    project.program.term = program;
    project
}
