use super::prelude::*;

use crate::intermediate_representation::{Arg as IrArg, ByteSize, Expression as IrExpression};

const APPLICABLE_SYMBOLS: [&str; 4] = ["scanf", "sscanf", "__isoc99_scanf", "__isoc99_sscanf"];
const SSCANF_SYMBOLS: [&str; 2] = ["sscanf", "__isoc99_sscanf"];

pub const DOMAIN_KNOWLEDGE: ExternalSymbolDomainKnowledge = ExternalSymbolDomainKnowledge {
    applicable_symbols: &APPLICABLE_SYMBOLS,
    apply_domain_knowledge_fp: apply_domain_knowledge_to,
};

fn apply_domain_knowledge_to(
    ir_extern_symbol: &mut IrExternSymbol,
    pcode_project: &PcodeProject,
) -> bool {
    let should_stop = true;

    ir_extern_symbol.no_return = false;
    ir_extern_symbol.has_var_args = true;

    if ir_extern_symbol.parameters.is_empty() {
        let ir_expr_sp = pcode_project.stack_pointer_register.to_ir_expr();
        let cconv = pcode_project
            .calling_conventions
            .get(ir_extern_symbol.calling_convention.as_ref().unwrap())
            .unwrap();
        let num_params = if SSCANF_SYMBOLS.contains(&ir_extern_symbol.name.as_str()) {
            2
        } else {
            1
        };

        // TODO: Insert domain knowledge about parameter type.
        ir_extern_symbol.parameters = (0..num_params)
            .map(|idx| match cconv.get_integer_parameter_register(idx) {
                Some(register) => register.to_ir_arg(&ir_expr_sp),
                // Calling conventions without integer parameter registers,
                // e.g., x86 cdecl, pass all parameters on the stack.
                None => get_stack_param(idx, pcode_project, &ir_expr_sp),
            })
            .collect();
    }

    should_stop
}

/// Returns the `idx`th pointer-sized parameter passed on the stack.
///
/// On x86 the return address is pushed to the stack by the call instruction,
/// i.e., the parameters start after it.
fn get_stack_param(idx: usize, pcode_project: &PcodeProject, ir_expr_sp: &IrExpression) -> IrArg {
    let pointer_size = pcode_project.stack_pointer_register.size();
    let first_param_offset = if pcode_project.cpu_arch.starts_with("x86") {
        pointer_size
    } else {
        0
    };

    IrArg::Stack {
        address: ir_expr_sp
            .clone()
            .plus_const((first_param_offset + idx as u64 * pointer_size) as i64),
        size: ByteSize::new(pointer_size),
        data_type: None,
    }
}
