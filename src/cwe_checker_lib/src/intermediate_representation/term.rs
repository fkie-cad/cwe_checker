use super::{ByteSize, CastOpType, Datatype, DatatypeProperties, Expression, Variable};
use crate::prelude::*;
use crate::utils::log::LogMessage;
use std::collections::HashSet;

mod builder;

/// A term identifier consisting of an ID string (which is required to be unique)
/// and an address to indicate where the term is located.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, PartialOrd, Ord)]
pub struct Tid {
    /// The unique ID of the term.
    id: String,
    /// The address where the term is located.
    pub address: String,
}

impl Tid {
    /// Generate a new term identifier with the given ID string
    /// and with unknown address.
    pub fn new<T: ToString>(val: T) -> Tid {
        Tid {
            id: val.to_string(),
            address: "UNKNOWN".to_string(),
        }
    }

    /// Add a suffix to the ID string and return the new `Tid`
    pub fn with_id_suffix(self, suffix: &str) -> Self {
        Tid {
            id: self.id + suffix,
            address: self.address,
        }
    }

    /// Generate the ID of a block starting at the given address.
    ///
    /// Note that the block may not actually exist.
    /// For cases where one assembly instruction generates more than one block,
    /// the returned block ID is the one that would be executed first if a jump to the given address happened.
    pub fn blk_id_at_address(address: &str) -> Tid {
        Tid {
            id: format!("blk_{}", address),
            address: address.to_string(),
        }
    }
}

impl std::fmt::Display for Tid {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "{}", self.id)
    }
}

/// A term is an object inside a binary with an address and an unique ID (both contained in the `tid`).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Term<T> {
    /// The term identifier, which also contains the address of the term
    pub tid: Tid,
    /// The object
    pub term: T,
}

/// A side-effectful operation.
/// Can be a register assignment or a memory load/store operation.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Def {
    /// A memory load into the register given by `var`.
    Load {
        /// The target register of the memory load.
        /// The size of `var` also determines the number of bytes read from memory.
        var: Variable,
        /// The expression computing the address from which to read from.
        /// The size of `address` is required to match the pointer size of the corresponding CPU architecture.
        address: Expression,
    },
    /// A memory store operation.
    Store {
        /// The expression computing the address that is written to.
        /// The size of `address` is required to match the pointer size of the corresponding CPU architecture.
        address: Expression,
        /// The expression computing the value that is written to memory.
        /// The size of `value` also determines the number of bytes written.
        value: Expression,
    },
    /// A register assignment, assigning the result of the expression `value` to the register `var`.
    Assign {
        /// The register that is written to.
        var: Variable,
        /// The expression computing the value that is assigned to the register.
        value: Expression,
    },
}

impl Term<Def> {
    /// This function checks whether the instruction
    /// is a zero extension of the overwritten sub register of the previous instruction.
    /// If so, returns its TID
    pub fn check_for_zero_extension(
        &self,
        output_name: String,
        output_sub_register: String,
    ) -> Option<Tid> {
        match &self.term {
            Def::Assign {
                var,
                value:
                    Expression::Cast {
                        op: CastOpType::IntZExt,
                        arg,
                        ..
                    },
            } if output_name == var.name => {
                let argument: &Expression = arg;
                match argument {
                    Expression::Var(var) if var.name == output_sub_register => {
                        Some(self.tid.clone())
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Substitute every occurence of `input_var` in the address and value expressions
    /// with `replace_with_expression`.
    /// Does not change the target variable of assignment- and load-instructions.
    pub fn substitute_input_var(
        &mut self,
        input_var: &Variable,
        replace_with_expression: &Expression,
    ) {
        match &mut self.term {
            Def::Assign { var: _, value } => {
                value.substitute_input_var(input_var, replace_with_expression)
            }
            Def::Load { var: _, address } => {
                address.substitute_input_var(input_var, replace_with_expression)
            }
            Def::Store { address, value } => {
                address.substitute_input_var(input_var, replace_with_expression);
                value.substitute_input_var(input_var, replace_with_expression);
            }
        }
    }
}

/// A `Jmp` instruction affects the control flow of a program, i.e. it may change the instruction pointer.
/// With the exception of `CallOther`, it has no other side effects.
///
/// `Jmp` instructions carry some semantic information with it, like whether a jump is intra- or interprocedural.
/// Note that this semantic information may not always be correct.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Jmp {
    /// A direct intraprocedural jump to the targeted `Blk` term identifier.
    Branch(Tid),
    /// An indirect intraprocedural jump to the address that the given expression evaluates to.
    BranchInd(Expression),
    /// A direct intraprocedural jump that is only taken if the condition evaluates to true (i.e. not zero).
    CBranch {
        /// The term ID of the target block of the jump.
        target: Tid,
        /// The jump is only taken if this expression evaluates to `true`, (i.e. not zero).
        condition: Expression,
    },
    /// A direct interprocedural jump representing a subroutine call.
    ///
    /// Note that this is syntactically equivalent to a `Jmp::Branch`.
    Call {
        /// The term ID of the target subroutine (`Sub`) or extern symbol of the call.
        target: Tid,
        /// The term ID of the block that the called function returns to.
        /// May be `None` if it is assumed that the called function never returns.
        return_: Option<Tid>,
    },
    /// An indirect interprocedural jump to the address the `target` expression evaluates to
    /// and representing a subroutine call.
    ///
    /// Note that this is syntactically equivalent to a `Jmp::BranchInd`.
    CallInd {
        /// An expression computing the target address of the call.
        target: Expression,
        /// The term ID of the block that the called function returns to.
        /// May be `None` if it is assumed that the called function never returns.
        return_: Option<Tid>,
    },
    /// A indirect interprocedural jump indicating a return from a subroutine.
    ///
    /// Note that this is syntactically equivalent to a `Jmp::BranchInd`.
    Return(Expression),
    /// This instruction is used for all side effects that are not representable by other instructions
    /// or not supported by the disassembler.
    ///
    /// E.g. syscalls and other interrupts are mapped to `CallOther`.
    /// Assembly instructions that the disassembler does not support are also mapped to `CallOther`.
    /// One can use the `description` field to match for and handle known side effects (e.g. syscalls).
    CallOther {
        /// A description of the side effect.
        description: String,
        /// The block term identifier of the block
        /// where the disassembler assumes that execution will continue after handling of the side effect.
        return_: Option<Tid>,
    },
}

impl Term<Jmp> {
    /// If the TID of a jump target or return target is not contained in `known_tids`
    /// replace it with a dummy TID and return an error message.
    fn retarget_nonexisting_jump_targets_to_dummy_tid(
        &mut self,
        known_tids: &HashSet<Tid>,
        dummy_sub_tid: &Tid,
        dummy_blk_tid: &Tid,
    ) -> Result<(), LogMessage> {
        use Jmp::*;
        match &mut self.term {
            BranchInd(_) => (),
            Branch(tid) | CBranch { target: tid, .. } if known_tids.get(tid).is_none() => {
                let error_msg = format!("Jump target at {} does not exist", tid.address);
                let error_log = LogMessage::new_error(error_msg).location(self.tid.clone());
                *tid = dummy_blk_tid.clone();
                return Err(error_log);
            }
            Call { target, return_ } if known_tids.get(target).is_none() => {
                let error_msg = format!("Call target at {} does not exist", target.address);
                let error_log = LogMessage::new_error(error_msg).location(self.tid.clone());
                *target = dummy_sub_tid.clone();
                *return_ = None;
                return Err(error_log);
            }
            Call {
                return_: Some(return_tid),
                ..
            }
            | CallInd {
                return_: Some(return_tid),
                ..
            }
            | CallOther {
                return_: Some(return_tid),
                ..
            } if known_tids.get(return_tid).is_none() => {
                let error_msg = format!("Return target at {} does not exist", return_tid.address);
                let error_log = LogMessage::new_error(error_msg).location(self.tid.clone());
                *return_tid = dummy_blk_tid.clone();
                return Err(error_log);
            }
            _ => (),
        }
        Ok(())
    }
}

/// A basic block is a sequence of `Def` instructions followed by up to two `Jmp` instructions.
///
/// The `Def` instructions represent side-effectful operations that are executed in order when the block is entered.
/// `Def` instructions do not affect the control flow of a program.
///
/// The `Jmp` instructions represent control flow affecting operations.
/// There can only be zero, one or two `Jmp`s:
/// - Zero `Jmp`s indicate that the next execution to be executed could not be discerned.
/// This should only happen on disassembler errors or on dead ends in the control flow graph that were deliberately inserted by the user.
/// - If there is exactly one `Jmp`, it is required to be an unconditional jump.
/// - For two jumps, the first one has to be a conditional jump,
/// where the second unconditional jump is only taken if the condition of the first jump evaluates to false.
///
/// If one of the `Jmp` instructions is an indirect jump,
/// then the `indirect_jmp_targets` is a list of possible jump target addresses for that jump.
/// The list may not be complete and the entries are not guaranteed to be correct.
///
/// Basic blocks are *single entry, single exit*, i.e. a basic block is only entered at the beginning
/// and is only exited by the jump instructions at the end of the block.
/// If a new control flow edge is discovered that would jump to the middle of a basic block,
/// the block structure needs to be updated accordingly.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Blk {
    /// The `Def` instructions of the basic block in order of execution.
    pub defs: Vec<Term<Def>>,
    /// The `Jmp` instructions of the basic block
    pub jmps: Vec<Term<Jmp>>,
    /// If the basic block contains an indirect jump,
    /// this field contains possible jump target addresses for the jump.
    pub indirect_jmp_targets: Vec<String>,
}

impl Term<Blk> {
    /// Remove indirect jump target addresses for which no corresponding target block exists.
    /// Return an error message for each removed address.
    pub fn remove_nonexisting_indirect_jump_targets(
        &mut self,
        known_block_tids: &HashSet<Tid>,
    ) -> Result<(), Vec<LogMessage>> {
        let mut logs = Vec::new();
        self.term.indirect_jmp_targets = self
            .term
            .indirect_jmp_targets
            .iter()
            .filter_map(|target_address| {
                if known_block_tids
                    .get(&Tid::blk_id_at_address(&target_address))
                    .is_some()
                {
                    Some(target_address.to_string())
                } else {
                    let error_msg =
                        format!("Indirect jump target at {} does not exist", target_address);
                    logs.push(LogMessage::new_error(error_msg).location(self.tid.clone()));
                    None
                }
            })
            .collect();
        if logs.is_empty() {
            Ok(())
        } else {
            Err(logs)
        }
    }

    /// Wherever possible, substitute input variables of expressions
    /// with the input expression that defines the input variable.
    ///
    /// Note that substitution is only possible
    /// if the input variables of the input expression itself did not change since the definition of said variable.
    ///
    /// The expression propagation allows the [`Project::substitute_trivial_expressions`] normalization pass
    /// to further simplify the generated expressions
    /// and allows more dead stores to be removed during [dead variable elimination](`crate::analysis::dead_variable_elimination`).
    pub fn propagate_input_expressions(&mut self) {
        let mut insertable_expressions = Vec::new();
        for def in self.term.defs.iter_mut() {
            match &mut def.term {
                Def::Assign {
                    var,
                    value: expression,
                } => {
                    // insert known input expressions
                    for (input_var, input_expr) in insertable_expressions.iter() {
                        expression.substitute_input_var(input_var, input_expr);
                    }
                    // expressions dependent on the assigned variable are no longer insertable
                    insertable_expressions.retain(|(input_var, input_expr)| {
                        input_var != var && !input_expr.input_vars().into_iter().any(|x| x == var)
                    });
                    // If the value of the assigned variable does not depend on the former value of the variable,
                    // then it is insertable for future expressions.
                    if !expression.input_vars().into_iter().any(|x| x == var) {
                        insertable_expressions.push((var.clone(), expression.clone()));
                    }
                }
                Def::Load {
                    var,
                    address: expression,
                } => {
                    // insert known input expressions
                    for (input_var, input_expr) in insertable_expressions.iter() {
                        expression.substitute_input_var(input_var, input_expr);
                    }
                    // expressions dependent on the assigned variable are no longer insertable
                    insertable_expressions.retain(|(input_var, input_expr)| {
                        input_var != var && !input_expr.input_vars().into_iter().any(|x| x == var)
                    });
                }
                Def::Store { address, value } => {
                    // insert known input expressions
                    for (input_var, input_expr) in insertable_expressions.iter() {
                        address.substitute_input_var(input_var, input_expr);
                        value.substitute_input_var(input_var, input_expr);
                    }
                }
            }
        }
        for jump in self.term.jmps.iter_mut() {
            match &mut jump.term {
                Jmp::Branch(_) | Jmp::Call { .. } | Jmp::CallOther { .. } => (),
                Jmp::BranchInd(expr)
                | Jmp::CBranch {
                    condition: expr, ..
                }
                | Jmp::CallInd { target: expr, .. }
                | Jmp::Return(expr) => {
                    // insert known input expressions
                    for (input_var, input_expr) in insertable_expressions.iter() {
                        expr.substitute_input_var(input_var, input_expr);
                    }
                }
            }
        }
    }

    /// Merge subsequent assignments to the same variable to a single assignment to that variable.
    ///
    /// The value expressions of merged assignments can often be simplified later on
    /// in the [`Project::substitute_trivial_expressions`] normalization pass.
    pub fn merge_def_assignments_to_same_var(&mut self) {
        let mut new_defs = Vec::new();
        let mut last_def_opt = None;
        for def in self.term.defs.iter() {
            if let Def::Assign {
                var: current_var, ..
            } = &def.term
            {
                if let Some(Term {
                    term:
                        Def::Assign {
                            var: last_var,
                            value: last_value,
                        },
                    ..
                }) = &last_def_opt
                {
                    if current_var == last_var {
                        let mut substituted_def = def.clone();
                        substituted_def.substitute_input_var(last_var, last_value);
                        last_def_opt = Some(substituted_def);
                    } else {
                        new_defs.push(last_def_opt.unwrap());
                        last_def_opt = Some(def.clone());
                    }
                } else if last_def_opt.is_some() {
                    panic!(); // Only assign-defs should be saved in last_def.
                } else {
                    last_def_opt = Some(def.clone());
                }
            } else {
                if let Some(last_def) = last_def_opt {
                    new_defs.push(last_def);
                }
                new_defs.push(def.clone());
                last_def_opt = None;
            }
        }
        if let Some(last_def) = last_def_opt {
            new_defs.push(last_def);
        }
        self.term.defs = new_defs;
    }
}

/// A `Sub` or subroutine represents a function with a given name and a list of basic blocks belonging to it.
///
/// Subroutines are *single-entry*,
/// i.e. calling a subroutine will execute the first block in the list of basic blocks.
/// A subroutine may have multiple exits, which are identified by `Jmp::Return` instructions.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Sub {
    /// The name of the subroutine
    pub name: String,
    /// The basic blocks belonging to the subroutine.
    /// The first block is also the entry point of the subroutine.
    pub blocks: Vec<Term<Blk>>,
}

/// A parameter or return argument of a function.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Arg {
    /// The argument is passed in the given register
    Register {
        /// The variable object representing the register.
        var: Variable,
        /// An optional data type indicator.
        data_type: Option<Datatype>,
    },
    /// The argument is passed on the stack.
    /// It is positioned at the given offset (in bytes) relative to the stack pointer on function entry
    /// and has the given size.
    Stack {
        /// The position of the argument on the stack
        /// given as offset relative to the stack pointer on function entry.
        offset: i64,
        /// The size in bytes of the argument.
        size: ByteSize,
        /// An optional data type indicator.
        data_type: Option<Datatype>,
    },
}

impl Arg {
    /// Returns the data type field of an Arg object.
    pub fn get_data_type(&self) -> Option<Datatype> {
        match self {
            Arg::Register { data_type, .. } => data_type.clone(),
            Arg::Stack { data_type, .. } => data_type.clone(),
        }
    }
}

/// An extern symbol represents a funtion that is dynamically linked from another binary.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct ExternSymbol {
    /// The term ID of the extern symbol.
    pub tid: Tid,
    /// Addresses of possibly multiple locations of the same extern symbol
    pub addresses: Vec<String>,
    /// The name of the extern symbol
    pub name: String,
    /// The calling convention used for the extern symbol if known
    pub calling_convention: Option<String>,
    /// Parameters of an extern symbol.
    /// May be empty if there are no parameters or the parameters are unknown.
    pub parameters: Vec<Arg>,
    /// Return values of an extern symbol.
    /// May be empty if there is no return value or the return values are unknown.
    pub return_values: Vec<Arg>,
    /// If set to `true`, the function is assumed to never return to its caller when called.
    pub no_return: bool,
    /// If the function has a variable number of parameters, this flag is set to `true`.
    pub has_var_args: bool,
}

impl ExternSymbol {
    /// If the extern symbol has exactly one return value that is passed in a register,
    /// return the register.
    pub fn get_unique_return_register(&self) -> Result<&Variable, Error> {
        if self.return_values.len() == 1 {
            match self.return_values[0] {
                Arg::Register { ref var, .. } => Ok(var),
                Arg::Stack { .. } => Err(anyhow!("Return value is passed on the stack")),
            }
        } else {
            Err(anyhow!("Wrong number of return values"))
        }
    }

    /// If the extern symbol has exactly one parameter, return the parameter.
    pub fn get_unique_parameter(&self) -> Result<&Arg, Error> {
        if self.parameters.len() == 1 {
            Ok(&self.parameters[0])
        } else {
            Err(anyhow!("Wrong number of parameter values"))
        }
    }

    /// Get the calling convention corresponding to the extern symbol.
    pub fn get_calling_convention<'a>(&self, project: &'a Project) -> &'a CallingConvention {
        let cconv_name: &str = self.calling_convention.as_deref().unwrap_or("default");
        project
            .calling_conventions
            .iter()
            .find(|cconv| cconv.name == cconv_name)
            .unwrap()
    }
}

/// The `Program` structure represents a disassembled binary.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Program {
    /// The known functions contained in the binary
    pub subs: Vec<Term<Sub>>,
    /// Extern symbols linked to the binary by the linker.
    pub extern_symbols: Vec<ExternSymbol>,
    /// Entry points into to binary,
    /// i.e. the term identifiers of functions that may be called from outside of the binary.
    pub entry_points: Vec<Tid>,
    /// An offset that has been added to all addresses in the program compared to the addresses
    /// as specified in the binary file.
    ///
    /// In certain cases, e.g. if the binary specifies a segment to be loaded at address 0,
    /// the Ghidra backend may shift the whole binary image by a constant value in memory.
    /// Thus addresses as specified by the binary and addresses as reported by Ghidra may differ by a constant offset,
    /// which is stored in this value.
    pub address_base_offset: u64,
}

impl Program {
    /// Find a block term by its term identifier.
    /// WARNING: The function simply iterates through all blocks,
    /// i.e. it is very inefficient for large projects!
    pub fn find_block(&self, tid: &Tid) -> Option<&Term<Blk>> {
        self.subs
            .iter()
            .map(|sub| sub.term.blocks.iter())
            .flatten()
            .find(|block| block.tid == *tid)
    }
}

/// Calling convention related data
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct CallingConvention {
    /// The name of the calling convention
    #[serde(rename = "calling_convention")]
    pub name: String,
    /// Possible integer parameter registers.
    pub integer_parameter_register: Vec<String>,
    /// Possible float parameter registers.
    pub float_parameter_register: Vec<String>,
    /// A list of possible return register
    pub return_register: Vec<String>,
    /// A list of callee-saved register,
    /// i.e. the values of these registers should be the same after the call as they were before the call.
    pub callee_saved_register: Vec<String>,
}

/// The `Project` struct is the main data structure representing a binary.
///
/// It contains information about the disassembled binary
/// and about the execution environment of the binary.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Project {
    /// All (known) executable code of the binary is contained in the `program` term.
    pub program: Term<Program>,
    /// The CPU architecture on which the binary is assumed to be executed.
    pub cpu_architecture: String,
    /// The stack pointer register for the given CPU architecture.
    pub stack_pointer_register: Variable,
    /// The known calling conventions that may be used for calls to extern functions.
    pub calling_conventions: Vec<CallingConvention>,
    /// A list of all known physical registers for the CPU architecture.
    /// Does only contain base registers, i.e. sub registers of other registers are not contained.
    pub register_list: Vec<Variable>,
    /// Contains the properties of C data types. (e.g. size)
    pub datatype_properties: DatatypeProperties,
}

impl Project {
    /// Return the size (in bytes) for pointers of the given architecture.
    pub fn get_pointer_bytesize(&self) -> ByteSize {
        self.stack_pointer_register.size
    }

    /// Try to guess a standard calling convention from the list of calling conventions in the project.
    pub fn get_standard_calling_convention(&self) -> Option<&CallingConvention> {
        self.calling_conventions
            .iter()
            .find(|cconv| cconv.name == "__stdcall" || cconv.name == "__cdecl")
    }
}

impl Project {
    /// For all expressions contained in the project,
    /// replace trivially computable subexpressions like `a XOR a` with their result.
    fn substitute_trivial_expressions(&mut self) {
        for sub in self.program.term.subs.iter_mut() {
            for block in sub.term.blocks.iter_mut() {
                for def in block.term.defs.iter_mut() {
                    match &mut def.term {
                        Def::Assign { value: expr, .. } | Def::Load { address: expr, .. } => {
                            expr.substitute_trivial_operations()
                        }
                        Def::Store { address, value } => {
                            address.substitute_trivial_operations();
                            value.substitute_trivial_operations();
                        }
                    }
                }
                for jmp in block.term.jmps.iter_mut() {
                    match &mut jmp.term {
                        Jmp::Branch(_) | Jmp::Call { .. } | Jmp::CallOther { .. } => (),
                        Jmp::BranchInd(expr)
                        | Jmp::CBranch {
                            condition: expr, ..
                        }
                        | Jmp::CallInd { target: expr, .. }
                        | Jmp::Return(expr) => expr.substitute_trivial_operations(),
                    }
                }
            }
        }
    }

    /// Replace jumps to nonexisting TIDs with jumps to a dummy target
    /// representing an artificial sink in the control flow graph.
    /// Return a log message for each replaced jump target.
    ///
    /// Nonexisting jump targets may be generated by the Ghidra backend
    /// if the data at the target address is not a valid assembly instruction.
    #[must_use]
    fn remove_references_to_nonexisting_tids(&mut self) -> Vec<LogMessage> {
        // Gather all existing jump targets
        let mut jump_target_tids = HashSet::new();
        for sub in self.program.term.subs.iter() {
            jump_target_tids.insert(sub.tid.clone());
            for block in sub.term.blocks.iter() {
                jump_target_tids.insert(block.tid.clone());
            }
        }
        for symbol in self.program.term.extern_symbols.iter() {
            jump_target_tids.insert(symbol.tid.clone());
        }
        // Replace all jumps to non-existing jump targets with jumps to dummy targets
        let dummy_sub_tid = Tid::new("Artificial Sink Sub");
        let dummy_blk_tid = Tid::new("Artificial Sink Block");
        let mut log_messages = Vec::new();
        for sub in self.program.term.subs.iter_mut() {
            for block in sub.term.blocks.iter_mut() {
                if let Err(mut logs) =
                    block.remove_nonexisting_indirect_jump_targets(&jump_target_tids)
                {
                    log_messages.append(&mut logs);
                }
                for jmp in block.term.jmps.iter_mut() {
                    if let Err(log_msg) = jmp.retarget_nonexisting_jump_targets_to_dummy_tid(
                        &jump_target_tids,
                        &dummy_sub_tid,
                        &dummy_blk_tid,
                    ) {
                        log_messages.push(log_msg);
                    }
                }
            }
        }
        // If at least one dummy jump was inserted, add the corresponding dummy sub and block to the program.
        if !log_messages.is_empty() {
            let dummy_sub: Term<Sub> = Term {
                tid: dummy_sub_tid,
                term: Sub {
                    name: "Artificial Sink Sub".to_string(),
                    blocks: vec![Term {
                        tid: dummy_blk_tid,
                        term: Blk {
                            defs: Vec::new(),
                            jmps: Vec::new(),
                            indirect_jmp_targets: Vec::new(),
                        },
                    }],
                },
            };
            self.program.term.subs.push(dummy_sub);
        }
        log_messages
    }

    /// Propagate input expressions along variable assignments.
    ///
    /// The propagation only occurs inside basic blocks
    /// but not across basic block boundaries.
    fn propagate_input_expressions(&mut self) {
        for sub in self.program.term.subs.iter_mut() {
            for block in sub.term.blocks.iter_mut() {
                block.merge_def_assignments_to_same_var();
                block.propagate_input_expressions();
            }
        }
    }

    /// Run some normalization passes over the project.
    ///
    /// Passes:
    /// - Propagate input expressions along variable assignments.
    /// - Replace trivial expressions like `a XOR a` with their result.
    /// - Replace jumps to nonexisting TIDs with jumps to an artificial sink target in the CFG.
    /// - Remove dead register assignments
    #[must_use]
    pub fn normalize(&mut self) -> Vec<LogMessage> {
        self.propagate_input_expressions();
        self.substitute_trivial_expressions();
        let logs = self.remove_references_to_nonexisting_tids();
        crate::analysis::dead_variable_elimination::remove_dead_var_assignments(self);
        logs
    }
}

#[cfg(test)]
mod tests {
    use crate::intermediate_representation::BinOpType;

    use super::*;

    impl Blk {
        pub fn mock() -> Term<Blk> {
            Term {
                tid: Tid::new("block"),
                term: Blk {
                    defs: Vec::new(),
                    jmps: Vec::new(),
                    indirect_jmp_targets: Vec::new(),
                },
            }
        }

        pub fn mock_with_tid(tid: &str) -> Term<Blk> {
            Term {
                tid: Tid::new(tid),
                term: Blk {
                    defs: Vec::new(),
                    jmps: Vec::new(),
                    indirect_jmp_targets: Vec::new(),
                },
            }
        }
    }

    impl Sub {
        pub fn mock(name: impl ToString) -> Term<Sub> {
            Term {
                tid: Tid::new(name.to_string()),
                term: Sub {
                    name: name.to_string(),
                    blocks: Vec::new(),
                },
            }
        }
    }

    impl Program {
        pub fn mock_empty() -> Program {
            Program {
                subs: Vec::new(),
                extern_symbols: Vec::new(),
                entry_points: Vec::new(),
                address_base_offset: 0,
            }
        }
    }

    impl CallingConvention {
        pub fn mock() -> CallingConvention {
            CallingConvention {
                name: "__stdcall".to_string(), // so that the mock is useable as standard calling convention in tests
                integer_parameter_register: vec!["RDI".to_string()],
                float_parameter_register: vec!["XMMO".to_string()],
                return_register: vec!["RAX".to_string()],
                callee_saved_register: vec!["RBP".to_string()],
            }
        }

        pub fn mock_with_parameter_registers(
            integer_parameter_register: Vec<String>,
            float_parameter_register: Vec<String>,
        ) -> CallingConvention {
            CallingConvention {
                name: "__stdcall".to_string(), // so that the mock is useable as standard calling convention in tests
                integer_parameter_register,
                float_parameter_register,
                return_register: vec!["RAX".to_string()],
                callee_saved_register: vec!["RBP".to_string()],
            }
        }
    }

    impl Arg {
        pub fn mock_register(name: impl ToString, size_in_bytes: impl Into<ByteSize>) -> Arg {
            Arg::Register {
                var: Variable::mock(name.to_string(), size_in_bytes),
                data_type: None,
            }
        }
    }

    impl ExternSymbol {
        pub fn mock() -> ExternSymbol {
            ExternSymbol {
                tid: Tid::new("mock_symbol"),
                addresses: vec!["UNKNOWN".to_string()],
                name: "mock_symbol".to_string(),
                calling_convention: Some("__stdcall".to_string()),
                parameters: vec![Arg::mock_register("RDI", 8)],
                return_values: vec![Arg::mock_register("RAX", 8)],
                no_return: false,
                has_var_args: false,
            }
        }
    }

    impl DatatypeProperties {
        pub fn mock() -> DatatypeProperties {
            DatatypeProperties {
                char_size: ByteSize::new(1),
                double_size: ByteSize::new(8),
                float_size: ByteSize::new(4),
                integer_size: ByteSize::new(4),
                long_double_size: ByteSize::new(8),
                long_long_size: ByteSize::new(8),
                long_size: ByteSize::new(4),
                pointer_size: ByteSize::new(8),
                short_size: ByteSize::new(2),
            }
        }
    }

    impl Project {
        pub fn mock_empty() -> Project {
            let register_list = vec!["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI"]
                .into_iter()
                .map(|name| Variable::mock(name, ByteSize::new(8)))
                .collect();
            Project {
                program: Term {
                    tid: Tid::new("program_tid"),
                    term: Program::mock_empty(),
                },
                cpu_architecture: "x86_64".to_string(),
                stack_pointer_register: Variable::mock("RSP", 8u64),
                calling_conventions: Vec::new(),
                register_list,
                datatype_properties: DatatypeProperties::mock(),
            }
        }
    }

    #[test]
    fn retarget_nonexisting_jumps() {
        let mut jmp_term = Term {
            tid: Tid::new("jmp"),
            term: Jmp::Branch(Tid::new("nonexisting_target")),
        };
        assert_eq!(jmp_term.term, Jmp::Branch(Tid::new("nonexisting_target")));
        assert!(jmp_term
            .retarget_nonexisting_jump_targets_to_dummy_tid(
                &HashSet::new(),
                &Tid::new("dummy_sub"),
                &Tid::new("dummy_blk")
            )
            .is_err());
        assert_eq!(jmp_term.term, Jmp::Branch(Tid::new("dummy_blk")));
    }

    #[test]
    fn zero_extension_check() {
        let eax_variable = Expression::Var(Variable {
            name: String::from("EAX"),
            size: ByteSize::new(4),
            is_temp: false,
        });
        let int_sub_expr = Expression::BinOp {
            op: BinOpType::IntSub,
            lhs: Box::new(Expression::Var(Variable {
                name: String::from("EAX"),
                size: ByteSize::new(4),
                is_temp: false,
            })),
            rhs: Box::new(Expression::Var(Variable {
                name: String::from("ECX"),
                size: ByteSize::new(4),
                is_temp: false,
            })),
        };

        let zero_extend_def = Term {
            tid: Tid::new("zero_tid"),
            term: Def::Assign {
                var: Variable {
                    name: String::from("RAX"),
                    size: ByteSize::new(8),
                    is_temp: false,
                },
                value: Expression::Cast {
                    op: CastOpType::IntZExt,
                    size: ByteSize::new(8),
                    arg: Box::new(eax_variable.clone()),
                },
            },
        };
        // An expression that is a zero extension but does not directly contain a variable
        let zero_extend_but_no_var_def = Term {
            tid: Tid::new("zero_tid"),
            term: Def::Assign {
                var: Variable {
                    name: String::from("RAX"),
                    size: ByteSize::new(8),
                    is_temp: false,
                },
                value: Expression::Cast {
                    op: CastOpType::IntZExt,
                    size: ByteSize::new(8),
                    arg: Box::new(int_sub_expr.clone()),
                },
            },
        };

        let non_zero_extend_def = Term {
            tid: Tid::new("zero_tid"),
            term: Def::Assign {
                var: Variable {
                    name: String::from("RAX"),
                    size: ByteSize::new(8),
                    is_temp: false,
                },
                value: Expression::Cast {
                    op: CastOpType::IntSExt,
                    size: ByteSize::new(8),
                    arg: Box::new(eax_variable.clone()),
                },
            },
        };

        assert_eq!(
            zero_extend_def.check_for_zero_extension(String::from("RAX"), String::from("EAX")),
            Some(Tid::new("zero_tid"))
        );
        assert_eq!(
            zero_extend_but_no_var_def
                .check_for_zero_extension(String::from("RAX"), String::from("EAX")),
            None
        );
        assert_eq!(
            non_zero_extend_def.check_for_zero_extension(String::from("RAX"), String::from("EAX")),
            None
        );
    }

    #[test]
    fn expression_propagation() {
        use crate::intermediate_representation::UnOpType;
        let defs = vec![
            Def::assign(
                "tid_1",
                Variable::mock("X", 8),
                Expression::var("Y", 8).un_op(UnOpType::IntNegate),
            ),
            Def::assign(
                "tid_2",
                Variable::mock("Y", 8),
                Expression::var("X", 8).plus(Expression::var("Y", 8)),
            ),
            Def::assign(
                "tid_3",
                Variable::mock("X", 8),
                Expression::var("X", 8).un_op(UnOpType::IntNegate),
            ),
            Def::assign(
                "tid_4",
                Variable::mock("Y", 8),
                Expression::var("Y", 8).un_op(UnOpType::IntNegate),
            ),
            Def::assign(
                "tid_5",
                Variable::mock("Y", 8),
                Expression::var("X", 8).plus(Expression::var("Y", 8)),
            ),
        ];
        let mut block = Term {
            tid: Tid::new("block"),
            term: Blk {
                defs,
                jmps: Vec::new(),
                indirect_jmp_targets: Vec::new(),
            },
        };
        block.merge_def_assignments_to_same_var();
        block.propagate_input_expressions();
        let result_defs = vec![
            Def::assign(
                "tid_1",
                Variable::mock("X", 8),
                Expression::var("Y", 8).un_op(UnOpType::IntNegate),
            ),
            Def::assign(
                "tid_2",
                Variable::mock("Y", 8),
                Expression::var("Y", 8)
                    .un_op(UnOpType::IntNegate)
                    .plus(Expression::var("Y", 8)),
            ),
            Def::assign(
                "tid_3",
                Variable::mock("X", 8),
                Expression::var("X", 8).un_op(UnOpType::IntNegate),
            ),
            Def::assign(
                "tid_5",
                Variable::mock("Y", 8),
                Expression::var("X", 8).plus(Expression::var("Y", 8).un_op(UnOpType::IntNegate)),
            ),
        ];
        assert_eq!(block.term.defs, result_defs);
    }
}
