use super::{ByteSize, Expression, Variable};
use crate::prelude::*;

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
    ///
    /// The size of `var` also determines the number of bytes read from memory.
    /// The size of `address` is required to match the pointer size of the corresponding CPU architecture.
    Load { var: Variable, address: Expression },
    /// A memory store operation.
    ///
    /// The size of `value` determines the number of bytes written.
    /// The size of `address` is required to match the pointer size of the corresponding CPU architecture.
    Store {
        address: Expression,
        value: Expression,
    },
    /// A register assignment, assigning the result of the expression `value` to the register `var`.
    Assign { var: Variable, value: Expression },
}

/// A `Jmp` instruction affects the control flow of a program, i.e. it may change the instruction pointer.
/// With the exception of `CallOther`, it has no other side effects.
///
/// `Jmp` instructions carry some semantic information with it, like whether a jump is intra- or interprocedural.
/// Note that this semantic information may not always be correct.
///
/// The targets (and return targets) of jumps are, if known, either basic blocks (`Blk`) or subroutines (`Sub`)
/// depending of the type of the jump.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Jmp {
    /// A direct intraprocedural jump to the targeted `Blk` term identifier.
    Branch(Tid),
    /// An indirect intraprocedural jump to the address that the given expression evaluates to.
    BranchInd(Expression),
    /// A direct intraprocedural jump that is only taken if the condition evaluates to true (i.e. not zero).
    CBranch { target: Tid, condition: Expression },
    /// A direct interprocedural jump representing a subroutine call.
    ///
    /// Note that this is syntactically equivalent to a `Jmp::Branch`.
    /// If the `return_` is `None`, then the called function does not return to its caller.
    Call { target: Tid, return_: Option<Tid> },
    /// An indirect interprocedural jump to the address the `target` expression evaluates to
    /// and representing a subroutine call.
    ///
    /// Note that this is syntactically equivalent to a `Jmp::BranchInd`.
    /// If the `return_` is `None`, then the called function is believed to not return to its caller.
    CallInd {
        target: Expression,
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
    ///
    /// The `return_` field indicates the `Blk` term identifier
    /// where the disassembler assumes that execution will continue after handling of the side effect.
    CallOther {
        description: String,
        return_: Option<Tid>,
    },
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
/// Basic blocks are *single entry, single exit*, i.e. a basic block is only entered at the beginning
/// and is only exited by the jump instructions at the end of the block.
/// If a new control flow edge is discovered that would jump to the middle of a basic block,
/// the block structure needs to be updated accordingly.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct Blk {
    pub defs: Vec<Term<Def>>,
    pub jmps: Vec<Term<Jmp>>,
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
    /// The argument is passed in a register
    Register(Variable),
    /// The argument is passed on the stack.
    /// It is positioned at the given offset (in bytes) relative to the stack pointer on function entry
    /// and has the given size.
    Stack { offset: i64, size: ByteSize },
}

/// An extern symbol represents a funtion that is dynamically linked from another binary.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct ExternSymbol {
    pub tid: Tid,
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
}

impl ExternSymbol {
    /// If the extern symbol has exactly one return value that is passed in a register,
    /// return the register.
    pub fn get_unique_return_register(&self) -> Result<&Variable, Error> {
        if self.return_values.len() == 1 {
            match self.return_values[0] {
                Arg::Register(ref var) => Ok(var),
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
        let cconv_name = match self.calling_convention {
            Some(ref name) => name,
            None => "default",
        };
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
    /// A list of possible parameter register
    pub parameter_register: Vec<String>,
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
}

impl Project {
    /// Return the size (in bytes) for pointers of the given architecture.
    pub fn get_pointer_bytesize(&self) -> ByteSize {
        self.stack_pointer_register.size
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

    /// Run some normalization passes over the project.
    ///
    /// Right now this only replaces trivial expressions like `a XOR a` with their result.
    pub fn normalize(&mut self) {
        self.substitute_trivial_expressions();
    }
}
