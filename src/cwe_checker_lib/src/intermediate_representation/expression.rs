use std::collections::HashMap;

use super::Variable;
use super::{ByteSize, Def};
use crate::{pcode::RegisterProperties, prelude::*};

mod builder;

/// An expression is a calculation rule
/// on how to compute a certain value given some variables (register values) as input.
///
/// The basic building blocks of expressions are the same as for Ghidra P-Code.
/// However, expressions can be nested, unlike original P-Code.
///
/// Computing the value of an expression is a side-effect-free operation.
///
/// Expressions are typed in the sense that each expression has a `ByteSize`
/// indicating the size of the result when evaluating the expression.
/// Some expressions impose restrictions on the sizes of their inputs
/// for the expression to be well-typed.
///
/// All operations are defined the same as the corresponding P-Code operation.
/// Further information about specific operations can be obtained by looking up the P-Code mnemonics in the
/// [P-Code Reference Manual](https://ghidra.re/courses/languages/html/pcoderef.html).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub enum Expression {
    /// A variable representing a register or temporary value of known size.
    Var(Variable),
    /// A constant value represented by a bitvector.
    Const(Bitvector),
    /// A binary operation.
    /// Note that most (but not all) operations require the left hand side (`lhs`)
    /// and right hand side (`rhs`) to be of equal size.
    BinOp {
        /// The opcode/type of the operation
        op: BinOpType,
        /// The left hand side expression
        lhs: Box<Expression>,
        /// The right hand side expression
        rhs: Box<Expression>,
    },
    /// A unary operation
    UnOp {
        /// The opcode/type of the operation
        op: UnOpType,
        /// The argument expression
        arg: Box<Expression>,
    },
    /// A cast operation for type cast between integer and floating point types of different byte lengths.
    Cast {
        /// The opcode/type of the cast operation
        op: CastOpType,
        /// The byte size of the result value of the expresion
        size: ByteSize,
        /// The argument of the expression
        arg: Box<Expression>,
    },
    /// An unknown value but with known size.
    /// This may be generated for e.g. unsupported assembly instructions.
    /// Note that computation of an unknown value is still required to be side-effect-free!
    Unknown {
        /// A description of the operation
        description: String,
        /// The byte size of the result of the unknown expression
        size: ByteSize,
    },
    /// Extracting a sub-bitvector from the argument expression.
    Subpiece {
        /// The lowest byte (i.e. least significant byte if interpreted as integer) of the sub-bitvector to extract.
        low_byte: ByteSize,
        /// The size of the resulting sub-bitvector
        size: ByteSize,
        /// The argument from which to extract the bitvector from.
        arg: Box<Expression>,
    },
}

impl Expression {
    /// Return the size (in bytes) of the result value of the expression.
    pub fn bytesize(&self) -> ByteSize {
        use BinOpType::*;
        use Expression::*;
        match self {
            Var(var) => var.size,
            Const(bitvec) => bitvec.width().into(),
            BinOp { op, lhs, rhs } => match op {
                Piece => lhs.bytesize() + rhs.bytesize(),
                IntEqual | IntNotEqual | IntLess | IntSLess | IntLessEqual | IntSLessEqual
                | IntCarry | IntSCarry | IntSBorrow | BoolXOr | BoolOr | BoolAnd | FloatEqual
                | FloatNotEqual | FloatLess | FloatLessEqual => ByteSize::new(1),
                IntAdd | IntSub | IntAnd | IntOr | IntXOr | IntLeft | IntRight | IntSRight
                | IntMult | IntDiv | IntRem | IntSDiv | IntSRem | FloatAdd | FloatSub
                | FloatMult | FloatDiv => lhs.bytesize(),
            },
            UnOp { op, arg } => match op {
                UnOpType::FloatNaN => ByteSize::new(1),
                _ => arg.bytesize(),
            },
            Cast { size, .. } | Unknown { size, .. } | Subpiece { size, .. } => *size,
        }
    }

    /// Return an array of all input variables of the given expression.
    /// The array may contain duplicates.
    pub fn input_vars(&self) -> Vec<&Variable> {
        use Expression::*;
        match self {
            Var(var) => vec![var],
            Const(_) | Unknown {..} => Vec::new(),
            BinOp {op:_, lhs, rhs} => {
                let mut vars = lhs.input_vars();
                vars.append(&mut rhs.input_vars());
                vars
            }
            UnOp{arg, ..} | Cast {arg, ..} | Subpiece {arg, ..} => {
                arg.input_vars()
            }
        }
    }

    /// Substitute trivial BinOp-expressions with their results,
    /// e.g. substitute `a or a` with `a`.
    ///
    /// This function assumes that `self` is a `BinOp`
    /// and it does not substitute trivial expressions in the two input expressions of the `BinOp`.
    fn substitute_trivial_binops(&mut self) {
        use BinOpType::*;
        use Expression::*;
        if let BinOp { op, lhs, rhs } = self {
            if lhs == rhs {
                match op {
                    BoolAnd | BoolOr | IntAnd | IntOr => {
                        // This is an identity operation
                        *self = (**lhs).clone();
                    }
                    BoolXOr | IntXOr => {
                        // `a xor a` always equals zero.
                        *self = Expression::Const(Bitvector::zero(lhs.bytesize().into()));
                    }
                    IntEqual | IntLessEqual | IntSLessEqual => {
                        *self = Expression::Const(Bitvector::one(ByteSize::new(1).into()));
                    }
                    IntNotEqual | IntLess | IntSLess => {
                        *self = Expression::Const(Bitvector::zero(ByteSize::new(1).into()));
                    }
                    _ => (),
                }
            } else {
                match (&**lhs, &**rhs) {
                    (Const(bitvec), other) | (other, Const(bitvec)) if bitvec.is_zero() => {
                        if matches!(op, IntOr | IntXOr | BoolOr | BoolXOr) {
                            // `a or 0 = a` and `a xor 0 = a`
                            *self = other.clone();
                        }
                    }
                    (Const(bitvec), other) | (other, Const(bitvec))
                        if bitvec.clone().into_bitnot().is_zero() =>
                    {
                        if matches!(op, IntAnd | BoolAnd) {
                            // `a and -1 = a` since all bits of -1 are 1.
                            *self = other.clone()
                        }
                    }
                    _ => (),
                }
            }
        }
    }

    /// Substitute some trivial expressions with their result.
    /// E.g. substitute `a XOR a` with zero or substitute `a OR a` with `a`.
    pub fn substitute_trivial_operations(&mut self) {
        use Expression::*;
        match self {
            Var(_) | Const(_) | Unknown { .. } => (),
            Subpiece {
                low_byte,
                size,
                arg,
            } => {
                arg.substitute_trivial_operations();
                if *low_byte == ByteSize::new(0) && *size == arg.bytesize() {
                    *self = (**arg).clone();
                }
            }
            Cast { op, size, arg } => {
                arg.substitute_trivial_operations();
                if (*op == CastOpType::IntSExt || *op == CastOpType::IntZExt)
                    && *size == arg.bytesize()
                {
                    *self = (**arg).clone();
                }
            }
            UnOp { op: _, arg } => arg.substitute_trivial_operations(),
            BinOp { op: _, lhs, rhs } => {
                lhs.substitute_trivial_operations();
                rhs.substitute_trivial_operations();
                self.substitute_trivial_binops();
            }
        }
    }

    /// This function checks for sub registers in pcode instruction and casts them into
    /// SUBPIECE expressions with the base register as argument. It also checks whether
    /// the given Term<Def> has a output sub register and if so, casts it into its
    /// corresponding base register.
    /// Lastly, it checks whether the following pcode instruction is a zero extension of
    /// the currently overwritten sub register. If so, the zero extension is wrapped around
    /// the current instruction and the TID of the zero extension instruction is returned
    /// for later removal.
    /// If there is no zero extension but an output register, the multiple SUBPIECEs are put
    /// together to the size of the corresponding output base register using the PIECE instruction.
    /// A few examples:
    /// 1. From: EAX = COPY EDX;
    ///    To:   RAX = COPY PIECE(SUBPIECE(RAX, 4, 4), SUBPIECE(RDX, 0, 4));
    ///
    /// 2. From:  AH = AH INT_XOR AH;
    ///    To:   RAX = PIECE(PIECE(SUBPIECE(RAX, 2, 6), (SUBPIECE(RAX, 1, 1) INT_XOR SUBPIECE(RAX, 1, 1)), SUBPIECE(RAX, 0, 1));
    ///
    /// 3. FROM EAX = COPY EDX && RAX = INT_ZEXT EAX;
    ///    To:  RAX = INT_ZEXT SUBPIECE(RDX, 0, 4);
    pub fn cast_sub_registers_to_base_register_subpieces(
        &mut self,
        output: Option<&mut Variable>,
        register_map: &HashMap<&String, &RegisterProperties>,
        peeked: Option<&&mut Term<Def>>,
    ) -> Option<Tid> {
        let mut output_base_size: Option<ByteSize> = None;
        let mut output_base_register: Option<&&RegisterProperties> = None;
        let mut output_sub_register: Option<&RegisterProperties> = None;
        let mut zero_extend_tid: Option<Tid> = None;

        if let Some(output_value) = output {
            if let Some(register) = register_map.get(&output_value.name) {
                if *register.register != *register.base_register {
                    output_sub_register = Some(register);
                    output_base_register = register_map.get(&register.base_register);
                    output_value.name = register.base_register.clone();
                    output_value.size = output_base_register.unwrap().size;
                    output_base_size = Some(output_value.size);

                    if let Some(peek) = peeked {
                        zero_extend_tid = peek.check_for_zero_extension(
                            output_value.name.clone(),
                            output_sub_register.unwrap().register.clone(),
                        );
                    }
                }
            }
        }
        self.replace_input_sub_register(register_map);
        // based on the zero extension and base register output, either piece the subpieces together,
        // zero extend the expression or do nothing (e.g. if output is a virtual register, no further actions should be taken)
        self.piece_zero_extend_or_none(
            zero_extend_tid.clone(),
            output_base_register,
            output_base_size,
            output_sub_register,
        );

        zero_extend_tid
    }

    /// This function recursively iterates into the expression and checks whether a sub register was used.
    /// If so, the sub register is turned into a SUBPIECE of the corresponding base register.
    fn replace_input_sub_register(&mut self, register_map: &HashMap<&String, &RegisterProperties>) {
        match self {
            Expression::BinOp { lhs, rhs, .. } => {
                lhs.replace_input_sub_register(register_map);
                rhs.replace_input_sub_register(register_map);
            }
            Expression::UnOp { arg, .. } | Expression::Cast { arg, .. } => {
                arg.replace_input_sub_register(register_map)
            }
            Expression::Subpiece { arg, .. } => {
                let truncated: &mut Expression = arg;
                // Check whether the truncated data source is a sub register and if so,
                // change it to its corresponding base register.
                match truncated {
                    Expression::Var(variable) => {
                        if let Some(register) = register_map.get(&variable.name) {
                            if variable.name != *register.base_register {
                                variable.name = register.base_register.clone();
                                variable.size =
                                    register_map.get(&register.base_register).unwrap().size
                            }
                        }
                    }
                    _ => arg.replace_input_sub_register(register_map),
                }
            }
            Expression::Var(variable) => {
                if let Some(register) = register_map.get(&variable.name) {
                    if variable.name != *register.base_register {
                        self.create_subpiece_from_sub_register(
                            register.base_register.clone(),
                            register.size,
                            register.lsb,
                            register_map,
                        );
                    }
                }
            }
            _ => (),
        }
    }

    /// This function creates a SUBPIECE expression
    /// from a sub_register containing the corresponding base register.
    fn create_subpiece_from_sub_register(
        &mut self,
        base: String,
        size: ByteSize,
        lsb: ByteSize,
        register_map: &HashMap<&String, &RegisterProperties>,
    ) {
        *self = Expression::Subpiece {
            low_byte: lsb,
            size,
            arg: Box::new(Expression::Var(Variable {
                name: base.clone(),
                size: register_map.get(&base).unwrap().size,
                is_temp: false,
            })),
        };
    }

    /// This function either wraps the current expression into a
    /// 1. zero extension expression: if the next instruction is a zero extension
    /// of the currently overwritten sub register
    /// 2. piece expression: if no zero extension is done the a sub register is overwritten
    /// or does nothing in case there is no overwritten sub register.
    fn piece_zero_extend_or_none(
        &mut self,
        zero_extend: Option<Tid>,
        output_base_register: Option<&&RegisterProperties>,
        output_size: Option<ByteSize>,
        sub_register: Option<&RegisterProperties>,
    ) {
        if zero_extend.is_some() {
            *self = Expression::Cast {
                op: CastOpType::IntZExt,
                size: output_size.unwrap(),
                arg: Box::new(self.clone()),
            }
        } else if output_base_register.is_some() {
            self.piece_two_expressions_together(
                *output_base_register.unwrap(),
                sub_register.unwrap(),
            );
        }
    }

    /// This function puts multiple SUBPIECE into PIECE of the size of the
    /// base register. Depending on the position of the LSB of the sub register,
    /// also nested PIECE instruction are possible.
    fn piece_two_expressions_together(
        &mut self,
        output_base_register: &RegisterProperties,
        sub_register: &RegisterProperties,
    ) {
        let base_size: ByteSize = output_base_register.size;
        let base_name: &String = &output_base_register.register;
        let sub_size: ByteSize = sub_register.size;
        let sub_lsb: ByteSize = sub_register.lsb;

        let base_subpiece = Box::new(Expression::Var(Variable {
            name: base_name.clone(),
            size: base_size,
            is_temp: false,
        }));

        // Build PIECE as PIECE(lhs:PIECE(lhs:higher subpiece, rhs:sub register), rhs:lower subpiece)
        if sub_register.lsb > ByteSize::new(0) {
            *self = Expression::BinOp {
                op: BinOpType::Piece,
                lhs: Box::new(Expression::BinOp {
                    op: BinOpType::Piece,
                    lhs: Box::new(Expression::Subpiece {
                        low_byte: sub_lsb + sub_size,
                        size: base_size - (sub_lsb + sub_size),
                        arg: base_subpiece.clone(),
                    }),
                    rhs: Box::new(self.clone()),
                }),
                rhs: Box::new(Expression::Subpiece {
                    low_byte: ByteSize::new(0),
                    size: sub_lsb,
                    arg: base_subpiece,
                }),
            }
        }
        // Build PIECE as PIECE(lhs: high subpiece, rhs: sub register)
        else {
            *self = Expression::BinOp {
                op: BinOpType::Piece,
                lhs: Box::new(Expression::Subpiece {
                    low_byte: sub_size,
                    size: base_size - sub_size,
                    arg: base_subpiece,
                }),
                rhs: Box::new(self.clone()),
            }
        }
    }
}

/// The type/mnemonic of a binary operation.
/// See the Ghidra P-Code documentation for more information.
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum BinOpType {
    Piece,
    IntEqual,
    IntNotEqual,
    IntLess,
    IntSLess,
    IntLessEqual,
    IntSLessEqual,
    IntAdd,
    IntSub,
    IntCarry,
    IntSCarry,
    IntSBorrow,
    IntXOr,
    IntAnd,
    IntOr,
    IntLeft,
    IntRight,
    IntSRight,
    IntMult,
    IntDiv,
    IntRem,
    IntSDiv,
    IntSRem,
    BoolXOr,
    BoolAnd,
    BoolOr,
    FloatEqual,
    FloatNotEqual,
    FloatLess,
    FloatLessEqual,
    FloatAdd,
    FloatSub,
    FloatMult,
    FloatDiv,
}

/// The type/mnemonic of a typecast
/// See the Ghidra P-Code documentation for more information.
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum CastOpType {
    IntZExt,
    IntSExt,
    Int2Float,
    Float2Float,
    Trunc,
    PopCount,
}

/// The type/mnemonic of an unary operation
/// See the Ghidra P-Code documentation for more information.
#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum UnOpType {
    IntNegate,
    Int2Comp,
    BoolNegate,
    FloatNegate,
    FloatAbs,
    FloatSqrt,
    FloatCeil,
    FloatFloor,
    FloatRound,
    FloatNaN,
}

#[cfg(test)]
mod tests;
