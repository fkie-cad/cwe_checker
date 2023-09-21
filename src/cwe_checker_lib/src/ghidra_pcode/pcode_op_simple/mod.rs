use super::*;
use serde::{Deserialize, Serialize};
mod jumps;
pub use jumps::*;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
pub struct PcodeOpSimple {
    /// Index of the operation within the pcode operation sequence.
    /// Starts at 0.
    pub pcode_index: u64,
    pub pcode_mnemonic: PcodeOperation,
    pub input0: VarnodeSimple,
    pub input1: Option<VarnodeSimple>,
    pub input2: Option<VarnodeSimple>,
    pub output: Option<VarnodeSimple>,
}

impl PcodeOpSimple {
    /// Returns `true` if at least one input is ram located.
    pub fn has_implicit_load(&self) -> bool {
        if self.input0.address_space == "ram" {
            return true;
        }
        if let Some(varnode) = &self.input1 {
            if varnode.address_space == "ram" {
                return true;
            }
        }
        if let Some(varnode) = &self.input2 {
            if varnode.address_space == "ram" {
                return true;
            }
        }
        false
    }
    // Returns `true` if the output is ram located.
    pub fn has_implicit_store(&self) -> bool {
        if let Some(varnode) = &self.output {
            if varnode.address_space == "ram" {
                return true;
            }
        }
        false
    }
    /// Returns artificial `Def::Load` instructions, if the operands are ram located.
    /// Otherwise returns empty `Vec`. Changes ram varnodes into virtual register varnodes
    /// using the explicitly loaded value.
    ///
    /// The created instructions use the virtual register `$load_tempX`, whereby `X` is
    /// either `0`, `1`or `2` representing which input is used.
    /// The created `Tid` is named `instr_<address>_<pcode index>_load<X>`.
    fn create_implicit_loads_for_def(&mut self, address: &str) -> Vec<Term<Def>> {
        let mut explicit_loads = vec![];
        if self.input0.address_space == "ram" {
            explicit_loads.push(self.input0.into_explicit_load(
                "load_temp0".to_string(),
                "load0".to_string(),
                address,
                self.pcode_index,
            ));
        }
        if let Some(varnode) = self.input1.as_mut() {
            if varnode.address_space == "ram" {
                explicit_loads.push(varnode.into_explicit_load(
                    "load_temp1".to_string(),
                    "load1".to_string(),
                    address,
                    self.pcode_index,
                ));
            }
        }
        if let Some(varnode) = self.input2.as_mut() {
            if varnode.address_space == "ram" {
                explicit_loads.push(varnode.into_explicit_load(
                    "load_temp2".to_string(),
                    "load2".to_string(),
                    address,
                    self.pcode_index,
                ));
            }
        }
        explicit_loads
    }

    /// Returns artificial `Def::Load` instructions,
    /// if an expression-valued operand of a jump-instruction is ram located.
    /// Otherwise returns empty `Vec`.
    /// Changes corresponding ram varnodes into virtual register varnodes using the explicitly loaded value.
    pub fn create_implicit_loads_for_jump(&mut self, address: &str) -> Vec<Term<Def>> {
        let mut explicit_loads = Vec::new();
        match self.pcode_mnemonic {
            PcodeOperation::JmpType(BRANCHIND)
            | PcodeOperation::JmpType(CALLIND)
            | PcodeOperation::JmpType(RETURN) => {
                if self.input0.address_space == "ram" {
                    explicit_loads.push(self.input0.into_explicit_load(
                        "$load_temp0".to_string(),
                        "load0".to_string(),
                        address,
                        self.pcode_index,
                    ));
                }
            }
            PcodeOperation::JmpType(CBRANCH) => {
                let varnode = self.input1.as_mut().unwrap();
                if varnode.address_space == "ram" {
                    explicit_loads.push(varnode.into_explicit_load(
                        "$load_temp1".to_string(),
                        "load1".to_string(),
                        address,
                        self.pcode_index,
                    ));
                }
            }
            _ => (),
        }
        explicit_loads
    }

    /// Translates a single pcode operation into at least one `Def`.
    ///
    /// Adds additional `Def::Load`, if the pcode operation performs implicit loads from ram
    pub fn into_ir_def(mut self, address: &str) -> Vec<Term<Def>> {
        let mut defs = vec![];
        // if the pcode operation contains implicit load operations, prepend them.
        if self.has_implicit_load() {
            let mut explicit_loads = self.create_implicit_loads_for_def(address);
            defs.append(&mut explicit_loads);
        }

        let def = match self.pcode_mnemonic {
            PcodeOperation::ExpressionType(expr_type) => self.create_def(address, expr_type),
            PcodeOperation::JmpType(_) => panic!("Jump operation cannot be translated into Def"),
        };

        defs.push(def);
        defs
    }

    /// Creates `Def::Store`, `Def::Load` or `Def::Assign` according to the pcode operations'
    /// expression type.
    fn create_def(&self, address: &str, expr_type: ExpressionType) -> Term<Def> {
        match expr_type {
            ExpressionType::LOAD => self.create_load(address),
            ExpressionType::STORE => self.create_store(address),
            ExpressionType::COPY => self.create_assign(address),
            ExpressionType::SUBPIECE => self.create_subpiece(address),
            _ if expr_type.into_ir_unop().is_some() => self.create_unop(address),
            _ if expr_type.into_ir_biop().is_some() => self.create_biop(address),
            _ if expr_type.into_ir_cast().is_some() => self.create_castop(address),
            _ => panic!("Unsupported pcode operation"),
        }
    }

    /// Translates pcode load operation into `Def::Load`
    ///
    /// Pcode load instruction:
    /// ($GHIDRA_PATH)/docs/languages/html/pcoderef.html#cpui_load
    /// Note: input0 ("Constant ID of space to load from") is not considered.
    ///
    /// Panics, if any of the following applies:
    /// * `output` is `None`
    /// * load destination is not a variable
    /// * `input1` is `None`
    /// * `into_ir_expr()` returns `Err` on any varnode
    fn create_load(&self, address: &str) -> Term<Def> {
        if !matches!(
            self.pcode_mnemonic,
            PcodeOperation::ExpressionType(ExpressionType::LOAD)
        ) {
            panic!("Pcode operation is not LOAD")
        }
        let target = self.output.as_ref().expect("Load without output");
        if let Expression::Var(var) = target
            .into_ir_expr()
            .expect("Load target translation failed")
        {
            let source = self
                .input1
                .as_ref()
                .expect("Load without source")
                .into_ir_expr()
                .expect("Load source address translation failed");

            let def = Def::Load {
                var,
                address: source,
            };
            Term {
                tid: Tid {
                    id: format!("instr_{}_{}", address, self.pcode_index),
                    address: address.to_string(),
                },
                term: def,
            }
        } else {
            panic!("Load target is not a variable")
        }
    }

    /// Translates pcode store operation into `Def::Store`
    ///
    /// Pcode store instruction:
    /// ($GHIDRA_PATH)/docs/languages/html/pcoderef.html#cpui_store
    /// Note: input0 ("Constant ID of space to store into") is not considered.
    ///
    /// Panics, if any of the following applies:
    /// * `input1` is None
    /// * `input2` is None
    /// * `into_ir_expr()` returns `Err` on any varnode
    fn create_store(&self, address: &str) -> Term<Def> {
        if !matches!(
            self.pcode_mnemonic,
            PcodeOperation::ExpressionType(ExpressionType::STORE)
        ) {
            panic!("Pcode operation is not STORE")
        }
        let target_expr = self
            .input1
            .as_ref()
            .expect("Store without target")
            .into_ir_expr()
            .expect("Store target translation failed.");

        let data = self.input2.as_ref().expect("Store without source data");
        if !matches!(data.address_space.as_str(), "unique" | "const" | "register") {
            panic!("Store source data is not a variable, temp variable nor constant.")
        }

        let source_expr = data
            .into_ir_expr()
            .expect("Store source translation failed");
        let def = Def::Store {
            address: target_expr,
            value: source_expr,
        };

        Term {
            tid: Tid {
                id: format!("instr_{}_{}", address, self.pcode_index),
                address: address.to_string(),
            },
            term: def,
        }
    }

    /// Translates pcode SUBPIECE instruction into `Def` with `Expression::Subpiece`.
    ///
    /// ($GHIDRA_PATH)/docs/languages/html/pcoderef.html#cpui_subpiece
    ///
    /// Panics, if
    /// * self.input1 is `None` or cannot be translated into `Expression:Const`
    /// * Amount of bytes to truncate cannot be translated into `u64`
    /// * `into_ir_expr()` returns `Err` `on self.input0`
    fn create_subpiece(&self, address: &str) -> Term<Def> {
        if let Expression::Const(truncate) = self
            .input1
            .as_ref()
            .expect("input0 of subpiece is None")
            .into_ir_expr()
            .expect("Subpiece truncation number translation failed")
        {
            let expr = Expression::Subpiece {
                low_byte: truncate.try_to_u64().unwrap().into(),
                size: self
                    .output
                    .as_ref()
                    .expect("Subpiece output is None")
                    .size
                    .into(),
                arg: Box::new(
                    self.input0
                        .into_ir_expr()
                        .expect("Subpiece source data translation failed"),
                ),
            };
            self.wrap_in_assign_or_store(address, expr)
        } else {
            panic!("Number of truncation bytes is not a constant")
        }
    }

    /// Translates pcode operation with one input into `Term<Def>` with unary `Expression`.
    /// The mapping is implemented in `into_ir_unop`.
    ///
    /// Panics if,
    /// * `self.pcode_mnemonic` is not `PcodeOperation::ExpressionType`
    /// * `self.output` is `None` or `into_it_expr()` returns not an `Expression::Var`
    /// * `into_ir_expr()` returns `Err` on `self.output` or `self.input0`
    fn create_unop(&self, address: &str) -> Term<Def> {
        if let PcodeOperation::ExpressionType(expr_type) = self.pcode_mnemonic {
            let expr = Expression::UnOp {
                op: expr_type
                    .into_ir_unop()
                    .expect("Translation into unary operation type failed"),
                arg: Box::new(self.input0.into_ir_expr().unwrap()),
            };
            self.wrap_in_assign_or_store(address, expr)
        } else {
            panic!("Not an expression type")
        }
    }

    /// Translates a pcode operation with two inputs into `Term<Def>` with binary `Expression`.
    /// The mapping is implemented in `into_ir_biop`.
    ///
    /// Panics if,
    /// * `self.pcode_mnemonic` is not `PcodeOperation::ExpressionType`
    /// * `self.output` is `None` or `into_it_expr()` returns not an `Expression::Var`
    /// * `into_ir_expr()` returns `Err` on `self.output`, `self.input0` or `self.input1`
    fn create_biop(&self, address: &str) -> Term<Def> {
        if let PcodeOperation::ExpressionType(expr_type) = self.pcode_mnemonic {
            let expr = Expression::BinOp {
                op: expr_type
                    .into_ir_biop()
                    .expect("Translation into binary operation type failed"),
                lhs: Box::new(self.input0.into_ir_expr().unwrap()),
                rhs: Box::new(
                    self.input1
                        .as_ref()
                        .expect("No input1 for binary operation")
                        .into_ir_expr()
                        .unwrap(),
                ),
            };
            self.wrap_in_assign_or_store(address, expr)
        } else {
            panic!("Not an expression type")
        }
    }

    /// Translates a cast pcode operation into `Term<Def>` with `Expression::Cast`.
    /// The mapping is implemented in `into_ir_castop`.
    ///
    /// Panics if,
    /// * `self.pcode_mnemonic` is not `PcodeOperation::ExpressionType`
    /// * `self.output` is `None` or `into_it_expr()` returns not an `Expression::Var`
    /// * `into_ir_expr()` returns `Err` on `self.output` or `self.input0`
    fn create_castop(&self, address: &str) -> Term<Def> {
        if let PcodeOperation::ExpressionType(expr_type) = self.pcode_mnemonic {
            let expr = Expression::Cast {
                op: expr_type
                    .into_ir_cast()
                    .expect("Translation into cast operation failed"),
                size: self
                    .output
                    .clone()
                    .expect("No output for cast operation")
                    .size
                    .into(),
                arg: Box::new(self.input0.into_ir_expr().unwrap()),
            };
            self.wrap_in_assign_or_store(address, expr)
        } else {
            panic!("Not an expression type")
        }
    }

    /// Translates `PcodeOperation::COPY` into `Term` containing `Def::Assign`.
    fn create_assign(&self, address: &str) -> Term<Def> {
        if let PcodeOperation::ExpressionType(ExpressionType::COPY) = self.pcode_mnemonic {
            let expr = self.input0.into_ir_expr().unwrap();
            self.wrap_in_assign_or_store(address, expr)
        } else {
            panic!("PcodeOperation is not COPY")
        }
    }

    /// Helper function for creating a Def::Assign operation, or Def::Store if an implicit
    /// store instruction is present.
    ///
    /// Panics if,
    /// * for Assign case: self.output is `None` or `into_ir_expr()` returns `Err`
    /// * for Assign case: self.output is not `Expression::Var`
    /// * for Store case: self.output is `None` or `get_ram_address()` returns `None`
    fn wrap_in_assign_or_store(&self, address: &str, expr: Expression) -> Term<Def> {
        let tid = Tid {
            id: format!("instr_{}_{}", address, self.pcode_index),
            address: address.to_string(),
        };
        if self.has_implicit_store() {
            return Term {
                tid,
                term: Def::Store {
                    address: Expression::Const(
                        self.output
                            .as_ref()
                            .expect("No output varnode")
                            .get_ram_address()
                            .expect("Output varnode is not ram"),
                    ),
                    value: expr,
                },
            };
        } else {
            if let Expression::Var(var) = self
                .output
                .as_ref()
                .expect("No output varnode")
                .into_ir_expr()
                .unwrap()
            {
                Term {
                    tid,
                    term: Def::Assign { var, value: expr },
                }
            } else {
                panic!("Output varnode is not a variable")
            }
        }
    }
}

#[cfg(test)]
pub mod tests;
