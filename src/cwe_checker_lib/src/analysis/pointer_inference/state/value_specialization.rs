//! Methods of [`State`] for specializing values through comparison operations.

use super::*;

impl State {
    /// Try to restrict the input variables of `expression` on `self`
    /// so that `expression` only evaluates to values represented by the given `result`.
    ///
    /// If `expression` cannot evaluate to any value represented by `self`, return an error.
    ///
    /// This function may restrict to upper bounds of possible values
    /// if the restriction cannot be made exact,
    /// i.e. after calling this function the state may still contain values
    /// for which `expression` does not evaluate to values represented by `result`.
    pub fn specialize_by_expression_result(
        &mut self,
        expression: &Expression,
        result: Data,
    ) -> Result<(), Error> {
        if let Expression::Var(var) = expression {
            self.set_register(var, self.eval(expression).intersect(&result)?);
            Ok(())
        } else if let Expression::BinOp { op, lhs, rhs } = expression {
            self.specialize_by_binop_expression_result(op, lhs, rhs, result)
        } else {
            match expression {
                Expression::Var(_) => panic!(),
                Expression::Const(input_bitvec) => {
                    if let Ok(result_bitvec) = result.try_to_bitvec() {
                        if *input_bitvec == result_bitvec {
                            Ok(())
                        } else {
                            Err(anyhow!("Unsatisfiable state"))
                        }
                    } else {
                        Ok(())
                    }
                }
                Expression::BinOp { .. } => {
                    panic!() // Already handled above
                }
                Expression::UnOp { op, arg } => {
                    use UnOpType::*;
                    match op {
                        IntNegate | BoolNegate | Int2Comp => {
                            let intermediate_result = result.un_op(*op);
                            self.specialize_by_expression_result(arg, intermediate_result)
                        }
                        _ => Ok(()),
                    }
                }
                Expression::Cast { op, size: _, arg } => match op {
                    CastOpType::IntZExt | CastOpType::IntSExt => {
                        let intermediate_result = result.subpiece(ByteSize::new(0), arg.bytesize());
                        self.specialize_by_expression_result(arg, intermediate_result)
                    }
                    _ => Ok(()),
                },
                Expression::Unknown {
                    description: _,
                    size: _,
                } => Ok(()),
                Expression::Subpiece {
                    low_byte,
                    size,
                    arg,
                } => {
                    if *low_byte == ByteSize::new(0) {
                        if let Some(arg_value) = self.eval(expression).get_if_absolute_value() {
                            if arg_value.fits_into_size(*size) {
                                let intermediate_result =
                                    result.cast(CastOpType::IntSExt, arg.bytesize());
                                return self
                                    .specialize_by_expression_result(arg, intermediate_result);
                            }
                        }
                    }
                    Ok(())
                }
            }
        }
    }

    /// Try to restrict the input variables of the given binary operation
    /// so that it only evaluates to the given `result_bitvec`.
    fn specialize_by_binop_expression_result(
        &mut self,
        op: &BinOpType,
        lhs: &Expression,
        rhs: &Expression,
        result: Data,
    ) -> Result<(), Error> {
        match op {
            BinOpType::IntAdd => {
                let intermediate_result = result.clone() - self.eval(lhs).without_widening_hints();
                self.specialize_by_expression_result(rhs, intermediate_result)?;

                let intermediate_result = result - self.eval(rhs).without_widening_hints();
                self.specialize_by_expression_result(lhs, intermediate_result)?;

                return Ok(());
            }
            BinOpType::IntSub => {
                let intermediate_result: Data =
                    self.eval(lhs).without_widening_hints() - result.clone();
                self.specialize_by_expression_result(rhs, intermediate_result)?;

                let intermediate_result = result + self.eval(rhs).without_widening_hints();
                self.specialize_by_expression_result(lhs, intermediate_result)?;

                return Ok(());
            }
            _ => (),
        }
        if let Ok(result_bitvec) = result.try_to_bitvec() {
            match op {
                BinOpType::IntXOr | BinOpType::BoolXOr => {
                    if let Ok(bitvec) = self.eval(lhs).try_to_bitvec() {
                        self.specialize_by_expression_result(
                            rhs,
                            (result_bitvec.clone() ^ &bitvec).into(),
                        )?;
                    }
                    if let Ok(bitvec) = self.eval(rhs).try_to_bitvec() {
                        self.specialize_by_expression_result(
                            lhs,
                            (result_bitvec ^ &bitvec).into(),
                        )?;
                    }
                    Ok(())
                }
                BinOpType::IntOr | BinOpType::BoolOr => {
                    if result_bitvec.is_zero() {
                        self.specialize_by_expression_result(lhs, result_bitvec.clone().into())?;
                        self.specialize_by_expression_result(rhs, result_bitvec.into())
                    } else if self
                        .eval(lhs)
                        .try_to_bitvec()
                        .map_or(false, |bitvec| bitvec.is_zero())
                    {
                        self.specialize_by_expression_result(rhs, result_bitvec.into())
                    } else if self
                        .eval(rhs)
                        .try_to_bitvec()
                        .map_or(false, |bitvec| bitvec.is_zero())
                    {
                        self.specialize_by_expression_result(lhs, result_bitvec.into())
                    } else {
                        Ok(())
                    }
                }
                BinOpType::BoolAnd => {
                    if !result_bitvec.is_zero() {
                        self.specialize_by_expression_result(lhs, result_bitvec.clone().into())?;
                        self.specialize_by_expression_result(rhs, result_bitvec.into())
                    } else if self
                        .eval(lhs)
                        .try_to_bitvec()
                        .map_or(false, |bitvec| !bitvec.is_zero())
                    {
                        self.specialize_by_expression_result(rhs, result_bitvec.into())
                    } else if self
                        .eval(rhs)
                        .try_to_bitvec()
                        .map_or(false, |bitvec| !bitvec.is_zero())
                    {
                        self.specialize_by_expression_result(lhs, result_bitvec.into())
                    } else {
                        Ok(())
                    }
                }
                BinOpType::IntEqual | BinOpType::IntNotEqual => {
                    match (op, !result_bitvec.is_zero()) {
                        (BinOpType::IntEqual, true) | (BinOpType::IntNotEqual, false) => {
                            // lhs == rhs
                            if let Ok(bitvec) = self.eval(lhs).try_to_bitvec() {
                                self.specialize_by_expression_result(rhs, bitvec.into())?;
                            }
                            if let Ok(bitvec) = self.eval(rhs).try_to_bitvec() {
                                self.specialize_by_expression_result(lhs, bitvec.into())?;
                            }
                            // Also specialize cases of pointer comparisons
                            self.specialize_pointer_comparison(&BinOpType::IntEqual, lhs, rhs)?;
                            Ok(())
                        }
                        (BinOpType::IntEqual, false) | (BinOpType::IntNotEqual, true) => {
                            // lhs != rhs
                            if let Ok(bitvec) = self.eval(lhs).try_to_bitvec() {
                                let new_result = self
                                    .eval(rhs)
                                    .without_widening_hints()
                                    .add_not_equal_bound(&bitvec)?;
                                self.specialize_by_expression_result(rhs, new_result)?;
                            }
                            if let Ok(bitvec) = self.eval(rhs).try_to_bitvec() {
                                let new_result = self
                                    .eval(lhs)
                                    .without_widening_hints()
                                    .add_not_equal_bound(&bitvec)?;
                                self.specialize_by_expression_result(lhs, new_result)?;
                            }
                            // Also specialize cases of pointer comparisons
                            self.specialize_pointer_comparison(&BinOpType::IntNotEqual, lhs, rhs)?;
                            Ok(())
                        }
                        _ => panic!(),
                    }
                }
                BinOpType::IntSLess
                | BinOpType::IntLess
                | BinOpType::IntLessEqual
                | BinOpType::IntSLessEqual => {
                    use BinOpType::*;
                    let mut op = *op;
                    let (mut left_expr, mut right_expr) = (lhs, rhs);
                    if result_bitvec.is_zero() {
                        std::mem::swap(&mut left_expr, &mut right_expr);
                        op = match op {
                            IntSLess => IntSLessEqual,
                            IntSLessEqual => IntSLess,
                            IntLess => IntLessEqual,
                            IntLessEqual => IntLess,
                            _ => panic!(),
                        }
                    }
                    self.specialize_by_comparison_op(&op, left_expr, right_expr)
                }
                _ => {
                    let original_expression = Expression::BinOp {
                        lhs: Box::new(lhs.clone()),
                        op: *op,
                        rhs: Box::new(rhs.clone()),
                    };
                    if let Ok(interval) = self.eval(&original_expression).try_to_interval() {
                        if !interval.contains(&result_bitvec) {
                            Err(anyhow!("Unsatisfiable bound"))
                        } else {
                            Ok(())
                        }
                    } else {
                        Ok(())
                    }
                }
            }
        } else {
            Ok(())
        }
    }

    /// If both `lhs` and `rhs` evaluate to pointers and `op` is a comparison operator that evaluates to `true`,
    /// specialize the input pointers accordingly.
    ///
    /// Note that the current implementation only specializes for `==` and `!=` operators
    /// and only if the pointers point to the same unique memory object.
    fn specialize_pointer_comparison(
        &mut self,
        op: &BinOpType,
        lhs: &Expression,
        rhs: &Expression,
    ) -> Result<(), Error> {
        let (lhs_pointer, rhs_pointer) = (
            self.eval(lhs).without_widening_hints(),
            self.eval(rhs).without_widening_hints(),
        );
        match (
            lhs_pointer.get_if_unique_target(),
            rhs_pointer.get_if_unique_target(),
        ) {
            (Some((lhs_id, lhs_offset)), Some((rhs_id, rhs_offset))) if lhs_id == rhs_id => {
                if !(self.memory.is_unique_object(lhs_id)?) {
                    // Since the pointers may or may not point to different instances referenced by the same ID we cannot compare them.
                    return Ok(());
                }
                if *op == BinOpType::IntEqual {
                    let specialized_offset = lhs_offset.clone().intersect(rhs_offset)?;
                    let specialized_domain: Data =
                        Data::from_target(lhs_id.clone(), specialized_offset);
                    self.specialize_by_expression_result(lhs, specialized_domain.clone())?;
                    self.specialize_by_expression_result(rhs, specialized_domain)?;
                } else if *op == BinOpType::IntNotEqual {
                    if let Ok(rhs_offset_bitvec) = rhs_offset.try_to_bitvec() {
                        let new_lhs_offset =
                            lhs_offset.clone().add_not_equal_bound(&rhs_offset_bitvec)?;
                        self.specialize_by_expression_result(
                            lhs,
                            Data::from_target(lhs_id.clone(), new_lhs_offset),
                        )?;
                    }
                    if let Ok(lhs_offset_bitvec) = lhs_offset.try_to_bitvec() {
                        let new_rhs_offset =
                            rhs_offset.clone().add_not_equal_bound(&lhs_offset_bitvec)?;
                        self.specialize_by_expression_result(
                            rhs,
                            Data::from_target(rhs_id.clone(), new_rhs_offset),
                        )?;
                    }
                }
            }
            _ => (), // Other cases not handled, since it depends on the meaning of pointer IDs, which may change in the future.
        }
        Ok(())
    }

    /// Try to restrict the input variables of the given comparison operation
    /// (signed and unsigned versions of `<` and `<=`)
    /// so that the comparison evaluates to `true`.
    fn specialize_by_comparison_op(
        &mut self,
        op: &BinOpType,
        lhs: &Expression,
        rhs: &Expression,
    ) -> Result<(), Error> {
        use BinOpType::*;
        if let Ok(mut lhs_bound) = self.eval(lhs).try_to_bitvec() {
            match op {
                IntSLess => {
                    if lhs_bound == Bitvector::signed_max_value(lhs_bound.width()) {
                        return Err(anyhow!("Unsatisfiable bound"));
                    }
                    lhs_bound += &Bitvector::one(lhs_bound.width());
                    let new_result = self
                        .eval(rhs)
                        .without_widening_hints()
                        .add_signed_greater_equal_bound(&lhs_bound)?;
                    self.specialize_by_expression_result(rhs, new_result)?;
                }
                IntSLessEqual => {
                    let new_result = self
                        .eval(rhs)
                        .without_widening_hints()
                        .add_signed_greater_equal_bound(&lhs_bound)?;
                    self.specialize_by_expression_result(rhs, new_result)?;
                }
                IntLess => {
                    if lhs_bound == Bitvector::unsigned_max_value(lhs_bound.width()) {
                        return Err(anyhow!("Unsatisfiable bound"));
                    }
                    lhs_bound += &Bitvector::one(lhs_bound.width());
                    let new_result = self
                        .eval(rhs)
                        .without_widening_hints()
                        .add_unsigned_greater_equal_bound(&lhs_bound)?;
                    self.specialize_by_expression_result(rhs, new_result)?;
                }
                IntLessEqual => {
                    let new_result = self
                        .eval(rhs)
                        .without_widening_hints()
                        .add_unsigned_greater_equal_bound(&lhs_bound)?;
                    self.specialize_by_expression_result(rhs, new_result)?;
                }
                _ => panic!(),
            }
        }
        if let Ok(mut rhs_bound) = self.eval(rhs).try_to_bitvec() {
            match op {
                IntSLess => {
                    if rhs_bound == Bitvector::signed_min_value(rhs_bound.width()) {
                        return Err(anyhow!("Unsatisfiable bound"));
                    }
                    rhs_bound -= &Bitvector::one(rhs_bound.width());
                    let new_result = self
                        .eval(lhs)
                        .without_widening_hints()
                        .add_signed_less_equal_bound(&rhs_bound)?;
                    self.specialize_by_expression_result(lhs, new_result)?;
                }
                IntSLessEqual => {
                    let new_result = self
                        .eval(lhs)
                        .without_widening_hints()
                        .add_signed_less_equal_bound(&rhs_bound)?;
                    self.specialize_by_expression_result(lhs, new_result)?;
                }
                IntLess => {
                    if rhs_bound == Bitvector::zero(rhs_bound.width()) {
                        return Err(anyhow!("Unsatisfiable bound"));
                    }
                    rhs_bound -= &Bitvector::one(rhs_bound.width());
                    let new_result = self
                        .eval(lhs)
                        .without_widening_hints()
                        .add_unsigned_less_equal_bound(&rhs_bound)?;
                    self.specialize_by_expression_result(lhs, new_result)?;
                }
                IntLessEqual => {
                    let new_result = self
                        .eval(lhs)
                        .without_widening_hints()
                        .add_unsigned_less_equal_bound(&rhs_bound)?;
                    self.specialize_by_expression_result(lhs, new_result)?;
                }
                _ => panic!(),
            }
        }
        Ok(())
    }
}
