use crate::{
    r1cs::{LinearCombination, RandomizableConstraintSystem, Variable},
    r1cs_mpc::{MpcLinearCombination, MpcRandomizableConstraintSystem},
};

pub struct OrGate {}
impl OrGate {
    /// Computes the logical OR of the two arguments
    ///
    /// The arguments are assumed to be binary (0 or 1), but this assumption should be
    /// constrained elsewhere in the calling circuit
    pub fn or<L, CS>(a: L, b: L, cs: &mut CS) -> LinearCombination
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        let (a, b, a_times_b) = cs.multiply(a.into(), b.into());
        a + b - a_times_b
    }
}
