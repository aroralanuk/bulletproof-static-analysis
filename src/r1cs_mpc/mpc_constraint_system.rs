//! Definition of the constraint system traits for a distributed prover

use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};

use crate::errors::R1CSError;

use super::{
    mpc_linear_combination::{MpcLinearCombination, MpcVariable},
    MultiproverError,
};

/// The interface for a constraint system, abstracting over the prover
/// and verifier's roles.
///
/// Statements to be proved by an [`R1CSProof`](::r1cs::R1CSProof) are specified by
/// programmatically constructing constraints.  These constraints need
/// to be identical between the prover and verifier, since the prover
/// and verifier need to construct the same statement.
///
/// To prevent code duplication or mismatches between the prover and
/// verifier, gadgets for the constraint system should be written
/// using the `ConstraintSystem` trait, so that the prover and
/// verifier share the logic for specifying constraints.
pub trait MpcConstraintSystem<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>> {
    /// Leases the proof transcript to the user, so they can
    /// add extra data to which the proof must be bound, but which
    /// is not available before creation of the constraint system.
    fn transcript(&mut self) -> &mut Transcript;

    /// Allocate and constrain multiplication variables.
    ///
    /// Allocate variables `left`, `right`, and `out`
    /// with the implicit constraint that
    /// ```text
    /// left * right = out
    /// ```
    /// and add the explicit constraints that
    /// ```text
    /// left = left_constraint
    /// right = right_constraint
    /// ```
    ///
    /// Returns `(left, right, out)` for use in further constraints.
    #[allow(clippy::type_complexity)]
    fn multiply(
        &mut self,
        left: &MpcLinearCombination<N, S>,
        right: &MpcLinearCombination<N, S>,
    ) -> Result<(MpcVariable<N, S>, MpcVariable<N, S>, MpcVariable<N, S>), MultiproverError>;

    /// Allocate a single variable.
    ///
    /// This either allocates a new multiplier and returns its `left` variable,
    /// or returns a `right` variable of a multiplier previously allocated by this method.
    /// The output of a multiplier is assigned on a even call, when `right` is assigned.
    ///
    /// When CS is committed at the end of the first or second phase, the half-assigned multiplier
    /// has the `right` assigned to zero and all its variables committed.
    ///
    /// Returns unconstrained `Variable` for use in further constraints.
    fn allocate(
        &mut self,
        assignment: Option<AuthenticatedScalar<N, S>>,
    ) -> Result<MpcVariable<N, S>, R1CSError>;

    /// Allocate variables `left`, `right`, and `out`
    /// with the implicit constraint that
    /// ```text
    /// left * right = out
    /// ```
    ///
    /// Returns `(left, right, out)` for use in further constraints.
    #[allow(clippy::type_complexity)]
    fn allocate_multiplier(
        &mut self,
        input_assignments: Option<(AuthenticatedScalar<N, S>, AuthenticatedScalar<N, S>)>,
    ) -> Result<(MpcVariable<N, S>, MpcVariable<N, S>, MpcVariable<N, S>), R1CSError>;

    /// Counts the amount of allocated multipliers.
    fn multipliers_len(&self) -> usize;

    /// Enforce the explicit constraint that
    /// ```text
    /// lc = 0
    /// ```
    fn constrain(&mut self, lc: MpcLinearCombination<N, S>);

    /// Evaluate a linear combination using the values allocated in the constraint system
    fn eval(
        &self,
        lc: &MpcLinearCombination<N, S>,
    ) -> Result<AuthenticatedScalar<N, S>, MultiproverError>;
}

/// An extension to the constraint system trait that permits randomized constraints.
/// Gadgets that do not use randomization should use trait bound `CS: ConstraintSystem`,
/// while gadgets that need randomization should use trait bound `CS: RandomizedConstraintSystem`.
/// Gadgets generally _should not_ use this trait as a bound on the CS argument: it should be used
/// by the higher-order protocol that composes gadgets together.
pub trait MpcRandomizableConstraintSystem<
    'a,
    N: 'a + MpcNetwork + Send,
    S: 'a + SharedValueSource<Scalar>,
>: MpcConstraintSystem<'a, N, S>
{
    /// Represents a concrete type for the CS in a randomization phase.
    type RandomizedCS: MpcRandomizedConstraintSystem<'a, N, S>;

    /// Specify additional variables and constraints randomized using a challenge scalar
    /// bound to the assignments of the non-randomized variables.
    ///
    /// If the constraint system’s low-level variables have not been committed yet,
    /// the call returns `Ok()` and saves a callback until later.
    ///
    /// If the constraint system’s low-level variables are committed already,
    /// the callback is invoked immediately and its result is return from this method.
    ///
    /// ### Usage
    ///
    /// Inside the closure you can generate one or more challenges using `challenge_scalar` method.
    ///
    /// ```text
    /// cs.specify_randomized_constraints(move |cs| {
    ///     let z = cs.challenge_scalar(b"some challenge");
    ///     // ...
    /// })
    /// ```
    fn specify_randomized_constraints<F>(&mut self, callback: F) -> Result<(), R1CSError>
    where
        F: 'a + Fn(&mut Self::RandomizedCS) -> Result<(), R1CSError>;
}

/// Represents a constraint system in the second phase:
/// when the challenges can be sampled to create randomized constraints.
///
/// Note: this trait also includes `ConstraintSystem` trait
/// in order to allow composition of gadgets: e.g. a shuffle gadget can be used in both phases.
pub trait MpcRandomizedConstraintSystem<
    'a,
    N: 'a + MpcNetwork + Send,
    S: 'a + SharedValueSource<Scalar>,
>: MpcConstraintSystem<'a, N, S>
{
    /// Generates a challenge scalar.
    ///
    /// ### Usage
    ///
    /// This method is available only within the scope of a closure provided
    /// to `specify_randomized_constraints`, which implements
    /// the "randomization" phase of the protocol.
    ///
    /// Arbitrary number of challenges can be generated with additional calls.
    ///
    /// ```text
    /// cs.specify_randomized_constraints(move |cs| {
    ///     let z = cs.challenge_scalar(b"some challenge");
    ///     // ...
    /// })
    /// ```
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
}
