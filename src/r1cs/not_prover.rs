#![allow(non_snake_case)]

use clear_on_drop::clear::Clear;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul};
use merlin::Transcript;

use super::{
    ConstraintSystem, LinearCombination, R1CSProof, RandomizableConstraintSystem,
    RandomizedConstraintSystem, Variable,
};

use crate::errors::R1CSError;
use crate::generators::{BulletproofGens, PedersenGens};
use crate::inner_product_proof::InnerProductProof;
use crate::transcript::TranscriptProtocol;

/// A [`ConstraintSystem`] implementation for use by the prover.
///
/// The prover commits high-level variables and their blinding factors `(v, v_blinding)`,
/// allocates low-level variables and creates constraints in terms of these
/// high-level variables and low-level variables.
///
/// When all constraints are added, the proving code calls `prove`
/// which consumes the `Prover` instance, samples random challenges
/// that instantiate the randomized constraints, and creates a complete proof.
pub struct Prover<'t, 'g> {
    transcript: &'t mut Transcript,
    pc_gens: &'g PedersenGens,
    /// The constraints accumulated so far.
    constraints: Vec<LinearCombination>,
    /// Stores assignments to the "left" of multiplication gates
    a_L: Vec<Scalar>,
    /// Stores assignments to the "right" of multiplication gates
    a_R: Vec<Scalar>,
    /// Stores assignments to the "output" of multiplication gates
    a_O: Vec<Scalar>,
    /// High-level witness data (value openings to V commitments)
    v: Vec<Scalar>,
    /// High-level witness data (blinding openings to V commitments)
    v_blinding: Vec<Scalar>,

    /// This list holds closures that will be called in the second phase of the protocol,
    /// when non-randomized variables are committed.
    #[allow(clippy::type_complexity)]
    deferred_constraints: Vec<Box<dyn Fn(&mut RandomizingProver<'t, 'g>) -> Result<(), R1CSError>>>,

    /// Index of a pending multiplier that's not fully assigned yet.
    pending_multiplier: Option<usize>,
}

/// Prover in the randomizing phase.
///
/// Note: this type is exported because it is used to specify the associated type
/// in the public impl of a trait `ConstraintSystem`, which boils down to allowing compiler to
/// monomorphize the closures for the proving and verifying code.
/// However, this type cannot be instantiated by the user and therefore can only be used within
/// the callback provided to `specify_randomized_constraints`.
pub struct RandomizingProver<'t, 'g> {
    prover: Prover<'t, 'g>,
}

/// Overwrite secrets with null bytes when they go out of scope.
impl<'t, 'g> Drop for Prover<'t, 'g> {
    fn drop(&mut self) {
        self.v.clear();
        self.v_blinding.clear();

        // Important: due to how ClearOnDrop auto-implements InitializableFromZeroed
        // for T: Default, calling .clear() on Vec compiles, but does not
        // clear the content. Instead, it only clears the Vec's header.
        // Clearing the underlying buffer item-by-item will do the job, but will
        // keep the header as-is, which is fine since the header does not contain secrets.
        for e in self.a_L.iter_mut() {
            e.clear();
        }
        for e in self.a_R.iter_mut() {
            e.clear();
        }
        for e in self.a_O.iter_mut() {
            e.clear();
        }
        // XXX use ClearOnDrop instead of doing the above
    }
}

impl<'t, 'g> ConstraintSystem for Prover<'t, 'g> {
    fn transcript(&mut self) -> &mut Transcript {
        self.transcript
    }

    fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    fn num_multipliers(&self) -> usize {
        self.a_O.len()
    }

    fn multiply(
        &mut self,
        mut left: LinearCombination,
        mut right: LinearCombination,
    ) -> (Variable, Variable, Variable) {
        // Synthesize the assignments for l,r,o
        let l = self.eval(&left);
        let r = self.eval(&right);
        let o = l * r;

        // Create variables for l,r,o ...
        let l_var = Variable::MultiplierLeft(self.a_L.len());
        let r_var = Variable::MultiplierRight(self.a_R.len());
        let o_var = Variable::MultiplierOutput(self.a_O.len());
        // ... and assign them
        self.a_L.push(l);
        self.a_R.push(r);
        self.a_O.push(o);

        // Constrain l,r,o:
        left.add_term(l_var, -Scalar::one());
        right.add_term(r_var, -Scalar::one());
        self.constrain(left);
        self.constrain(right);

        (l_var, r_var, o_var)
    }

    fn allocate(&mut self, assignment: Option<Scalar>) -> Result<Variable, R1CSError> {
        let scalar = assignment.ok_or(R1CSError::MissingAssignment)?;

        match self.pending_multiplier {
            None => {
                let i = self.a_L.len();
                self.pending_multiplier = Some(i);
                self.a_L.push(scalar);
                self.a_R.push(Scalar::zero());
                self.a_O.push(Scalar::zero());
                Ok(Variable::MultiplierLeft(i))
            }
            Some(i) => {
                self.pending_multiplier = None;
                self.a_R[i] = scalar;
                self.a_O[i] = self.a_L[i] * self.a_R[i];
                Ok(Variable::MultiplierRight(i))
            }
        }
    }

    fn allocate_multiplier(
        &mut self,
        input_assignments: Option<(Scalar, Scalar)>,
    ) -> Result<(Variable, Variable, Variable), R1CSError> {
        let (l, r) = input_assignments.ok_or(R1CSError::MissingAssignment)?;
        let o = l * r;

        // Create variables for l,r,o ...
        let l_var = Variable::MultiplierLeft(self.a_L.len());
        let r_var = Variable::MultiplierRight(self.a_R.len());
        let o_var = Variable::MultiplierOutput(self.a_O.len());
        // ... and assign them
        self.a_L.push(l);
        self.a_R.push(r);
        self.a_O.push(o);

        Ok((l_var, r_var, o_var))
    }

    /// Creates a commitment to a public (statement) variable. We do not blind these
    /// commitments as their values are assumed to be public. Instead, we use a constant
    /// "blinding" factor of one to ensure that the verifier can mimic the commitment
    /// when it goes to verify the proof.
    fn commit_public(&mut self, v: Scalar) -> Variable {
        self.commit(v, Scalar::one()).1
    }

    fn constrain(&mut self, lc: LinearCombination) {
        // TODO: check that the linear combinations are valid
        // (e.g. that variables are valid, that the linear combination evals to 0 for prover, etc).
        self.constraints.push(lc);
    }

    fn eval(&self, lc: &LinearCombination) -> Scalar {
        lc.terms
            .iter()
            .map(|(var, coeff)| {
                coeff
                    * match var {
                        Variable::MultiplierLeft(i) =>
                        {
                            println!("a_L[{}] = {:?}", i, self.a_L[*i]);
                            return self.a_L[*i];
                        },
                        Variable::MultiplierRight(i) => self.a_R[*i],
                        Variable::MultiplierOutput(i) => self.a_O[*i],
                        Variable::Committed(i) => self.v[*i],
                        Variable::One() => Scalar::one(),
                        Variable::Zero() => Scalar::zero(),
                    }
            })
            .sum()
    }
}

impl<'t, 'g> RandomizableConstraintSystem for Prover<'t, 'g> {
    type RandomizedCS = RandomizingProver<'t, 'g>;

    fn specify_randomized_constraints<F>(&mut self, callback: F) -> Result<(), R1CSError>
    where
        F: 'static + Fn(&mut Self::RandomizedCS) -> Result<(), R1CSError>,
    {
        self.deferred_constraints.push(Box::new(callback));
        Ok(())
    }
}

impl<'t, 'g> ConstraintSystem for RandomizingProver<'t, 'g> {
    fn transcript(&mut self) -> &mut Transcript {
        self.prover.transcript
    }

    fn num_constraints(&self) -> usize {
        self.prover.num_constraints()
    }

    fn num_multipliers(&self) -> usize {
        self.prover.num_multipliers()
    }

    fn multiply(
        &mut self,
        left: LinearCombination,
        right: LinearCombination,
    ) -> (Variable, Variable, Variable) {
        self.prover.multiply(left, right)
    }

    fn allocate(&mut self, assignment: Option<Scalar>) -> Result<Variable, R1CSError> {
        self.prover.allocate(assignment)
    }

    fn allocate_multiplier(
        &mut self,
        input_assignments: Option<(Scalar, Scalar)>,
    ) -> Result<(Variable, Variable, Variable), R1CSError> {
        self.prover.allocate_multiplier(input_assignments)
    }

    fn commit_public(&mut self, value: Scalar) -> Variable {
        self.prover.commit_public(value)
    }

    fn constrain(&mut self, lc: LinearCombination) {
        self.prover.constrain(lc)
    }

    fn eval(&self, lc: &LinearCombination) -> Scalar {
        self.prover.eval(lc)
    }
}

impl<'t, 'g> RandomizedConstraintSystem for RandomizingProver<'t, 'g> {
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        self.prover.transcript.challenge_scalar(label)
    }
}

impl<'t, 'g> Prover<'t, 'g> {
    /// Construct an empty constraint system with specified external
    /// input variables.
    ///
    /// # Inputs
    ///
    /// The `bp_gens` and `pc_gens` are generators for Bulletproofs
    /// and for the Pedersen commitments, respectively.  The
    /// [`BulletproofGens`] should have `gens_capacity` greater than
    /// the number of multiplication constraints that will eventually
    /// be added into the constraint system.
    ///
    /// The `transcript` parameter is a Merlin proof transcript.  The
    /// `ProverCS` holds onto the `&mut Transcript` until it consumes
    /// itself during [`ProverCS::prove`], releasing its borrow of the
    /// transcript.  This ensures that the transcript cannot be
    /// altered except by the `ProverCS` before proving is complete.
    ///
    /// # Returns
    ///
    /// Returns a new `Prover` instance.
    pub fn new(pc_gens: &'g PedersenGens, transcript: &'t mut Transcript) -> Self {
        transcript.r1cs_domain_sep();

        Prover {
            pc_gens,
            transcript,
            v: Vec::new(),
            v_blinding: Vec::new(),
            constraints: Vec::new(),
            a_L: Vec::new(),
            a_R: Vec::new(),
            a_O: Vec::new(),
            deferred_constraints: Vec::new(),
            pending_multiplier: None,
        }
    }

    /// Creates commitment to a high-level variable and adds it to the transcript.
    ///
    /// # Inputs
    ///
    /// The `v` and `v_blinding` parameters are openings to the
    /// commitment to the external variable for the constraint
    /// system.  Passing the opening (the value together with the
    /// blinding factor) makes it possible to reference pre-existing
    /// commitments in the constraint system.  All external variables
    /// must be passed up-front, so that challenges produced by
    /// [`ConstraintSystem::challenge_scalar`] are bound to the
    /// external variables.
    ///
    /// # Returns
    ///
    /// Returns a pair of a Pedersen commitment (as a compressed Ristretto point),
    /// and a [`Variable`] corresponding to it, which can be used to form constraints.
    pub fn commit(&mut self, v: Scalar, v_blinding: Scalar) -> (CompressedRistretto, Variable) {
        let i = self.v.len();
        self.v.push(v);
        self.v_blinding.push(v_blinding);

        // Add the commitment to the transcript.
        let V = self.pc_gens.commit(v, v_blinding).compress();
        self.transcript.append_point(b"V", &V);

        (V, Variable::Committed(i))
    }

    pub fn commit_analyze(&mut self, v: Scalar, v_blinding: Scalar) -> (CompressedRistretto, Variable, Vec<Scalar>) {
        let i = self.v.len();
        self.v.push(v);
        self.v_blinding.push(v_blinding);

        // Add the commitment to the transcript.
        let V = self.pc_gens.commit(v, v_blinding).compress();
        self.transcript.append_point(b"V", &V);

        let v_clone = self.v.clone();
        (V, Variable::Committed(i), v_clone)
    }

    /// Use a challenge, `z`, to flatten the constraints in the
    /// constraint system into vectors used for proving and
    /// verification.
    ///
    /// # Output
    ///
    /// Returns a tuple of
    /// ```text
    /// (wL, wR, wO, wV)
    /// ```
    /// where `w{L,R,O}` is \\( z \cdot z^Q \cdot W_{L,R,O} \\).
    fn flattened_constraints(
        &mut self,
        z: &Scalar,
    ) -> (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Vec<Scalar>) {
        let n = self.a_L.len();
        let m = self.v.len();

        let mut wL = vec![Scalar::zero(); n];
        let mut wR = vec![Scalar::zero(); n];
        let mut wO = vec![Scalar::zero(); n];
        let mut wV = vec![Scalar::zero(); m];

        let mut exp_z = *z;
        for lc in self.constraints.iter() {
            for (var, coeff) in &lc.terms {
                match var {
                    Variable::MultiplierLeft(i) => {
                        wL[*i] += exp_z * coeff;
                    }
                    Variable::MultiplierRight(i) => {
                        wR[*i] += exp_z * coeff;
                    }
                    Variable::MultiplierOutput(i) => {
                        wO[*i] += exp_z * coeff;
                    }
                    Variable::Committed(i) => {
                        wV[*i] -= exp_z * coeff;
                    }
                    Variable::One() | Variable::Zero() => {
                        // The prover doesn't need to handle constant terms
                    }
                }
            }
            exp_z *= z;
        }

        (wL, wR, wO, wV)
    }

    /// Calls all remembered callbacks with an API that
    /// allows generating challenge scalars.
    fn create_randomized_constraints(mut self) -> Result<Self, R1CSError> {
        // Clear the pending multiplier (if any) because it was committed into A_L/A_R/S.
        self.pending_multiplier = None;

        if self.deferred_constraints.is_empty() {
            self.transcript.r1cs_1phase_domain_sep();
            Ok(self)
        } else {
            self.transcript.r1cs_2phase_domain_sep();
            // Note: the wrapper could've used &mut instead of ownership,
            // but specifying lifetimes for boxed closures is not going to be nice,
            // so we move the self into wrapper and then move it back out afterwards.
            let mut callbacks = std::mem::take(&mut self.deferred_constraints);
            let mut wrapped_self = RandomizingProver { prover: self };
            for callback in callbacks.drain(..) {
                callback(&mut wrapped_self)?;
            }
            Ok(wrapped_self.prover)
        }
    }

    /// Checks whether all the constraints are satisfied, does not prove the statement
    pub fn constraints_satisfied(&self) -> bool {
        self.constraints
            .iter()
            .all(|constraint| self.eval(constraint) == Scalar::zero())
    }
}
