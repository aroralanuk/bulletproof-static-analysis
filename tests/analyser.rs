extern crate curve25519_dalek;
extern crate merlin;

use mpc_bulletproof::r1cs::*;
use mpc_bulletproof::examples::OrGate;
use mpc_bulletproof::{PedersenGens};
use merlin::Transcript;

use curve25519_dalek::scalar::Scalar;
// use crate::examples::OrGate;


#[test]
fn test_or_gate() {


    let pc_gens = PedersenGens::default();
    let mut transcript = Transcript::new(b"test");

    let mut cs = Prover::new(
        &pc_gens,
        &mut transcript,
    );

    let a = Scalar::one();
    let b = Scalar::zero();
    let expected_result = a + b - (a * b);

    let result = OrGate::or(a, b, &mut cs);
    println!("result: {:?}", cs.eval(&result));

    assert!(1 == 2);
    cs.commit(a, Scalar::one());
    let result_lc = cs.commit(b, Scalar::one());


    // let result_scalar = cs.get_value(result_lc);
    // assert_eq!(result_scalar, expected_result);
}






