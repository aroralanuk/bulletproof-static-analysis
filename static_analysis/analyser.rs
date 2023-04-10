extern crate curve25519_dalek;
extern crate merlin;

use mpc_bulletproof::r1cs::*;
use mpc_bulletproof::{PedersenGens};
use merlin::Transcript;

use curve25519_dalek::scalar::Scalar;
// use crate::examples::OrGate;

pub struct R1CSAnalyzer {
}

impl R1CSAnalyzer {
    pub fn analyze(cs: &impl ConstraintSystem) {
        // let mut unconstrained_vars = Vec::new();
        // for i in 0..cs.num_multipliers() {
        //     let lc = LinearCombination::new(vec![(Variable::MultiplierOutput(i), Scalar::one())]);
        //     let lc_val = cs.eval(&lc);
        //     if lc_val != Scalar::zero() {
        //         unconstrained_vars.push(format!("{:?}", Variable::MultiplierOutput(i)));
        //     }
        // }


        // for i in 0..cs.num_constraints() {
        //     let lc = LinearCombination::new(vec![(Variable::Committed(i), Scalar::one())]);

        //     let lc_val = cs.eval(&lc);
        //     if lc_val != Scalar::zero() {
        //         unconstrained_vars.push(format!("{:?}", Variable::Committed(i)));
        //     }
        // }
        // if unconstrained_vars.is_empty() {
        //     print!("No unconstrained variables found");
        // } else {
        //     print!("Unconstrained variables: {:?}", unconstrained_vars);
        // }
    }
}

// fn analyze_variables(cs: &impl ConstraintSystem) -> HashSet<Variable> {
//     let mut allocated_vars = HashSet::new();

//     for i in 0..cs.num_vars() {
//         allocated_vars.insert(Variable::MultiplierLeft(i));
//         allocated_vars.insert(Variable::MultiplierRight(i));
//         allocated_vars.insert(Variable::MultiplierOutput(i));
//         allocated_vars.insert(Variable::Committed(i));
//     }

//     allocated_vars
// }

// pub struct R1CSAnalyser {
//     pub prover: Prover,
// }

// fn r1cs_instance() -> (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>) {
//     let n = 3;

//     let mut cs = Prover::new(&mpc_bulletproof::generators::PedersenGens::default(), &mut merlin::Transcript::new(b"example"));
//     let a = vec![Scalar::random(&mut rand::thread_rng()); n];
//     let b = vec![Scalar::random(&mut rand::thread_rng()); n];
//     let c = vec![Scalar::random(&mut rand::thread_rng()); n];
//     for i in 0..n {
//         let (_, _, _) = cs.multiply(a[i], b[i], c[i]);
//     }
// }

// pub fn under_constrained_analysis(
//     pc_gens: &'b PedersenGens,
//     transcript: &'a mut Transcript,
// )  {
//     let mut prover = Prover::new(&pc_gens, transcript);

// }


// impl

pub fn analyse() {
    let pc_gens = PedersenGens::default();
    let mut transcript = Transcript::new(b"test");

    let mut cs = Prover::new(
        &pc_gens,
        &mut transcript,
    );

    let mut blinding_rng = rand::thread_rng();



        //     let input: Vec<Scalar> = (0..4)
        //     .map(|_| Scalar::from(rng.gen_range(min, max)))
        //     .collect();
        // let mut output = input.clone();



    let (_,_,v) = cs.commit_analyze(Scalar::one(), Scalar::zero());
    println!("v: {:?}", v);

    // let a = cs.allocate_multiplier();
    // let b = cs.allocate_multiplier(Scalar::one());
    // let c = cs.allocate_multiplier(Scalar::one());

    // apply the gadget
    // ShuffleProof::gadget(&mut prover, input_vars, output_vars)?;

    // let constrained_vars = analyze_constraints(&cs);
    // let allocated_vars = analyze_variables(&cs);




    // let (x, _) = cs.commit(Scalar::one(), Scalar::zero());
    // let (y, _) = cs.commit(Scalar::one(), Scalar::zero());
}

#[test]
fn test_or_gate() {


    let pc_gens = PedersenGens::default();
    let mut transcript = Transcript::new(b"test");

    let mut cs = Prover::new(
        &pc_gens,
        &mut transcript,
    );

    let a = Scalar::one();
    let b = Scalar::one();
    let expected_result = a + b - (a * b);

    // let result = crate::examples::OrGate::or(a, b, &mut cs);
    // println!("result: {:?}", result);

    // println!("{:?}", cs.v_constraints.len());
    // println!("{:?}", cs.v.len());
    // let result_lc = cs.commit(result);

    // let result_scalar = cs.prover.get_value(result_lc);
    // assert_eq!(result_scalar, expected_result);
}







