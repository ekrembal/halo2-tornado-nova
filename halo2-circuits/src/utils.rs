use halo2_base::{
    gates::{GateChip, GateInstructions},
    poseidon::hasher::{spec::OptimizedPoseidonSpec, state::PoseidonState},
    utils::BigPrimeField,
    AssignedValue, Context,
};

pub fn poseidon1<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    inputs: &[AssignedValue<F>; 1],
) -> AssignedValue<F> {
    const R_F: usize = 8;
    const R_P: usize = 56;
    const T: usize = 2;
    const RATE: usize = 1;
    let spec = OptimizedPoseidonSpec::<F, T, RATE>::new::<R_F, R_P, 0>();
    let zero = ctx.load_constant(F::ZERO);
    let mut state = PoseidonState::<F, T, RATE> {
        s: [zero, inputs[0]],
    };
    let inputs = [F::ZERO; RATE]
        .iter()
        .map(|f| ctx.load_constant(*f))
        .collect::<Vec<_>>();
    state.permutation(ctx, gate, &inputs, None, &spec); // avoid padding
    let state_0 = state.s;
    state_0[0]
}


pub fn poseidon2<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    inputs: &[AssignedValue<F>; 2],
) -> AssignedValue<F> {
    const R_F: usize = 8;
    const R_P: usize = 57;
    const T: usize = 3;
    const RATE: usize = 2;
    let spec = OptimizedPoseidonSpec::<F, T, RATE>::new::<R_F, R_P, 0>();
    let zero = ctx.load_constant(F::ZERO);
    let mut state = PoseidonState::<F, T, RATE> {
        s: [zero, inputs[0], inputs[1]],
    };
    let inputs = [F::ZERO; RATE]
        .iter()
        .map(|f| ctx.load_constant(*f))
        .collect::<Vec<_>>();
    state.permutation(ctx, gate, &inputs, None, &spec); // avoid padding
    let state_0 = state.s;
    state_0[0]
}

pub fn poseidon3<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    inputs: &[AssignedValue<F>; 3],
) -> AssignedValue<F> {
    const R_F: usize = 8;
    const R_P: usize = 56;
    const T: usize = 4;
    const RATE: usize = 3;
    let spec = OptimizedPoseidonSpec::<F, T, RATE>::new::<R_F, R_P, 0>();
    let zero = ctx.load_constant(F::ZERO);
    let mut state = PoseidonState::<F, T, RATE> {
        s: [zero, inputs[0], inputs[1], inputs[2]],
    };
    let inputs = [F::ZERO; RATE]
        .iter()
        .map(|f| ctx.load_constant(*f))
        .collect::<Vec<_>>();
    state.permutation(ctx, gate, &inputs, None, &spec); // avoid padding
    let state_0 = state.s;
    state_0[0]
}

///     Assume sel is binary.
///     If sel == 0 then outL = L and outR=R
///     If sel == 1 then outL = R and outR=L
pub fn cond_swap<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    l: AssignedValue<F>,
    r: AssignedValue<F>,
    sel: AssignedValue<F>,
) -> (AssignedValue<F>, AssignedValue<F>) {
    let temp = gate.sub(ctx, r, l);
    let aux = gate.mul(ctx, temp, sel);
    let out_l = gate.add(ctx, aux, l);
    let out_r = gate.sub(ctx, r, aux);
    return (out_l, out_r);
}


pub fn force_equal_if_enabled<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    enabled: AssignedValue<F>,
    l: AssignedValue<F>,
    r: AssignedValue<F>,
) {
    let subb = gate.sub(ctx, r, l);
    let is_sub_zero = gate.is_zero(ctx, subb);
    let should_be_zero = gate.mul_not(ctx, is_sub_zero, enabled);
    let zero = &ctx.load_constant(F::ZERO);
    ctx.constrain_equal(&should_be_zero, &zero);
}

pub fn merkle_proof<F: BigPrimeField, const DEPTH: usize>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    leaf: AssignedValue<F>,
    path_elements: [AssignedValue<F>; DEPTH],
    path_indices: AssignedValue<F>,
) -> AssignedValue<F> {
    let bits = gate.num_to_bits(ctx, path_indices, DEPTH);
    let mut prev_hash = leaf;
    for i in 0..DEPTH {
        // println!("i: {:?}, bit: {:?}", i, bits[i].value());
        let (out_l, out_r) = cond_swap(ctx, gate, prev_hash, path_elements[i], bits[i]);
        prev_hash = poseidon2(ctx, gate, &[out_l, out_r]);
    }
    prev_hash
}



#[cfg(test)]
mod test {
    use crate::utils::{cond_swap, merkle_proof, poseidon1, poseidon2, poseidon3};
    use halo2_base::{
        gates::RangeInstructions, halo2_proofs::halo2curves::bn256::Fr, utils::testing::base_test,
    };
    use k256::elliptic_curve::PrimeField;

    use super::force_equal_if_enabled;

    #[test]
    fn test_poseidon1() {
        base_test()
            .k(16)
            .lookup_bits(15)
            .expect_satisfied(true)
            .run(|ctx, range| {
                let inputs = [
                    ctx.load_constant(Fr::from_u128(123456789)),
                ];
                let result = poseidon1::<Fr>(ctx, range.gate(), &inputs);
                let expected = Fr::from_str_vartime(
                    "7110303097080024260800444665787206606103183587082596139871399733998958991511",
                )
                .unwrap();
                assert_eq!(result.value(), &expected);
            });
    }

    #[test]
    fn test_poseidon2() {
        base_test()
            .k(16)
            .lookup_bits(15)
            .expect_satisfied(true)
            .run(|ctx, range| {
                let inputs = [
                    ctx.load_constant(Fr::from_u128(1)),
                    ctx.load_constant(Fr::from_u128(2)),
                ];
                let result = poseidon2::<Fr>(ctx, range.gate(), &inputs);
                let expected = Fr::from_str_vartime(
                    "7853200120776062878684798364095072458815029376092732009249414926327459813530",
                )
                .unwrap();
                assert_eq!(result.value(), &expected);
            });
    }

    #[test]
    fn test_poseidon3() {
        base_test()
            .k(16)
            .lookup_bits(15)
            .expect_satisfied(true)
            .run(|ctx, range| {
                let inputs = [
                    ctx.load_constant(Fr::from_u128(5)),
                    ctx.load_constant(Fr::from_u128(100)),
                    ctx.load_constant(Fr::from_u128(12)),
                ];
                let result = poseidon3::<Fr>(ctx, range.gate(), &inputs);
                let expected = Fr::from_str_vartime(
                    "5319931801700408838773613711433984525642385015127430562413700874159618665041",
                )
                .unwrap();
                assert_eq!(result.value(), &expected);
            });
    }

    #[test]
    fn test_cond_swap() {
        base_test()
            .k(16)
            .lookup_bits(15)
            .expect_satisfied(true)
            .run(|ctx, range| {
                let a_fr = Fr::from_u128(5);
                let b_fr = Fr::from_u128(19);
                let zero = ctx.load_constant(Fr::from_u128(0));
                let one = ctx.load_constant(Fr::from_u128(1));
                let a = ctx.load_constant(a_fr.clone());
                let b = ctx.load_constant(b_fr.clone());
                let (result1, result2) = cond_swap(ctx, range.gate(), a, b, zero);
                assert_eq!(result1.value(), a.value());
                assert_eq!(result2.value(), b.value());

                let (result1, result2) = cond_swap(ctx, range.gate(), a, b, one);
                assert_eq!(result1.value(), b.value());
                assert_eq!(result2.value(), a.value());
            });
    }

    #[test]
    fn test_force_equal_if_enabled(){
        base_test()
        .k(16)
        .lookup_bits(15)
        .expect_satisfied(false)
        .run(|ctx, range| {
            let a = ctx.load_constant(Fr::from_u128(0));
            let b = ctx.load_constant(Fr::from_u128(1));
            let one = ctx.load_constant(Fr::from_u128(2));
            force_equal_if_enabled(ctx, range.gate(), one, a, b);
        });

        base_test()
        .k(16)
        .lookup_bits(15)
        .expect_satisfied(true)
        .run(|ctx, range| {
            let a = ctx.load_constant(Fr::from_u128(0));
            let b = ctx.load_constant(Fr::from_u128(0));
            let one = ctx.load_constant(Fr::from_u128(2));
            force_equal_if_enabled(ctx, range.gate(), one, a, b);
        });

        base_test()
        .k(16)
        .lookup_bits(15)
        .expect_satisfied(true)
        .run(|ctx, range| {
            let a = ctx.load_constant(Fr::from_u128(1));
            let b = ctx.load_constant(Fr::from_u128(0));
            let one = ctx.load_constant(Fr::from_u128(0));
            force_equal_if_enabled(ctx, range.gate(), one, a, b);
        });

    }

    #[test]
    fn test_merkle_proof() {
        base_test()
            .k(16)
            .lookup_bits(15)
            .expect_satisfied(true)
            .run(|ctx, range| {
                let index: u128 = 3;
                let path_elements = [
                    "3838703076139458158224947594036512042000043446471024000798052594176466679369",
                    "3893613244610910836444638277981783398004478574254675759421090531211378581230",
                    "15126246733515326086631621937388047923581111613947275249184377560170833782629",
                    "6404200169958188928270149728908101781856690902670925316782889389790091378414",
                    "17903822129909817717122288064678017104411031693253675943446999432073303897479",
                ];
                let leaf =
                    "15024914651444060533957420166727519953059353127928544376365404062173113496849";
                let expected_root =
                    "16567540828078488368062131969210584154677498854032521347548454584709283442700";

                let index = ctx.load_constant(Fr::from_u128(index));
                let path_elements = path_elements
                    .map(|elem| ctx.load_constant(Fr::from_str_vartime(elem).unwrap()));
                let leaf = ctx.load_constant(Fr::from_str_vartime(leaf).unwrap());

                let root = merkle_proof(ctx, range.gate(), leaf, path_elements, index);
                println!("Found root: {:?}", root);
                assert_eq!(root.value(), &Fr::from_str_vartime(expected_root).unwrap());
            });
    }
}
