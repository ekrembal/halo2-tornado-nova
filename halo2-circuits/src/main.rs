// use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
// use halo2_base::gates::circuit::{BaseCircuitParams, CircuitBuilderStage};
// use halo2_base::gates::{GateInstructions, RangeInstructions};
// use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
// use halo2_base::utils::fs::gen_srs;

// use itertools::Itertools;
// use snark_verifier_sdk::halo2::aggregation::{AggregationConfigParams, VerifierUniversality};
// use snark_verifier_sdk::{CircuitExt, SHPLONK};
// use snark_verifier_sdk::{
//     gen_pk,
//     halo2::{aggregation::AggregationCircuit, gen_snark_shplonk},
//     Snark,
// };

// fn generate_circuit(k: u32, fill: bool) -> Snark {
//     let lookup_bits = k as usize - 1;
//     let circuit_params = BaseCircuitParams {
//         k: k as usize,
//         num_advice_per_phase: vec![10],
//         num_lookup_advice_per_phase: vec![5],
//         num_fixed: 1,
//         lookup_bits: Some(lookup_bits),
//         num_instance_columns: 1,
//     };
//     let mut builder = BaseCircuitBuilder::new(false).use_params(circuit_params);
//     let range = builder.range_chip();

//     let ctx = builder.main(0);

//     let x = ctx.load_witness(Fr::from(14));
//     if fill {
//         for _ in 0..2 << k {
//             range.gate().add(ctx, x, x);
//         }
//     }

//     let params = gen_srs(k);
//     // do not call calculate_params, we want to use fixed params
//     let pk = gen_pk(&params, &builder, None);
//     // std::fs::remove_file(Path::new("examples/app.pk")).ok();
//     // let _pk = gen_pk(&params, &builder, Some(Path::new("examples/app.pk")));
//     // let pk = read_pk::<BaseCircuitBuilder<_>>(
//     //     Path::new("examples/app.pk"),
//     //     builder.config_params.clone(),
//     // )
//     // .unwrap();
//     // std::fs::remove_file(Path::new("examples/app.pk")).ok();
//     // builder now has break_point set
//     gen_snark_shplonk(&params, &pk, builder, None::<&str>)
// }


// // fn main() {
// //     println!("poseidon test");
// //     let k = 20;
// //     let params = gen_srs(k);
// //     let lookup_bits = k as usize - 1;
// //     let circuit_params = BaseCircuitParams {
// //         k: k as usize,
// //         num_advice_per_phase: vec![10],
// //         num_lookup_advice_per_phase: vec![5],
// //         num_fixed: 1,
// //         lookup_bits: Some(lookup_bits),
// //         num_instance_columns: 1,
// //     };
// //     let mut builer = RangeCircuitBuilder::new(false).use_params(circuit_params);
    
// //     let range = builer.range_chip();
// //     let ctx = builer.main(0);
// //     let input_str = "{\"root\":\"6236561457989376074176018488019421579161539135318625690441656311431723728549\",\"input_nullifier\":[\"1180527464675466364947346812275476841704893136054438685613436541567884406277\",\"3624864453768104979984857675696661253661295107687299308887972547477498629728\"],\"output_commitment\":[\"6936108624735118759059388226273871790642394807138886525626792373841761324566\",\"223936773215441090053244272775551609199091841171340835890935137789153583457\"],\"public_amount\":\"21888242871839275222246405745257275088548364400416034343698134186575808495617\",\"ext_data_hash\":\"19549490880112325170796214496051912215490309687168828675571300862379866733366\",\"in_amount\":[\"0\",\"70000000000000000\"],\"in_private_key\":[\"75683826066300646161382397696634627824214000087160436590400178558667565167254\",\"52251818396513140874729618045029800910137522860977040457961337733932941032134\"],\"in_blinding\":[\"340847250210271778370575479400972594414731488424966095036006924337350193250\",\"362334520356308078012467733335780612756780671030163084712091928217124434472\"],\"in_path_indices\":[\"0\",\"0\"],\"in_path_elements\":[[\"0\",\"0\",\"0\",\"0\",\"0\"],[\"21272070509224971496507280758158442760938911018065833307693033427165682628805\",\"8995896153219992062710898675021891003404871425075198597897889079729967997688\",\"15126246733515326086631621937388047923581111613947275249184377560170833782629\",\"6404200169958188928270149728908101781856690902670925316782889389790091378414\",\"17903822129909817717122288064678017104411031693253675943446999432073303897479\"]],\"out_amount\":[\"0\",\"0\"],\"out_blinding\":[\"123381971265817162984529262278237669475586127067073205138030364908173284501\",\"270052950233698114711237476605334387159001569914075636139758157146640809022\"],\"out_pubkey\":[\"12447076327449158073265847808583608933968610719241204702897185970206886375588\",\"2865950430993041938664645749306326259673240542231823924829767181533636121330\"]}";

// //     let input_str: TransactionInputStr<5, 2, 2> = serde_json::from_str(input_str).unwrap();

// //     let inp = input_str.to_assigned(ctx);

// //     verify_transaction(ctx, range.gate(), inp);
// //     let pk = gen_pk(&params, &builer, None);
// //     let proof = gen_snark_shplonk(&params, &pk, builer, None::<&str>);

// //     // gen_snark_shplonk(&params, pk, circuit, path);

// //     // base_test()
// //     // .k(20)
// //     // .lookup_bits(15)
// //     // .expect_satisfied(true)
// //     // .run(|ctx, range| {

// //     //     verify_transaction(ctx, range.gate(), inp);
// //     // });
// // }


fn main(){
    println!("Hello, world!");
}