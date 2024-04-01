use halo2_base::{
    gates::{GateChip, GateInstructions},
    utils::BigPrimeField,
    AssignedValue, Context,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::utils::{force_equal_if_enabled, merkle_proof, poseidon1, poseidon3};

#[derive(Clone, Debug)]
pub struct TransactionInput<
    F: BigPrimeField,
    const LEVELS: usize,
    const N_INS: usize,
    const N_OUTS: usize,
> {
    pub root: AssignedValue<F>,
    pub public_amount: AssignedValue<F>,
    pub ext_data_hash: AssignedValue<F>,
    pub input_nullifier: [AssignedValue<F>; N_INS],
    pub in_amount: [AssignedValue<F>; N_INS],
    pub in_private_key: [AssignedValue<F>; N_INS],
    pub in_blinding: [AssignedValue<F>; N_INS],
    pub in_path_indices: [AssignedValue<F>; N_INS],
    pub in_path_elements: [[AssignedValue<F>; LEVELS]; N_INS],
    pub output_commitment: [AssignedValue<F>; N_OUTS],
    pub out_amount: [AssignedValue<F>; N_OUTS],
    pub out_pubkey: [AssignedValue<F>; N_OUTS],
    pub out_blinding: [AssignedValue<F>; N_OUTS],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionInputStr<const LEVELS: usize, const N_INS: usize, const N_OUTS: usize>
where
    [String; N_INS]: Serialize + DeserializeOwned,
    [String; N_OUTS]: Serialize + DeserializeOwned,
    [String; LEVELS]: Serialize + DeserializeOwned,
    [[String; LEVELS]; N_INS]: Serialize + DeserializeOwned,
{
    pub root: String,
    pub public_amount: String,
    pub ext_data_hash: String,
    pub input_nullifier: [String; N_INS],
    pub in_amount: [String; N_INS],
    pub in_private_key: [String; N_INS],
    pub in_blinding: [String; N_INS],
    pub in_path_indices: [String; N_INS],
    pub in_path_elements: [[String; LEVELS]; N_INS],
    pub output_commitment: [String; N_OUTS],
    pub out_amount: [String; N_OUTS],
    pub out_pubkey: [String; N_OUTS],
    pub out_blinding: [String; N_OUTS],
}

impl<const LEVELS: usize, const N_INS: usize, const N_OUTS: usize>
    TransactionInputStr<LEVELS, N_INS, N_OUTS>
where
    [String; N_INS]: Serialize + DeserializeOwned,
    [String; N_OUTS]: Serialize + DeserializeOwned,
    [String; LEVELS]: Serialize + DeserializeOwned,
    [[String; LEVELS]; N_INS]: Serialize + DeserializeOwned,
{
    pub fn to_assigned<F: BigPrimeField>(
        &self,
        ctx: &mut Context<F>,
    ) -> TransactionInput<F, LEVELS, N_INS, N_OUTS> {
        macro_rules! load_witness_from_str {
            ($x: expr) => {
                ctx.load_witness(
                    F::from_str_vartime(&$x).expect("deserialize field element should not fail"),
                )
            };
        }

        macro_rules! load_witness_from_str_arr {
            ($x: expr) => {
                $x.map(|x| {
                    ctx.load_witness(
                        F::from_str_vartime(&x).expect("deserialize field element should not fail"),
                    )
                })
            };
        }

        TransactionInput {
            root: load_witness_from_str!(self.root),
            public_amount: load_witness_from_str!(self.public_amount),
            ext_data_hash: load_witness_from_str!(self.ext_data_hash),
            input_nullifier: load_witness_from_str_arr!(self.input_nullifier.clone()),
            in_amount: load_witness_from_str_arr!(self.in_amount.clone()),
            in_private_key: load_witness_from_str_arr!(self.in_private_key.clone()),
            in_blinding: load_witness_from_str_arr!(self.in_blinding.clone()),
            in_path_indices: load_witness_from_str_arr!(self.in_path_indices.clone()),
            in_path_elements: self
                .in_path_elements
                .clone()
                .map(|path_elems| load_witness_from_str_arr!(path_elems)),
            output_commitment: load_witness_from_str_arr!(self.output_commitment.clone()),
            out_amount: load_witness_from_str_arr!(self.out_amount.clone()),
            out_blinding: load_witness_from_str_arr!(self.out_blinding.clone()),
            out_pubkey: load_witness_from_str_arr!(self.out_pubkey.clone()),
        }
    }
}

pub fn verify_transaction<
    F: BigPrimeField,
    const LEVELS: usize,
    const N_INS: usize,
    const N_OUTS: usize,
>(
    ctx: &mut Context<F>,
    gate: &GateChip<F>,
    inp: TransactionInput<F, LEVELS, N_INS, N_OUTS>,
) {
    let mut sum_ins = ctx.load_constant(F::ZERO);
    for tx in 0..N_INS {
        // inKeypair[tx] = Keypair();
        // inKeypair[tx].privateKey <== inPrivateKey[tx];
        let public_key = poseidon1(ctx, gate, &[inp.in_private_key[tx]]);
        // println!("For input {:?}, public key = {:?}\npriv key={:?}", tx, public_key.value(), inp.in_private_key[tx].value());

        // inCommitmentHasher[tx] = Poseidon(3);
        // inCommitmentHasher[tx].inputs[0] <== inAmount[tx];
        // inCommitmentHasher[tx].inputs[1] <== inKeypair[tx].publicKey;
        // inCommitmentHasher[tx].inputs[2] <== inBlinding[tx];

        let in_commitment = poseidon3(
            ctx,
            gate,
            &[inp.in_amount[tx], public_key, inp.in_blinding[tx]],
        );

        // inSignature[tx] = Signature();
        // inSignature[tx].privateKey <== inPrivateKey[tx];
        // inSignature[tx].commitment <== inCommitmentHasher[tx].out;
        // inSignature[tx].merklePath <== inPathIndices[tx];

        let in_signature = poseidon3(
            ctx,
            gate,
            &[
                inp.in_private_key[tx],
                in_commitment,
                inp.in_path_indices[tx],
            ],
        );

        // inNullifierHasher[tx] = Poseidon(3);
        // inNullifierHasher[tx].inputs[0] <== inCommitmentHasher[tx].out;
        // inNullifierHasher[tx].inputs[1] <== inPathIndices[tx];
        // inNullifierHasher[tx].inputs[2] <== inSignature[tx].out;

        let in_nullifier = poseidon3(
            ctx,
            gate,
            &[in_commitment, inp.in_path_indices[tx], in_signature],
        );

        // inNullifierHasher[tx].out === inputNullifier[tx];

        // println!("in_nullifier = {:?}", in_nullifier.value());
        // println!("expected in_nullifier = {:?}", inp.input_nullifier[tx].value());

        ctx.constrain_equal(&in_nullifier, &inp.input_nullifier[tx]);

        // inTree[tx] = MerkleProof(levels);
        // inTree[tx].leaf <== inCommitmentHasher[tx].out;
        // inTree[tx].pathIndices <== inPathIndices[tx];
        // for (var i = 0; i < levels; i++) {
        //     inTree[tx].pathElements[i] <== inPathElements[tx][i];
        // }

        let found_root = merkle_proof(
            ctx,
            gate,
            in_commitment,
            inp.in_path_elements[tx],
            inp.in_path_indices[tx],
        );

        // inCheckRoot[tx] = ForceEqualIfEnabled();
        // inCheckRoot[tx].in[0] <== root;
        // inCheckRoot[tx].in[1] <== inTree[tx].root;
        // inCheckRoot[tx].enabled <== inAmount[tx];

        force_equal_if_enabled(ctx, gate, inp.in_amount[tx], inp.root, found_root);

        // sumIns += inAmount[tx];
        sum_ins = gate.add(ctx, sum_ins, inp.in_amount[tx]);
    }

    let mut sum_outs = ctx.load_constant(F::ZERO);
    for tx in 0..N_OUTS {
        // outCommitmentHasher[tx] = Poseidon(3);
        // outCommitmentHasher[tx].inputs[0] <== outAmount[tx];
        // outCommitmentHasher[tx].inputs[1] <== outPubkey[tx];
        // outCommitmentHasher[tx].inputs[2] <== outBlinding[tx];

        let out_commitment = poseidon3(
            ctx,
            gate,
            &[inp.out_amount[tx], inp.out_pubkey[tx], inp.out_blinding[tx]],
        );

        ctx.constrain_equal(&out_commitment, &inp.output_commitment[tx]);

        // outCommitmentHasher[tx].out === outputCommitment[tx];

        gate.num_to_bits(ctx, inp.out_amount[tx], 248);

        sum_outs = gate.add(ctx, sum_outs, inp.out_amount[tx]);
    }

    let zero = ctx.load_constant(F::ZERO);
    // check that there are no same nullifiers among all inputs
    for i in 0..N_INS {
        for j in i + 1..N_INS {
            let is_equal_result =
                gate.is_equal(ctx, inp.input_nullifier[i], inp.input_nullifier[j]);
            ctx.constrain_equal(&is_equal_result, &zero);
        }
    }

    let sum_in_plus_public_amount = gate.add(ctx, sum_ins, inp.public_amount);
    ctx.constrain_equal(&sum_in_plus_public_amount, &sum_outs)
}

#[cfg(test)]
mod test {
    use halo2_base::{gates::RangeInstructions, utils::testing::base_test};

    use crate::transaction::verify_transaction;

    use super::TransactionInputStr;

    #[test]
    fn test_transaction() {
        base_test()
            .k(20)
            .lookup_bits(15)
            .expect_satisfied(true)
            .run(|ctx, range| {
                let input_str = "{\"root\":\"6236561457989376074176018488019421579161539135318625690441656311431723728549\",\"input_nullifier\":[\"1180527464675466364947346812275476841704893136054438685613436541567884406277\",\"3624864453768104979984857675696661253661295107687299308887972547477498629728\"],\"output_commitment\":[\"6936108624735118759059388226273871790642394807138886525626792373841761324566\",\"223936773215441090053244272775551609199091841171340835890935137789153583457\"],\"public_amount\":\"21888242871839275222246405745257275088548364400416034343698134186575808495617\",\"ext_data_hash\":\"19549490880112325170796214496051912215490309687168828675571300862379866733366\",\"in_amount\":[\"0\",\"70000000000000000\"],\"in_private_key\":[\"75683826066300646161382397696634627824214000087160436590400178558667565167254\",\"52251818396513140874729618045029800910137522860977040457961337733932941032134\"],\"in_blinding\":[\"340847250210271778370575479400972594414731488424966095036006924337350193250\",\"362334520356308078012467733335780612756780671030163084712091928217124434472\"],\"in_path_indices\":[\"0\",\"0\"],\"in_path_elements\":[[\"0\",\"0\",\"0\",\"0\",\"0\"],[\"21272070509224971496507280758158442760938911018065833307693033427165682628805\",\"8995896153219992062710898675021891003404871425075198597897889079729967997688\",\"15126246733515326086631621937388047923581111613947275249184377560170833782629\",\"6404200169958188928270149728908101781856690902670925316782889389790091378414\",\"17903822129909817717122288064678017104411031693253675943446999432073303897479\"]],\"out_amount\":[\"0\",\"0\"],\"out_blinding\":[\"123381971265817162984529262278237669475586127067073205138030364908173284501\",\"270052950233698114711237476605334387159001569914075636139758157146640809022\"],\"out_pubkey\":[\"12447076327449158073265847808583608933968610719241204702897185970206886375588\",\"2865950430993041938664645749306326259673240542231823924829767181533636121330\"]}";

                let input_str: TransactionInputStr<5, 2, 2> = serde_json::from_str(input_str).unwrap();

                let inp = input_str.to_assigned(ctx);

                verify_transaction(ctx, range.gate(), inp);
            });
    }
}
