use chain_code::two_party::party1::ChainCode1;
use chain_code::two_party::party2::ChainCode2;
use ecdsa::two_party::{MasterKey1, MasterKey2};
use zk_paillier::zkproofs::SALT_STRING;

pub fn test_key_gen() -> (MasterKey1, MasterKey2) {
    use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::{party_two, party_one};
    let (kg_party_one_first_message, kg_comm_witness, kg_ec_key_pair_party1) =
        MasterKey1::key_gen_first_message();
    let (kg_party_two_first_message, kg_ec_key_pair_party2) =
        MasterKey2::key_gen_first_message();
    let (kg_party_one_second_message, party_one_paillier_key_pair, party_one_private) =
        MasterKey1::key_gen_second_message(
            kg_comm_witness.clone(),
            &kg_ec_key_pair_party1,
            &kg_party_two_first_message.d_log_proof,
        );

    println!("---->{:?}", serde_json::to_string(&kg_party_two_first_message.d_log_proof).unwrap());

    let key_gen_second_message = MasterKey2::key_gen_second_message(
        kg_party_one_first_message,
        &kg_party_one_second_message,
        SALT_STRING,
    );
    assert!(key_gen_second_message.is_ok());

    let party_two_paillier = key_gen_second_message.unwrap().1;

    // chain code
    let (cc_party_one_first_message, cc_comm_witness, cc_ec_key_pair1) =
        ChainCode1::chain_code_first_message();
    let (cc_party_two_first_message, cc_ec_key_pair2) =
        ChainCode2::chain_code_first_message();
    let cc_party_one_second_message = ChainCode1::chain_code_second_message(
        cc_comm_witness,
        &cc_party_two_first_message.d_log_proof,
    );

    let cc_party_two_second_message = ChainCode2::chain_code_second_message(
        &cc_party_one_first_message,
        &cc_party_one_second_message,
    );
    assert!(cc_party_two_second_message.is_ok());

    let party1_cc = ChainCode1::compute_chain_code(
        &cc_ec_key_pair1,
        &cc_party_two_first_message.public_share,
    );

    let party2_cc = ChainCode2::compute_chain_code(
        &cc_ec_key_pair2,
        &cc_party_one_second_message.comm_witness.public_share,
    );

    let party_one_master_key = MasterKey1::set_master_key(
        &party1_cc.chain_code,
        party_one_private,
        &kg_comm_witness.public_share,
        &kg_party_two_first_message.public_share,
        party_one_paillier_key_pair,
    );

    let party_two_master_key = MasterKey2::set_master_key(
        &party2_cc.chain_code,
        &kg_ec_key_pair_party2,
        &kg_party_one_second_message
            .ecdh_second_message
            .comm_witness
            .public_share,
        &party_two_paillier,
    );
    (party_one_master_key, party_two_master_key)
}


#[cfg(test)]
pub mod tests {
    use poc::test_key_gen;

    #[test]
    fn test_encrypt_and_decrypt_segment() {
        test_key_gen();
    }
}