use k256;
use elliptic_curve;
use hex_literal::hex;

//#[derive(Debug)];

//#[derive(Debug)];

fn main() {
    
    
    //let test = k256::sm2::try_sign_prehashed();

    let secret_key = hex!("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9");
    let public_key = hex!("DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8");
    let message = hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    let aux_rand = hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    let Y = hex!("DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8");

    let sk = k256::schnorr::SigningKey::from_bytes(&secret_key).unwrap();

    //println!("{:#?}",sk);

    let test = k256::schnorr::SigningKey::try_pre_sign_prehashed(&sk, &message, &aux_rand, &Y).unwrap().bytes;

    let rand_test = k256::schnorr::SigningKey::test(&sk, &message, &aux_rand);

    //let rand = rand_test.0.bytes;

    //let rand_hex = hex::encode_upper(rand_test);

    let test_hex = hex::encode_upper(test);

    println!("{:#?}",test_hex);

    

}
