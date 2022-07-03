use k256;
use elliptic_curve;
use hex_literal::hex;
use k256::schnorr::SigningKey;

//#[derive(Debug)];

//#[derive(Debug)];

fn main() {
    
    
    //let test = k256::sm2::try_sign_prehashed();

    let secret_key = hex!("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9");
    let public_key = hex!("DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8");
    let message = hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    let aux_rand = hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    let Y = hex!("DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8");
    let y = hex!("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9");
    let pre_signature = hex!("
                A9464E2E31D3A34FB1B640971595FBA31801FEF5159A76B4DB2B24DF5B0B4C56
                7599C15E11A6423BA0E34FCB1A443DD414386A22D47055DECC3DFE178A077034
                4A6313C6F3D0D89A5F76676100E6A7750655D89819C0EC3BFF01CA4189801BA5");

    let signature = hex!("
                A9464E2E31D3A34FB1B640971595FBA31801FEF5159A76B4DB2B24DF5B0B4C56
                3EA99C00330F047065A9B2569B205AA6828BDB44AF8F82170E775E30F4E614BC
                4A6313C6F3D0D89A5F76676100E6A7750655D89819C0EC3BFF01CA4189801BA5");

    let sk = k256::schnorr::SigningKey::from_bytes(&secret_key).unwrap();

    let pre_test = k256::schnorr::SigningKey::try_pre_sign_prehashed(&sk, &message, &aux_rand, &Y).unwrap().bytes;

    //let rand_test = k256::schnorr::SigningKey::test(&sk, &message, &aux_rand);

    //let rand = rand_test.0.bytes;

    //let rand_hex = hex::encode_upper(rand_test);

    //let signature_test = k256::schnorr::Signature::from_bytes(signature);

    let pre_test_hex = hex::encode_upper(pre_test);

    let sign_test = k256::schnorr::SigningKey::try_sign_prehashed(&sk, &pre_signature,  &y).unwrap().bytes;

    let sign_test_hex = hex::encode_upper(sign_test);

    let y_test = k256::schnorr::SigningKey::try_extract_y(&sk, &pre_signature, &signature);

    let y_test_hex = hex::encode_upper(y_test);


    println!("预签名值为{:#?}",pre_test_hex);
    println!("签名值为{:#?}",sign_test_hex);
    println!("y的值为{:#?}",y_test_hex);

    

}
