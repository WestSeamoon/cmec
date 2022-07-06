use k256;
use elliptic_curve;
use hex_literal::hex;
use k256::schnorr::SigningKey;

//#[derive(Debug)];

//#[derive(Debug)];

fn main() {
    
    
    //let test = k256::sm2::try_sign_prehashed();

    let secret_key = hex!("ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f");
    let public_key = hex!("779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcd");
    let message = hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    let aux_rand = hex!("0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    let upper_y = hex!("25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517");
    let y = hex!("0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710");
    let pre_signature = hex!("
                8C09A4B2625C016605739FA60B41B3AD4428684C2A26879114AE847162992FBC
                A970DF9CD5B917B90652D3D7393F77C82BFA2C3CDCD4ED84FEBE96AC12276BD3
                91D5CBBD8069F5092AD1EBBA5E0AF38C53F08BA57A476303C3958FF8735B72BE");

    let signature = hex!("
                8C09A4B2625C016605739FA60B41B3AD4428684C2A26879114AE847162992FBC
                B4B40AC34D4C8B3AB5432F8763A664983E715C9FAC148FD99D038C3AE46782E3");

    let sk = k256::schnorr::SigningKey::from_bytes(&secret_key).unwrap();
    let pk = k256::schnorr::VerifyingKey::from_bytes(&public_key).unwrap();

    let pre_test = k256::schnorr::SigningKey::try_pre_sign_prehashed(&sk, &message, &aux_rand, &upper_y).unwrap();
    let pre_test_hex = hex::encode_upper(pre_test);
    println!("预签名值为{:#?}",pre_test_hex);

    let sign_test = k256::schnorr::SigningKey::try_sign_prehashed(&sk, &pre_signature,  &y).unwrap().bytes;
    let sign_test_hex = hex::encode_upper(sign_test);
    println!("签名值为{:#?}",sign_test_hex);
 
    let y_test = k256::schnorr::SigningKey::try_extract_y(&sk, &pre_signature, &signature);

    let y_test_hex = hex::encode_upper(y_test);
    println!("y的值为{:#?}",y_test_hex);

    let valid = k256::schnorr::VerifyingKey::verify_pre_prehashed(&pk, &message, &pre_signature).is_ok();
    //let valid_hex = hex::encode_upper(valid);
    if valid == true {
        println!("预签名验证:此预签名有效");
    } else {
        println!("预签名验证:此预签名无效");
    }

    

}
