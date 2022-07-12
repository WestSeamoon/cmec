use elliptic_curve::rand_core::{CryptoRng, RngCore, OsRng};
use hex_literal::hex;
use mysql::prelude::*;
use mysql::*;
//use k256::sm2::SigningKey;

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

    let sk = k256::sm2::SigningKey::from_bytes(&secret_key).unwrap();
    let pk = k256::sm2::VerifyingKey::from_bytes(&public_key).unwrap();

    //预签名生成，传入私钥，message，随机数，困难关系状态Y
    let pre_test = k256::sm2::SigningKey::try_pre_sign_prehashed(&sk, &message, &aux_rand, &upper_y).unwrap();
    let pre_test_hex = hex::encode_upper(pre_test);
    println!("预签名值为{:#?}",pre_test_hex);

    //预签名验证，传入公钥，消息，预签名
    let valid = k256::sm2::VerifyingKey::verify_pre_prehashed(&pk, &message, &pre_signature).is_ok();
    //let valid_hex = hex::encode_upper(valid);
    if valid == true {
        println!("预签名验证:此预签名有效");
    } else {
        println!("预签名验证:此预签名无效");
    }

    //适配算法，传入y和预签名
    let sign_test = k256::sm2::SigningKey::try_sign_prehashed(&sk, &pre_signature,  &y).unwrap();
    let sign_test_hex = hex::encode_upper(sign_test);
    println!("签名值为{:#?}",sign_test_hex);
 
    //提取算法，传入预签名和正式签名
    let y_test = k256::sm2::SigningKey::try_extract_y(&sk, &pre_signature, &signature);

    let y_test_hex = hex::encode_upper(y_test);
    println!("y的值为{:#?}",y_test_hex);

   

    //密钥对生成
    let sum_key = k256::sm2::SigningKey::gen_key(&mut OsRng);
    let secret_key = hex::encode_upper(sum_key.0);
    let pub_key = hex::encode_upper(sum_key.1);
    println!("私钥的值为{:#?}",secret_key);
    println!("公钥的值为{:#?}",pub_key);
 
    //把公钥放mysql
    //连接数据库，设置连接字符串
    let url = "mysql://root:122513gzhGZH!!@decs.pcl.ac.cn:1762/search_engine";
    //let opts = Opts::from_url(url).unwrap();// 类型转换将 url 转为opts
     //连接数据库 这里 老版本是直接传url 字符串即可 新版本21版要求必须为opts类型
    let pool = Pool::new(url).unwrap();
    let mut conn = pool.get_conn().unwrap();

    //数据库操作
    let stmt = conn.prep("insert into regist(id, public_key) values (?, ?)").unwrap();
    let ret = conn.exec_iter(stmt, (123, pub_key)).unwrap();
    println!("{:?}", ret.affected_rows());
    //let stmt = conn.prep("insert into regist (id, public_key) values (:id, :public_key)").unwrap();
    //conn.exec_drop(&stmt, params! {
      //  "id" => 123,
        //"public_key" => pub_key,
    //}).unwrap();
    //println!("last generated key: {}", conn.last_insert_id())

}
