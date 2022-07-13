use super::{tagged_hash, Signature, pre_Signature, VerifyingKey, AUX_TAG, CHALLENGE_TAG, NONCE_TAG};
use crate::{arithmetic::FieldElement, AffinePoint, FieldBytes, NonZeroScalar, ProjectivePoint, PublicKey, Scalar};
use ecdsa_core::signature::{
    digest::{consts::U32, FixedOutput},
    DigestSigner, Error, RandomizedDigestSigner, RandomizedSigner, Result, Signer,
};
use elliptic_curve::{
    bigint::U256,
    ops::Reduce,
    rand_core::{CryptoRng, RngCore},
    subtle::ConditionallySelectable,
};
use sha2::{Digest, Sha256};

/// Taproot sm2 signing key.
#[derive(Clone)]
pub struct SigningKey {
    /// Secret key material
    secret_key: NonZeroScalar,

    /// Verifying key
    verifying_key: VerifyingKey,
}

impl SigningKey {
    /// Generate a cryptographically random [`SigningKey`].
    pub fn random(rng: impl CryptoRng + RngCore) -> Self {
        let bytes = NonZeroScalar::random(rng).to_bytes();
        Self::from_bytes(&bytes).unwrap()
    }

    /// Parse signing key from big endian-encoded bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (secret_key, verifying_point) = Self::raw_from_bytes(bytes)?;
        let verifying_key = PublicKey::from_affine(verifying_point).map_err(|_| Error::new())?;

        Ok(Self {
            secret_key,
            verifying_key: verifying_key.try_into()?,
        })
    }

    // a little type dance for use in SigningKey's `from_bytes` and `try_sign`.
    fn raw_from_bytes(bytes: &[u8]) -> Result<(NonZeroScalar, AffinePoint)> {
        let trial_secret_key = NonZeroScalar::try_from(bytes).map_err(|_| Error::new())?;

        let even = (ProjectivePoint::GENERATOR * *trial_secret_key)
            .to_affine()
            .y
            .normalize()
            .is_even();

        let secret_key =
            NonZeroScalar::conditional_select(&-trial_secret_key, &trial_secret_key, even);


        //let verifying_point = (ProjectivePoint::GENERATOR * *secret_key).to_affine();

        let point_test = ProjectivePoint::GENERATOR.to_affine();

        Ok((secret_key, point_test))
        // Ok((secret_key, verifying_point))
    }

    /// Serialize as bytes.
    pub fn to_bytes(&self) -> FieldBytes {
        self.secret_key.to_bytes()
    }

    /// Get the [`VerifyingKey`] that corresponds to this signing key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Compute sm2 signature.
    ///
    /// # ⚠️ Warning
    ///
    /// This is a low-level interface intended only for unusual use cases
    /// involving signing pre-hashed messages.
    ///
    /// The preferred interfaces are the [`Signer`] or [`RandomizedSigner`] traits.
    /// 

    ///预签名生成
    pub fn try_pre_sign_prehashed(
        &self,
        msg_digest: &[u8; 32],
        aux_rand: &[u8; 32],
        Y: &[u8],
    ) -> Result<pre_Signature> {

        //生成k和K        
        let k = Scalar::from_bytes_unchecked(&aux_rand);

        //let K = ProjectivePoint::GENERATOR.to_affine() * k ;
        //let K = (G_Aff * k).to_affine();

        let G_Aff = ProjectivePoint::GENERATOR.to_affine();
        let K = AffinePoint::pub_mul(G_Aff, &k);

        //转换Y的类型
        let Y = VerifyingKey::from_bytes(&Y).unwrap();
        let Y = Y.as_affine();

        let hm = <Scalar as Reduce<U256>>::from_be_bytes_reduced(
            tagged_hash(CHALLENGE_TAG)
                .chain_update(msg_digest)
                .finalize(),
        );

        //let d_1 = Scalar::add(&self.secret_key, &Scalar::ONE);

        //计算Q
        //let Q_Pro = AffinePoint::pub_mul(*Y, &d_1);
        //let Q = Q_Pro.to_affine();
        let Q = (*Y * (*self.secret_key + Scalar::ONE)).to_affine();

        //将Q转换为ProjectivePoint类型
        //let Q_Pro = ProjectivePoint::from(Q);

        //计算Q+K
        let f_Point = ProjectivePoint::add_mixed(&K, &Q);

        //转换为AffinePoint类型
        let f_Aff = ProjectivePoint::to_affine(&f_Point);
        
        //获取x
        let f_x = Scalar::pub_from_repr(f_Aff.x.to_bytes()).unwrap();
        //let f_x = <Scalar as Reduce<U256>>::from_be_bytes_reduced(f_Aff.x.to_bytes());

        let r = Scalar::add(&hm, &f_x);
/*
        let rd = Scalar::mul(&r, &self.secret_key);

        let k_rd = Scalar::sub(&k, &rd);

        //计算d+1并取倒数
        let d_1_invert = d_1.invert().unwrap();
*/
        //求预签名值pre_sign
        //let pre_sign = Scalar::mul(&d_1_invert, &k_rd);
        let pre_sign = (k - r * *self.secret_key) * (*self.secret_key + Scalar::ONE).invert().unwrap();
        
        //预签名w为(r,pre_sign,Q)

        let pre_sign: NonZeroScalar = Option::from(NonZeroScalar::new(pre_sign)).ok_or_else(Error::new)?;

        let mut bytes = [0u8; pre_Signature::BYTE_SIZE];
        let (r_bytes, sq_bytes) = bytes.split_at_mut(pre_Signature::BYTE_SIZE / 3);
        let (s_bytes, q_bytes) = sq_bytes.split_at_mut(pre_Signature::BYTE_SIZE / 3);
        r_bytes.copy_from_slice(&r.to_bytes());
        s_bytes.copy_from_slice(&pre_sign.to_bytes());  
        q_bytes.copy_from_slice(&Q.x.to_bytes()); 

/* 
        //验证测试
        let rs = Scalar::add(&r, &pre_sign);
        let sg = ProjectivePoint::GENERATOR * *pre_sign;
        let P = ProjectivePoint::GENERATOR * *self.secret_key;
        let P_Aff = P.to_affine();
        let rsp = (P * rs).to_affine();
        let KK = ProjectivePoint::add_mixed(&sg, &rsp);
        let R = ProjectivePoint::add_mixed(&KK, &Q).to_affine();
        //let rx =<Scalar as Reduce<U256>>::from_be_bytes_reduced(R.x.to_bytes());
        let rx = Scalar::pub_from_repr(R.x.to_bytes()).unwrap();
        let rr = Scalar::add(&hm, &rx);
        if rr != r {
            let r = Scalar::ZERO;
            r_bytes.copy_from_slice(&r.to_bytes());
        }
*/
        let sig = pre_Signature { bytes, r: r, sign: pre_sign, Q:Q };
        Ok(sig)
    }


    ///适配算法，获取签名值
    pub fn try_sign_prehashed(
        &self,
        &pre_sign: &[u8; 96],
        y: &[u8; 32],
    ) -> Result<Signature> {

        let pre_sign = pre_Signature::pub_from_bytes(&pre_sign).unwrap();

        //将预签名分解获取r和s
        let r = *pre_sign.split().0;

        let pre_sign = pre_sign.split().1;

        //转换y的类型
        let y = Scalar::from_bytes_unchecked(&y);
    
        //计算正式签名
        let sign = Scalar::add(&pre_sign, &y);
        //let sign = *s + y;

        let sign: NonZeroScalar = Option::from(NonZeroScalar::new(sign)).ok_or_else(Error::new)?;

        let mut bytes = [0u8; Signature::BYTE_SIZE];
        let (r_bytes, s_bytes) = bytes.split_at_mut(Signature::BYTE_SIZE / 2);
        r_bytes.copy_from_slice(&r.to_bytes());
        s_bytes.copy_from_slice(&sign.to_bytes());  

        let sig = Signature { bytes, r, sign };

        Ok(sig)

    }


    ///提取算法，提取y
    pub fn try_extract_y(
        &self,
        &pre_sign: &[u8; 96],
        &sign: &[u8; 64],
    ) -> [u8; 32] {

        //转换两个签名的类型
        let pre_sign = pre_Signature::pub_from_bytes(&pre_sign).unwrap();

        let sign = Signature::pub_from_bytes(&sign).unwrap();

        //获取两个签名的值
        let pre_sign = pre_sign.split().1;

        let sign = sign.split().1;

        //计算y
        let y = Scalar::sub(sign, pre_sign);

        let mut y_bytes = [0u8; 32];
        
        y_bytes.copy_from_slice(&y.to_bytes());

        y_bytes

    }

    ///生成密钥对
    pub fn gen_key(rng: impl CryptoRng + RngCore) -> ([u8; 32],[u8; 32]) {
        let key = SigningKey::random(rng);
        let G_Aff = ProjectivePoint::GENERATOR.to_affine();
        let pub_key_pro = AffinePoint::pub_mul(G_Aff, &key.secret_key);
        let pub_key = pub_key_pro.to_affine();
        let mut secret_bytes = [0u8; 32];
        let mut pub_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&key.secret_key.to_bytes());
        pub_bytes.copy_from_slice(&pub_key.x.to_bytes());
        (secret_bytes,pub_bytes)
    }


    ///生成困难关系对
    pub fn gen_diff(rng: impl CryptoRng + RngCore) -> ([u8; 32],[u8; 32]) {
        let key = SigningKey::random(rng);
        let G_Aff = ProjectivePoint::GENERATOR.to_affine();
        let y_upper_pro = AffinePoint::pub_mul(G_Aff, &key.secret_key);
        let y_upper_key = y_upper_pro.to_affine();
        let mut y_bytes = [0u8; 32];
        let mut y_upper_bytes = [0u8; 32];
        y_bytes.copy_from_slice(&key.secret_key.to_bytes());
        y_upper_bytes.copy_from_slice(&y_upper_key.x.to_bytes());
        (y_bytes,y_upper_bytes)
    }

}

