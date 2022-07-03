use super::{tagged_hash, Signature, VerifyingKey, AUX_TAG, CHALLENGE_TAG, NONCE_TAG};
    use crate::{AffinePoint, FieldBytes, NonZeroScalar, ProjectivePoint, PublicKey, Scalar};
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
    
    /// Taproot Schnorr signing key.
    #[derive(Clone)]
    pub struct SigningKey {
        /// Secret key material
        secret_key: NonZeroScalar,
    
        /// Verifying key
        verifying_key: VerifyingKey,
    }
    
impl SigningKey {    
    pub fn try_sign_prehashed(
        &self,
        msg_digest: &[u8; 32],
        aux_rand: &[u8; 32],
        Y: AffinePoint,
    ) -> Result<Signature> {
        // the ephemeral key "k"临时密钥k
        let (k, K_point) = SigningKey::raw_from_bytes(&rand)?;
    
        //预签名生成
        //let Y = (ProjectivePoint::GENERATOR * *y).to_affine();

        let hm = <Scalar as Reduce<U256>>::from_be_bytes_reduced(
            tagged_hash(CHALLENGE_TAG)
                .chain_update(msg_digest)
                .finalize(),
        );

        //计算Q
        let Q = (Y * (*self.secret_key + Scalar::ONE)).to_affine();

        //将Q转换为ProjectivePoint类型
        let Q_Pro = ProjectivePoint::from(Q);

        //计算Q+K
        let f_Point = ProjectivePoint::add_mixed(&Q_Pro, &K_point);

        //转换为AffinePoint类型
        let f_Aff = ProjectivePoint::to_affine(&f_Point);
    
        //获取x
        let f_x = <Scalar as Reduce<U256>>::from_be_bytes_reduced(f_Aff.x.to_bytes());

        let r = hm + f_x;

        //let k_rd = *sk - r * *sk;

        //let d_1 = (*self.k + Scalar::ONE).invert().unwrap();


        //计算预签名
        let pre_sign = (*k - r * *self.secret_key) * (*self.secret_key + Scalar::ONE).invert().unwrap();

        //预签名值(r,pre_sign,Q)




        //预签名验证部分
        let KK = ProjectivePoint::GENERATOR * pre_sign + self.verifying_key * (r + pre_sign);
        let rr = hm + (KK + Q).x.normalize();
        if r==rr {
            //验证通过
        }

        //适配算法，获取签名值
        let sign = pre_sign + y;

        //提取y
        let yy = sign - pre_sign;


        let s: NonZeroScalar = Option::from(NonZeroScalar::new(s)).ok_or_else(Error::new)?;

        let mut bytes = [0u8; Signature::BYTE_SIZE];
        let (r_bytes, s_bytes) = bytes.split_at_mut(Signature::BYTE_SIZE / 2);
        r_bytes.copy_from_slice(&r.to_bytes());
        s_bytes.copy_from_slice(&s.to_bytes());

        let sig = Signature { bytes, r, s };


        #[cfg(debug_assertions)]
        self.verifying_key.verify_prehashed(msg_digest, &sig)?;

        Ok(sig)    

    }
    
}
    
    

            
    


