
use super::{tagged_hash, Signature, VerifyingKey, AUX_TAG, CHALLENGE_TAG, NONCE_TAG};
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

/// Taproot Schnorr signing key.
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

    /// Compute Schnorr signature.
    ///
    /// # ⚠️ Warning
    ///
    /// This is a low-level interface intended only for unusual use cases
    /// involving signing pre-hashed messages.
    ///
    /// The preferred interfaces are the [`Signer`] or [`RandomizedSigner`] traits.
    /// 
    


    pub fn test(&self, msg_digest: &[u8; 32], aux_rand: &[u8; 32]) -> (NonZeroScalar, AffinePoint) {

        let mut t = tagged_hash(AUX_TAG).chain_update(aux_rand).finalize();

        for (a, b) in t.iter_mut().zip(self.secret_key.to_bytes().iter()) {
            *a ^= b
        }

        let rand = tagged_hash(NONCE_TAG)
            .chain_update(&t)
            .chain_update(&self.verifying_key.as_affine().x.to_bytes())
            .chain_update(msg_digest)
            .finalize();

        let (k, K) = SigningKey::raw_from_bytes(&rand).unwrap();

        (k, K)
        
    }

    
    pub fn try_pre_sign_prehashed(
        &self,
        msg_digest: &[u8; 32],
        aux_rand: &[u8; 32],
        Y: &[u8],
    ) -> (Result<Signature>) {

        let mut t = tagged_hash(AUX_TAG).chain_update(aux_rand).finalize();

        for (a, b) in t.iter_mut().zip(self.secret_key.to_bytes().iter()) {
            *a ^= b
        }

        let rand = tagged_hash(NONCE_TAG)
            .chain_update(&t)
            .chain_update(&self.verifying_key.as_affine().x.to_bytes())
            .chain_update(msg_digest)
            .finalize();

        //生成kH和K
        let (k, K) = SigningKey::raw_from_bytes(&rand)?;


        //预签名生成

        //转换Y的类型
        let Y = VerifyingKey::from_bytes(&Y).unwrap();
        let Y = Y.as_affine();

        let hm = <Scalar as Reduce<U256>>::from_be_bytes_reduced(
            tagged_hash(CHALLENGE_TAG)
                .chain_update(msg_digest)
                .finalize(),
        );

        //计算Q
        let Q = (*Y * (*self.secret_key + Scalar::ONE)).to_affine();

        //将Q转换为ProjectivePoint类型
        let Q_Pro = ProjectivePoint::from(Q);

        //计算Q+K
        let f_Point = ProjectivePoint::add_mixed(&Q_Pro, &K);

        //转换为AffinePoint类型
        let f_Aff = ProjectivePoint::to_affine(&f_Point);
        
        //获取x
        let f_x = <Scalar as Reduce<U256>>::from_be_bytes_reduced(f_Aff.x.to_bytes());

        let r = hm + f_x;

        //let k_rd = *secret_key - r * *secret_key;

        //let d_1 = (*self.secret_key + Scalar::ONE).invert().unwrap();


        //求预签名值pre_sign
        let pre_sign = (*k - r * *self.secret_key) * (*self.secret_key + Scalar::ONE).invert().unwrap();
        
        //预签名w为(r,pre_sign,Q)

        let pre_sign: NonZeroScalar = Option::from(NonZeroScalar::new(pre_sign)).ok_or_else(Error::new)?;

        let mut bytes = [0u8; Signature::BYTE_SIZE];
        let (r_bytes, s_bytes) = bytes.split_at_mut(Signature::BYTE_SIZE / 2);
        //let (s_bytes, q_bytes) = sq_bytes.split_at_mut(Signature::BYTE_SIZE / 2);
        r_bytes.copy_from_slice(&r.to_bytes());
        s_bytes.copy_from_slice(&pre_sign.to_bytes());   
        //q_bytes.copy_from_slice(&Q.from_bytes()); 
        let sig = Signature { bytes, r: r, sign: pre_sign, Q:Q };

        Ok(sig)
    }


    //适配算法，获取签名值
    pub fn try_sign_prehashed(
        &self,
        &pre_sign: &Signature,
        y: &[u8; 32],
    ) -> Result<Signature> {

        let (r, s, Q) = pre_sign.split();

        let r = *r;

        let Q = *Q;

        //转换y的类型
        let y = Scalar::from_bytes_unchecked(&y);
    
        //计算正式签名
        let sign = Scalar::add(&s, &y);
        //let sign = *s + y;

        let mut bytes = [0u8; Signature::BYTE_SIZE];

        let sign: NonZeroScalar = Option::from(NonZeroScalar::new(sign)).ok_or_else(Error::new)?;

        let sig = Signature { bytes, r, sign, Q };

        Ok(sig)

        //提取y
        //let yy = sign - pre_sign;
    }


    //提取算法，提取y
    pub fn try_extract_y(
        &self,
        &pre_sign: &Signature,
        &sign: &Signature,
    ) -> Scalar { //[u8; 32] {

        let (r, pre_sign, Q) = pre_sign.split();

        let (r, sign, Q) = sign.split();

        let y = Scalar::sub(sign, pre_sign);

        //let y = Scalar::as_bytes();

        let mut bytes = [0u8; Signature::BYTE_SIZE];

        y

        //提取y
        //let yy = sign - pre_sign;
    }

}

