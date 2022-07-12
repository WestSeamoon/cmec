//! Taproot sm2 verifying key.

use super::{tagged_hash, pre_Signature, Signature, CHALLENGE_TAG};
use crate::{AffinePoint, FieldBytes, ProjectivePoint, PublicKey, Scalar};
use ecdsa_core::signature::{DigestVerifier, Error, Result, Verifier};
use elliptic_curve::{
    bigint::U256,
    ops::{LinearCombination, Reduce},
    DecompactPoint,
};
use sha2::{
    digest::{consts::U32, FixedOutput},
    Digest, Sha256,
};

/// Taproot sm2 verifying key.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VerifyingKey {
    /// Inner public key
    inner: PublicKey,
}

impl VerifyingKey {
    /// Verify sm2 signature.
    ///
    /// # ⚠️ Warning
    ///
    /// This is a low-level interface intended only for unusual use cases
    /// involving verifying pre-hashed messages.
    ///
    /// The preferred interface is the [`Verifier`] trait.
    pub fn verify_prehashed(&self, msg_digest: &[u8; 32], sig: &Signature) -> Result<()> {
        let (r, s) = sig.split();

        let e = <Scalar as Reduce<U256>>::from_be_bytes_reduced(
            tagged_hash(CHALLENGE_TAG)
                .chain_update(&sig.bytes[..32])
                .chain_update(self.to_bytes())
                .chain_update(msg_digest)
                .finalize(),
        );

        let R = ProjectivePoint::lincomb(
            &ProjectivePoint::GENERATOR,
            &*s,
            &self.inner.to_projective(),
            &-e,
        )
        .to_affine();

        if R.y.normalize().is_odd().into() || <Scalar as Reduce<U256>>::from_be_bytes_reduced(R.x.to_bytes()) != *r {
            return Err(Error::new());
        }


        Ok(())
    }


    ///验证预签名正确性
    pub fn verify_pre_prehashed(&self, msg_digest: &[u8; 32], &pre_sign: &[u8; 96]) -> Result<()> { //[u8;32] {//

        let pre_sign = pre_Signature::pub_from_bytes(&pre_sign).unwrap();
        
        //分解预签名
        let (r, s, Q) = pre_sign.split();

        //将传入的消息m取哈希
        let hm = <Scalar as Reduce<U256>>::from_be_bytes_reduced(
            tagged_hash(CHALLENGE_TAG)
                .chain_update(msg_digest)
                .finalize(),
        );

        //计算r+s
        let rs = Scalar::add(r, s);

        //计算KK = s·G + (r+s)·P
        let KK = ProjectivePoint::lincomb(
            &ProjectivePoint::GENERATOR,
            &*s,
            &self.inner.to_projective(),
            &rs,
        )
        .to_affine();

        //转换KK的类型
        let KK_pro = ProjectivePoint::from(KK);

        //计算R = KK+Q
        let R = ProjectivePoint::add_mixed(&KK_pro, &Q).to_affine();

        //取R的横坐标f_x
        //let f_x = <Scalar as Reduce<U256>>::from_be_bytes_reduced(R.x.to_bytes());
        let f_x = Scalar::pub_from_repr(R.x.to_bytes()).unwrap();

        //计算rr
        let rr = Scalar::add(&hm, &f_x);//hm + f_x;
/*
        let mut rr_bytes = [0u8; 32];
        
        rr_bytes.copy_from_slice(&rr.to_bytes());

        rr_bytes
*/
        
        //验证预签名解析出来的r与计算出来的rr是否相等，相等则验证通过，否则无效返回错误
        if rr != *r {
            return Err(Error::new());
        } else {
            Ok(())
        }
        
    }

    /// Borrow the inner [`AffinePoint`] this type wraps.
    pub fn as_affine(&self) -> &AffinePoint {
        self.inner.as_affine()
    }

    /// Serialize as bytes.
    pub fn to_bytes(&self) -> FieldBytes {
        self.as_affine().x.to_bytes()
    }

    /// Parse verifying key from big endian-encoded x-coordinate.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let maybe_affine_point = AffinePoint::decompact(FieldBytes::from_slice(bytes));
        let affine_point = Option::from(maybe_affine_point).ok_or_else(Error::new)?;
        PublicKey::from_affine(affine_point)
            .map_err(|_| Error::new())?
            .try_into()
    }
}

impl From<VerifyingKey> for AffinePoint {
    fn from(vk: VerifyingKey) -> AffinePoint {
        *vk.as_affine()
    }
}

impl From<&VerifyingKey> for AffinePoint {
    fn from(vk: &VerifyingKey) -> AffinePoint {
        *vk.as_affine()
    }
}

impl From<VerifyingKey> for PublicKey {
    fn from(vk: VerifyingKey) -> PublicKey {
        vk.inner
    }
}

impl From<&VerifyingKey> for PublicKey {
    fn from(vk: &VerifyingKey) -> PublicKey {
        vk.inner
    }
}

impl TryFrom<PublicKey> for VerifyingKey {
    type Error = Error;

    fn try_from(public_key: PublicKey) -> Result<VerifyingKey> {
        if public_key.as_affine().y.normalize().is_even().into() {
            Ok(Self { inner: public_key })
        } else {
            Err(Error::new())
        }
    }
}

impl TryFrom<&PublicKey> for VerifyingKey {
    type Error = Error;

    fn try_from(public_key: &PublicKey) -> Result<VerifyingKey> {
        Self::try_from(*public_key)
    }
}
