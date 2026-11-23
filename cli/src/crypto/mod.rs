//! Модуль криптографии: ГОСТ Р 34.10-2012 (подпись) и ГОСТ Р 34.11-2012 (хеш).

pub mod cert_util;
pub mod ecc_params;
pub mod gost2012_hash;
pub mod gost2012_sign;
pub mod signature_builder;

#[cfg(test)]
mod debug_ec;

#[cfg(test)]
mod gost2012_sign_integration;

#[cfg(test)]
mod wave6_debug;

#[cfg(test)]
mod wave7_debug;

#[cfg(test)]
mod wave8_debug;

#[cfg(test)]
mod wave8_full_verify;

#[cfg(test)]
mod wave8_integration;

#[cfg(test)]
mod wave9_final;

pub use gost2012_hash::{gost_hash_data, gost_hash_file, GostHasher, Hash256};
pub use gost2012_sign::GostSigner;
pub use signature_builder::{CmsBuilder, CmsSigner, SignatureParams, encode_signature_to_base64};

/// Вспомогательная функция для безопасного модульного вычитания: (a - b) mod p
pub fn mod_sub(a: &num_bigint::BigUint, b: &num_bigint::BigUint, p: &num_bigint::BigUint) -> num_bigint::BigUint {
    if a >= b {
        (a - b) % p
    } else {
        ((a + p) - b) % p
    }
}
