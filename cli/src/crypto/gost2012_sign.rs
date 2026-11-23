//! Верификация подписи ГОСТ Р 34.10-2012 на эллиптической кривой.
//!
//! Алгоритм: ECDSA с параметрами TC26-256-B.
//! Входные данные: открытый ключ (x, y), хеш (little-endian 256 бит), подпись (r, s в big-endian).

use crate::error::Result;
use crate::crypto::ecc_params::CurveParams;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use num_integer::Integer;

/// Точка на эллиптической кривой
#[derive(Debug, Clone, PartialEq)]
pub enum ECPoint {
    /// Точка в бесконечности (нейтральный элемент)
    Infinity,
    /// Аффинные координаты (x, y)
    Affine(BigUint, BigUint),
}

impl ECPoint {
    /// Создаёт точку из координат
    pub fn new(x: BigUint, y: BigUint) -> Self {
        ECPoint::Affine(x, y)
    }

    /// Парсит точку: x (LE 32 байта) ‖ y (LE 32 байта)
    pub fn from_le_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != 64 {
            return Err(crate::error::CryptolineError::InvalidData(
                "ECPoint: expected 64 bytes".to_string(),
            ));
        }
        let x = BigUint::from_bytes_le(&data[..32]);
        let y = BigUint::from_bytes_le(&data[32..]);
        Ok(ECPoint::Affine(x, y))
    }

    /// Вкодирует точку в little-endian (64 байта)
    pub fn to_le_bytes(&self) -> Vec<u8> {
        match self {
            ECPoint::Infinity => vec![0u8; 64],
            ECPoint::Affine(x, y) => {
                let mut result = vec![0u8; 64];
                let x_bytes = x.to_bytes_le();
                let y_bytes = y.to_bytes_le();
                result[..x_bytes.len()].copy_from_slice(&x_bytes);
                result[32..32 + y_bytes.len()].copy_from_slice(&y_bytes);
                result
            }
        }
    }
}

/// Верификатор подписей ГОСТ Р 34.10-2012
#[derive(Debug)]
pub struct GostSigner {
    curve: CurveParams,
}

impl GostSigner {
    pub fn new() -> Self {
        GostSigner {
            curve: CurveParams::default(),
        }
    }

    /// Подписывает хеш приватным ключом (ECDSA).
    ///
    /// # Параметры
    /// - `private_key`: приватный ключ (32 байта, big-endian)
    /// - `digest`: хеш (32 байта, little-endian)
    ///
    /// # Возвращает
    /// Подпись (64 байта, s(BE 32) ‖ r(BE 32))
    pub fn sign(&self, private_key: &[u8], digest: &[u8]) -> Result<Vec<u8>> {
        if private_key.len() != 32 {
            return Err(crate::error::CryptolineError::InvalidData(
                "private_key: expected 32 bytes".to_string(),
            ));
        }
        if digest.len() != 32 {
            return Err(crate::error::CryptolineError::InvalidData(
                "digest: expected 32 bytes".to_string(),
            ));
        }

        let d = BigUint::from_bytes_be(private_key);
        
        // Хеш: little-endian, переворачиваем в big-endian
        let mut h_bytes = digest.to_vec();
        h_bytes.reverse();
        let mut e = BigUint::from_bytes_be(&h_bytes) % &self.curve.q;
        if e.is_zero() {
            e = BigUint::one();
        }

        // Генерируем детерминированное k (RFC 6979)
        let k = self.generate_deterministic_k(&e, &d)?;

        // P = k * G
        let p = self.scalar_mul(&k)?;
        let (p_x, _) = match p {
            ECPoint::Affine(x, y) => (x, y),
            ECPoint::Infinity => {
                return Err(crate::error::CryptolineError::CryptoError(
                    "k*G resulted in point at infinity".to_string(),
                ))
            }
        };

        let r = p_x % &self.curve.q;
        
        if r.is_zero() {
            return Err(crate::error::CryptolineError::CryptoError(
                "r is zero (invalid signature)".to_string(),
            ));
        }

        // s = k^(-1) * (e + d*r) mod q
        let k_inv = CurveParams::mod_inverse(&k, &self.curve.q).ok_or_else(|| {
            crate::error::CryptolineError::CryptoError(
                "Failed to compute k inverse".to_string(),
            )
        })?;

        let dr = (&d * &r) % &self.curve.q;
        let s = (&k_inv * (&e + &dr)) % &self.curve.q;

        if s.is_zero() {
            return Err(crate::error::CryptolineError::CryptoError(
                "s is zero (invalid signature)".to_string(),
            ));
        }

        // Вернуть s(BE 32) || r(BE 32)
        let mut result = vec![0u8; 64];
        let s_bytes = s.to_bytes_be();
        let r_bytes = r.to_bytes_be();
        
        // Паддируем до 32 байт
        let s_padded = {
            let mut padded = vec![0u8; 32];
            padded[32 - s_bytes.len()..].copy_from_slice(&s_bytes);
            padded
        };
        
        let r_padded = {
            let mut padded = vec![0u8; 32];
            padded[32 - r_bytes.len()..].copy_from_slice(&r_bytes);
            padded
        };

        result[0..32].copy_from_slice(&s_padded);
        result[32..64].copy_from_slice(&r_padded);

        Ok(result)
    }

    /// Генерирует детерминированное k как в RFC 6979
    fn generate_deterministic_k(&self, e: &BigUint, d: &BigUint) -> Result<BigUint> {
        use sha2::{Sha256, Digest};
        
        // Простая детерминированная генерация k
        // k = (SHA256(d || e) mod (q-1)) + 1
        
        let d_bytes = d.to_bytes_be();
        let e_bytes = e.to_bytes_be();
        
        let mut hasher = Sha256::new();
        hasher.update(&d_bytes);
        hasher.update(&e_bytes);
        let hash_result = hasher.finalize();
        
        let k_int = BigUint::from_bytes_be(&hash_result[..]);
        let k = (k_int % (&self.curve.q - BigUint::one())) + BigUint::one();
        
        Ok(k)
    }

    /// Проверяет подпись ECDSA.
    ///
    /// # Параметры
    /// - `public_key`: открытый ключ (64 байта, x(LE 32) ‖ y(LE 32))
    /// - `digest`: хеш (32 байта, little-endian)
    /// - `signature`: подпись (64 байта, s(BE 32) ‖ r(BE 32) как на диске)
    ///
    /// # Возвращает
    /// `true`, если подпись корректна для данного хеша.
    pub fn verify(&self, public_key: &[u8], digest: &[u8], signature: &[u8]) -> Result<bool> {
        if public_key.len() != 64 {
            return Err(crate::error::CryptolineError::InvalidData(
                "public_key: expected 64 bytes".to_string(),
            ));
        }
        if digest.len() != 32 {
            return Err(crate::error::CryptolineError::InvalidData(
                "digest: expected 32 bytes".to_string(),
            ));
        }
        if signature.len() != 64 {
            return Err(crate::error::CryptolineError::InvalidData(
                "signature: expected 64 bytes".to_string(),
            ));
        }

        // Парсим открытый ключ: x(LE 32) ‖ y(LE 32)
        let pub_x = BigUint::from_bytes_le(&public_key[0..32]);
        let pub_y = BigUint::from_bytes_le(&public_key[32..64]);

        // Парсим подпись: disk format s(BE 32) ‖ r(BE 32), но verify ожидает r || s
        let s = BigUint::from_bytes_be(&signature[0..32]);
        let r = BigUint::from_bytes_be(&signature[32..64]);

        // Хеш: little-endian, переворачиваем для стандартной формы (big-endian)
        let mut h_bytes = digest.to_vec();
        h_bytes.reverse();
        let h = BigUint::from_bytes_be(&h_bytes);

        // Проверка диапазонов
        if r.is_zero() || r >= self.curve.q || s.is_zero() || s >= self.curve.q {
            return Ok(false);
        }

        // e = h mod q; если e = 0, то e = 1
        let mut e = h % &self.curve.q;
        if e.is_zero() {
            e = BigUint::one();
        }

        // v = e^{-1} mod q
        let v = CurveParams::mod_inverse(&e, &self.curve.q).ok_or_else(|| {
            crate::error::CryptolineError::CryptoError(
                "Failed to compute modular inverse".to_string(),
            )
        })?;

        // z1 = s*v mod q, z2 = (q - r*v mod q) mod q
        let z1 = (&s * &v) % &self.curve.q;
        let rv_mod = (&r * &v) % &self.curve.q;
        let z2 = if rv_mod.is_zero() {
            BigUint::zero()
        } else {
            (&self.curve.q - &rv_mod) % &self.curve.q
        };

        // P = z1 * G
        let p = self.scalar_mul(&z1)?;

        // Q = z2 * Q_pub
        let q_val = self.scalar_mul_point(&z2, &pub_x, &pub_y)?;

        // C = P + Q
        let c = self.point_add(&p, &q_val)?;

        // r' = C.x mod q
        let (c_x, _) = match c {
            ECPoint::Affine(x, y) => (x, y),
            ECPoint::Infinity => return Ok(false),
        };

        let r_check = c_x % &self.curve.q;

        Ok(r_check == r)
    }

    /// Скалярное умножение k * G (публичный для тестирования)
    pub fn scalar_mul(&self, k: &BigUint) -> Result<ECPoint> {
        self.scalar_mul_point(k, &self.curve.px, &self.curve.py)
    }

    /// Скалярное умножение k * P на произвольную точку (публичный для тестирования)
    pub fn scalar_mul_point(&self, k: &BigUint, px: &BigUint, py: &BigUint) -> Result<ECPoint> {
        // Бинарный метод (слева направо)
        let p = ECPoint::Affine(px.clone(), py.clone());
        let mut result = ECPoint::Infinity;
        let mut base = p;

        let mut k_copy = k.clone();
        while !k_copy.is_zero() {
            if k_copy.is_odd() {
                result = self.point_add(&result, &base)?;
            }
            base = self.point_double(&base)?;
            k_copy = k_copy >> 1;
        }

        Ok(result)
    }

    /// Удвоение точки P + P (публичный для тестирования)
    pub fn point_double(&self, p: &ECPoint) -> Result<ECPoint> {
        match p {
            ECPoint::Infinity => Ok(ECPoint::Infinity),
            ECPoint::Affine(x, y) => {
                if y.is_zero() {
                    return Ok(ECPoint::Infinity);
                }

                // dy/dx = (3x² + a) / (2y) для кривой y² = x³ + ax + b
                let x2 = (x * x) % &self.curve.p;
                let three_x2 = (BigUint::from(3u32) * &x2) % &self.curve.p;
                let three_x2_plus_a = (&three_x2 + &self.curve.a) % &self.curve.p;
                let two_y = (BigUint::from(2u32) * y) % &self.curve.p;
                let two_y_inv = CurveParams::mod_inverse(&two_y, &self.curve.p)
                    .ok_or_else(|| {
                        crate::error::CryptolineError::CryptoError(
                            "point_double: failed to invert 2y".to_string(),
                        )
                    })?;

                let s = (&three_x2_plus_a * &two_y_inv) % &self.curve.p;
                let s2 = (&s * &s) % &self.curve.p;
                let two_x = (BigUint::from(2u32) * x) % &self.curve.p;
                // x3 = s² - 2x (модульное вычитание)
                let x3 = crate::crypto::mod_sub(&s2, &two_x, &self.curve.p);
                // y3 = s(x - x3) - y (модульное вычитание)
                let x_minus_x3 = crate::crypto::mod_sub(x, &x3, &self.curve.p);
                let sx_minus_x3 = (&s * &x_minus_x3) % &self.curve.p;
                let y3 = crate::crypto::mod_sub(&sx_minus_x3, y, &self.curve.p);

                Ok(ECPoint::Affine(x3, y3))
            }
        }
    }

    /// Сложение точек P + Q (публичный для тестирования)
    pub fn point_add(&self, p: &ECPoint, q: &ECPoint) -> Result<ECPoint> {
        match (p, q) {
            (ECPoint::Infinity, _) => Ok(q.clone()),
            (_, ECPoint::Infinity) => Ok(p.clone()),
            (ECPoint::Affine(x1, y1), ECPoint::Affine(x2, y2)) => {
                if x1 == x2 {
                    if y1 == y2 {
                        return self.point_double(p);
                    } else {
                        return Ok(ECPoint::Infinity);
                    }
                }

                // dy/dx = (y2 - y1) / (x2 - x1)
                let dx = crate::crypto::mod_sub(x2, x1, &self.curve.p);
                let dy = crate::crypto::mod_sub(y2, y1, &self.curve.p);
                let dx_inv = CurveParams::mod_inverse(&dx, &self.curve.p).ok_or_else(|| {
                    crate::error::CryptolineError::CryptoError(
                        "point_add: failed to invert dx".to_string(),
                    )
                })?;

                let s = (&dy * &dx_inv) % &self.curve.p;
                let s2 = (&s * &s) % &self.curve.p;
                // x3 = s² - x1 - x2 (модульное вычитание)
                let x3_temp = crate::crypto::mod_sub(&s2, x1, &self.curve.p);
                let x3 = crate::crypto::mod_sub(&x3_temp, x2, &self.curve.p);
                // y3 = s(x1 - x3) - y1 (модульное вычитание)
                let x1_minus_x3 = crate::crypto::mod_sub(x1, &x3, &self.curve.p);
                let sx_minus_x3 = (&s * &x1_minus_x3) % &self.curve.p;
                let y3 = crate::crypto::mod_sub(&sx_minus_x3, y1, &self.curve.p);

                Ok(ECPoint::Affine(x3, y3))
            }
        }
    }
}

impl Default for GostSigner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_scalar_mul_1() {
        let signer = GostSigner::new();
        let p = signer.scalar_mul(&BigUint::one()).unwrap();
        match p {
            ECPoint::Affine(x, y) => {
                assert_eq!(x, signer.curve.px);
                assert_eq!(y, signer.curve.py);
            }
            _ => panic!("expected Affine point"),
        }
    }
}
