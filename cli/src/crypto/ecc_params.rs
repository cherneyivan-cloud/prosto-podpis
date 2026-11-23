//! Параметры кривой TC26-256-B (id-tc26-gost-3410-2012-256-paramSetB).
//! 
//! Источник: RFC 7836, RFC 4357.
//! Валидация: константы проверены верификацией оригинальных подписей CryptoLine.

use num_bigint::BigUint;

/// Параметры эллиптической кривой y² = x³ - 3x + b (mod p)
#[derive(Debug, Clone)]
pub struct CurveParams {
    /// Модуль поля
    pub p: BigUint,
    /// Коэффициент a (всегда p - 3 для этой семейства)
    pub a: BigUint,
    /// Коэффициент b
    pub b: BigUint,
    /// Порядок подгруппы q
    pub q: BigUint,
    /// Базовая точка G: x-координата
    pub px: BigUint,
    /// Базовая точка G: y-координата
    pub py: BigUint,
}

impl CurveParams {
    /// TC26-256-B (same as CryptoPro-XchA), используется в CryptoLine.
    pub fn tc26_256_b() -> Self {
        let p_hex = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97";
        let a_hex = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94";
        let b_hex = "a6";
        let q_hex = "ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893";
        let px_hex = "1";
        let py_hex = "8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14";

        CurveParams {
            p: BigUint::parse_bytes(p_hex.as_bytes(), 16).expect("p parse"),
            a: BigUint::parse_bytes(a_hex.as_bytes(), 16).expect("a parse"),
            b: BigUint::parse_bytes(b_hex.as_bytes(), 16).expect("b parse"),
            q: BigUint::parse_bytes(q_hex.as_bytes(), 16).expect("q parse"),
            px: BigUint::parse_bytes(px_hex.as_bytes(), 16).expect("px parse"),
            py: BigUint::parse_bytes(py_hex.as_bytes(), 16).expect("py parse"),
        }
    }

    /// Проверка точки на кривой: y² ≡ x³ + ax + b (mod p)
    pub fn is_on_curve(&self, x: &BigUint, y: &BigUint) -> bool {
        let x2 = (x * x) % &self.p;
        let x3 = (&x2 * x) % &self.p;
        let ax = (&self.a * x) % &self.p;
        let lhs = (y * y) % &self.p;
        let rhs = (&x3 + &ax + &self.b) % &self.p;
        lhs == rhs
    }

    /// Модульное обращение: вычисляет a⁻¹ mod m (используя Fermat's Little Theorem для простых полей)
    /// Для простого модуля p: a⁻¹ ≡ a^(p-2) (mod p)
    pub fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
        use num_traits::Zero;
        if a.is_zero() {
            return None;
        }
        
        // Используем Fermat's Little Theorem: a^(p-1) ≡ 1 (mod p) для простого p
        // Поэтому a^(-1) ≡ a^(p-2) (mod p)
        let exp = m - BigUint::from(2u32);
        Some(Self::mod_pow(a, &exp, m))
    }
    
    /// Модульное возведение в степень: a^exp mod m
    fn mod_pow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
        use num_traits::{One, Zero};
        
        if modulus.is_one() {
            return BigUint::zero();
        }
        
        let mut result = BigUint::one();
        let mut base = base % modulus;
        let mut exp = exp.clone();
        
        while !exp.is_zero() {
            if &exp % 2u32 == BigUint::one() {
                result = (&result * &base) % modulus;
            }
            exp = &exp >> 1;
            base = (&base * &base) % modulus;
        }
        
        result
    }
}

impl Default for CurveParams {
    fn default() -> Self {
        Self::tc26_256_b()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_on_curve() {
        let curve = CurveParams::tc26_256_b();
        assert!(
            curve.is_on_curve(&curve.px, &curve.py),
            "Generator must be on curve"
        );
    }

    #[test]
    fn mod_inverse_identity() {
        let m = BigUint::from(13u32);
        let a = BigUint::from(5u32);
        let inv = CurveParams::mod_inverse(&a, &m).unwrap();
        assert_eq!((&a * &inv) % &m, BigUint::from(1u32));
    }
}
