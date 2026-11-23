#[cfg(test)]
mod wave8_scalar_mul_debug {
    use crate::crypto::ecc_params::CurveParams;
    use crate::crypto::GostSigner;
    use num_bigint::BigUint;
    use num_traits::Zero;
    use num_integer::Integer;

    #[test]
    fn debug_scalar_multiplication_step_by_step() {
        let curve = CurveParams::default();
        let signer = GostSigner::new();

        // Используем простой скаляр для отладки
        let k = BigUint::from(5u32);  // 5 = 101 в двоичной
        let px = BigUint::from(1u32);
        let py = curve.py.clone();

        println!("\n=== WAVE 8: SCALAR MULTIPLICATION DEBUG ===\n");
        println!("Computing {}*P where P = ({}, {})", k, px, py);
        println!("Binary representation of {}: {:b}", k, k);

        // Ручная реализация с отладкой
        let mut result = crate::crypto::gost2012_sign::ECPoint::Infinity;
        let mut base = crate::crypto::gost2012_sign::ECPoint::Affine(px.clone(), py.clone());
        let mut k_copy = k.clone();
        let mut iteration = 0;

        println!("\n--- Iterations ---");
        while !k_copy.is_zero() {
            iteration += 1;
            let bit = if k_copy.is_odd() { 1 } else { 0 };

            println!("\nIteration {}:", iteration);
            println!("  k_copy = {} ({:b})", k_copy, k_copy);
            println!("  Current bit (LSB) = {}", bit);

            // Print current base
            match &base {
                crate::crypto::gost2012_sign::ECPoint::Affine(bx, by) => {
                    println!("  Base.x = {}", bx);
                    println!("  Base.y = {}", by);
                }
                crate::crypto::gost2012_sign::ECPoint::Infinity => {
                    println!("  Base = Infinity");
                }
            }

            // Print current result
            match &result {
                crate::crypto::gost2012_sign::ECPoint::Affine(rx, ry) => {
                    println!("  Result.x = {}", rx);
                    println!("  Result.y = {}", ry);
                }
                crate::crypto::gost2012_sign::ECPoint::Infinity => {
                    println!("  Result = Infinity");
                }
            }

            if bit == 1 {
                println!("  Action: result = result + base");
                result = signer.point_add(&result, &base).expect("point_add failed");

                match &result {
                    crate::crypto::gost2012_sign::ECPoint::Affine(rx, ry) => {
                        println!("  New result.x = {}", rx);
                        println!("  New result.y = {}", ry);
                    }
                    crate::crypto::gost2012_sign::ECPoint::Infinity => {
                        println!("  New result = Infinity");
                    }
                }
            } else {
                println!("  Action: skip (bit = 0)");
            }

            println!("  Action: base = 2*base");
            base = signer.point_double(&base).expect("point_double failed");

            match &base {
                crate::crypto::gost2012_sign::ECPoint::Affine(bx, by) => {
                    println!("  New base.x = {}", bx);
                    println!("  New base.y = {}", by);
                }
                crate::crypto::gost2012_sign::ECPoint::Infinity => {
                    println!("  New base = Infinity");
                }
            }

            k_copy = k_copy.clone() >> 1;
        }

        println!("\n--- Final Result ---");
        match &result {
            crate::crypto::gost2012_sign::ECPoint::Affine(rx, ry) => {
                println!("{}*P.x = {}", k, rx);
                println!("{}*P.y = {}", k, ry);
            }
            crate::crypto::gost2012_sign::ECPoint::Infinity => {
                println!("{}*P = Infinity", k);
            }
        }

        // Now test with actual data
        println!("\n=== REAL TEST: z2*Q ===");
        let z2 = BigUint::parse_bytes(
            b"94690180427711328700439370610485435930762866914039874865835358569906256694520",
            10,
        ).unwrap();
        let pub_x = BigUint::parse_bytes(
            b"46793724705382309969820791814063951830609433558463396879898128518130696910128",
            10,
        ).unwrap();
        let pub_y = BigUint::parse_bytes(
            b"77099144004220165810571882956635076398356007885967543299752888253763467045258",
            10,
        ).unwrap();

        let expected_qx = BigUint::parse_bytes(
            b"88892389094344711344131785713452845762417585908110642864932569544741161835112",
            10,
        ).unwrap();

        let result_q = signer
            .scalar_mul_point(&z2, &pub_x, &pub_y)
            .expect("scalar_mul_point failed");

        match &result_q {
            crate::crypto::gost2012_sign::ECPoint::Affine(qx, qy) => {
                println!("z2*Q.x = {}", qx);
                println!("z2*Q.y = {}", qy);
                println!("\nExpected Q.x = {}", expected_qx);
                println!("Match: {}", qx == &expected_qx);

                if qx != &expected_qx {
                    println!("\nDifference: {}", 
                        if qx > &expected_qx { 
                            qx - &expected_qx 
                        } else { 
                            &expected_qx - qx 
                        }
                    );
                }
            }
            crate::crypto::gost2012_sign::ECPoint::Infinity => {
                println!("z2*Q = Infinity (ERROR!)");
            }
        }
    }
}
