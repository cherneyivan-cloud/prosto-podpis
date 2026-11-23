/// Debug: проверить операции на точке

use num_bigint::BigUint;
use crate::crypto::ecc_params::CurveParams;

pub fn test_point_double_manual() {
    let curve = CurveParams::tc26_256_b();
    let x = &curve.px;
    let y = &curve.py;
    
    println!("Testing point_double on generator G");
    println!("x = {}", x);
    println!("y = {}", y);
    
    // Вычислим s = (3x² + a) / (2y)
    let x2 = (x * x) % &curve.p;
    println!("x² mod p = {}", x2);
    
    let three_x2 = (BigUint::from(3u32) * &x2) % &curve.p;
    println!("3x² mod p = {}", three_x2);
    
    let three_x2_plus_a = (&three_x2 + &curve.a) % &curve.p;
    println!("3x² + a mod p = {}", three_x2_plus_a);
    
    let two_y = (BigUint::from(2u32) * y) % &curve.p;
    println!("2y mod p = {}", two_y);
    
    // Инверсия
    let two_y_inv = CurveParams::mod_inverse(&two_y, &curve.p)
        .expect("Failed to invert 2y");
    println!("(2y)⁻¹ mod p = {}", two_y_inv);
    
    let s = (&three_x2_plus_a * &two_y_inv) % &curve.p;
    println!("s = (3x² + a) / (2y) = {}", s);
    
    // x3 = s² - 2x
    let s2 = (&s * &s) % &curve.p;
    println!("s² mod p = {}", s2);
    
    let two_x = (BigUint::from(2u32) * x) % &curve.p;
    println!("2x mod p = {}", two_x);
    
    // Безопасное вычитание в модульной арифметике
    let x3 = {
        let diff = if s2 >= two_x {
            &s2 - &two_x
        } else {
            (&s2 + &curve.p) - &two_x
        };
        &diff % &curve.p
    };
    println!("x3 = s² - 2x = {}", x3);
    
    // y3 = s(x - x3) - y
    // Сначала (x - x3) в модульной арифметике
    let x_minus_x3 = if x >= &x3 {
        (x - &x3) % &curve.p
    } else {
        ((x + &curve.p) - &x3) % &curve.p
    };
    println!("x - x3 mod p = {}", x_minus_x3);
    
    let s_times_x_minus_x3 = (&s * &x_minus_x3) % &curve.p;
    println!("s(x - x3) mod p = {}", s_times_x_minus_x3);
    
    let y3 = {
        let diff = if &s_times_x_minus_x3 >= y {
            &s_times_x_minus_x3 - y
        } else {
            (&s_times_x_minus_x3 + &curve.p) - y
        };
        &diff % &curve.p
    };
    println!("y3 = s(x - x3) - y = {}", y3);
    
    println!("\nResulting point 2G:");
    println!("x = {}", x3);
    println!("y = {}", y3);
}
