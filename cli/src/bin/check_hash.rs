//! Проверка Стрибог-256 против настоящих данных CryptoLine.
//!
//! Ожидаемые значения взяты из поля messageDigest (OID 1.2.840.113549.1.9.4)
//! в подписях, созданных оригинальным CryptoLine.exe.

use std::path::Path;

fn main() {
    let cases: &[(&str, &str)] = &[
        (
            r"C:\Users\i.cherney\AppData\Local\Temp\opencode\cryptoline_test_data\test1.txt",
            "2c53509bc0391f0b8f602066718a7814ba52589240e8b366b00f3658ad6dc7ff",
        ),
        (
            r"C:\Users\i.cherney\AppData\Local\Temp\opencode\cryptoline_test_data\test1.bin",
            "bcf41ff0e4910701e9f82b6e7d5ca024f5b4a811dadeea90bc3799222b69bebd",
        ),
    ];

    let mut ok = 0usize;
    let mut fail = 0usize;

    for (path, expected) in cases {
        let p = Path::new(path);
        match cryptoline_rust::crypto::gost_hash_file(p) {
            Ok(hash) => {
                let got = cryptoline_rust::crypto::gost2012_hash::to_hex(&hash);
                if got == *expected {
                    println!("[OK]   {} = {}", p.file_name().unwrap().to_string_lossy(), got);
                    ok += 1;
                } else {
                    println!("[FAIL] {}", p.file_name().unwrap().to_string_lossy());
                    println!("       ожидалось {}", expected);
                    println!("       получено  {}", got);
                    fail += 1;
                }
            }
            Err(e) => {
                println!("[ERR]  {}: {}", p.display(), e);
                fail += 1;
            }
        }
    }

    println!("\nИтого: {} совпало, {} не совпало", ok, fail);
    if fail > 0 {
        std::process::exit(1);
    }
}
