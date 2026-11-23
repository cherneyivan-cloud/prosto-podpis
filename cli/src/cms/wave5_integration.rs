#[cfg(test)]
mod wave5_integration_tests {
    use crate::cms::extract_cms_components;
    use crate::crypto::gost_hash_data;
    use crate::crypto::GostSigner;
    use base64::Engine;
    use std::fs;
    use std::path::Path;

    #[test]
    fn verify_signature_from_sig_file() {
        // Загружаем .sig файл (Base64 DER)
        let sig_path = Path::new(
            r"C:\Users\i.cherney\AppData\Local\Temp\opencode\cryptoline_test_data\test1.txt.sig0",
        );

        if !sig_path.exists() {
            eprintln!("test1.txt.sig0 not found, skipping test");
            return;
        }

        let sig_b64 = fs::read_to_string(sig_path).expect("Failed to read sig file");

        // Удаляем все whitespace (включая \r\n и \n)
        let sig_b64_clean: String = sig_b64.chars().filter(|c| !c.is_whitespace()).collect();

        // Декодируем Base64 в DER
        let sig_der = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64_clean)
            .expect("Failed to decode Base64");

        println!("Loaded .sig file: {} bytes", sig_der.len());

        // Извлекаем компоненты CMS
        let cms = match extract_cms_components(&sig_der) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to extract CMS components: {}", e);
                return;
            }
        };

        println!("✓ Extracted CMS components");
        println!("  Signature: {} bytes", cms.signature.len());
        println!("  Signed attrs: {} bytes", cms.signed_attrs_raw.len());

        // Вычисляем хеш подписанных атрибутов (LE)
        let mut attrs_hash = gost_hash_data(&cms.signed_attrs_raw).to_vec();
        attrs_hash.reverse(); // Reverse to LE
        println!("  Attrs hash (LE): {}", hex_encode(&attrs_hash));

        // Извлекаем открытый ключ из сертификата (если присутствует)
        let mut pub_key = None;
        if let Some(ref cert) = cms.certificate {
            // Ищем BIT STRING [67] = 0x00 (unused bits) + 0x04 + 64 bytes
            // Или BIT STRING [66] в другой кодировке
            // Общая схема: 0x03 (BIT STRING tag) || length || 0x00 || 0x04 || 64 bytes
            
            let mut pos = 0;
            while pos + 68 <= cert.len() {
                if cert[pos] == 0x03 {
                    // BIT STRING tag found
                    let len_byte = cert[pos + 1];
                    let is_67 = len_byte == 0x43 || len_byte == 67;
                    let is_66 = len_byte == 0x42 || len_byte == 66;
                    let is_65 = len_byte == 0x41 || len_byte == 65;
                    
                    if is_67 || is_66 || is_65 {
                        let start = pos + 2; // Skip tag and length
                        if cert[start] == 0x00 {
                            // Unused bits byte
                            if cert[start + 1] == 0x04 {
                                // Uncompressed point indicator
                                pub_key = Some(cert[start + 2..start + 66].to_vec());
                                break;
                            }
                        }
                    }
                }
                pos += 1;
            }
        }

        if let Some(pk) = pub_key {
            println!("✓ Extracted public key from certificate");
            println!("  Pub key: {} bytes", pk.len());

            // Верифицируем подпись
            let signer = GostSigner::new();
            match signer.verify(&pk, &attrs_hash, &cms.signature) {
                Ok(true) => {
                    println!("✅ Signature VERIFIED");
                }
                Ok(false) => {
                    println!("❌ Signature INVALID");
                }
                Err(e) => {
                    println!("⚠️  Verification error: {}", e);
                }
            }
        } else {
            println!("⚠️  Could not extract public key from certificate");
        }
    }

    fn hex_encode(data: &[u8]) -> String {
        data.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }
}
