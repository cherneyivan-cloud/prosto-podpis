//! CMS/PKCS#7 Structure Extractor - Wave 5 Fixed Version
//! 
//! Правильная навигация по DER структуре для извлечения компонентов

use crate::error::{CryptolineError, Result};

/// Компоненты подписи, извлечённые из CMS
#[derive(Debug, Clone)]
pub struct CmsComponents {
    /// Подпись: s(BE 32) ‖ r(BE 32)
    pub signature: Vec<u8>,
    /// Подписанные атрибуты как SET (0x31) для хеширования
    pub signed_attrs_raw: Vec<u8>,
    /// Хеш сообщения из атрибутов (если присутствует)
    pub message_digest: Option<Vec<u8>>,
    /// Сертификат (если присутствует)
    pub certificate: Option<Vec<u8>>,
}

/// Helper для DER парсинга
struct DerNode {
    tag: u8,
    value: Vec<u8>,
}

fn parse_one(data: &[u8], mut pos: usize) -> Result<(DerNode, usize)> {
    if pos >= data.len() {
        return Err(CryptolineError::DerParseError("Unexpected EOF".to_string()));
    }
    
    let tag = data[pos];
    pos += 1;
    
    if pos >= data.len() {
        return Err(CryptolineError::DerParseError("No length byte".to_string()));
    }
    
    let len_byte = data[pos];
    pos += 1;

    // BER с неопределённой длиной (CryptoPro/КриптоПро): 0x80 ... 00 00.
    // Встречается в реальных .sig с порталов — читаем до EOC на этом уровне.
    if len_byte == 0x80 {
        let content_start = pos;
        let mut scan = pos;
        loop {
            if scan + 2 > data.len() {
                return Err(CryptolineError::DerParseError(
                    "No end-of-contents for indefinite length".to_string(),
                ));
            }
            if data[scan] == 0x00 && data[scan + 1] == 0x00 {
                break;
            }
            let (_, next) = parse_one(data, scan)?;
            if next <= scan {
                return Err(CryptolineError::DerParseError(
                    "Invalid BER nesting".to_string(),
                ));
            }
            scan = next;
        }
        let value = data[content_start..scan].to_vec();
        return Ok((DerNode { tag, value }, scan + 2));
    }

    let length = if len_byte & 0x80 == 0 {
        len_byte as usize
    } else {
        let num_octets = (len_byte & 0x7F) as usize;
        if pos + num_octets > data.len() {
            return Err(CryptolineError::DerParseError("Truncated length".to_string()));
        }
        let len_bytes = &data[pos..pos + num_octets];
        pos += num_octets;
        let mut length = 0usize;
        for &b in len_bytes {
            length = (length << 8) | (b as usize);
        }
        length
    };
    
    if pos + length > data.len() {
        return Err(CryptolineError::DerParseError("Value truncated".to_string()));
    }
    
    let value = data[pos..pos + length].to_vec();
    pos += length;
    
    Ok((DerNode { tag, value }, pos))
}

pub fn extract_cms_components(der_data: &[u8]) -> Result<CmsComponents> {
    let mut pos = 0;
    
    // ContentInfo SEQUENCE
    let (content_info, _) = parse_one(der_data, pos)?;
    if content_info.tag != 0x30 {
        return Err(CryptolineError::DerParseError(
            "Expected SEQUENCE for ContentInfo".to_string(),
        ));
    }
    
    // Parse ContentInfo children: OID, [0]
    let mut ci_pos = 0;
    let (_oid, ci_pos) = parse_one(&content_info.value, ci_pos)?;
    let (content_field, _) = parse_one(&content_info.value, ci_pos)?;
    
    if content_field.tag != 0xA0 {
        return Err(CryptolineError::DerParseError(
            "Expected [0] for SignedData content".to_string(),
        ));
    }
    
    // SignedData SEQUENCE is inside [0]
    let (signed_data, _) = parse_one(&content_field.value, 0)?;
    if signed_data.tag != 0x30 {
        return Err(CryptolineError::DerParseError(
            "Expected SEQUENCE for SignedData".to_string(),
        ));
    }
    
    // Parse SignedData: version, digestAlgorithms, contentInfo, [certificates], signerInfos
    let mut sd_pos = 0;
    
    // version
    let (_, sd_pos) = parse_one(&signed_data.value, sd_pos)?;
    
    // digestAlgorithms
    let (_, sd_pos) = parse_one(&signed_data.value, sd_pos)?;
    
    // contentInfo (EncapsulatedContentInfo)
    let (_, sd_pos) = parse_one(&signed_data.value, sd_pos)?;
    
    // [0] certificates (optional)
    let mut sd_pos = sd_pos;
    let mut certificate = None;
    if sd_pos < signed_data.value.len() && signed_data.value[sd_pos] == 0xA0 {
        let (certs_field, new_pos) = parse_one(&signed_data.value, sd_pos)?;
        certificate = Some(certs_field.value);
        sd_pos = new_pos;
    }
    
    // signerInfos SET
    let (signer_infos, _) = parse_one(&signed_data.value, sd_pos)?;
    if signer_infos.tag != 0x31 {
        return Err(CryptolineError::DerParseError(
            "Expected SET for signerInfos".to_string(),
        ));
    }
    
    // SignerInfo SEQUENCE (first one in set)
    let (signer_info, _) = parse_one(&signer_infos.value, 0)?;
    if signer_info.tag != 0x30 {
        return Err(CryptolineError::DerParseError(
            "Expected SEQUENCE for SignerInfo".to_string(),
        ));
    }
    
    // Parse SignerInfo: version, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm, signature
    let mut si_pos = 0;
    
    // version
    let (_, si_pos) = parse_one(&signer_info.value, si_pos)?;
    
    // sid (IssuerAndSerialNumber)
    let (_, si_pos) = parse_one(&signer_info.value, si_pos)?;
    
    // digestAlgorithm
    let (_, si_pos) = parse_one(&signer_info.value, si_pos)?;
    
    // [0] IMPLICIT signedAttrs
    let mut signed_attrs_raw = Vec::new();
    let mut si_pos = si_pos;
    if si_pos < signer_info.value.len() && signer_info.value[si_pos] == 0xA0 {
        let attrs_tag_pos = si_pos;
        let (attrs_field, new_pos) = parse_one(&signer_info.value, si_pos)?;
        si_pos = new_pos;
        
        // Reconstruct as SET (0x31)
        signed_attrs_raw.push(0x31);
        
        // Re-encode length
        let len = attrs_field.value.len();
        if len < 128 {
            signed_attrs_raw.push(len as u8);
        } else {
            let mut len_bytes = Vec::new();
            let mut l = len;
            while l > 0 {
                len_bytes.push((l & 0xFF) as u8);
                l >>= 8;
            }
            len_bytes.reverse();
            signed_attrs_raw.push(0x80 | len_bytes.len() as u8);
            signed_attrs_raw.extend_from_slice(&len_bytes);
        }
        signed_attrs_raw.extend_from_slice(&attrs_field.value);
    }
    
    // signatureAlgorithm
    let (_, si_pos) = parse_one(&signer_info.value, si_pos)?;
    
    // signature (OCTET STRING)
    let (sig_field, _) = parse_one(&signer_info.value, si_pos)?;
    if sig_field.tag != 0x04 {
        return Err(CryptolineError::DerParseError(
            "Expected OCTET STRING for signature".to_string(),
        ));
    }
    
    let signature = sig_field.value;
    
    // Extract message digest from attributes
    let message_digest = extract_message_digest(&signed_attrs_raw)?;
    
    Ok(CmsComponents {
        signature,
        signed_attrs_raw,
        message_digest,
        certificate,
    })
}

fn extract_message_digest(signed_attrs: &[u8]) -> Result<Option<Vec<u8>>> {
    // signed_attrs is now a proper SET: 0x31 || length || content
    // Inside we're looking for SEQUENCE with OID 1.2.840.113549.1.9.4
    
    if signed_attrs.len() < 3 || signed_attrs[0] != 0x31 {
        return Ok(None);
    }
    
    // Parse SET length and skip to content
    let mut pos = 1;
    let len_byte = signed_attrs[pos];
    pos += 1;
    
    let _ = if len_byte & 0x80 == 0 {
        len_byte as usize
    } else {
        let num_octets = (len_byte & 0x7F) as usize;
        pos += num_octets;
        0usize
    };
    
    // Now search for the messageDigest attribute
    // OID 1.2.840.113549.1.9.4 = 06 09 2a 86 48 86 f7 0d 01 09 04
    const MESSAGE_DIGEST_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
    
    while pos + 11 < signed_attrs.len() {
        if signed_attrs[pos] == 0x06
            && signed_attrs[pos + 1] == 0x09
            && &signed_attrs[pos + 2..pos + 11] == MESSAGE_DIGEST_OID
        {
            pos += 11;
            // Next should be SET with OCTET STRING
            if pos < signed_attrs.len() && signed_attrs[pos] == 0x31 {
                pos += 1;
                // Skip SET length
                let len_byte = signed_attrs[pos];
                pos += 1;
                if len_byte & 0x80 != 0 {
                    let num_octets = (len_byte & 0x7F) as usize;
                    pos += num_octets;
                }
                
                // OCTET STRING
                if pos < signed_attrs.len() && signed_attrs[pos] == 0x04 {
                    pos += 1;
                    let oct_len = signed_attrs[pos] as usize;
                    pos += 1;
                    
                    if pos + oct_len <= signed_attrs.len() {
                        return Ok(Some(signed_attrs[pos..pos + oct_len].to_vec()));
                    }
                }
            }
        }
        pos += 1;
    }
    
    Ok(None)
}

