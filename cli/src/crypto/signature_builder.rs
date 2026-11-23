//! Сборка CMS/PKCS#7 SignedData структур.
//!
//! Формат повторяет то, что создаёт CryptoLine.exe: отсоединённая подпись
//! (detached) с атрибутами contentType, signingTime, messageDigest и
//! signingCertificateV2 (ESSCertIDv2). Подписывается DER-кодированный
//! SET атрибутов (тег 0x31), а не сам файл.

use crate::crypto::cert_util::{parse_certificate, CertParts};
use crate::crypto::gost2012_hash::gost_hash_data;
use crate::error::{CryptolineError, Result};
use base64::Engine;

/// Параметры для построения подписи
#[derive(Clone)]
pub struct SignatureParams {
    /// Содержимое подписываемого файла
    pub data: Vec<u8>,
    /// Открытый ключ (64 байта, как в сертификате: x ‖ y little-endian)
    pub public_key: Vec<u8>,
    /// Подпись (64 байта: s(BE 32) ‖ r(BE 32))
    pub signature: Vec<u8>,
    /// Сертификат в DER
    pub certificate: Vec<u8>,
    /// Время подписи в формате UTCTime: YYMMDDHHMMSSZ
    pub signing_time: String,
}



/// Текущее время UTC в формате UTCTime (YYMMDDHHMMSSZ).
pub fn current_utc_time() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = now.div_euclid(86_400);
    let secs = now.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        year % 100,
        month,
        day,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Преобразование числа дней с 1970-01-01 в дату (алгоритм Говарда Хиннанта).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32, d as u32)
}

/// Строитель CMS SignedData
/// Один подписант при сборке общего CMS (несколько SignerInfo).
pub struct CmsSigner {
    pub certificate: Vec<u8>,
    pub signature: Vec<u8>,
    pub signed_attrs_set: Vec<u8>,
}

pub struct CmsBuilder;

impl CmsBuilder {
    /// Строит DER `SET OF Attribute` — именно эти байты и подписываются.
    pub fn build_signed_attrs(params: &SignatureParams) -> Result<Vec<u8>> {
        let cert = parse_certificate(&params.certificate)?;
        let file_digest = gost_hash_data(&params.data);
        let cert_digest = gost_hash_data(&params.certificate);

        let mut attrs = vec![
            Self::build_content_type_attr()?,
            Self::build_signing_time_attr(&params.signing_time)?,
            Self::build_message_digest_attr(&file_digest)?,
            Self::build_signing_certificate_v2_attr(&cert, &cert_digest)?,
        ];
        // SET OF в DER требует лексикографической сортировки элементов.
        attrs.sort();
        Self::encode_set(&attrs)
    }

    /// Собирает CMS из готовой подписи и уже построенных signedAttrs.
    ///
    /// `signed_attrs_set` — результат `build_signed_attrs` (тег 0x31).
    pub fn build(params: &SignatureParams, signed_attrs_set: &[u8]) -> Result<Vec<u8>> {
        let signer = CmsSigner {
            certificate: params.certificate.clone(),
            signature: params.signature.clone(),
            signed_attrs_set: signed_attrs_set.to_vec(),
        };
        Self::build_multi(&params.data, &[signer], false)
    }

    /// Собирает CMS с несколькими подписантами и, при необходимости,
    /// с содержимым документа внутри (присоединенная подпись).
    pub fn build_multi(
        data: &[u8],
        signers: &[CmsSigner],
        attached: bool,
    ) -> Result<Vec<u8>> {
        if signers.is_empty() {
            return Err(CryptolineError::InvalidData(
                "нет подписантов".to_string(),
            ));
        }

        let digest_alg = Self::encode_algorithm_identifier("1.2.643.7.1.1.2.2")?;
        let sig_alg = Self::encode_algorithm_identifier_no_params("1.2.643.7.1.1.1.1")?;

        let mut certs = Vec::new();
        let mut signer_infos = Vec::new();
        for signer in signers {
            let cert = parse_certificate(&signer.certificate)?;
            let attrs_implicit =
                Self::retag_as_implicit(&signer.signed_attrs_set, 0xA0)?;
            let sig_value = Self::encode_octet_string(&signer.signature)?;
            signer_infos.push(Self::build_signer_info(
                &cert,
                &digest_alg,
                &attrs_implicit,
                &sig_alg,
                &sig_value,
            )?);
            certs.extend_from_slice(&signer.certificate);
        }

        let signer_infos = Self::encode_set(&signer_infos)?;
        let certs = Self::build_certificates_implicit(&certs)?;
        let encap_content = Self::build_encapsulated_content_info(data, attached)?;
        let signed_data =
            Self::build_signed_data(&digest_alg, &encap_content, &certs, &signer_infos)?;
        Self::build_content_info(&signed_data)
    }

    // === Атрибуты ===

    fn build_message_digest_attr(digest: &[u8]) -> Result<Vec<u8>> {
        let oid = Self::encode_oid("1.2.840.113549.1.9.4")?;
        let oct = Self::encode_octet_string(digest)?;
        let set = Self::encode_set(&[oct])?;
        Self::encode_sequence(&[oid, set])
    }

    fn build_content_type_attr() -> Result<Vec<u8>> {
        let oid = Self::encode_oid("1.2.840.113549.1.9.3")?;
        let data_oid = Self::encode_oid("1.2.840.113549.1.7.1")?;
        let set = Self::encode_set(&[data_oid])?;
        Self::encode_sequence(&[oid, set])
    }

    fn build_signing_time_attr(time: &str) -> Result<Vec<u8>> {
        let oid = Self::encode_oid("1.2.840.113549.1.9.5")?;
        let value = Self::encode_utc_time(time)?;
        let set = Self::encode_set(&[value])?;
        Self::encode_sequence(&[oid, set])
    }

    /// signingCertificateV2 (RFC 5035): 1.2.840.113549.1.9.16.2.47
    fn build_signing_certificate_v2_attr(
        cert: &CertParts,
        cert_digest: &[u8],
    ) -> Result<Vec<u8>> {
        let oid = Self::encode_oid("1.2.840.113549.1.9.16.2.47")?;

        // AlgorithmIdentifier ГОСТ Р 34.11-2012-256 без параметров.
        let hash_alg_oid = Self::encode_oid("1.2.643.7.1.1.2.2")?;
        let hash_alg = Self::encode_sequence(&[hash_alg_oid])?;

        let cert_hash = Self::encode_octet_string(cert_digest)?;

        // GeneralNames ::= [4] directoryName (полное имя издателя).
        let issuer_name = Self::encode_implicit_primitive(0xA4, &cert.issuer)?;
        let serial = Self::encode_integer_raw(&cert.serial)?;
        let issuer_serial = Self::encode_sequence(&[issuer_name, serial])?;

        let ess_cert_id = Self::encode_sequence(&[hash_alg, cert_hash, issuer_serial])?;
        let certs = Self::encode_sequence(&[ess_cert_id])?;
        let signing_certificate_v2 = Self::encode_sequence(&[certs])?;

        let set = Self::encode_set(&[signing_certificate_v2])?;
        Self::encode_sequence(&[oid, set])
    }

    // === Основные структуры ===

    fn build_signer_info(
        cert: &CertParts,
        digest_alg: &[u8],
        signed_attrs: &[u8],
        sig_alg: &[u8],
        sig_value: &[u8],
    ) -> Result<Vec<u8>> {
        let version = Self::encode_integer(1)?;

        // IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }
        let serial = Self::encode_integer_raw(&cert.serial)?;
        let issuer_sn = Self::encode_sequence(&[cert.issuer.clone(), serial])?;

        Self::encode_sequence(&[
            version,
            issuer_sn,
            digest_alg.to_vec(),
            signed_attrs.to_vec(),
            sig_alg.to_vec(),
            sig_value.to_vec(),
        ])
    }

    fn build_signed_data(
        digest_alg: &[u8],
        encap_content: &[u8],
        certs: &[u8],
        signer_infos: &[u8],
    ) -> Result<Vec<u8>> {
        let version = Self::encode_integer(1)?;
        let digest_set = Self::encode_set(&[digest_alg.to_vec()])?;
        Self::encode_sequence(&[
            version,
            digest_set,
            encap_content.to_vec(),
            certs.to_vec(),
            signer_infos.to_vec(),
        ])
    }

    /// EncapsulatedContentInfo: при присоединенной подписи содержит
    /// OCTET STRING с данными документа.
    fn build_encapsulated_content_info(data: &[u8], attached: bool) -> Result<Vec<u8>> {
        let content_oid = Self::encode_oid("1.2.840.113549.1.7.1")?;
        if attached {
            let octet = Self::encode_octet_string(data)?;
            let explicit = Self::encode_tlv(0xA0, &octet)?;
            Self::encode_sequence(&[content_oid, explicit])
        } else {
            Self::encode_sequence(&[content_oid])
        }
    }

    fn build_certificates_implicit(certs: &[u8]) -> Result<Vec<u8>> {
        Self::encode_tlv(0xA0, certs)
    }

    fn build_content_info(signed_data: &[u8]) -> Result<Vec<u8>> {
        let oid = Self::encode_oid("1.2.840.113549.1.7.2")?;
        let content = Self::encode_tlv(0xA0, signed_data)?;
        Self::encode_sequence(&[oid, content])
    }

    // === Вспомогательные функции для кодирования DER ===

    fn encode_sequence(elements: &[Vec<u8>]) -> Result<Vec<u8>> {
        let mut content = Vec::new();
        for elem in elements {
            content.extend_from_slice(elem);
        }
        Self::encode_tlv(0x30, &content)
    }

    fn encode_set(elements: &[Vec<u8>]) -> Result<Vec<u8>> {
        let mut content = Vec::new();
        for elem in elements {
            content.extend_from_slice(elem);
        }
        Self::encode_tlv(0x31, &content)
    }

    fn encode_oid(oid_str: &str) -> Result<Vec<u8>> {
        let parts: Vec<&str> = oid_str.split('.').collect();
        if parts.len() < 2 {
            return Err(CryptolineError::InvalidData("Invalid OID format".to_string()));
        }

        let mut content = Vec::new();
        let first = parts[0].parse::<u32>().map_err(|_| {
            CryptolineError::InvalidData("OID first component not a number".to_string())
        })?;
        let second = parts[1].parse::<u32>().map_err(|_| {
            CryptolineError::InvalidData("OID second component not a number".to_string())
        })?;

        content.push((first * 40 + second) as u8);

        for part_str in &parts[2..] {
            let val = part_str.parse::<u32>().map_err(|_| {
                CryptolineError::InvalidData("OID component not a number".to_string())
            })?;
            Self::encode_oid_component(&mut content, val);
        }

        Self::encode_tlv(0x06, &content)
    }

    fn encode_oid_component(content: &mut Vec<u8>, mut val: u32) {
        if val < 128 {
            content.push(val as u8);
        } else {
            let mut bytes = Vec::new();
            bytes.push((val & 0x7F) as u8);
            val >>= 7;
            while val > 0 {
                bytes.push(((val & 0x7F) | 0x80) as u8);
                val >>= 7;
            }
            bytes.reverse();
            content.extend_from_slice(&bytes);
        }
    }

    fn encode_integer(val: i32) -> Result<Vec<u8>> {
        let bytes = val.to_be_bytes();
        let mut trimmed = bytes.to_vec();
        while trimmed.len() > 1 && trimmed[0] == 0 && (trimmed[1] & 0x80) == 0 {
            trimmed.remove(0);
        }
        Self::encode_tlv(0x02, &trimmed)
    }

    /// INTEGER из уже готового содержимого (как в сертификате).
    fn encode_integer_raw(value: &[u8]) -> Result<Vec<u8>> {
        Self::encode_tlv(0x02, value)
    }

    fn encode_octet_string(data: &[u8]) -> Result<Vec<u8>> {
        Self::encode_tlv(0x04, data)
    }

    fn encode_utc_time(time_str: &str) -> Result<Vec<u8>> {
        Self::encode_tlv(0x17, time_str.as_bytes())
    }

    /// AlgorithmIdentifier с параметром NULL (как в digestAlgorithms).
    fn encode_algorithm_identifier(oid: &str) -> Result<Vec<u8>> {
        let oid_bytes = Self::encode_oid(oid)?;
        let null = Self::encode_tlv(0x05, &[])?;
        Self::encode_sequence(&[oid_bytes, null])
    }

    /// AlgorithmIdentifier без параметров (как signatureAlgorithm для ГОСТ 2012).
    fn encode_algorithm_identifier_no_params(oid: &str) -> Result<Vec<u8>> {
        let oid_bytes = Self::encode_oid(oid)?;
        Self::encode_sequence(&[oid_bytes])
    }

    fn encode_implicit_primitive(tag: u8, data: &[u8]) -> Result<Vec<u8>> {
        Self::encode_tlv(tag, data)
    }

    /// Меняет тег уже собранного элемента (SET -> [0] IMPLICIT).
    fn retag_as_implicit(element: &[u8], new_tag: u8) -> Result<Vec<u8>> {
        if element.is_empty() {
            return Err(CryptolineError::InvalidData(
                "Пустой DER-элемент".to_string(),
            ));
        }
        let mut out = element.to_vec();
        out[0] = new_tag;
        Ok(out)
    }

    fn encode_tlv(tag: u8, content: &[u8]) -> Result<Vec<u8>> {
        let mut result = vec![tag];

        let len = content.len();
        if len < 128 {
            result.push(len as u8);
        } else {
            let mut len_bytes = Vec::new();
            let mut l = len;
            while l > 0 {
                len_bytes.push((l & 0xFF) as u8);
                l >>= 8;
            }
            len_bytes.reverse();
            result.push(0x80 | len_bytes.len() as u8);
            result.extend_from_slice(&len_bytes);
        }

        result.extend_from_slice(content);
        Ok(result)
    }
}



/// Кодирует подпись в Base64 для файла .sig
pub fn encode_signature_to_base64(der: &[u8]) -> String {
    const ENGINE: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::STANDARD;
    ENGINE.encode(der)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_oid_simple() {
        assert!(!CmsBuilder::encode_oid("1.2.840.113549.1.7.2").unwrap().is_empty());
    }

    #[test]
    fn test_encode_integer() {
        let int = CmsBuilder::encode_integer(1).unwrap();
        assert_eq!(int, vec![0x02, 0x01, 0x01]);
    }

    #[test]
    fn test_utc_time_format() {
        let t = current_utc_time();
        assert_eq!(t.len(), 13);
        assert!(t.ends_with('Z'));
    }

    #[test]
    fn test_retag() {
        let set = CmsBuilder::encode_set(&[CmsBuilder::encode_integer(1).unwrap()]).unwrap();
        let implicit = CmsBuilder::retag_as_implicit(&set, 0xA0).unwrap();
        assert_eq!(implicit[0], 0xA0);
        assert_eq!(&implicit[1..], &set[1..]);
    }
}
