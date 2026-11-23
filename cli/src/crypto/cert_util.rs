//! Разбор X.509-сертификата: серийный номер, издатель, субъект, открытый ключ.
//!
//! Нужен для сборки CMS: sid (issuerAndSerialNumber) и атрибут
//! signingCertificateV2 (ESSCertIDv2) должны в точности повторять сертификат.

use crate::error::{CryptolineError, Result};

/// Извлечённые из сертификата поля.
#[derive(Debug, Clone)]
pub struct CertParts {
    /// Содержимое INTEGER serialNumber (без тега и длины).
    pub serial: Vec<u8>,
    /// Полный DER имени издателя (SEQUENCE ...).
    pub issuer: Vec<u8>,
    /// Полный DER имени субъекта (SEQUENCE ...).
    pub subject: Vec<u8>,
    /// Открытый ключ 64 байта в том виде, как он лежит в сертификате
    /// (x — 32 байта, y — 32 байта, little-endian).
    pub public_key: Vec<u8>,
}

/// Элемент TLV: тег, длина заголовка, длина содержимого.
fn read_tlv(data: &[u8], pos: usize) -> Result<(u8, usize, usize)> {
    if pos + 2 > data.len() {
        return Err(CryptolineError::CertificateError(
            "TLV: unexpected end".to_string(),
        ));
    }
    let tag = data[pos];
    let first = data[pos + 1];
    if first & 0x80 == 0 {
        return Ok((tag, 2, first as usize));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || pos + 2 + n > data.len() {
        return Err(CryptolineError::CertificateError(
            "TLV: bad length".to_string(),
        ));
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | data[pos + 2 + i] as usize;
    }
    Ok((tag, 2 + n, len))
}

/// Обходит дочерние элементы внутри value от `start` до `end`.
fn children(data: &[u8], start: usize, end: usize) -> Result<Vec<(u8, usize, usize)>> {
    let mut out = Vec::new();
    let mut p = start;
    while p < end {
        let (tag, h, l) = read_tlv(data, p)?;
        let total = h + l;
        if p + total > end {
            return Err(CryptolineError::CertificateError(
                "TLV: child overflows parent".to_string(),
            ));
        }
        out.push((tag, p, total));
        p += total;
    }
    Ok(out)
}

/// Полный DER элемента (тег + длина + значение).
fn element(data: &[u8], start: usize, total: usize) -> Vec<u8> {
    data[start..start + total].to_vec()
}

/// Разбирает сертификат.
pub fn parse_certificate(cert: &[u8]) -> Result<CertParts> {
    let (tag, h, l) = read_tlv(cert, 0)?;
    if tag != 0x30 {
        return Err(CryptolineError::CertificateError(
            "Certificate: expected SEQUENCE".to_string(),
        ));
    }
    let cert_children = children(cert, h, h + l)?;
    if cert_children.is_empty() {
        return Err(CryptolineError::CertificateError(
            "Certificate: empty".to_string(),
        ));
    }
    let (_, tbs_start, _) = cert_children[0];
    let (tbs_tag, tbs_h, tbs_l) = read_tlv(cert, tbs_start)?;
    if tbs_tag != 0x30 {
        return Err(CryptolineError::CertificateError(
            "tbsCertificate: expected SEQUENCE".to_string(),
        ));
    }
    let tbs = children(cert, tbs_start + tbs_h, tbs_start + tbs_h + tbs_l)?;

    let mut idx = 0;
    // [0] EXPLICIT version — необязателен.
    if !tbs.is_empty() && tbs[0].0 == 0xA0 {
        idx = 1;
    }
    if tbs.len() < idx + 6 {
        return Err(CryptolineError::CertificateError(
            "tbsCertificate: too few fields".to_string(),
        ));
    }

    // serialNumber
    let (serial_tag, serial_start, serial_total) = tbs[idx];
    if serial_tag != 0x02 {
        return Err(CryptolineError::CertificateError(
            "serialNumber: expected INTEGER".to_string(),
        ));
    }
    let (_, serial_h, serial_l) = read_tlv(cert, serial_start)?;
    let serial = cert[serial_start + serial_h..serial_start + serial_h + serial_l].to_vec();

    // signature AlgorithmIdentifier
    idx += 1;
    // issuer Name
    idx += 1;
    let (issuer_tag, issuer_start, issuer_total) = tbs[idx];
    if issuer_tag != 0x30 {
        return Err(CryptolineError::CertificateError(
            "issuer: expected SEQUENCE".to_string(),
        ));
    }
    let issuer = element(cert, issuer_start, issuer_total);

    // validity
    idx += 1;
    // subject Name
    idx += 1;
    let (subject_tag, subject_start, subject_total) = tbs[idx];
    if subject_tag != 0x30 {
        return Err(CryptolineError::CertificateError(
            "subject: expected SEQUENCE".to_string(),
        ));
    }
    let subject = element(cert, subject_start, subject_total);

    // subjectPublicKeyInfo
    idx += 1;
    let (spki_tag, spki_start, spki_total) = tbs[idx];
    if spki_tag != 0x30 {
        return Err(CryptolineError::CertificateError(
            "subjectPublicKeyInfo: expected SEQUENCE".to_string(),
        ));
    }
    let spki_h = read_tlv(cert, spki_start)?.1;
    let spki_children = children(cert, spki_start + spki_h, spki_start + spki_total)?;
    if spki_children.len() < 2 {
        return Err(CryptolineError::CertificateError(
            "subjectPublicKeyInfo: no BIT STRING".to_string(),
        ));
    }
    let (bit_tag, bit_start, bit_total) = spki_children[1];
    if bit_tag != 0x03 {
        return Err(CryptolineError::CertificateError(
            "subjectPublicKey: expected BIT STRING".to_string(),
        ));
    }
    let bit_h = read_tlv(cert, bit_start)?.1;
    let bit_value = &cert[bit_start + bit_h..bit_start + bit_total];

    let public_key = extract_gost_point(bit_value).ok_or_else(|| {
        CryptolineError::CertificateError("GOST public key not found".to_string())
    })?;

    Ok(CertParts {
        serial,
        issuer,
        subject,
        public_key,
    })
}

/// BIT STRING содержит OCTET STRING (04 40) с 64 байтами точки.
fn extract_gost_point(bit_value: &[u8]) -> Option<Vec<u8>> {
    // bit_value[0] — число неиспользуемых бит.
    let body = if bit_value.is_empty() { bit_value } else { &bit_value[1..] };
    if body.len() >= 2 && body[0] == 0x04 && body[1] == 0x40 {
        return Some(body[2..66].to_vec());
    }
    // Запасной вариант: ищем 04 40 внутри.
    for i in 0..body.len().saturating_sub(2) {
        if body[i] == 0x04 && body[i + 1] == 0x40 && i + 66 <= body.len() {
            return Some(body[i + 2..i + 66].to_vec());
        }
    }
    if body.len() >= 64 {
        return Some(body[body.len() - 64..].to_vec());
    }
    None
}

/// Декодирует OID из содержимого (без тега/длины) в строку.
fn decode_oid(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let mut parts = vec![
        (bytes[0] / 40).to_string(),
        (bytes[0] % 40).to_string(),
    ];
    let mut i = 1;
    while i < bytes.len() {
        let mut v: u64 = 0;
        loop {
            if i >= bytes.len() {
                return None;
            }
            let b = bytes[i];
            i += 1;
            v = (v << 7) | (b & 0x7f) as u64;
            if b & 0x80 == 0 {
                break;
            }
        }
        parts.push(v.to_string());
    }
    Some(parts.join("."))
}

/// Значение строкового атрибута DN (UTF8String/PrintableString/TeletexString).
fn string_value(data: &[u8], pos: usize, total: usize) -> Option<String> {
    let (tag, h, l) = read_tlv(data, pos).ok()?;
    let bytes = data.get(pos + h..pos + h + l)?;
    let _ = total;
    if tag == 0x1E {
        // BMPString (UTF-16BE)
        let units: Vec<u16> = bytes
            .chunks(2)
            .map(|c| ((c[0] as u16) << 8) | *c.get(1).unwrap_or(&0) as u16)
            .collect();
        return String::from_utf16(&units).ok();
    }
    // UTF8String / PrintableString / IA5String / TeletexString
    String::from_utf8(bytes.to_vec()).ok()
}

/// Ищет значение атрибута в имени (например, "2.5.4.4" — фамилия).
pub fn subject_attribute(name_der: &[u8], oid: &str) -> Option<String> {
    let (tag, h, l) = read_tlv(name_der, 0).ok()?;
    if tag != 0x30 {
        return None;
    }
    let rdns = children(name_der, h, h + l).ok()?;
    for (set_tag, set_start, set_total) in rdns {
        if set_tag != 0x31 {
            continue;
        }
        let set_h = read_tlv(name_der, set_start).ok()?.1;
        let atvs = children(name_der, set_start + set_h, set_start + set_total).ok()?;
        for (atv_tag, atv_start, atv_total) in atvs {
            if atv_tag != 0x30 {
                continue;
            }
            let atv_h = read_tlv(name_der, atv_start).ok()?.1;
            let parts =
                children(name_der, atv_start + atv_h, atv_start + atv_total).ok()?;
            if parts.len() < 2 {
                continue;
            }
            let (oid_tag, oid_start, oid_total) = parts[0];
            if oid_tag != 0x06 {
                continue;
            }
            let oid_h = read_tlv(name_der, oid_start).ok()?.1;
            let oid_bytes = &name_der[oid_start + oid_h..oid_start + oid_total];
            if decode_oid(oid_bytes).as_deref() == Some(oid) {
                let (_, val_start, val_total) = parts[1];
                return string_value(name_der, val_start, val_total);
            }
        }
    }
    None
}

/// Фамилия владельца сертификата (SURNAME, OID 2.5.4.4).
pub fn subject_surname(name_der: &[u8]) -> Option<String> {
    subject_attribute(name_der, "2.5.4.4")
}

/// Владелец для имени файла подписи: «Фамилия_ИО» (например, «Черней_ИВ»).
///
/// Фамилия пишется полностью с заглавной буквы, имя и отчество — только
/// первыми буквами. Если в сертификате нет ФИО (организация), берётся CN.
pub fn subject_owner(name_der: &[u8]) -> Option<String> {
    let surname = subject_attribute(name_der, "2.5.4.4");
    let given = subject_attribute(name_der, "2.5.4.42");
    let cn = subject_attribute(name_der, "2.5.4.3");

    let owner = match (surname, given) {
        (Some(sn), Some(gn)) => {
            let sn = title_case(&sn);
            let io = initials(&gn);
            if io.is_empty() {
                sn
            } else {
                format!("{}_{}", sn, io)
            }
        }
        (Some(sn), None) => {
            let sn = title_case(&sn);
            // В CN принят порядок «Фамилия Имя Отчество» — берём всё после фамилии.
            let rest = cn
                .as_deref()
                .map(|cn| {
                    let words: Vec<&str> = cn.split_whitespace().collect();
                    if words.len() > 1 {
                        words[1..].join(" ")
                    } else {
                        String::new()
                    }
                })
                .unwrap_or_default();
            let io = initials(&rest);
            if io.is_empty() {
                sn
            } else {
                format!("{}_{}", sn, io)
            }
        }
        (None, Some(gn)) => {
            let sn = cn
                .as_deref()
                .and_then(|cn| cn.split_whitespace().next())
                .map(title_case)
                .unwrap_or_default();
            let io = initials(&gn);
            if sn.is_empty() {
                return None;
            }
            if io.is_empty() {
                sn
            } else {
                format!("{}_{}", sn, io)
            }
        }
        (None, None) => {
            // Организация: используем CN без кавычек, пробелы — подчёркивания.
            let cn = cn?;
            let cleaned: Vec<String> = cn
                .replace('"', "")
                .split_whitespace()
                .map(|w| w.to_string())
                .collect();
            let joined = cleaned.join("_");
            let sanitized = sanitize_file_part(&joined);
            if sanitized.is_empty() {
                return None;
            }
            sanitized
        }
    };

    Some(owner)
}

/// «ЧЕРНЕЙ» → «Черней», «МАК-ДОНАЛЬД» → «Мак-Дональд».
fn title_case(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut capitalize = true;
    for ch in value.trim().chars() {
        if ch.is_alphabetic() {
            if capitalize {
                out.extend(ch.to_uppercase());
                capitalize = false;
            } else {
                out.extend(ch.to_lowercase());
            }
        } else {
            out.push(ch);
            if ch == '-' || ch == ' ' {
                capitalize = true;
            }
        }
    }
    out.trim_matches('"').trim().to_string()
}

/// «Иван Валериянович» → «ИВ».
fn initials(value: &str) -> String {
    let mut out = String::new();
    for word in value.split_whitespace() {
        if let Some(ch) = word.chars().find(|c| c.is_alphabetic()) {
            out.extend(ch.to_uppercase());
            if out.chars().count() >= 2 {
                break;
            }
        }
    }
    out
}

/// Убирает из части имени символы, недопустимые в имени файла Windows.
fn sanitize_file_part(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut last_underscore = false;
    for ch in value.chars() {
        let ch = if matches!(ch, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
            '_'
        } else if ch.is_whitespace() {
            '_'
        } else {
            ch
        };
        if ch == '_' {
            if last_underscore {
                continue;
            }
            last_underscore = true;
        } else {
            last_underscore = false;
        }
        out.push(ch);
    }
    out.trim_matches(|c| c == '_' || c == '.').to_string()
}

impl CertParts {
    /// Полное имя субъекта одной строкой (для логов).
    pub fn subject_string(&self) -> String {
        let mut out = Vec::new();
        if let Some(sn) = subject_attribute(&self.subject, "2.5.4.4") {
            out.push(format!("SURNAME={}", sn));
        }
        if let Some(gn) = subject_attribute(&self.subject, "2.5.4.42") {
            out.push(format!("GIVENNAME={}", gn));
        }
        if let Some(cn) = subject_attribute(&self.subject, "2.5.4.3") {
            out.push(format!("CN={}", cn));
        }
        out.join(", ")
    }
}
