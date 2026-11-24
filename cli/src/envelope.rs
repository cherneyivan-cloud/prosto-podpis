//! Шифрование документов для получателей (CMS EnvelopedData).
//!
//! Ключ и параметры шифрования создаёт КриптоПро CSP через CryptoAPI:
//! содержимое шифруется по ГОСТ Р 34.12-2015, ключ заворачивается на
//! открытый ключ каждого получателя (ГОСТ Р 34.10-2012).

use crate::error::{CryptolineError, Result};
use std::path::Path;

/// Варианты шифрования содержимого.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    /// ГОСТ Р 34.12-2015 «Кузнечик» (по умолчанию).
    Kuznyechik,
    /// ГОСТ Р 34.12-2015 «Магма».
    Magma,
    /// ГОСТ 28147-89 — запасной вариант для старых CSP.
    Gost28147,
}

impl Cipher {
    pub fn oid(self) -> &'static str {
        match self {
            Cipher::Kuznyechik => "1.2.643.7.1.1.5.2",
            Cipher::Magma => "1.2.643.7.1.1.5.1",
            Cipher::Gost28147 => "1.2.643.2.2.21",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Cipher::Kuznyechik => "Кузнечик (ГОСТ Р 34.12-2015)",
            Cipher::Magma => "Магма (ГОСТ Р 34.12-2015)",
            Cipher::Gost28147 => "ГОСТ 28147-89",
        }
    }
}

/// Сведения о получившемся контейнере.
#[derive(Clone, Debug)]
pub struct EnvelopeInfo {
    pub cipher: &'static str,
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::ffi::CString;
    use std::os::raw::{c_char, c_void};

    type Handle = usize;
    type PCertContext = *mut c_void;

    const X509_ASN_ENCODING: u32 = 0x0000_0001;
    const PKCS_7_ASN_ENCODING: u32 = 0x0001_0000;
    const PROV_GOST_2012_256: u32 = 80;
    const CRYPT_VERIFYCONTEXT: u32 = 0xF000_0000;
    const CRYPT_SILENT: u32 = 0x0000_0040;

    #[repr(C)]
    struct CryptDataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    #[repr(C)]
    struct CryptAlgorithmIdentifier {
        psz_obj_id: *const c_char,
        parameters: CryptDataBlob,
    }

    #[repr(C)]
    struct CryptEncryptMessagePara {
        cb_size: u32,
        dw_msg_encoding_type: u32,
        h_crypt_prov: Handle,
        content_encryption_algorithm: CryptAlgorithmIdentifier,
        pv_encryption_aux_info: *mut c_void,
        dw_flags: u32,
        dw_inner_content_type: u32,
    }

    #[repr(C)]
    struct CryptDecryptMessagePara {
        cb_size: u32,
        dw_msg_encoding_type: u32,
        c_msg_cert_stores: u32,
        rg_msg_cert_stores: *mut *mut c_void,
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptEncryptMessage(
            p_encrypt_para: *const CryptEncryptMessagePara,
            c_recipient_cert: u32,
            rgp_recipient_cert: *const PCertContext,
            pb_to_be_encrypted: *const u8,
            cb_to_be_encrypted: u32,
            pb_encrypted_blob: *mut u8,
            pcb_encrypted_blob: *mut u32,
        ) -> i32;
        fn CryptDecryptMessage(
            p_decrypt_para: *const CryptDecryptMessagePara,
            pb_encrypted_blob: *const u8,
            cb_encrypted_blob: u32,
            pb_decrypted_blob: *mut u8,
            pcb_decrypted_blob: *mut u32,
            pp_xchg_cert: *mut PCertContext,
        ) -> i32;
        fn CertCreateCertificateContext(enc: u32, pb: *const u8, cb: u32) -> PCertContext;
        fn CertFreeCertificateContext(ctx: PCertContext) -> i32;
    }

    fn last_error() -> String {
        std::io::Error::last_os_error().to_string()
    }

    /// Владелец контекста сертификата: освобождает его при выходе из области.
    struct CertCtx(PCertContext);

    impl CertCtx {
        fn create(der: &[u8]) -> Option<Self> {
            let ctx =
                unsafe { CertCreateCertificateContext(X509_ASN_ENCODING, der.as_ptr(), der.len() as u32) };
            if ctx.is_null() {
                None
            } else {
                Some(CertCtx(ctx))
            }
        }
    }

    impl Drop for CertCtx {
        fn drop(&mut self) {
            unsafe { CertFreeCertificateContext(self.0) };
        }
    }

    // --- Разбор контейнера: какой алгоритм реально применил CSP ---------------

    /// Читает TLV: (тег, смещение значения, длина значения).
    fn tlv(buf: &[u8], pos: usize) -> Option<(u8, usize, usize)> {
        if pos + 2 > buf.len() {
            return None;
        }
        let tag = buf[pos];
        let first = buf[pos + 1];
        let (len, header) = if first & 0x80 == 0 {
            (first as usize, 2usize)
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 || pos + 2 + n > buf.len() {
                return None;
            }
            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | buf[pos + 2 + i] as usize;
            }
            (len, 2 + n)
        };
        let start = pos + header;
        if start + len > buf.len() {
            return None;
        }
        Some((tag, start, len))
    }

    /// Достаёт OID алгоритма шифрования содержимого из CMS EnvelopedData.
    ///
    /// Путь: SEQUENCE → [0] → SEQUENCE → version, recipientInfos,
    /// encryptedContentInfo { contentType, algorithm { OID, params }, … }.
    fn content_cipher_oid(der: &[u8]) -> Option<Vec<u8>> {
        let (tag, start, _) = tlv(der, 0)?;
        if tag != 0x30 {
            return None;
        }
        let (t1, s1, l1) = tlv(der, start)?; // OID envelopedData
        if t1 != 0x06 {
            return None;
        }
        let (t2, s2, _) = tlv(der, s1 + l1)?; // [0] EXPLICIT
        if t2 != 0xA0 {
            return None;
        }
        let (t3, s3, _) = tlv(der, s2)?; // SEQUENCE EnvelopedData
        if t3 != 0x30 {
            return None;
        }
        let (_, s4, l4) = tlv(der, s3)?; // INTEGER version
        let (t5, s5, l5) = tlv(der, s4 + l4)?; // SET recipientInfos
        if t5 != 0x31 {
            return None;
        }
        let (t6, s6, _) = tlv(der, s5 + l5)?; // SEQUENCE encryptedContentInfo
        if t6 != 0x30 {
            return None;
        }
        let (_, s7, l7) = tlv(der, s6)?; // OID contentType
        let (t8, s8, _) = tlv(der, s7 + l7)?; // SEQUENCE algorithm
        if t8 != 0x30 {
            return None;
        }
        let (t9, s9, l9) = tlv(der, s8)?; // OID алгоритма
        if t9 != 0x06 {
            return None;
        }
        Some(der[s9..s9 + l9].to_vec())
    }

    /// Определяет алгоритм по OID из контейнера (без эвристик по байтам).
    fn detect_cipher(der: &[u8]) -> Option<Cipher> {
        let oid = content_cipher_oid(der)?;
        match oid.as_slice() {
            [0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x05, 0x02] => Some(Cipher::Kuznyechik),
            [0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x05, 0x01] => Some(Cipher::Magma),
            [0x2A, 0x85, 0x03, 0x02, 0x02, 0x15] => Some(Cipher::Gost28147),
            _ => None,
        }
    }

    fn encrypt_with(
        certs: &[PCertContext],
        oid: &str,
        data: &[u8],
    ) -> std::result::Result<Vec<u8>, String> {
        let oid_c = CString::new(oid).map_err(|e| e.to_string())?;
        let para = CryptEncryptMessagePara {
            cb_size: std::mem::size_of::<CryptEncryptMessagePara>() as u32,
            dw_msg_encoding_type: X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            h_crypt_prov: 0,
            content_encryption_algorithm: CryptAlgorithmIdentifier {
                psz_obj_id: oid_c.as_ptr(),
                // Параметры (IV) генерирует сам CSP — фиксированный IV нельзя.
                parameters: CryptDataBlob {
                    cb_data: 0,
                    pb_data: std::ptr::null_mut(),
                },
            },
            pv_encryption_aux_info: std::ptr::null_mut(),
            dw_flags: 0,
            dw_inner_content_type: 0,
        };

        let mut len = 0u32;
        let ok = unsafe {
            CryptEncryptMessage(
                &para,
                certs.len() as u32,
                certs.as_ptr(),
                data.as_ptr(),
                data.len() as u32,
                std::ptr::null_mut(),
                &mut len,
            )
        };
        if ok == 0 || len == 0 {
            return Err(last_error());
        }

        let mut buf = vec![0u8; len as usize];
        let ok = unsafe {
            CryptEncryptMessage(
                &para,
                certs.len() as u32,
                certs.as_ptr(),
                data.as_ptr(),
                data.len() as u32,
                buf.as_mut_ptr(),
                &mut len,
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        buf.truncate(len as usize);
        Ok(buf)
    }

    pub fn encrypt_file(input: &Path, certs: &[Vec<u8>], out: &Path) -> Result<EnvelopeInfo> {
        if certs.is_empty() {
            return Err(CryptolineError::CertificateError(
                "не выбран ни один сертификат получателя".to_string(),
            ));
        }

        let data = std::fs::read(input)
            .map_err(|e| CryptolineError::FileError(format!("{}: {}", input.display(), e)))?;

        let mut guards: Vec<CertCtx> = Vec::new();
        for der in certs {
            let guard = CertCtx::create(der).ok_or_else(|| {
                CryptolineError::CertificateError(format!(
                    "сертификат получателя не разобран: {}",
                    last_error()
                ))
            })?;
            guards.push(guard);
        }
        let contexts: Vec<PCertContext> = guards.iter().map(|g| g.0).collect();

        let mut last = String::new();
        let mut result = None;
        for cipher in [Cipher::Kuznyechik, Cipher::Magma, Cipher::Gost28147] {
            match encrypt_with(&contexts, cipher.oid(), &data) {
                Ok(der) => match detect_cipher(&der) {
                    Some(real) if real == cipher => {
                        result = Some((cipher, der));
                        break;
                    }
                    Some(_) => {
                        // CSP подменил алгоритм — не выдаём одно за другое.
                        last = format!("{}: CSP не поддерживает этот алгоритм", cipher.title());
                    }
                    None => {
                        last = format!("{}: не удалось определить алгоритм в контейнере", cipher.title());
                    }
                },
                Err(e) => last = format!("{}: {}", cipher.title(), e),
            }
        }
        drop(guards);

        let (cipher, der) = result.ok_or_else(|| {
            CryptolineError::CertificateError(format!("шифрование не удалось ({})", last))
        })?;

        std::fs::write(out, &der)
            .map_err(|e| CryptolineError::FileError(format!("{}: {}", out.display(), e)))?;

        Ok(EnvelopeInfo {
            cipher: cipher.title(),
        })
    }

    pub fn decrypt_file(input: &Path, out: &Path) -> Result<()> {
        let data = std::fs::read(input)
            .map_err(|e| CryptolineError::FileError(format!("{}: {}", input.display(), e)))?;

        let para = CryptDecryptMessagePara {
            cb_size: std::mem::size_of::<CryptDecryptMessagePara>() as u32,
            dw_msg_encoding_type: X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            c_msg_cert_stores: 0,
            rg_msg_cert_stores: std::ptr::null_mut(),
        };

        let mut len = 0u32;
        unsafe {
            CryptDecryptMessage(
                &para,
                data.as_ptr(),
                data.len() as u32,
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
            )
        };
        if len == 0 {
            return Err(CryptolineError::CertificateError(format!(
                "не удалось расшифровать: {}",
                last_error()
            )));
        }

        let mut buf = vec![0u8; len as usize];
        let ok = unsafe {
            CryptDecryptMessage(
                &para,
                data.as_ptr(),
                data.len() as u32,
                buf.as_mut_ptr(),
                &mut len,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(CryptolineError::CertificateError(format!(
                "не удалось расшифровать: {}",
                last_error()
            )));
        }
        buf.truncate(len as usize);

        std::fs::write(out, buf)
            .map_err(|e| CryptolineError::FileError(format!("{}: {}", out.display(), e)))?;
        Ok(())
    }
}

#[cfg(not(windows))]
mod win {
    use super::*;

    pub fn encrypt_file(_: &Path, _: &[Vec<u8>], _: &Path) -> Result<EnvelopeInfo> {
        Err(CryptolineError::CryptoError(
            "шифрование поддерживается только в Windows".to_string(),
        ))
    }

    pub fn decrypt_file(_: &Path, _: &Path) -> Result<()> {
        Err(CryptolineError::CryptoError(
            "расшифровка поддерживается только в Windows".to_string(),
        ))
    }
}

pub use win::{decrypt_file, encrypt_file};
