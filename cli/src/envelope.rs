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

    #[link(name = "advapi32")]
    extern "system" {
        fn CryptAcquireContextA(
            ph_prov: *mut Handle,
            sz_container: *const c_char,
            sz_provider: *const c_char,
            dw_prov_type: u32,
            dw_flags: u32,
        ) -> i32;
        fn CryptReleaseContext(h_prov: Handle, dw_flags: u32) -> i32;
    }

    fn last_error() -> String {
        std::io::Error::last_os_error().to_string()
    }

    /// Определяет, каким алгоритмом реально зашифровано содержимое.
    fn detect_cipher(der: &[u8]) -> Cipher {
        const KUZ: [u8; 10] = [0x06, 0x08, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x05, 0x02];
        const MAG: [u8; 10] = [0x06, 0x08, 0x2A, 0x85, 0x03, 0x07, 0x01, 0x01, 0x05, 0x01];
        let tail = &der[der.len().saturating_sub(600)..];
        if tail.windows(KUZ.len()).any(|w| w == KUZ) {
            Cipher::Kuznyechik
        } else if tail.windows(MAG.len()).any(|w| w == MAG) {
            Cipher::Magma
        } else {
            Cipher::Gost28147
        }
    }

    fn encrypt_with(
        certs: &[PCertContext],
        oid: &str,
        params: &mut [u8],
        data: &[u8],
        prov: Handle,
    ) -> std::result::Result<Vec<u8>, String> {
        let oid_c = CString::new(oid).map_err(|e| e.to_string())?;
        let para = CryptEncryptMessagePara {
            cb_size: std::mem::size_of::<CryptEncryptMessagePara>() as u32,
            dw_msg_encoding_type: X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            h_crypt_prov: 0,
            content_encryption_algorithm: CryptAlgorithmIdentifier {
                psz_obj_id: oid_c.as_ptr(),
                parameters: CryptDataBlob {
                    cb_data: params.len() as u32,
                    pb_data: if params.is_empty() {
                        std::ptr::null_mut()
                    } else {
                        params.as_mut_ptr()
                    },
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

        let mut contexts: Vec<PCertContext> = Vec::new();
        for der in certs {
            let ctx = unsafe {
                CertCreateCertificateContext(X509_ASN_ENCODING, der.as_ptr(), der.len() as u32)
            };
            if ctx.is_null() {
                for c in &contexts {
                    unsafe { CertFreeCertificateContext(*c) };
                }
                return Err(CryptolineError::CertificateError(format!(
                    "сертификат получателя не разобран: {}",
                    last_error()
                )));
            }
            contexts.push(ctx);
        }

        // Прогреваем провайдер КриптоПро: без него CryptoAPI не создаст
        // сессионный ключ для ГОСТ-алгоритма.
        let mut prov: Handle = 0;
        let provider = CString::new("Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider")
            .ok();
        unsafe {
            if CryptAcquireContextA(
                &mut prov,
                std::ptr::null(),
                provider
                    .as_ref()
                    .map(|c| c.as_ptr())
                    .unwrap_or(std::ptr::null()),
                PROV_GOST_2012_256,
                CRYPT_VERIFYCONTEXT | CRYPT_SILENT,
            ) == 0
            {
                prov = 0;
            }
        }

        let mut last = String::new();
        let mut result = None;
        for cipher in [Cipher::Kuznyechik, Cipher::Magma, Cipher::Gost28147] {
            // Параметры алгоритма: SEQUENCE { IV OCTET STRING }.
            let iv_len = match cipher {
                Cipher::Kuznyechik => 16,
                _ => 8,
            };
            let mut iv = vec![0u8; iv_len];
            iv[0] = 0x5A; // любой ненулевой IV, CSP всё равно работает в CBC
            let mut params = if cipher == Cipher::Kuznyechik {
                // Для Кузнечика параметры — OCTET STRING с IV.
                let mut p = vec![0x04, iv_len as u8];
                p.extend_from_slice(&iv);
                p
            } else {
                let mut p = vec![0x30, 0x04 + iv_len as u8, 0x04, iv_len as u8];
                p.extend_from_slice(&iv);
                p
            };
            let mut params = params.into_boxed_slice();

            match encrypt_with(&contexts, cipher.oid(), &mut params, &data, prov) {
                Ok(mut der) => {
                    let real = detect_cipher(&der);
                    if real != cipher {
                        // CSP подменил алгоритм — не выдаём одно за другое.
                        der.clear();
                        last = format!(
                            "{}: CSP не поддерживает этот алгоритм",
                            cipher.title()
                        );
                        continue;
                    }
                    result = Some((cipher, der));
                    break;
                }
                Err(e) => last = format!("{}: {}", cipher.title(), e),
            }
        }

        unsafe {
            if prov != 0 {
                CryptReleaseContext(prov, 0);
            }
            for c in &contexts {
                CertFreeCertificateContext(*c);
            }
        }

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
