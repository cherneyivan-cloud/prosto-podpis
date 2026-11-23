//! Подпись через CryptoPro CSP (CryptoAPI).
//!
//! Оригинальный CryptoLine.exe тоже не реализует ГОСТ сам, а обращается
//! к провайдеру `Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider`
//! (в его строках есть PROV_GOST_2012_256 и KeyContainerName).
//!
//! Поэтому и мы подписываем хеш через CSP: закрытый ключ остаётся
//! в защищённом контейнере и не копируется в нашу программу.

use crate::error::{CryptolineError, Result};

#[cfg(windows)]
mod win {
    use super::{CryptolineError, Result};
    use std::ffi::CString;
    use std::os::raw::{c_char, c_void};

    type Handle = usize;

    const PROV_GOST_2012_256: u32 = 80;
    const CRYPT_SILENT: u32 = 0x0000_0040;
    const CRYPT_VERIFYCONTEXT: u32 = 0xF000_0000;
    const CRYPT_FIRST: u32 = 0x0000_0001;
    const PP_ENUMCONTAINERS: u32 = 2;
    const HP_HASHVAL: u32 = 2;
    const AT_KEYEXCHANGE: u32 = 1;
    const AT_SIGNATURE: u32 = 2;
    const PUBLICKEYBLOB: u32 = 6;
    const PRIVATEKEYBLOB: u32 = 7;
    const CALG_GR3411_2012_256: u32 = 0x8021;

    #[link(name = "advapi32")]
    extern "system" {
        fn CryptAcquireContextA(
            ph_prov: *mut Handle,
            sz_container: *const c_char,
            sz_provider: *const c_char,
            dw_prov_type: u32,
            dw_flags: u32,
        ) -> i32;
        fn CryptGetProvParam(
            h_prov: Handle,
            dw_param: u32,
            pb_data: *mut u8,
            pdw_data_len: *mut u32,
            dw_flags: u32,
        ) -> i32;
        fn CryptGetUserKey(h_prov: Handle, dw_key_spec: u32, ph_user_key: *mut Handle) -> i32;
        fn CryptExportKey(
            h_key: Handle,
            h_exp_key: Handle,
            dw_blob_type: u32,
            dw_flags: u32,
            pb_data: *mut u8,
            pdw_data_len: *mut u32,
        ) -> i32;
        fn CryptCreateHash(
            h_prov: Handle,
            alg_id: u32,
            h_key: Handle,
            dw_flags: u32,
            ph_hash: *mut Handle,
        ) -> i32;
        fn CryptSetHashParam(h_hash: Handle, dw_param: u32, pb_data: *const u8, dw_flags: u32)
            -> i32;
        fn CryptSignHashA(
            h_hash: Handle,
            dw_key_spec: u32,
            s_description: *const c_char,
            dw_flags: u32,
            pb_signature: *mut u8,
            pdw_sig_len: *mut u32,
        ) -> i32;
        fn CryptDestroyHash(h_hash: Handle) -> i32;
        fn CryptDestroyKey(h_key: Handle) -> i32;
        fn CryptReleaseContext(h_prov: Handle, dw_flags: u32) -> i32;
    }

    fn last_error(what: &str) -> CryptolineError {
        CryptolineError::CryptoError(format!(
            "{}: код ошибки 0x{:08X}",
            what,
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32
        ))
    }

    /// Перечисляет имена контейнеров провайдера (в ANSI/Cp1251).
    pub fn enum_containers(provider: &str) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        let prov = match CString::new(provider) {
            Ok(v) => v,
            Err(_) => return result,
        };
        let mut h_prov: Handle = 0;
        let ok = unsafe {
            CryptAcquireContextA(
                &mut h_prov,
                std::ptr::null(),
                prov.as_ptr(),
                PROV_GOST_2012_256,
                CRYPT_VERIFYCONTEXT | CRYPT_SILENT,
            )
        };
        if ok == 0 {
            return result;
        }

        let mut flags = CRYPT_FIRST;
        loop {
            let mut len: u32 = 0;
            unsafe {
                CryptGetProvParam(h_prov, PP_ENUMCONTAINERS, std::ptr::null_mut(), &mut len, flags);
            }
            if len == 0 {
                break;
            }
            let mut buf = vec![0u8; len as usize];
            let ok = unsafe {
                CryptGetProvParam(
                    h_prov,
                    PP_ENUMCONTAINERS,
                    buf.as_mut_ptr(),
                    &mut len,
                    flags,
                )
            };
            if ok == 0 {
                break;
            }
            flags = 0;
            if let Some(nul) = buf.iter().position(|&b| b == 0) {
                buf.truncate(nul);
            }
            if !buf.is_empty() {
                result.push(buf);
            }
        }
        unsafe {
            CryptReleaseContext(h_prov, 0);
        }
        result
    }

    /// Открывает контейнер по имени. Возвращает дескриптор провайдера.
    pub fn acquire_container(provider: &str, container: &[u8]) -> Option<Handle> {
        let prov = CString::new(provider).ok()?;
        let cont = CString::new(container).ok()?;
        let mut h_prov: Handle = 0;
        let ok = unsafe {
            CryptAcquireContextA(
                &mut h_prov,
                cont.as_ptr(),
                prov.as_ptr(),
                PROV_GOST_2012_256,
                CRYPT_SILENT,
            )
        };
        if ok != 0 {
            Some(h_prov)
        } else {
            None
        }
    }

    pub fn get_user_key(h_prov: Handle) -> Option<(Handle, u32)> {
        for spec in [AT_KEYEXCHANGE, AT_SIGNATURE] {
            let mut h_key: Handle = 0;
            let ok = unsafe { CryptGetUserKey(h_prov, spec, &mut h_key) };
            if ok != 0 {
                return Some((h_key, spec));
            }
        }
        None
    }

    pub fn export_public_key(h_key: Handle) -> Option<Vec<u8>> {
        let mut len: u32 = 0;
        unsafe {
            CryptExportKey(h_key, 0, PUBLICKEYBLOB, 0, std::ptr::null_mut(), &mut len);
        }
        if len == 0 || len > 4096 {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        let ok = unsafe { CryptExportKey(h_key, 0, PUBLICKEYBLOB, 0, buf.as_mut_ptr(), &mut len) };
        if ok == 0 {
            return None;
        }
        buf.truncate(len as usize);
        Some(buf)
    }

    /// Подписывает хеш (32 байта). Возвращает подпись в формате CMS
    /// `s(BE) || r(BE)` (64 байта).
    pub fn sign_hash(h_prov: Handle, key_spec: u32, digest: &[u8]) -> Result<Vec<u8>> {
        let mut h_hash: Handle = 0;
        let ok = unsafe { CryptCreateHash(h_prov, CALG_GR3411_2012_256, 0, 0, &mut h_hash) };
        if ok == 0 {
            return Err(last_error("CryptCreateHash"));
        }
        let ok = unsafe { CryptSetHashParam(h_hash, HP_HASHVAL, digest.as_ptr(), 0) };
        if ok == 0 {
            unsafe { CryptDestroyHash(h_hash) };
            return Err(last_error("CryptSetHashParam"));
        }
        let mut len: u32 = 0;
        unsafe {
            CryptSignHashA(h_hash, key_spec, std::ptr::null(), 0, std::ptr::null_mut(), &mut len);
        }
        if len == 0 {
            unsafe { CryptDestroyHash(h_hash) };
            return Err(last_error("CryptSignHash (размер)"));
        }
        let mut sig = vec![0u8; len as usize];
        let ok = unsafe {
            CryptSignHashA(h_hash, key_spec, std::ptr::null(), 0, sig.as_mut_ptr(), &mut len)
        };
        unsafe { CryptDestroyHash(h_hash) };
        if ok == 0 {
            return Err(last_error("CryptSignHash"));
        }
        sig.truncate(len as usize);
        if sig.len() != 64 {
            return Err(CryptolineError::CryptoError(format!(
                "CSP вернул подпись неожиданной длины: {}",
                sig.len()
            )));
        }
        // CSP отдаёт r(LE) || s(LE); в CMS нужно s(BE) || r(BE).
        sig.reverse();
        Ok(sig)
    }

    pub fn release(provider: Handle, key: Option<Handle>) {
        unsafe {
            if let Some(k) = key {
                CryptDestroyKey(k);
            }
            CryptReleaseContext(provider, 0);
        }
    }
}

/// Список имён провайдеров GOST 2012-256, которые встречаются у CryptoPro.
const PROVIDER_NAMES: &[&str] = &[
    "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider",
    "Crypto-Pro GOST R 34.10-2012 KC1 Strong Cryptographic Service Provider",
    "Crypto-Pro GOST R 34.10-2012 KC2 Strong Cryptographic Service Provider",
];

/// Находит контейнер, открытый ключ которого совпадает с ключом сертификата,
/// и подписывает хеш.
///
/// `public_key` — 64 байта в том виде, как они лежат в сертификате
/// (x ‖ y, little-endian).
pub fn sign_digest(public_key: &[u8], digest: &[u8]) -> Result<Vec<u8>> {
    #[cfg(not(windows))]
    {
        let _ = (public_key, digest);
        return Err(CryptolineError::CryptoError(
            "Подпись через CryptoPro CSP доступна только в Windows".to_string(),
        ));
    }

    #[cfg(windows)]
    {
        if public_key.len() != 64 {
            return Err(CryptolineError::InvalidData(
                "sign_digest: открытый ключ должен быть 64 байта".to_string(),
            ));
        }
        if digest.len() != 32 {
            return Err(CryptolineError::InvalidData(
                "sign_digest: хеш должен быть 32 байта".to_string(),
            ));
        }

        for provider in PROVIDER_NAMES {
            for container in win::enum_containers(provider) {
                let h_prov = match win::acquire_container(provider, &container) {
                    Some(p) => p,
                    None => continue,
                };
                let (h_key, spec) = match win::get_user_key(h_prov) {
                    Some(k) => k,
                    None => {
                        win::release(h_prov, None);
                        continue;
                    }
                };
                let matches = win::export_public_key(h_key)
                    .map(|blob| blob.ends_with(public_key))
                    .unwrap_or(false);
                if matches {
                    let result = win::sign_hash(h_prov, spec, digest);
                    win::release(h_prov, Some(h_key));
                    return result;
                }
                win::release(h_prov, Some(h_key));
            }
        }

        Err(CryptolineError::CryptoError(
            "Не найден ключевой контейнер CryptoPro для этого сертификата. \
             Убедитесь, что CryptoPro CSP установлен, а контейнер закрытого ключа доступен."
                .to_string(),
        ))
    }
}

/// Есть ли в системе контейнер, подходящий к сертификату.
pub fn has_key_for(public_key: &[u8]) -> bool {
    #[cfg(windows)]
    {
        for provider in PROVIDER_NAMES {
            for container in win::enum_containers(provider) {
                if let Some(h_prov) = win::acquire_container(provider, &container) {
                    if let Some((h_key, _)) = win::get_user_key(h_prov) {
                        let matches = win::export_public_key(h_key)
                            .map(|blob| blob.ends_with(public_key))
                            .unwrap_or(false);
                        win::release(h_prov, Some(h_key));
                        if matches {
                            return true;
                        }
                    } else {
                        win::release(h_prov, None);
                    }
                }
            }
        }
        false
    }
    #[cfg(not(windows))]
    {
        let _ = public_key;
        false
    }
}

