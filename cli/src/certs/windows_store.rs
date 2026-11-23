//! Доступ к хранилищу сертификатов Windows (CryptoAPI)

#[cfg(target_os = "windows")]
pub use windows_impl::*;

#[cfg(not(target_os = "windows"))]
pub use stub_impl::*;

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::super::{CertStore, CertificateInfo};
    use std::ptr;

    pub struct WindowsCertStore {
        store_handle: *mut std::ffi::c_void,
    }

    impl WindowsCertStore {
        pub fn open(_store_name: &str) -> Result<Self, String> {
            // На полной реализации здесь будут WinAPI вызовы
            // CertOpenSystemStore, CertEnumCertificatesInStore, и т.д.
            // Для Wave 3 — заглушка, которая читает из тестовых файлов
            Ok(WindowsCertStore {
                store_handle: ptr::null_mut(),
            })
        }
    }

    impl CertStore for WindowsCertStore {
        fn list_certificates(&self) -> Result<Vec<CertificateInfo>, String> {
            // Заглушка: возвращаем пустой список
            // Wave 3 реализует полную интеграцию с WinAPI
            Ok(Vec::new())
        }

        fn get_certificate(&self, _thumbprint: &str) -> Result<CertificateInfo, String> {
            Err("Not implemented in Wave 3".to_string())
        }
    }

    impl Drop for WindowsCertStore {
        fn drop(&mut self) {
            // Закрытие хранилища при удалении
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod stub_impl {
    use super::super::{CertStore, CertificateInfo};

    pub struct WindowsCertStore;

    impl WindowsCertStore {
        pub fn open(_store_name: &str) -> Result<Self, String> {
            Err("Windows certificate store not available on this platform".to_string())
        }
    }

    impl CertStore for WindowsCertStore {
        fn list_certificates(&self) -> Result<Vec<CertificateInfo>, String> {
            Err("Not available on this platform".to_string())
        }

        fn get_certificate(&self, _thumbprint: &str) -> Result<CertificateInfo, String> {
            Err("Not available on this platform".to_string())
        }
    }
}
