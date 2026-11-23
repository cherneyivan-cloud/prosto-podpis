//! Работа с хранилищами сертификатов

pub mod windows_store;

pub use windows_store::WindowsCertStore;

/// Информация о сертификате
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// DER-кодированный сертификат
    pub der: Vec<u8>,
    /// Отпечаток (SHA-1)
    pub thumbprint: String,
    /// Субъект (CN)
    pub subject: String,
    /// Издатель
    pub issuer: String,
    /// Открытый ключ (для ГОСТ — 64 байта)
    pub public_key: Vec<u8>,
}

/// Интерфейс для хранилища сертификатов
pub trait CertStore {
    /// Получить список доступных сертификатов
    fn list_certificates(&self) -> Result<Vec<CertificateInfo>, String>;
    
    /// Получить сертификат по отпечатку
    fn get_certificate(&self, thumbprint: &str) -> Result<CertificateInfo, String>;
}
