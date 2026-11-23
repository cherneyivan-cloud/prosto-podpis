/// Типы ошибок для криптолинии
use std::fmt;

#[derive(Debug, Clone)]
pub enum CryptolineError {
    /// Ошибка парсинга DER
    DerParseError(String),
    
    /// Ошибка парсинга CMS/PKCS#7
    CmsParseError(String),
    
    /// Ошибка декодирования Base64
    Base64Error(String),
    
    /// Ошибка работы с сертификатом
    CertificateError(String),
    
    /// Ошибка криптографической операции
    CryptoError(String),
    
    /// Ошибка работы с файлом
    FileError(String),
    
    /// Ошибка конфигурации
    ConfigError(String),
    
    /// Неизвестная ошибка
    Other(String),
    
    /// Данные имеют неверный формат
    InvalidData(String),
    
    /// Функция не реализована
    Unimplemented(String),
}

impl fmt::Display for CryptolineError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CryptolineError::DerParseError(msg) => write!(f, "DER parse error: {}", msg),
            CryptolineError::CmsParseError(msg) => write!(f, "CMS parse error: {}", msg),
            CryptolineError::Base64Error(msg) => write!(f, "Base64 decode error: {}", msg),
            CryptolineError::CertificateError(msg) => write!(f, "Certificate error: {}", msg),
            CryptolineError::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
            CryptolineError::FileError(msg) => write!(f, "File error: {}", msg),
            CryptolineError::ConfigError(msg) => write!(f, "Config error: {}", msg),
            CryptolineError::Other(msg) => write!(f, "Error: {}", msg),
            CryptolineError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            CryptolineError::Unimplemented(msg) => write!(f, "Not implemented: {}", msg),
        }
    }
}

impl std::error::Error for CryptolineError {}

/// Результат операции
pub type Result<T> = std::result::Result<T, CryptolineError>;
