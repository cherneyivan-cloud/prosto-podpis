/// Криптолиния на Rust - Парсер и создание УКЭП
/// 
/// Архитектура:
/// - Волна 1 (Claude Opus 5.5): Парсер DER/CMS
/// - Волна 2 (Deepseek Flash): GOST криптография  
/// - Волна 3 (Claude Opus 5.5): GUI интеграция
/// - Волна 4 (Deepseek Flash): Тесты и оптимизация

pub mod error;
pub mod der;
pub mod cms;
pub mod crypto;
pub mod certs;
pub mod csp;
pub mod envelope;

pub use error::{CryptolineError, Result};
pub use der::{DerParser, DerValue, DerElement};
pub use cms::{CmsSignedData, Certificate, SignerInfo};

/// Версия приложения
pub const VERSION: &str = "0.1.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
