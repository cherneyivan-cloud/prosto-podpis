/// CMS SignedData структура
/// Основная структура для цифровой подписи по стандарту CMS/PKCS#7

use crate::error::Result;
use crate::der::{DerValue, DerElement, DerTag};

/// CMS SignedData
#[derive(Debug, Clone)]
pub struct CmsSignedData {
    /// Версия (1 или 3)
    pub version: u32,
    
    /// Алгоритмы хеширования
    pub digest_algorithms: Vec<String>,
    
    /// Информация о содержимом
    pub content_info: ContentInfo,
    
    /// Сертификаты (опционально)
    pub certificates: Vec<Vec<u8>>,
    
    /// Информация подписавших
    pub signer_infos: Vec<crate::cms::SignerInfo>,
}

/// ContentInfo структура
#[derive(Debug, Clone)]
pub struct ContentInfo {
    /// Тип содержимого (OID)
    pub content_type: String,
    
    /// Содержимое (опционально, для открепленных подписей)
    pub content: Option<Vec<u8>>,
}

impl CmsSignedData {
    /// Парсит CMS SignedData из DER элемента
    pub fn from_der(element: &DerElement) -> Result<Self> {
        // Проверяем, что это SEQUENCE
        if !matches!(element.tag, DerTag::Sequence) {
            return Err(crate::error::CryptolineError::CmsParseError(
                "Expected SEQUENCE for SignedData".to_string(),
            ));
        }
        
        // TODO: Реальный парсинг
        Ok(CmsSignedData {
            version: 1,
            digest_algorithms: vec!["1.2.643.7.1.1.2.2".to_string()], // GOST R 34.11-2012
            content_info: ContentInfo {
                content_type: "1.2.840.113549.1.7.1".to_string(),
                content: None,
            },
            certificates: Vec::new(),
            signer_infos: Vec::new(),
        })
    }
    
    /// Проверяет, что это подпись GOST
    pub fn is_gost_signature(&self) -> bool {
        self.digest_algorithms.iter().any(|alg| {
            alg.starts_with("1.2.643") // GOST OID
        })
    }
    
    /// Получает основной алгоритм подписи
    pub fn primary_algorithm(&self) -> Option<&str> {
        self.digest_algorithms.first().map(|s| s.as_str())
    }
}

impl Default for CmsSignedData {
    fn default() -> Self {
        CmsSignedData {
            version: 1,
            digest_algorithms: Vec::new(),
            content_info: ContentInfo {
                content_type: String::new(),
                content: None,
            },
            certificates: Vec::new(),
            signer_infos: Vec::new(),
        }
    }
}
