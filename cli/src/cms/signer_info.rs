/// SignerInfo структура
/// Информация о подписавшем (сертификат и параметры подписи)

use crate::error::Result;

/// SignerInfo в CMS
#[derive(Debug, Clone)]
pub struct SignerInfo {
    /// Версия (1 или 3)
    pub version: u32,
    
    /// Идентификатор подписавшего (issuer + serial number)
    pub sid: SignerIdentifier,
    
    /// Алгоритм хеширования (OID)
    pub digest_algorithm: String,
    
    /// Подписанные атрибуты
    pub signed_attrs: SignedAttributes,
    
    /// Алгоритм подписи (OID)
    pub signature_algorithm: String,
    
    /// Значение подписи
    pub signature: Vec<u8>,
    
    /// Неподписанные атрибуты (опционально)
    pub unsigned_attrs: Option<Vec<(String, Vec<u8>)>>,
}

/// Идентификатор подписавшего
#[derive(Debug, Clone)]
pub enum SignerIdentifier {
    /// IssuerAndSerialNumber
    IssuerAndSerial {
        issuer: Vec<u8>,
        serial_number: Vec<u8>,
    },
    
    /// SubjectKeyIdentifier
    SubjectKeyId(Vec<u8>),
}

/// Подписанные атрибуты
#[derive(Debug, Clone)]
pub struct SignedAttributes {
    /// Тип содержимого (OID)
    pub content_type: Option<String>,
    
    /// Дайджест сообщения (хеш)
    pub message_digest: Option<Vec<u8>>,
    
    /// Время подписания
    pub signing_time: Option<String>,
    
    /// Сертификат подписавшего
    pub signing_certificate: Option<Vec<u8>>,
}

impl SignerInfo {
    /// Проверяет, что это GOST подпись
    pub fn is_gost_signature(&self) -> bool {
        // GOST OID начинаются с 1.2.643
        self.signature_algorithm.starts_with("1.2.643")
            && self.digest_algorithm.starts_with("1.2.643")
    }
    
    /// Получает размер подписи
    pub fn signature_size(&self) -> usize {
        self.signature.len()
    }
}

impl Default for SignerInfo {
    fn default() -> Self {
        SignerInfo {
            version: 1,
            sid: SignerIdentifier::IssuerAndSerial {
                issuer: Vec::new(),
                serial_number: Vec::new(),
            },
            digest_algorithm: String::new(),
            signed_attrs: SignedAttributes::default(),
            signature_algorithm: String::new(),
            signature: Vec::new(),
            unsigned_attrs: None,
        }
    }
}

impl Default for SignedAttributes {
    fn default() -> Self {
        SignedAttributes {
            content_type: None,
            message_digest: None,
            signing_time: None,
            signing_certificate: None,
        }
    }
}
