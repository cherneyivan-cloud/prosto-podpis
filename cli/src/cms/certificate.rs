/// X.509 Certificate парсинг
/// Работа с сертификатами для подписей

use crate::error::Result;

/// X.509 Сертификат
#[derive(Debug, Clone)]
pub struct Certificate {
    /// Версия (1, 2 или 3)
    pub version: u32,
    
    /// Серийный номер
    pub serial_number: Vec<u8>,
    
    /// Алгоритм подписи (OID)
    pub signature_algorithm: String,
    
    /// Издатель (DN)
    pub issuer: Vec<u8>,
    
    /// Субъект (DN)
    pub subject: Vec<u8>,
    
    /// Начало действия
    pub not_before: String,
    
    /// Конец действия
    pub not_after: String,
    
    /// Открытый ключ
    pub public_key: PublicKey,
    
    /// Расширения
    pub extensions: Vec<Extension>,
}

/// Открытый ключ
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// Алгоритм (OID)
    pub algorithm: String,
    
    /// Ключевые данные
    pub key_data: Vec<u8>,
}

/// Расширение сертификата
#[derive(Debug, Clone)]
pub struct Extension {
    /// OID расширения
    pub oid: String,
    
    /// Критичность
    pub critical: bool,
    
    /// Значение
    pub value: Vec<u8>,
}

impl Certificate {
    /// Проверяет, что это сертификат для GOST подписей
    pub fn is_gost_certificate(&self) -> bool {
        self.public_key.algorithm.starts_with("1.2.643")
            && self.signature_algorithm.starts_with("1.2.643")
    }
    
    /// Получает размер ключа из алгоритма
    pub fn key_size_bits(&self) -> Option<u16> {
        match self.public_key.algorithm.as_str() {
            "1.2.643.7.1.1.1.1" => Some(256),  // GOST R 34.10-2012 (256 bit)
            "1.2.643.7.1.1.1.2" => Some(512),  // GOST R 34.10-2012 (512 bit)
            "1.2.643.2.2.20" => Some(256),      // GOST R 34.10-94
            _ => None,
        }
    }
    
    /// Получает удобное имя субъекта
    pub fn subject_name(&self) -> String {
        // TODO: Правильный парсинг DN
        format!("Subject({} bytes)", self.subject.len())
    }
    
    /// Получает удобное имя издателя
    pub fn issuer_name(&self) -> String {
        // TODO: Правильный парсинг DN
        format!("Issuer({} bytes)", self.issuer.len())
    }
}

impl Default for Certificate {
    fn default() -> Self {
        Certificate {
            version: 3,
            serial_number: Vec::new(),
            signature_algorithm: String::new(),
            issuer: Vec::new(),
            subject: Vec::new(),
            not_before: String::new(),
            not_after: String::new(),
            public_key: PublicKey {
                algorithm: String::new(),
                key_data: Vec::new(),
            },
            extensions: Vec::new(),
        }
    }
}
