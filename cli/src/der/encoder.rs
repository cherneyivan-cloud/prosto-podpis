/// DER энкодер
/// Кодирует структуры в DER формат

use crate::error::Result;
use super::types::{DerValue, DerElement};

pub struct DerEncoder;

impl DerEncoder {
    /// Кодирует элемент в DER
    pub fn encode_element(element: &DerElement) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        
        // Пишем тэг
        result.push(element.tag.to_byte());
        
        // Пишем длину и значение
        let value_bytes = Self::encode_value(&element.value)?;
        Self::encode_length(&mut result, value_bytes.len());
        result.extend_from_slice(&value_bytes);
        
        Ok(result)
    }
    
    /// Кодирует значение
    fn encode_value(value: &DerValue) -> Result<Vec<u8>> {
        match value {
            DerValue::Boolean(b) => {
                Ok(vec![if *b { 0xFF } else { 0x00 }])
            }
            
            DerValue::Integer(bytes) => {
                Ok(bytes.clone())
            }
            
            DerValue::OctetString(bytes) => {
                Ok(bytes.clone())
            }
            
            DerValue::Null => {
                Ok(Vec::new())
            }
            
            DerValue::ObjectIdentifier(oid_str) => {
                Self::encode_oid(oid_str)
            }
            
            DerValue::PrintableString(s) => {
                Ok(s.as_bytes().to_vec())
            }
            
            DerValue::Utf8String(s) => {
                Ok(s.as_bytes().to_vec())
            }
            
            DerValue::IA5String(s) => {
                Ok(s.as_bytes().to_vec())
            }
            
            DerValue::Sequence(elements) | DerValue::Set(elements) => {
                let mut result = Vec::new();
                for element in elements {
                    result.extend_from_slice(&Self::encode_element(element)?);
                }
                Ok(result)
            }
            
            DerValue::BitString { unused_bits, data } => {
                let mut result = vec![*unused_bits];
                result.extend_from_slice(data);
                Ok(result)
            }
            
            DerValue::UTCTime(s) | DerValue::GeneralizedTime(s) => {
                Ok(s.as_bytes().to_vec())
            }
        }
    }
    
    /// Кодирует длину
    fn encode_length(result: &mut Vec<u8>, length: usize) {
        if length < 128 {
            result.push(length as u8);
        } else {
            let mut len_bytes = Vec::new();
            let mut l = length;
            
            while l > 0 {
                len_bytes.insert(0, (l & 0xFF) as u8);
                l >>= 8;
            }
            
            result.push(0x80 | len_bytes.len() as u8);
            result.extend_from_slice(&len_bytes);
        }
    }
    
    /// Кодирует OID
    fn encode_oid(oid_str: &str) -> Result<Vec<u8>> {
        let parts: Result<Vec<u32>> = oid_str
            .split('.')
            .map(|p| p.parse::<u32>()
                .map_err(|_| crate::error::CryptolineError::DerParseError(
                    format!("Invalid OID component: {}", p)
                )))
            .collect();
        
        let parts = parts?;
        
        if parts.len() < 2 {
            return Err(crate::error::CryptolineError::DerParseError(
                "OID must have at least 2 components".to_string()
            ));
        }
        
        let mut result = vec![parts[0] as u8 * 40 + parts[1] as u8];
        
        for &part in &parts[2..] {
            if part < 128 {
                result.push(part as u8);
            } else {
                let mut bytes = Vec::new();
                let mut p = part;
                
                while p > 0 {
                    bytes.insert(0, (p & 0x7F) as u8);
                    p >>= 7;
                }
                
                for i in 0..bytes.len() - 1 {
                    result.push(bytes[i] | 0x80);
                }
                result.push(*bytes.last().unwrap());
            }
        }
        
        Ok(result)
    }
}
