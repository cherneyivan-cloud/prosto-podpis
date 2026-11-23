/// DER парсер
/// Парсит Tag-Length-Value структуры из бинарных данных

use crate::error::{CryptolineError, Result};
use super::types::{DerTag, DerValue, DerElement};

pub struct DerParser {
    data: Vec<u8>,
    position: usize,
}

impl DerParser {
    /// Создаёт новый парсер
    pub fn new(data: Vec<u8>) -> Self {
        DerParser { data, position: 0 }
    }
    
    /// Парсит один DER элемент
    pub fn parse_element(&mut self) -> Result<DerElement> {
        let tag = self.read_tag()?;
        let length = self.read_length()?;
        let value = self.read_value(tag, length)?;
        
        Ok(DerElement::new(tag, value))
    }
    
    /// Парсит все элементы
    pub fn parse_all(&mut self) -> Result<Vec<DerElement>> {
        let mut elements = Vec::new();
        
        while self.position < self.data.len() {
            elements.push(self.parse_element()?);
        }
        
        Ok(elements)
    }
    
    /// Читает тэг
    fn read_tag(&mut self) -> Result<DerTag> {
        if self.position >= self.data.len() {
            return Err(CryptolineError::DerParseError(
                "Unexpected end of data while reading tag".to_string(),
            ));
        }
        
        let byte = self.data[self.position];
        self.position += 1;
        
        // TODO: Обработка многобайтовых тэгов
        Ok(DerTag::from_byte(byte))
    }
    
    /// Читает длину
    fn read_length(&mut self) -> Result<usize> {
        if self.position >= self.data.len() {
            return Err(CryptolineError::DerParseError(
                "Unexpected end of data while reading length".to_string(),
            ));
        }
        
        let byte = self.data[self.position];
        self.position += 1;
        
        if (byte & 0x80) == 0 {
            // Короткая форма
            Ok(byte as usize)
        } else {
            // Длинная форма
            let len_bytes = (byte & 0x7F) as usize;
            
            if len_bytes == 0 {
                return Err(CryptolineError::DerParseError(
                    "Indefinite length not supported".to_string(),
                ));
            }
            
            if self.position + len_bytes > self.data.len() {
                return Err(CryptolineError::DerParseError(
                    "Unexpected end of data while reading length value".to_string(),
                ));
            }
            
            let length_bytes = &self.data[self.position..self.position + len_bytes];
            self.position += len_bytes;
            
            let mut length = 0usize;
            for &byte in length_bytes {
                length = (length << 8) | (byte as usize);
            }
            
            Ok(length)
        }
    }
    
    /// Читает значение
    fn read_value(&mut self, tag: DerTag, length: usize) -> Result<DerValue> {
        if self.position + length > self.data.len() {
            return Err(CryptolineError::DerParseError(
                "Unexpected end of data while reading value".to_string(),
            ));
        }
        
        let value_data = &self.data[self.position..self.position + length];
        self.position += length;
        
        match tag {
            DerTag::Boolean => {
                if length != 1 {
                    return Err(CryptolineError::DerParseError(
                        "Invalid boolean length".to_string(),
                    ));
                }
                Ok(DerValue::Boolean(value_data[0] != 0))
            }
            
            DerTag::Integer => {
                Ok(DerValue::Integer(value_data.to_vec()))
            }
            
            DerTag::OctetString => {
                Ok(DerValue::OctetString(value_data.to_vec()))
            }
            
            DerTag::Null => {
                if length != 0 {
                    return Err(CryptolineError::DerParseError(
                        "Invalid null length".to_string(),
                    ));
                }
                Ok(DerValue::Null)
            }
            
            DerTag::ObjectIdentifier => {
                let oid_string = self.decode_oid(value_data)?;
                Ok(DerValue::ObjectIdentifier(oid_string))
            }
            
            DerTag::PrintableString => {
                let string = String::from_utf8(value_data.to_vec())
                    .map_err(|_| CryptolineError::DerParseError(
                        "Invalid PrintableString encoding".to_string(),
                    ))?;
                Ok(DerValue::PrintableString(string))
            }
            
            DerTag::Utf8String => {
                let string = String::from_utf8(value_data.to_vec())
                    .map_err(|_| CryptolineError::DerParseError(
                        "Invalid UTF8String encoding".to_string(),
                    ))?;
                Ok(DerValue::Utf8String(string))
            }
            
            DerTag::IA5String => {
                let string = String::from_utf8(value_data.to_vec())
                    .map_err(|_| CryptolineError::DerParseError(
                        "Invalid IA5String encoding".to_string(),
                    ))?;
                Ok(DerValue::IA5String(string))
            }
            
            DerTag::Sequence | DerTag::Set => {
                // Рекурсивный парсинг
                let mut sub_parser = DerParser::new(value_data.to_vec());
                let elements = sub_parser.parse_all()?;
                
                match tag {
                    DerTag::Sequence => Ok(DerValue::Sequence(elements)),
                    DerTag::Set => Ok(DerValue::Set(elements)),
                    _ => unreachable!(),
                }
            }
            
            DerTag::BitString => {
                if length < 1 {
                    return Err(CryptolineError::DerParseError(
                        "BitString too short".to_string(),
                    ));
                }
                let unused_bits = value_data[0];
                let data = value_data[1..].to_vec();
                Ok(DerValue::BitString { unused_bits, data })
            }
            
            DerTag::UTCTime => {
                let time_str = String::from_utf8(value_data.to_vec())
                    .map_err(|_| CryptolineError::DerParseError(
                        "Invalid UTCTime encoding".to_string(),
                    ))?;
                Ok(DerValue::UTCTime(time_str))
            }
            
            DerTag::GeneralizedTime => {
                let time_str = String::from_utf8(value_data.to_vec())
                    .map_err(|_| CryptolineError::DerParseError(
                        "Invalid GeneralizedTime encoding".to_string(),
                    ))?;
                Ok(DerValue::GeneralizedTime(time_str))
            }
            
            _ => Err(CryptolineError::DerParseError(
                format!("Unsupported tag: {:?}", tag),
            )),
        }
    }
    
    /// Декодирует OID
    fn decode_oid(&self, data: &[u8]) -> Result<String> {
        if data.is_empty() {
            return Err(CryptolineError::DerParseError(
                "Empty OID".to_string(),
            ));
        }
        
        let mut oid = Vec::new();
        
        // Первый байт кодирует два компонента
        let first = data[0];
        oid.push((first / 40).to_string());
        oid.push((first % 40).to_string());
        
        let mut i = 1;
        while i < data.len() {
            let mut value = 0u32;
            
            loop {
                let byte = data[i] as u32;
                i += 1;
                
                value = (value << 7) | (byte & 0x7F);
                
                if (byte & 0x80) == 0 {
                    break;
                }
            }
            
            oid.push(value.to_string());
        }
        
        Ok(oid.join("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_der_parser_integer() {
        // INTEGER 42
        let data = vec![0x02, 0x01, 0x2A];
        let mut parser = DerParser::new(data);
        let element = parser.parse_element().unwrap();
        
        assert!(matches!(element.tag, DerTag::Integer));
    }
}
