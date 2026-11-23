/// DER типы и тэги
use std::fmt;

/// DER теги (основные)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerTag {
    // Примитивные типы
    Boolean,
    Integer,
    BitString,
    OctetString,
    Null,
    ObjectIdentifier,
    PrintableString,
    Utf8String,
    IA5String,
    UTCTime,
    GeneralizedTime,
    
    // Конструктивные типы
    Sequence,
    Set,
    
    // Контекстные тэги
    Context(u8, bool), // (номер, constructed)
    
    // Неизвестный
    Unknown(u8),
}

impl DerTag {
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => DerTag::Boolean,
            0x02 => DerTag::Integer,
            0x03 => DerTag::BitString,
            0x04 => DerTag::OctetString,
            0x05 => DerTag::Null,
            0x06 => DerTag::ObjectIdentifier,
            0x13 => DerTag::PrintableString,
            0x0C => DerTag::Utf8String,
            0x16 => DerTag::IA5String,
            0x17 => DerTag::UTCTime,
            0x18 => DerTag::GeneralizedTime,
            0x30 => DerTag::Sequence,
            0x31 => DerTag::Set,
            b if (b & 0xC0) == 0x80 => {
                let constructed = (b & 0x20) != 0;
                let tag_num = b & 0x1F;
                DerTag::Context(tag_num, constructed)
            }
            b => DerTag::Unknown(b),
        }
    }
    
    pub fn to_byte(&self) -> u8 {
        match self {
            DerTag::Boolean => 0x01,
            DerTag::Integer => 0x02,
            DerTag::BitString => 0x03,
            DerTag::OctetString => 0x04,
            DerTag::Null => 0x05,
            DerTag::ObjectIdentifier => 0x06,
            DerTag::PrintableString => 0x13,
            DerTag::Utf8String => 0x0C,
            DerTag::IA5String => 0x16,
            DerTag::UTCTime => 0x17,
            DerTag::GeneralizedTime => 0x18,
            DerTag::Sequence => 0x30,
            DerTag::Set => 0x31,
            DerTag::Context(num, constructed) => {
                0x80 | if *constructed { 0x20 } else { 0 } | (*num & 0x1F)
            }
            DerTag::Unknown(b) => *b,
        }
    }
}

impl fmt::Display for DerTag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DerTag::Boolean => write!(f, "BOOLEAN"),
            DerTag::Integer => write!(f, "INTEGER"),
            DerTag::BitString => write!(f, "BIT STRING"),
            DerTag::OctetString => write!(f, "OCTET STRING"),
            DerTag::Null => write!(f, "NULL"),
            DerTag::ObjectIdentifier => write!(f, "OID"),
            DerTag::PrintableString => write!(f, "PrintableString"),
            DerTag::Utf8String => write!(f, "UTF8String"),
            DerTag::IA5String => write!(f, "IA5String"),
            DerTag::UTCTime => write!(f, "UTCTime"),
            DerTag::GeneralizedTime => write!(f, "GeneralizedTime"),
            DerTag::Sequence => write!(f, "SEQUENCE"),
            DerTag::Set => write!(f, "SET"),
            DerTag::Context(n, c) => write!(f, "[{}]{}", n, if *c { "" } else { " IMPLICIT" }),
            DerTag::Unknown(b) => write!(f, "Tag(0x{:02x})", b),
        }
    }
}

/// DER значение
#[derive(Debug, Clone)]
pub enum DerValue {
    Boolean(bool),
    Integer(Vec<u8>),
    BitString { unused_bits: u8, data: Vec<u8> },
    OctetString(Vec<u8>),
    Null,
    ObjectIdentifier(String),
    PrintableString(String),
    Utf8String(String),
    IA5String(String),
    UTCTime(String),
    GeneralizedTime(String),
    Sequence(Vec<DerElement>),
    Set(Vec<DerElement>),
}

/// DER элемент (тэг + значение)
#[derive(Debug, Clone)]
pub struct DerElement {
    pub tag: DerTag,
    pub value: DerValue,
}

impl DerElement {
    pub fn new(tag: DerTag, value: DerValue) -> Self {
        DerElement { tag, value }
    }
}
