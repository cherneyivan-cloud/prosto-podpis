//! CLI приложение для подписания и проверки файлов.
//!
//! Подпись создаётся через CryptoPro CSP (CryptoAPI), как это делает
//! оригинальный CryptoLine.exe: закрытый ключ не покидает контейнер.

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

use base64::Engine;
use cryptoline_rust::crypto::cert_util::{parse_certificate, subject_owner};
use cryptoline_rust::crypto::signature_builder::current_utc_time;
use cryptoline_rust::crypto::{gost_hash_data, gost_hash_file, CmsBuilder, CmsSigner, GostSigner, SignatureParams};
use cryptoline_rust::error::Result;
use cryptoline_rust::CryptolineError;

#[derive(Parser)]
#[command(name = "cryptoline")]
#[command(about = "CryptoLine Rust — УКЭП подпись (ГОСТ Р 34.10-2012 + Streebog-256)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Создать подпись файла
    Sign {
        /// Путь к файлу для подписания
        #[arg(short, long)]
        file: PathBuf,

        /// Путь к сертификату (DER или .cer). Можно несколько: --cert a --cert b
        #[arg(short, long, required = true)]
        cert: Vec<PathBuf>,

        /// Присоединенная подпись: содержимое документа внутри CMS
        #[arg(long)]
        attached: bool,

        /// Путь для сохранения подписи (по умолчанию <имя>_<Фамилия_ИО>.sig)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Проверить подпись файла
    Verify {
        /// Путь к файлу
        #[arg(short, long)]
        file: PathBuf,

        /// Путь к подписи (.sig, Base64)
        #[arg(short, long)]
        signature: PathBuf,
    },
    /// Вычислить хеш файла (Streebog-256)
    Hash {
        /// Путь к файлу
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Показать сведения о сертификате
    Cert {
        /// Путь к сертификату (DER или .cer)
        #[arg(short, long)]
        cert: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Sign {
            file,
            cert,
            attached,
            output,
        } => {
            sign_file(&file, &cert, attached, &output)?;
        }
        Commands::Verify { file, signature } => {
            verify_file(&file, &signature)?;
        }
        Commands::Hash { file } => {
            hash_file(&file)?;
        }
        Commands::Cert { cert } => {
            show_cert(&cert)?;
        }
    }

    Ok(())
}

/// Читает файл, сообщая путь в случае ошибки.
fn read_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| {
        CryptolineError::FileError(format!("{}: {}", path.display(), e))
    })
}

fn sign_file(
    file: &PathBuf,
    certs: &[PathBuf],
    attached: bool,
    output: &Option<PathBuf>,
) -> Result<()> {
    if !file.exists() {
        return Err(CryptolineError::FileError(format!(
            "файл не найден: {}",
            file.display()
        )));
    }
    if certs.is_empty() {
        return Err(CryptolineError::InvalidData(
            "не указан ни один сертификат".to_string(),
        ));
    }

    let file_data = read_file(file)?;
    let mut signers = Vec::new();
    let mut subjects = Vec::new();

    for cert_path in certs {
        let cert_data = read_file(cert_path)?;
        let parts = parse_certificate(&cert_data)?;

        // 1. Подписанные атрибуты и их хеш — подписывается именно SET.
        let params = SignatureParams {
            data: file_data.clone(),
            public_key: parts.public_key.clone(),
            signature: Vec::new(),
            certificate: cert_data.clone(),
            signing_time: current_utc_time(),
        };
        let signed_attrs = CmsBuilder::build_signed_attrs(&params)?;
        let attrs_digest = gost_hash_data(&signed_attrs);

        // 2. Подпись через CryptoPro CSP.
        let signature =
            cryptoline_rust::csp::sign_digest(&parts.public_key, &attrs_digest)?;

        signers.push(CmsSigner {
            certificate: cert_data,
            signature,
            signed_attrs_set: signed_attrs,
        });
        subjects.push(parts.subject.clone());
    }

    // 3. Общий CMS: один или несколько подписантов, открепленный или
    //    присоединенный (с содержимым документа).
    let cms_der = CmsBuilder::build_multi(&file_data, &signers, attached)?;

    // 4. Base64 с переносами строк, как оригинал.
    let cms_b64 = encode_base64_wrapped(&cms_der);

    let out_path = output
        .clone()
        .unwrap_or_else(|| default_sig_path(file, &subjects));
    std::fs::write(&out_path, cms_b64).map_err(|e| {
        CryptolineError::FileError(format!("{}: {}", out_path.display(), e))
    })?;

    println!("✓ Подпись сохранена: {}", out_path.display());
    for subject in &subjects {
        if let Some(owner) = subject_owner(subject) {
            println!("  подписант: {}", owner);
        }
    }
    Ok(())
}

/// Имя файла подписи: <имя>_<Фамилия_ИО>[_и_<Фамилия_ИО>].sig.
fn default_sig_path(file: &Path, subjects: &[Vec<u8>]) -> PathBuf {
    let stem = file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("signature");
    let owners: Vec<String> = subjects
        .iter()
        .map(|s| subject_owner(s).unwrap_or_else(|| "signature".to_string()))
        .collect();
    let owner = if owners.is_empty() {
        "signature".to_string()
    } else {
        owners.join("_и_")
    };
    let name = format!("{}_{}.sig", stem, owner);
    match file.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(name),
        _ => PathBuf::from(name),
    }
}

fn verify_file(file: &PathBuf, signature: &PathBuf) -> Result<()> {
    let file_data = read_file(file)?;
    let sig_bytes = read_file(signature)?;
    // Подпись может быть как Base64 (.sig с порталов), так и бинарным DER/BER.
    let cms_der = if sig_bytes.first() == Some(&0x30) {
        sig_bytes
    } else {
        let text = String::from_utf8_lossy(&sig_bytes);
        let text = text.trim_start_matches('\u{feff}');
        decode_base64(text)?
    };

    let components = cryptoline_rust::cms::extract_cms_components(&cms_der)?;
    let certificate = components
        .certificate
        .as_ref()
        .ok_or_else(|| CryptolineError::CmsParseError("подпись без сертификата".to_string()))?;
    let parts = parse_certificate(certificate)?;

    // 1. Целостность файла: messageDigest из атрибутов.
    let file_digest = gost_hash_data(&file_data);
    let digest_ok = components
        .message_digest
        .as_ref()
        .map(|d| d == &file_digest)
        .unwrap_or(false);
    println!(
        "  {} messageDigest файла",
        if digest_ok { "✓" } else { "✗" }
    );

    // 2. Подпись по хешу подписанных атрибутов.
    let attrs_digest = gost_hash_data(&components.signed_attrs_raw);
    let signer = GostSigner::new();
    let sig_ok = signer
        .verify(&parts.public_key, &attrs_digest, &components.signature)
        .unwrap_or(false);
    println!(
        "  {} подпись сертификата",
        if sig_ok { "✓" } else { "✗" }
    );

    println!("  сертификат: {}", parts.subject_string());

    if digest_ok && sig_ok {
        println!("✓ Подпись верна");
        Ok(())
    } else {
        Err(CryptolineError::CryptoError(
            "подпись недействительна".to_string(),
        ))
    }
}

fn show_cert(cert: &PathBuf) -> Result<()> {
    let data = read_file(cert)?;
    let parts = parse_certificate(&data)?;
    println!("Субъект:  {}", parts.subject_string());
    println!("Серийный: {}", hex_encode(&parts.serial));
    println!("Ключ:     {}", hex_encode(&parts.public_key));
    println!("SHA-256:  {}", hex_encode(&gost_hash_data(&data)));
    Ok(())
}

fn hash_file(file: &PathBuf) -> Result<()> {
    let hash = gost_hash_file(file)?;
    println!("Streebog-256({}): {}", file.display(), hex_encode(&hash));
    Ok(())
}

/// Base64 с переносами через 76 символов и CRLF — как в CryptoLine.exe.
fn encode_base64_wrapped(data: &[u8]) -> String {
    const ENGINE: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::STANDARD;
    let b64 = ENGINE.encode(data);
    let mut out = String::with_capacity(b64.len() + b64.len() / 76 * 2 + 2);
    // Чанки вместо split_off: для присоединенной подписи Base64 бывает
    // десятки мегабайт, а split_off делал копирование O(n²).
    for chunk in b64.as_bytes().chunks(76) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push_str("\r\n");
    }
    out
}

/// Base64 с игнорированием пробельных символов и переносов.
fn decode_base64(text: &str) -> Result<Vec<u8>> {
    const ENGINE: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::STANDARD;
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    ENGINE
        .decode(cleaned)
        .map_err(|e| CryptolineError::Base64Error(e.to_string()))
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}
