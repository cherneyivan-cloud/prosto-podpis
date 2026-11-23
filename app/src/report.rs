//! Отчёт о подписях: текстовый файл и книга Excel (.xlsx).
//!
//! XLSX собирается вручную: это ZIP с несколькими XML-частями, поэтому
//! обходимся без тяжёлых зависимостей.

use std::fs::File;
use std::io::Write;
use std::path::Path;

use chrono::Local;

/// Одна подпись (или документ без подписей — с прочерками).
pub struct ReportRow {
    pub file: String,
    pub size: String,
    pub status: String,
    pub signer: String,
    pub signature_file: String,
    pub signature_hash: String,
    pub signed_at: String,
}

const HEADERS: [&str; 7] = [
    "Документ",
    "Размер",
    "Статус",
    "Подписант",
    "Файл подписи",
    "Hash подписи (SHA-256)",
    "Дата подписи",
];

pub fn write_txt(path: &Path, folder: &Path, rows: &[ReportRow]) -> std::io::Result<()> {
    let mut out = String::new();
    out.push_str("ПРОСТО ПОДПИСЬ — ОТЧЁТ О ПОДПИСЯХ\n");
    out.push_str(&format!(
        "Сформирован: {}\n",
        Local::now().format("%d.%m.%Y %H:%M")
    ));
    out.push_str(&format!("Папка: {}\n", folder.display()));
    out.push_str(&"-".repeat(72));
    out.push('\n');

    let mut last_file: Option<&str> = None;
    for row in rows {
        if last_file != Some(row.file.as_str()) {
            out.push_str(&format!(
                "{} · {} · {}\n",
                row.file, row.size, row.status
            ));
            last_file = Some(row.file.as_str());
        }

        if row.signature_file == "—" {
            out.push_str("  Подписей нет\n");
        } else {
            out.push_str(&format!("  Подписант:  {}\n", row.signer));
            out.push_str(&format!("  Подпись:    {}\n", row.signature_file));
            out.push_str(&format!(
                "  Hash:       {} (SHA-256)\n",
                row.signature_hash
            ));
            out.push_str(&format!("  Дата:       {}\n", row.signed_at));
            out.push('\n');
        }
    }

    let documents = rows
        .iter()
        .map(|r| r.file.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let signatures = rows.iter().filter(|r| r.signature_file != "—").count();
    out.push_str(&format!(
        "Документов: {} · подписей: {}\n",
        documents, signatures
    ));
    out.push_str("Hash подписи — SHA-256 файла .sig.\n");

    std::fs::write(path, out)
}

pub fn write_xlsx(path: &Path, rows: &[ReportRow]) -> Result<(), String> {
    let file = File::create(path).map_err(|e| format!("{}: {}", path.display(), e))?;
    let mut zip = zip::ZipWriter::new(file);

    add(&mut zip, "[Content_Types].xml", CONTENT_TYPES)?;
    add(&mut zip, "_rels/.rels", ROOT_RELS)?;
    add(&mut zip, "xl/workbook.xml", WORKBOOK)?;
    add(&mut zip, "xl/_rels/workbook.xml.rels", WORKBOOK_RELS)?;
    add(&mut zip, "xl/styles.xml", STYLES)?;
    add(&mut zip, "xl/worksheets/sheet1.xml", &sheet_xml(rows))?;

    zip.finish().map_err(|e| e.to_string())?;
    Ok(())
}

fn add(zip: &mut zip::ZipWriter<File>, name: &str, data: &str) -> Result<(), String> {
    let options = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    zip.start_file(name, options).map_err(|e| e.to_string())?;
    zip.write_all(data.as_bytes()).map_err(|e| e.to_string())
}

fn row_values(row: &ReportRow) -> [&str; 7] {
    [
        &row.file,
        &row.size,
        &row.status,
        &row.signer,
        &row.signature_file,
        &row.signature_hash,
        &row.signed_at,
    ]
}

fn sheet_xml(rows: &[ReportRow]) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><cols><col min="1" max="1" width="34" customWidth="1"/><col min="2" max="2" width="12" customWidth="1"/><col min="3" max="3" width="14" customWidth="1"/><col min="4" max="4" width="36" customWidth="1"/><col min="5" max="5" width="42" customWidth="1"/><col min="6" max="6" width="68" customWidth="1"/><col min="7" max="7" width="18" customWidth="1"/></cols><sheetData>"#,
    );

    push_row(&mut xml, 1, &HEADERS, true);
    for (i, row) in rows.iter().enumerate() {
        let values = row_values(row);
        push_row(&mut xml, i + 2, &values, false);
    }

    xml.push_str("</sheetData></worksheet>");
    xml
}

fn push_row(xml: &mut String, number: usize, values: &[&str; 7], bold: bool) {
    xml.push_str(&format!("<row r=\"{}\">", number));
    for (i, value) in values.iter().enumerate() {
        let col = (b'A' + i as u8) as char;
        let style = if bold { " s=\"1\"" } else { "" };
        xml.push_str(&format!(
            "<c r=\"{}{}\"{} t=\"inlineStr\"><is><t xml:space=\"preserve\">{}</t></is></c>",
            col,
            number,
            style,
            xml_escape(value)
        ));
    }
    xml.push_str("</row>");
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const CONTENT_TYPES: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>"#;

const ROOT_RELS: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#;

const WORKBOOK: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Подписи" sheetId="1" r:id="rId1"/></sheets></workbook>"#;

const WORKBOOK_RELS: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>"#;

const STYLES: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>"#;
