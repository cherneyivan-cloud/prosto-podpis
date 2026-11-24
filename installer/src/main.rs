//! Установщик «Просто Подпись» для текущего пользователя.
//!
//! Ничего не требует от администратора: файлы кладутся в
//! %LOCALAPPDATA%\Programs\Просто Подпись, ярлыки — на рабочий стол и в меню
//! «Пуск», запись деинсталлятора — в HKCU.

#![windows_subsystem = "windows"]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const APP_NAME: &str = "Просто Подпись";
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const EXE_NAME: &str = "Podpis.exe";
const CLI_NAME: &str = "Podpis-cli.exe";
const PDF_NAME: &str = "Просто подпись — инструкция.pdf";
const UNINSTALL_NAME: &str = "uninstall.exe";
const REG_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\ProstoPodpis";

/// Не показывать консольные окна дочерних процессов.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

static APP_EXE: &[u8] = include_bytes!("../payload/Podpis.exe");
static APP_CLI: &[u8] = include_bytes!("../payload/Podpis-cli.exe");
static APP_PDF: &[u8] = include_bytes!("../payload/manual.pdf");

// --- Win32 MessageBox -------------------------------------------------------

const MB_OK: u32 = 0x0000_0000;
const MB_YESNO: u32 = 0x0000_0004;
const MB_ICONERROR: u32 = 0x0000_0010;
const MB_ICONQUESTION: u32 = 0x0000_0020;
const MB_ICONINFORMATION: u32 = 0x0000_0040;
const IDYES: i32 = 6;

#[link(name = "user32")]
extern "system" {
    fn MessageBoxW(hwnd: usize, text: *const u16, caption: *const u16, utype: u32) -> i32;
}

fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn message(text: &str, flags: u32) -> i32 {
    let body = wide(text);
    let title = wide(APP_NAME);
    unsafe { MessageBoxW(0, body.as_ptr(), title.as_ptr(), flags) }
}

fn ask(text: &str) -> bool {
    message(text, MB_YESNO | MB_ICONQUESTION) == IDYES
}

fn info(text: &str) {
    message(text, MB_OK | MB_ICONINFORMATION);
}

fn fail(text: &str) {
    message(text, MB_OK | MB_ICONERROR);
}

// --- Вспомогательное --------------------------------------------------------

fn hidden(mut cmd: Command) -> Command {
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

/// Строковый литерал PowerShell в одинарных кавычках.
///
/// Внутри одинарных кавычек PowerShell единственный спецсимвол — `'`,
/// он экранируется удвоением. Это защищает от подстановки команд,
/// если в пути окажется кавычка или другой символ.
fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn install_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("Programs").join(APP_NAME)
}

fn run_powershell(script: &str) -> Result<(), String> {
    let output = hidden(Command::new("powershell"))
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map_err(|e| format!("PowerShell: {}", e))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(())
}

// --- Установка --------------------------------------------------------------

fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let path = dir.join(name);
    std::fs::write(&path, bytes).map_err(|e| format!("{}: {}", path.display(), e))
}

fn create_shortcuts(dir: &Path) -> Result<(), String> {
    let exe = dir.join(EXE_NAME);
    let exe = exe.to_string_lossy();
    let workdir = dir.to_string_lossy();

    let script = format!(
        "$W=New-Object -ComObject WScript.Shell; \
         $d=[Environment]::GetFolderPath('Desktop'); \
         $m=[Environment]::GetFolderPath('Programs'); \
         $name={name}; \
         foreach($p in @((Join-Path $d ($name + '.lnk')),(Join-Path $m ($name + '.lnk')))){{ \
           $s=$W.CreateShortcut($p); $s.TargetPath={exe}; $s.WorkingDirectory={dir}; \
           $s.IconLocation=({exe} + ',0'); $s.Description=$name; $s.Save() }}",
        name = ps_quote(APP_NAME),
        exe = ps_quote(&exe),
        dir = ps_quote(&workdir),
    );

    run_powershell(&script)
}

fn write_registry(dir: &Path, size_kb: u64) -> Result<(), String> {
    let exe = dir.join(EXE_NAME).to_string_lossy().into_owned();
    let uninstall = dir.join(UNINSTALL_NAME).to_string_lossy().into_owned();
    let location = dir.to_string_lossy().into_owned();

    let uninstall_string = format!("\"{}\" --uninstall", uninstall);
    let entries: [(&str, &str, &str); 6] = [
        ("DisplayName", "REG_SZ", APP_NAME),
        ("DisplayVersion", "REG_SZ", APP_VERSION),
        ("Publisher", "REG_SZ", APP_NAME),
        ("DisplayIcon", "REG_SZ", &exe),
        ("InstallLocation", "REG_SZ", &location),
        ("UninstallString", "REG_SZ", &uninstall_string),
    ];

    for (name, kind, value) in entries {
        let status = hidden(Command::new("reg"))
            .args(["add", REG_KEY, "/v", name, "/t", kind, "/d", value, "/f"])
            .status()
            .map_err(|e| format!("reg: {}", e))?;
        if !status.success() {
            return Err(format!("не удалось записать {}", name));
        }
    }

    for flag in ["NoModify", "NoRepair"] {
        let _ = hidden(Command::new("reg"))
            .args(["add", REG_KEY, "/v", flag, "/t", "REG_DWORD", "/d", "1", "/f"])
            .status();
    }
    let _ = hidden(Command::new("reg"))
        .args([
            "add",
            REG_KEY,
            "/v",
            "EstimatedSize",
            "/t",
            "REG_DWORD",
            "/d",
            &size_kb.to_string(),
            "/f",
        ])
        .status();

    Ok(())
}

/// Копирует файлы программы. При ошибке вызывающий код откатывает установку.
fn install_files(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("не удалось создать {}: {}", dir.display(), e))?;

    write_file(dir, EXE_NAME, APP_EXE)?;
    write_file(dir, CLI_NAME, APP_CLI)?;
    write_file(dir, PDF_NAME, APP_PDF)?;

    // Деинсталлятор — копия этого файла.
    let self_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let uninstall_path = dir.join(UNINSTALL_NAME);
    if std::fs::copy(&self_exe, &uninstall_path).is_err() {
        let bytes = std::fs::read(&self_exe).map_err(|e| e.to_string())?;
        std::fs::write(&uninstall_path, bytes).map_err(|e| e.to_string())?;
    }

    Ok(())
}

fn rollback(dir: &Path, remove_dir: bool) {
    for name in [EXE_NAME, CLI_NAME, PDF_NAME, UNINSTALL_NAME] {
        let _ = std::fs::remove_file(dir.join(name));
    }
    if remove_dir {
        let _ = std::fs::remove_dir(dir);
    }
}

fn install() -> Result<PathBuf, String> {
    let dir = install_dir();
    let created_dir = !dir.exists();

    let result = install_files(&dir)
        .and_then(|()| create_shortcuts(&dir))
        .and_then(|()| {
            let size_kb = (APP_EXE.len() + APP_CLI.len() + APP_PDF.len()) as u64 / 1024;
            write_registry(&dir, size_kb)
        });

    if let Err(e) = result {
        rollback(&dir, created_dir);
        return Err(e);
    }

    Ok(dir.join(EXE_NAME))
}

// --- Удаление ---------------------------------------------------------------

fn remove_shortcuts() {
    let script = format!(
        "$d=[Environment]::GetFolderPath('Desktop'); \
         $m=[Environment]::GetFolderPath('Programs'); \
         $name={name}; \
         foreach($p in @((Join-Path $d ($name + '.lnk')),(Join-Path $m ($name + '.lnk')))){{ \
           if (Test-Path $p) {{ Remove-Item -LiteralPath $p -Force }} }}; \
         $f=Join-Path $m $name; if (Test-Path $f) {{ Remove-Item -LiteralPath $f -Recurse -Force }}",
        name = ps_quote(APP_NAME)
    );
    let _ = run_powershell(&script);
}

fn uninstall() -> Result<(), String> {
    let dir = install_dir();
    remove_shortcuts();

    let _ = hidden(Command::new("reg"))
        .args(["delete", REG_KEY, "/f"])
        .status();

    for name in [EXE_NAME, CLI_NAME, PDF_NAME] {
        let _ = std::fs::remove_file(dir.join(name));
    }

    // Папку удалит cmd после выхода процесса: сам файл занят.
    let dir_arg = dir.to_string_lossy().into_owned();
    let _ = hidden(Command::new("cmd"))
        .args([
            "/C",
            "ping",
            "127.0.0.1",
            "-n",
            "3",
            ">",
            "nul",
            "&",
            "rmdir",
            "/s",
            "/q",
            &dir_arg,
        ])
        .spawn();

    Ok(())
}

// --- Точка входа ------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let uninstall_mode = args.iter().any(|a| a == "--uninstall");
    let silent = args.iter().any(|a| a == "--silent");

    if uninstall_mode {
        if silent || ask(&format!("Удалить «{}» с этого компьютера?", APP_NAME)) {
            match uninstall() {
                Ok(()) => {
                    if !silent {
                        info(&format!(
                            "«{}» удалена.\n\nЯрлыки и папка программы удалены.",
                            APP_NAME
                        ))
                    }
                }
                Err(e) => {
                    if !silent {
                        fail(&format!("Не удалось удалить: {}", e))
                    }
                }
            }
        }
        return;
    }

    let dir = install_dir();
    let question = format!(
        "Установить «{}» для текущего пользователя?\n\nПапка: {}\n\nПрава администратора не нужны.",
        APP_NAME,
        dir.display()
    );
    if !silent && !ask(&question) {
        return;
    }

    match install() {
        Ok(exe) => {
            if !silent
                && ask(&format!(
                    "«{}» установлена.\n\nЗапустить программу сейчас?",
                    APP_NAME
                ))
            {
                let _ = Command::new(&exe).spawn();
            }
        }
        Err(e) => {
            if silent {
                std::process::exit(1);
            }
            fail(&format!("Не удалось установить:\n{}", e))
        }
    }
}
