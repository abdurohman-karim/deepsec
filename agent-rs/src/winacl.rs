//! Аудит Windows: политика auditpol и SACL (правила аудита) на папках tdata, ловушках и canary.

use std::path::Path;
use std::process::Command;

use anyhow::{Result, bail};

use crate::detector::{AUDIT_POLICY_CHANGE_GUID, FILE_SYSTEM_GUID, LOGON_GUID};
use crate::win;

/// Аудит «Чтение данных» для Everyone (SID S-1-1-0 — не зависит от языка Windows). Через
/// GetAccessControl('Audit') трогаем только SACL — без ошибок про владельца, как у Set-Acl.
const PS_ADD_AUDIT: &str = r#"
$ErrorActionPreference = 'Stop'
$sid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-1-0'
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    $sid,
    [System.Security.AccessControl.FileSystemRights]::ReadData,
    [System.Security.AccessControl.InheritanceFlags]$env:DEEPSEC_INHERIT,
    [System.Security.AccessControl.PropagationFlags]$env:DEEPSEC_PROPAGATE,
    [System.Security.AccessControl.AuditFlags]::Success)
$item = Get-Item -LiteralPath $env:DEEPSEC_TARGET -Force
$acl = $item.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
$acl.AddAuditRule($rule)
$item.SetAccessControl($acl)
"#;

fn run_checked(command: &mut Command) -> Result<()> {
    use std::os::windows::process::CommandExt;
    let output = command.creation_flags(win::CREATE_NO_WINDOW).output()?;
    if !output.status.success() {
        bail!("{}", win::output_text(&output));
    }
    Ok(())
}

pub fn enable_audit_policy() -> Result<()> {
    // GUID вместо названий — названия подкатегорий переведены в русской Windows
    for guid in [FILE_SYSTEM_GUID, LOGON_GUID, AUDIT_POLICY_CHANGE_GUID] {
        run_checked(Command::new("auditpol").args(["/set", &format!("/subcategory:{guid}"), "/success:enable", "/failure:enable"]))?;
    }
    // 200 МБ журнала Security, чтобы события не вытеснялись за пару часов
    run_checked(Command::new("wevtutil").args(["sl", "Security", "/ms:209715200"]))
}

/// recursive=false — только файлы прямо в папке; true — на любой глубине. Сами папки не аудируются,
/// поэтому просмотр папки в Проводнике не вызывает тревогу — только чтение содержимого файлов.
pub fn add_read_audit(target: &Path, recursive: bool) -> Result<()> {
    run_checked(
        Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", PS_ADD_AUDIT])
            .env("DEEPSEC_TARGET", target)
            .env("DEEPSEC_INHERIT", "ObjectInherit")
            .env("DEEPSEC_PROPAGATE", if recursive { "InheritOnly" } else { "InheritOnly, NoPropagateInherit" }),
    )
}

/// Папки аккаунтов в tdata, например D877F783D5D3EF8C.
pub fn is_account_dir(name: &str) -> bool {
    name.len() == 16 && name.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())
}

/// Аудит key_datas и файлов в корне tdata + maps в папках аккаунтов. Кэш медиа (user_data) не трогаем —
/// иначе журнал утонет в событиях от самого Telegram.
pub fn protect_tdata(tdata: &Path) -> Result<()> {
    add_read_audit(tdata, false)?;
    for entry in std::fs::read_dir(tdata)?.flatten() {
        if entry.path().is_dir() && is_account_dir(&entry.file_name().to_string_lossy()) {
            add_read_audit(&entry.path(), false)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn account_dirs() {
        assert!(super::is_account_dir("D877F783D5D3EF8C"));
        assert!(!super::is_account_dir("user_data") && !super::is_account_dir("d877f783d5d3ef8c"));
    }
}
