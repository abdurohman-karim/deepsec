//! Обёртки над Win32: процессы, цифровая подпись, права, запуск команд без окна.

use std::ffi::c_void;
use std::os::windows::process::CommandExt;
use std::process::{Command, Output};

use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows::Win32::Globalization::{CP_OEMCP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS, MultiByteToWideChar};
use windows::Win32::Security::Cryptography::{CERT_NAME_ATTR_TYPE, CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW, szOID_ORGANIZATION_NAME};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvSignerFromChain,
    WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW};
use windows::Win32::UI::Shell::IsUserAnAdmin;
use windows::core::{PCWSTR, PWSTR};

use crate::trust::Signature;

pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[derive(Clone, Debug)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
}

pub fn processes() -> Vec<ProcessInfo> {
    let mut list = Vec::new();
    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else { return list };
        let mut entry = PROCESSENTRY32W { dwSize: size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut ok = Process32FirstW(snapshot, &mut entry).is_ok();
        while ok {
            let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
            list.push(ProcessInfo {
                pid: entry.th32ProcessID,
                ppid: entry.th32ParentProcessID,
                name: String::from_utf16_lossy(&entry.szExeFile[..len]),
            });
            ok = Process32NextW(snapshot, &mut entry).is_ok();
        }
        let _ = CloseHandle(snapshot);
    }
    list
}

/// Полный путь exe процесса (пусто — нет доступа или процесс уже завершился).
pub fn exe_path(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buffer = [0u16; 1024];
        let mut size = buffer.len() as u32;
        let result = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buffer.as_mut_ptr()), &mut size);
        let _ = CloseHandle(handle);
        result.ok()?;
        Some(String::from_utf16_lossy(&buffer[..size as usize]))
    }
}

pub fn own_exe() -> String {
    std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()
}

pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin().as_bool() }
}

/// Подпись Authenticode через WinVerifyTrust — без PowerShell (у Python-агента на это уходили секунды).
pub fn read_signature(path: &str) -> Signature {
    let file = wide(path);
    let mut info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(file.as_ptr()),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut info },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL, // без походов в сеть за списками отзыва
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    unsafe {
        let code = WinVerifyTrust(HWND(-1isize as *mut c_void), &mut action, &mut data as *mut _ as *mut c_void) as u32;
        let status = match code {
            0 => "Valid".to_string(),
            0x800B_0100 => "NotSigned".to_string(),
            0x8009_6010 => "HashMismatch".to_string(),
            0x800B_0111 => "NotTrusted".to_string(),
            other => format!("Error 0x{other:08X}"),
        };
        let mut subject = String::new();
        let provider = WTHelperProvDataFromStateData(data.hWVTStateData);
        if !provider.is_null() {
            let signer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
            if !signer.is_null() && (*signer).csCertChain > 0 {
                let cert = (*(*signer).pasCertChain).pCert;
                let cn = cert_name(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, None);
                let org = cert_name(cert, CERT_NAME_ATTR_TYPE, Some(szOID_ORGANIZATION_NAME.0 as *const c_void));
                subject = format!("CN={}, O={}", quote_rdn(&cn), quote_rdn(&org));
            }
        }
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(HWND(-1isize as *mut c_void), &mut action, &mut data as *mut _ as *mut c_void);
        Signature { status, subject }
    }
}

unsafe fn cert_name(cert: *const windows::Win32::Security::Cryptography::CERT_CONTEXT, kind: u32, param: Option<*const c_void>) -> String {
    let mut buffer = [0u16; 512];
    let len = unsafe { CertGetNameStringW(cert, kind, 0, param, Some(&mut buffer)) } as usize;
    String::from_utf16_lossy(&buffer[..len.saturating_sub(1)])
}

/// Значение с запятыми — в кавычках, как в Subject у Get-AuthenticodeSignature (его разбирает trust::parse_subject).
fn quote_rdn(value: &str) -> String {
    if value.contains(',') || value.contains('"') { format!("\"{}\"", value.replace('"', "\"\"")) } else { value.to_string() }
}

/// Вывод консольных утилит Windows (netsh, schtasks) — в OEM-кодировке (cp866 в русской Windows).
pub fn oem_to_string(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    unsafe {
        let len = MultiByteToWideChar(CP_OEMCP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0), bytes, None);
        let mut buffer = vec![0u16; len.max(0) as usize];
        MultiByteToWideChar(CP_OEMCP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0), bytes, Some(&mut buffer));
        String::from_utf16_lossy(&buffer)
    }
}

/// Запустить консольную программу без окна и дождаться её.
pub fn run_hidden(program: &str, args: &[&str]) -> std::io::Result<Output> {
    Command::new(program).args(args).creation_flags(CREATE_NO_WINDOW).output()
}

pub fn output_text(output: &Output) -> String {
    let mut text = oem_to_string(&output.stdout);
    text.push_str(&oem_to_string(&output.stderr));
    text.trim().to_string()
}

pub fn close(handle: HANDLE) {
    unsafe {
        let _ = CloseHandle(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_of_a_windows_binary() {
        // notepad.exe подписан через каталог, а не встроенной подписью — WinVerifyTrust по файлу его не видит;
        // зато сам проверяемый механизм должен отвечать, не падая
        let sig = read_signature(r"C:\Windows\System32\notepad.exe");
        assert!(!sig.status.is_empty());
        let none = read_signature(r"C:\definitely\missing.exe");
        assert_ne!(none.status, "Valid");
    }

    /// cargo test -- --ignored: настоящий Telegram.exe на этом ПК должен быть «Valid» от Telegram FZ-LLC.
    #[test]
    #[ignore]
    fn real_telegram_signature() {
        let path = std::path::Path::new(&std::env::var("APPDATA").unwrap()).join(r"Telegram Desktop\Telegram.exe");
        let sig = read_signature(path.to_str().unwrap());
        println!("{sig:?}");
        let allowed = crate::config::parse_trusted(crate::config::DEFAULT_TRUSTED);
        assert!(sig.status == "Valid" && crate::trust::signer_matches(&sig.subject, &allowed["telegram.exe"]));
    }

    #[test]
    fn processes_and_own_path() {
        let me = std::process::id();
        let list = processes();
        assert!(list.iter().any(|p| p.pid == me));
        assert!(exe_path(me).unwrap().to_lowercase().ends_with(".exe"));
    }
}
