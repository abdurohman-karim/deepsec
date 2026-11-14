//! Активная реакция: завершение процесса, блокировка в брандмауэре, карантин, блокировка сеансов, изоляция.
//! Функции блокирующие — агент вызывает их через spawn_blocking. Тексты результатов — как у Python-агента.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use sha1::{Digest, Sha1};
use windows::Win32::Foundation::WAIT_OBJECT_0;
use windows::Win32::System::RemoteDesktop::{WTS_SESSION_INFOW, WTSActive, WTSDisconnectSession, WTSEnumerateSessionsW, WTSFreeMemory};
use windows::Win32::System::Shutdown::LockWorkStation;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject};

use crate::detector::norm_path;
use crate::win;

pub const RULE_PREFIX: &str = "DeepSec-Block-";
pub const ISOLATION_RULES: [&str; 3] = ["DeepSec-Isolation-Agent", "DeepSec-Isolation-DNS-UDP", "DeepSec-Isolation-DNS-TCP"];
/// Эти процессы нельзя убивать — получим синий экран или сломанную систему.
const PROTECTED: [&str; 12] = [
    "system", "registry", "memory compression", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe",
];

pub fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

pub fn is_protected_path(path: &str) -> bool {
    path.is_empty() || PROTECTED.contains(&basename(path).to_lowercase().as_str())
}

pub fn is_protected(pid: Option<u32>, path: &str) -> bool {
    pid.is_none_or(|p| p <= 4) || is_protected_path(path)
}

fn netsh(args: &[&str]) -> Result<()> {
    let mut full = vec!["advfirewall"];
    full.extend_from_slice(args);
    let output = win::run_hidden("netsh", &full)?;
    if !output.status.success() {
        let text = win::output_text(&output);
        bail!("{}", if text.is_empty() { format!("netsh вернул {}", output.status) } else { text });
    }
    Ok(())
}

pub fn kill_tree(pid: u32, expected_path: Option<&str>) -> String {
    let Some(exe) = win::exe_path(pid) else {
        return if win::processes().iter().any(|p| p.pid == pid) {
            format!("нет доступа к процессу {pid}")
        } else {
            format!("процесс {pid} уже завершился")
        };
    };
    if expected_path.is_some_and(|e| norm_path(e) != norm_path(&exe)) {
        return format!("PID {pid} уже занят другим процессом — не трогаю");
    }
    if is_protected(Some(pid), &exe) {
        return format!("{} — системный процесс, завершать нельзя", basename(&exe));
    }
    // Всё дерево: стилеры часто перезапускают себя дочерними процессами
    let list = win::processes();
    let children: HashMap<u32, Vec<u32>> = list.iter().fold(HashMap::new(), |mut map, p| {
        map.entry(p.ppid).or_default().push(p.pid);
        map
    });
    let mut tree = vec![pid];
    let mut seen: HashSet<u32> = [pid].into();
    let mut i = 0;
    while i < tree.len() {
        for &child in children.get(&tree[i]).map(Vec::as_slice).unwrap_or(&[]) {
            if child != tree[i] && seen.insert(child) {
                tree.push(child);
            }
        }
        i += 1;
    }
    let handles: Vec<_> = tree
        .iter()
        .rev()
        .filter_map(|&p| unsafe { OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, false, p).ok() })
        .collect();
    for &h in &handles {
        unsafe {
            let _ = TerminateProcess(h, 1);
        }
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut gone = 0;
    for &h in &handles {
        let left = deadline.saturating_duration_since(Instant::now()).as_millis() as u32;
        if unsafe { WaitForSingleObject(h, left) } == WAIT_OBJECT_0 {
            gone += 1;
        }
        win::close(h);
    }
    let failed = tree.len() - gone;
    let mut result = format!("завершено процессов: {gone}");
    if failed > 0 {
        result.push_str(&format!(", не удалось: {failed}"));
    }
    result
}

pub fn block_rule_name(path: &str) -> String {
    let digest = hex::encode(Sha1::digest(norm_path(path).as_bytes()));
    format!("{RULE_PREFIX}{}", &digest[..10])
}

/// Запрещает exe любой сетевой трафик (даже если его запустят снова). Возвращает имя правила.
pub fn block_program(path: &str) -> Result<String> {
    if is_protected_path(path) {
        bail!("{} — системный процесс, блокировать нельзя", basename(path));
    }
    let name = block_rule_name(path);
    for direction in ["out", "in"] {
        netsh(&["firewall", "add", "rule", &format!("name={name}"), &format!("dir={direction}"), "action=block",
            &format!("program={path}"), "enable=yes"])?;
    }
    Ok(name)
}

pub fn unblock(rule: &str) -> Result<()> {
    netsh(&["firewall", "delete", "rule", &format!("name={rule}")])
}

pub fn quarantine(path: &str, data_dir: &Path) -> Result<String> {
    if is_protected_path(path) {
        bail!("{} — системный файл, в карантин нельзя", basename(path));
    }
    let dir = data_dir.join("quarantine");
    std::fs::create_dir_all(&dir)?;
    let target = dir.join(format!("{}_{}.quarantine", chrono::Local::now().format("%Y%m%d-%H%M%S"), basename(path)));
    if let Err(e) = std::fs::rename(path, &target) {
        // Другой диск — копия и удаление
        std::fs::copy(path, &target)
            .and_then(|_| std::fs::remove_file(path))
            .map_err(|_| anyhow::anyhow!("не удалось переместить (процесс ещё жив?): {e}"))?;
    }
    Ok(target.to_string_lossy().into_owned())
}

/// Отключает все активные сеансы — консольный (экран блокировки) и RDP (выкидывает подключившегося).
pub fn lock_sessions() -> Result<String> {
    let mut locked = Vec::new();
    unsafe {
        let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count = 0u32;
        WTSEnumerateSessionsW(None, 0, 1, &mut info, &mut count)?;
        for session in std::slice::from_raw_parts(info, count as usize) {
            // WTSActive и не служебная session 0
            if session.State == WTSActive && session.SessionId != 0 && WTSDisconnectSession(None, session.SessionId, false).is_ok() {
                let name = session.pWinStationName.to_string().unwrap_or_default();
                locked.push(if name.is_empty() { session.SessionId.to_string() } else { name });
            }
        }
        WTSFreeMemory(info as *mut std::ffi::c_void);
        if locked.is_empty() {
            // Агент запущен не от SYSTEM и не смог отключить сеанс — блокируем хотя бы свой
            if LockWorkStation().is_ok() {
                return Ok("рабочая станция заблокирована".into());
            }
            bail!("нет активных сеансов или недостаточно прав");
        }
    }
    Ok(format!("отключены сеансы: {}", locked.join(", ")))
}

/// Режет весь сетевой трафик ПК, кроме самого агента (чтобы бот остался на связи) и DNS.
pub fn isolate(agent_exe: &str) -> Result<()> {
    netsh(&["set", "allprofiles", "state", "on"])?;
    netsh(&["firewall", "add", "rule", &format!("name={}", ISOLATION_RULES[0]), "dir=out", "action=allow",
        &format!("program={agent_exe}"), "enable=yes"])?;
    netsh(&["firewall", "add", "rule", &format!("name={}", ISOLATION_RULES[1]), "dir=out", "action=allow",
        "protocol=UDP", "remoteport=53", "enable=yes"])?;
    netsh(&["firewall", "add", "rule", &format!("name={}", ISOLATION_RULES[2]), "dir=out", "action=allow",
        "protocol=TCP", "remoteport=53", "enable=yes"])?;
    netsh(&["set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"])
}

pub fn unisolate() -> Result<()> {
    netsh(&["set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"])?;
    for name in ISOLATION_RULES {
        let _ = netsh(&["firewall", "delete", "rule", &format!("name={name}")]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_processes() {
        assert!(is_protected(Some(4), r"C:\x.exe") && is_protected(None, r"C:\x.exe"));
        assert!(is_protected_path(r"C:\Windows\System32\LSASS.exe") && is_protected_path(""));
        assert!(!is_protected(Some(1234), r"C:\Users\me\Downloads\crack.exe"));
    }

    #[test]
    fn rule_name_is_stable_like_python() {
        // Python: "DeepSec-Block-" + sha1(ntpath.normcase(ntpath.normpath(path))).hexdigest()[:10]
        let digest = hex::encode(Sha1::digest(br"c:\users\me\crack.exe"));
        assert_eq!(block_rule_name(r"C:\Users\ME\crack.exe"), format!("DeepSec-Block-{}", &digest[..10]));
    }

    #[test]
    fn kill_refuses_reused_pid() {
        let me = std::process::id();
        assert!(kill_tree(me, Some(r"C:\other.exe")).contains("уже занят другим процессом"));
        assert!(kill_tree(0x7FFF_FFF0, None).contains("уже завершился"));
    }
}
