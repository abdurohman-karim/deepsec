//! Экран и программы пользователя — по запросу владельца из бота (как deepsec/desktop.py).
//!
//! Агент работает от SYSTEM в сеансе 0, откуда экран и окна пользователя не видны. На время запроса он
//! запускает себя же (`DeepSecAgent.exe desktop screenshot|apps|close`) в сеансе того, кто сидит за
//! компьютером, с правами этого пользователя. Помощник печатает JSON в канал и завершается.

use std::collections::{BTreeMap, HashSet};
use std::ffi::c_void;
use std::io::Read;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use serde_json::{Value, json};
use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
use windows::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, HWND, LPARAM, SetHandleInformation, TRUE, UNICODE_STRING, WPARAM};
use windows::Win32::Graphics::Dwm::{DWMWA_CLOAKED, DwmGetWindowAttribute};
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CAPTUREBLT, CreateCompatibleBitmap, CreateCompatibleDC, DIB_RGB_COLORS, DeleteDC,
    DeleteObject, GetDC, GetDIBits, ReleaseDC, SRCCOPY, SelectObject,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::ReadFile;
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTS_SESSION_INFOW, WTSActive, WTSEnumerateSessionsW, WTSFreeMemory, WTSGetActiveConsoleSessionId, WTSQueryUserToken,
};
use windows::Win32::System::StationsAndDesktops::{CloseDesktop, DESKTOP_READOBJECTS, DESKTOP_CONTROL_FLAGS, GetUserObjectInformationW, OpenInputDesktop, UOI_NAME};
use windows::Win32::System::SystemInformation::GetTickCount;
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, OpenProcess, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE, STARTF_USESTDHANDLES, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};
use windows::Win32::System::WindowsProgramming::GetUserNameW;
use windows::Win32::UI::HiDpi::{DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext};
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows::Win32::UI::Shell::CommandLineToArgvW;
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GW_OWNER, GWL_EXSTYLE, GetClassNameW, GetForegroundWindow, GetSystemMetrics, GetWindow, GetWindowLongW, GetWindowTextW,
    GetWindowThreadProcessId, IsIconic, IsWindow, IsWindowVisible, PostMessageW, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
    SM_YVIRTUALSCREEN, WM_CLOSE, WS_EX_TOOLWINDOW,
};
use windows::core::{PCWSTR, PWSTR};

use crate::win::{self, wide};

/// Секунды: сервер ждёт ответа агента 60 с — агент успеет сказать, что помощник завис.
pub const HELPER_TIMEOUT: Duration = Duration::from_secs(30);
/// Telegram всё равно ужмёт фото до 2560 px по длинной стороне.
const MAX_SIDE: u32 = 2560;
const JPEG_QUALITY: u8 = 70;
const MAX_TITLE: usize = 100;
const MAX_BACKGROUND: usize = 40;
/// Секунды на опрос фоновых процессов в «Что запущено».
const BACKGROUND_BUDGET: Duration = Duration::from_secs(3);
/// Столько ждём, что программа закроется сама, прежде чем агент её завершит.
pub const CLOSE_WAIT: Duration = Duration::from_secs(6);

// ---------- агент (SYSTEM): запуск помощника в сеансе пользователя ----------

/// Сеанс, в котором сейчас работают: сначала консоль (монитор компьютера), иначе активный RDP.
fn active_session() -> Option<u32> {
    let mut active = Vec::new();
    unsafe {
        let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count = 0u32;
        WTSEnumerateSessionsW(None, 0, 1, &mut info, &mut count).ok()?;
        for s in std::slice::from_raw_parts(info, count as usize) {
            if s.State == WTSActive && s.SessionId != 0 {
                active.push(s.SessionId);
            }
        }
        WTSFreeMemory(info as *mut c_void);
        let console = WTSGetActiveConsoleSessionId();
        if active.contains(&console) { Some(console) } else { active.first().copied() }
    }
}

fn require_session() -> Result<u32> {
    active_session().context("за компьютером никто не работает: открыт экран входа или пользователь отключён")
}

fn session_of(pid: u32) -> Option<u32> {
    let mut session = 0;
    unsafe { ProcessIdToSessionId(pid, &mut session).ok().map(|_| session) }
}

fn quote_args(args: &[String]) -> String {
    args.iter()
        .map(|a| if a.is_empty() || a.contains([' ', '\t', '"']) { format!("\"{}\"", a.replace('"', "\\\"")) } else { a.clone() })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Командная строка помощника: сам DeepSecAgent.exe с аргументами.
pub fn helper_command(args: &[&str]) -> Vec<String> {
    std::iter::once(win::own_exe()).chain(args.iter().map(|a| a.to_string())).collect()
}

pub fn run_in_user_session(args: &[&str]) -> Result<Value> {
    let session = require_session()?;
    let cmd = helper_command(args);
    let raw = if session_of(std::process::id()) == Some(session) {
        // Агент запущен не от SYSTEM, а в том же сеансе (отладка) — токен не нужен
        run_plain(&cmd)?
    } else {
        run_as_user(session, &cmd)?
    };
    parse_output(&raw)
}

fn run_plain(cmd: &[String]) -> Result<Vec<u8>> {
    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(win::CREATE_NO_WINDOW)
        .spawn()?;
    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = stdout.read_to_end(&mut out);
        out
    });
    let started = Instant::now();
    while child.try_wait()?.is_none() {
        if started.elapsed() > HELPER_TIMEOUT {
            let _ = child.kill();
            bail!("помощник не ответил вовремя");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(reader.join().unwrap_or_default())
}

/// Процесс с правами пользователя сеанса, на его рабочем столе. Возвращает (дескриптор, PID).
fn create_as_user(session: u32, cmd: &[String], stdout: Option<HANDLE>) -> Result<(HANDLE, u32)> {
    unsafe {
        let mut token = HANDLE::default();
        WTSQueryUserToken(session, &mut token).map_err(|e| anyhow!("нет доступа к сеансу пользователя ({e}) — агент должен работать от SYSTEM"))?;
        let mut env: *mut c_void = std::ptr::null_mut();
        let _ = CreateEnvironmentBlock(&mut env, Some(token), false);
        let mut desktop = wide("winsta0\\default");
        let mut startup = STARTUPINFOW { cb: size_of::<STARTUPINFOW>() as u32, lpDesktop: PWSTR(desktop.as_mut_ptr()), ..Default::default() };
        if let Some(out) = stdout {
            startup.dwFlags = STARTF_USESTDHANDLES;
            startup.hStdOutput = out;
        }
        let mut line = wide(&quote_args(cmd));
        let workdir = wide(&std::path::Path::new(&cmd[0]).parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default());
        let mut info = PROCESS_INFORMATION::default();
        let result = CreateProcessAsUserW(
            Some(token),
            PCWSTR::null(),
            Some(PWSTR(line.as_mut_ptr())),
            None,
            None,
            stdout.is_some(),
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            (!env.is_null()).then_some(env as *const c_void),
            PCWSTR(workdir.as_ptr()),
            &startup,
            &mut info,
        );
        if !env.is_null() {
            let _ = DestroyEnvironmentBlock(env);
        }
        win::close(token);
        result.map_err(|e| anyhow!("не удалось запустить помощника: {e}"))?;
        win::close(info.hThread);
        Ok((info.hProcess, info.dwProcessId))
    }
}

fn run_as_user(session: u32, cmd: &[String]) -> Result<Vec<u8>> {
    unsafe {
        let attrs = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, bInheritHandle: TRUE, ..Default::default() };
        let (mut read, mut write) = (HANDLE::default(), HANDLE::default());
        CreatePipe(&mut read, &mut write, Some(&attrs), 0)?;
        let _ = SetHandleInformation(read, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)); // помощнику — только запись
        let created = create_as_user(session, cmd, Some(write));
        win::close(write); // иначе чтение не увидит конца, когда помощник завершится
        let (process, _) = match created {
            Ok(p) => p,
            Err(e) => {
                win::close(read);
                return Err(e);
            }
        };
        let process_raw = process.0 as usize;
        let done = Arc::new(Mutex::new(false));
        let timed_out = Arc::new(Mutex::new(false));
        let (done_k, timed_k) = (done.clone(), timed_out.clone());
        let killer = std::thread::spawn(move || {
            let started = Instant::now();
            while started.elapsed() < HELPER_TIMEOUT {
                if *done_k.lock().unwrap() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            *timed_k.lock().unwrap() = true;
            let _ = TerminateProcess(HANDLE(process_raw as *mut c_void), 1);
        });
        let mut output = Vec::new();
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            let mut got = 0u32;
            if ReadFile(read, Some(&mut chunk), Some(&mut got), None).is_err() || got == 0 {
                break; // ERROR_BROKEN_PIPE — помощник закончил
            }
            output.extend_from_slice(&chunk[..got as usize]);
        }
        *done.lock().unwrap() = true;
        let _ = killer.join();
        let _ = WaitForSingleObject(process, 5000);
        win::close(read);
        win::close(process);
        if *timed_out.lock().unwrap() {
            bail!("помощник не ответил вовремя");
        }
        Ok(output)
    }
}

/// Запускает помощника в сеансе пользователя и не ждёт его (глаз живёт, пока его не уберут). Возвращает PID.
pub fn start_in_user_session(args: &[&str]) -> Result<u32> {
    let session = require_session()?;
    let cmd = helper_command(args);
    if session_of(std::process::id()) == Some(session) {
        let child = Command::new(&cmd[0]).args(&cmd[1..]).creation_flags(win::CREATE_NO_WINDOW).spawn()?;
        return Ok(child.id());
    }
    let (process, pid) = create_as_user(session, &cmd, None)?;
    win::close(process);
    Ok(pid)
}

pub fn parse_output(raw: &[u8]) -> Result<Value> {
    let text = String::from_utf8_lossy(raw);
    let line = text.trim().lines().last().context("помощник завершился без ответа")?;
    let data: Value = serde_json::from_str(line).map_err(|_| anyhow!("помощник завершился без ответа"))?;
    if !data.is_object() {
        bail!("помощник ответил непонятно");
    }
    Ok(data)
}

/// Командная строка чужого процесса (ProcessCommandLineInformation, Windows 8.1+).
pub fn command_line(pid: u32) -> Option<Vec<String>> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buffer = vec![0u8; 8192];
        let mut len = 0u32;
        let status = NtQueryInformationProcess(handle, PROCESSINFOCLASS(60), buffer.as_mut_ptr() as *mut c_void, buffer.len() as u32, &mut len);
        win::close(handle);
        if status.is_err() {
            return None;
        }
        let us = &*(buffer.as_ptr() as *const UNICODE_STRING);
        let text = std::slice::from_raw_parts(us.Buffer.0, (us.Length / 2) as usize);
        let line = wide(&String::from_utf16_lossy(text));
        let mut argc = 0;
        let argv = CommandLineToArgvW(PCWSTR(line.as_ptr()), &mut argc);
        if argv.is_null() {
            return None;
        }
        let args = (0..argc as usize).map(|i| (*argv.add(i)).to_string().unwrap_or_default()).collect();
        let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(argv as *mut c_void)));
        Some(args)
    }
}

/// Аргументы помощника: всё после DeepSecAgent.exe (и после «-m deepsec» у Python-версии).
pub fn helper_args(cmdline: &[String]) -> Vec<String> {
    for (i, part) in cmdline.iter().enumerate() {
        if i == 0 && part.to_lowercase().ends_with("deepsecagent.exe") {
            return cmdline[1..].to_vec();
        }
        if part == "deepsec" && i > 0 && cmdline[i - 1] == "-m" {
            return cmdline[i + 1..].to_vec();
        }
    }
    Vec::new()
}

/// Завершает запущенных помощников этой команды (например, глаз). Возвращает, сколько было.
pub fn stop_helpers(command: &str) -> usize {
    let me = std::process::id();
    let mut count = 0;
    for p in win::processes() {
        if p.pid == me || !p.name.eq_ignore_ascii_case("DeepSecAgent.exe") {
            continue;
        }
        if command_line(p.pid).is_some_and(|c| helper_args(&c).first().map(String::as_str) == Some(command)) {
            unsafe {
                if let Ok(h) = OpenProcess(PROCESS_TERMINATE, false, p.pid) {
                    let _ = TerminateProcess(h, 1);
                    win::close(h);
                    count += 1;
                }
            }
        }
    }
    count
}

// ---------- помощник (сеанс пользователя) ----------

pub fn helper_main(what: &str, args: &[String]) -> i32 {
    unsafe {
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2); // иначе на 125% снимок обрезан
    }
    let data = match what {
        "close" => match (args.first().and_then(|a| a.parse().ok()), args.get(1).and_then(|a| a.parse::<isize>().ok())) {
            (Some(pid), Some(hwnd)) => close_window(pid, hwnd, CLOSE_WAIT),
            _ => json!({"error": "нужны PID и HWND окна"}),
        },
        _ => collect(what),
    };
    println!("{data}");
    0
}

fn collect(what: &str) -> Value {
    let foreground = unsafe { GetForegroundWindow() };
    let locked = input_desktop() != "default";
    let windows = list_windows(foreground);
    let active = windows.iter().find(|w| w["active"] == true).cloned().unwrap_or(Value::Null);
    let mut data = json!({"user": user_name(), "locked": locked, "idle": idle_seconds(), "active": active});
    if what == "screenshot" {
        if locked {
            data["error"] = "экран заблокирован — на нём только окно входа в Windows".into();
        } else {
            match screenshot() {
                Ok((jpeg, size)) => {
                    data["jpeg"] = base64::engine::general_purpose::STANDARD.encode(jpeg).into();
                    data["size"] = json!(size);
                }
                Err(e) => data["error"] = e.to_string().into(),
            }
        }
    } else {
        let window_exes: HashSet<String> = windows.iter().filter_map(|w| w["exe"].as_str()).map(str::to_lowercase).collect();
        let (background, complete) = background(&window_exes, BACKGROUND_BUDGET);
        data["windows"] = Value::Array(windows);
        data["background"] = json!(background);
        if !complete {
            data["background_partial"] = true.into();
        }
    }
    data
}

fn user_name() -> String {
    let mut buffer = [0u16; 257];
    let mut len = buffer.len() as u32;
    unsafe {
        if GetUserNameW(Some(PWSTR(buffer.as_mut_ptr())), &mut len).is_ok() {
            return String::from_utf16_lossy(&buffer[..len.saturating_sub(1) as usize]);
        }
    }
    String::new()
}

fn input_desktop() -> String {
    unsafe {
        // Экран блокировки: к нему у пользователя доступа нет
        let Ok(desktop) = OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) else { return "winlogon".into() };
        let mut buffer = [0u16; 128];
        let mut needed = 0u32;
        let ok = GetUserObjectInformationW(HANDLE(desktop.0), UOI_NAME, Some(buffer.as_mut_ptr() as *mut c_void), 256, Some(&mut needed));
        let _ = CloseDesktop(desktop);
        if ok.is_err() {
            return "winlogon".into();
        }
        let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        String::from_utf16_lossy(&buffer[..len]).to_lowercase()
    }
}

fn idle_seconds() -> f64 {
    let mut info = LASTINPUTINFO { cbSize: size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
    unsafe {
        if !GetLastInputInfo(&mut info).as_bool() {
            return 0.0;
        }
        GetTickCount().wrapping_sub(info.dwTime) as f64 / 1000.0
    }
}

fn screenshot() -> Result<(Vec<u8>, [i32; 2])> {
    let (x, y, w, h) = unsafe {
        (GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN), GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN))
    };
    if w <= 0 || h <= 0 {
        bail!("не удалось узнать размер экрана");
    }
    let mut bgra = vec![0u8; (w * h * 4) as usize];
    unsafe {
        let screen = GetDC(None);
        let mem = CreateCompatibleDC(Some(screen));
        let bitmap = CreateCompatibleBitmap(screen, w, h);
        let old = SelectObject(mem, bitmap.into());
        let copied = BitBlt(mem, 0, 0, w, h, Some(screen), x, y, SRCCOPY | CAPTUREBLT);
        let mut info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: w,
                biHeight: -h, // сверху вниз
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        GetDIBits(mem, bitmap, 0, h as u32, Some(bgra.as_mut_ptr() as *mut c_void), &mut info, DIB_RGB_COLORS);
        SelectObject(mem, old);
        let _ = DeleteObject(bitmap.into());
        let _ = DeleteDC(mem);
        ReleaseDC(None, screen);
        copied.context("не удалось снять экран")?;
    }
    if bgra.chunks_exact(4).all(|p| p[0] < 8 && p[1] < 8 && p[2] < 8) {
        bail!("снимок получился чёрным — вероятно, открыт запрос UAC или защищённый экран");
    }
    let (rgb, tw, th) = downscale(&bgra, w as u32, h as u32, MAX_SIDE);
    let mut jpeg = Vec::new();
    jpeg_encoder::Encoder::new(&mut jpeg, JPEG_QUALITY).encode(&rgb, tw as u16, th as u16, jpeg_encoder::ColorType::Rgb)?;
    Ok((jpeg, [w, h]))
}

/// BGRA → RGB с уменьшением усреднением по площади, если длинная сторона больше max_side.
pub fn downscale(bgra: &[u8], w: u32, h: u32, max_side: u32) -> (Vec<u8>, u32, u32) {
    let scale = (max_side as f64 / w.max(h) as f64).min(1.0);
    let (tw, th) = (((w as f64) * scale).round().max(1.0) as u32, ((h as f64) * scale).round().max(1.0) as u32);
    let mut rgb = vec![0u8; (tw * th * 3) as usize];
    for ty in 0..th {
        let (y0, y1) = ((ty * h / th) as usize, (((ty + 1) * h).div_ceil(th)).min(h) as usize);
        for tx in 0..tw {
            let (x0, x1) = ((tx * w / tw) as usize, (((tx + 1) * w).div_ceil(tw)).min(w) as usize);
            let mut sum = [0u32; 3];
            for y in y0..y1 {
                let row = &bgra[y * w as usize * 4..];
                for x in x0..x1 {
                    sum[0] += row[x * 4 + 2] as u32;
                    sum[1] += row[x * 4 + 1] as u32;
                    sum[2] += row[x * 4] as u32;
                }
            }
            let n = ((y1 - y0) * (x1 - x0)).max(1) as u32;
            let i = ((ty * tw + tx) * 3) as usize;
            rgb[i..i + 3].copy_from_slice(&[(sum[0] / n) as u8, (sum[1] / n) as u8, (sum[2] / n) as u8]);
        }
    }
    (rgb, tw, th)
}

fn window_text(hwnd: HWND) -> String {
    let mut buffer = [0u16; 512];
    let len = unsafe { GetWindowTextW(hwnd, &mut buffer) }.max(0) as usize;
    String::from_utf16_lossy(&buffer[..len])
}

fn exe_name(pid: u32) -> String {
    win::exe_path(pid).map(|p| crate::response::basename(&p).to_string()).unwrap_or_else(|| "?".into())
}

/// Окна, которые видны на панели задач: с заголовком, без владельца, не служебные и не скрытые DWM.
fn list_windows(foreground: HWND) -> Vec<Value> {
    unsafe extern "system" fn visit(hwnd: HWND, lparam: LPARAM) -> windows::core::BOOL {
        let found = unsafe { &mut *(lparam.0 as *mut Vec<HWND>) };
        found.push(hwnd);
        TRUE
    }
    let mut all: Vec<HWND> = Vec::new();
    unsafe {
        let _ = EnumWindows(Some(visit), LPARAM(&mut all as *mut _ as isize));
    }
    let mut result = Vec::new();
    for hwnd in all {
        unsafe {
            if !IsWindowVisible(hwnd).as_bool() || GetWindow(hwnd, GW_OWNER).is_ok_and(|o| !o.is_invalid()) {
                continue;
            }
            if (GetWindowLongW(hwnd, GWL_EXSTYLE) as u32) & WS_EX_TOOLWINDOW.0 != 0 {
                continue;
            }
            let title = window_text(hwnd).trim().to_string();
            let mut class = [0u16; 64];
            let class_len = GetClassNameW(hwnd, &mut class).max(0) as usize;
            let mut cloaked = 0i32;
            let _ = DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, &mut cloaked as *mut _ as *mut c_void, 4);
            if title.is_empty() || String::from_utf16_lossy(&class[..class_len]) == "Progman" || cloaked != 0 {
                continue;
            }
            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            let short: String = title.chars().take(MAX_TITLE).collect();
            result.push(json!({
                "title": short, "exe": exe_name(pid), "pid": pid, "hwnd": hwnd.0 as isize,
                "minimized": IsIconic(hwnd).as_bool(), "active": hwnd == foreground,
            }));
        }
    }
    result
}

fn session_processes() -> Vec<(String, String)> {
    let me = std::process::id();
    let Some(session) = session_of(me) else { return Vec::new() };
    let list = win::processes();
    let parent = list.iter().find(|p| p.pid == me).map(|p| p.ppid).unwrap_or(0);
    list.into_iter()
        .filter(|p| p.pid != me && p.pid != parent && session_of(p.pid) == Some(session))
        .map(|p| {
            let exe = win::exe_path(p.pid).unwrap_or_default();
            (p.name, exe)
        })
        .collect()
}

/// Программы пользователя без окон (трей, фоновые). Процессы Windows и уже показанные окнами — не нужны.
pub fn background_names(processes: &[(String, String)], window_exes: &HashSet<String>, system_root: &str) -> Vec<String> {
    let root = format!("{}\\", system_root.trim_end_matches('\\').to_lowercase());
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    for (name, exe) in processes {
        if name.is_empty() || exe.is_empty() || exe.to_lowercase().starts_with(&root) || window_exes.contains(&name.to_lowercase()) {
            continue;
        }
        names.entry(name.to_lowercase()).or_insert_with(|| name.clone());
    }
    names.into_values().take(MAX_BACKGROUND).collect()
}

/// Не дольше budget: под тяжёлой нагрузкой опрос процессов растягивается на десятки секунд.
fn background(window_exes: &HashSet<String>, budget: Duration) -> (Vec<String>, bool) {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(session_processes());
    });
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    match rx.recv_timeout(budget) {
        Ok(list) => (background_names(&list, window_exes, &root), true),
        Err(_) => (Vec::new(), false),
    }
}

/// Закрывает окно как крестиком (WM_CLOSE) и ждёт. Не закрылось — решает агент: добивать ли процесс.
fn close_window(pid: u32, hwnd: isize, wait: Duration) -> Value {
    let hwnd = HWND(hwnd as *mut c_void);
    unsafe {
        let mut owner = 0u32;
        if !IsWindow(Some(hwnd)).as_bool() || {
            GetWindowThreadProcessId(hwnd, Some(&mut owner));
            owner != pid
        } {
            return json!({"error": "этого окна уже нет — обновите список"}); // заодно защита от чужого PID
        }
        let info = json!({"exe": exe_name(pid), "title": window_text(hwnd).chars().take(MAX_TITLE).collect::<String>(),
            "path": win::exe_path(pid).unwrap_or_default()});
        let _ = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0));
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            if !IsWindow(Some(hwnd)).as_bool() || win::exe_path(pid).is_none() {
                let mut done = info.clone();
                done["closed"] = true.into();
                return done;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let mut stuck = info;
        stuck["closed"] = false.into();
        stuck
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_takes_last_json_line() {
        assert_eq!(parse_output(b"warning\r\n{\"user\": \"me\"}\r\n").unwrap()["user"], "me");
        assert!(parse_output(b"Traceback ...").is_err());
        assert!(parse_output(b"").is_err());
    }

    #[test]
    fn helper_args_from_command_line() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(helper_args(&v(&[r"C:\Program Files\DeepSec\DeepSecAgent.exe", "pet", "watch"])), v(&["pet", "watch"]));
        assert_eq!(helper_args(&v(&["python.exe", "-m", "deepsec", "pet", "sleep"])), v(&["pet", "sleep"]));
        assert!(helper_args(&v(&["notepad.exe", "pet.txt"])).is_empty());
    }

    #[test]
    fn background_skips_windows_and_windowed_apps() {
        let p = |n: &str, e: &str| (n.to_string(), e.to_string());
        let procs = vec![
            p("svchost.exe", r"C:\Windows\System32\svchost.exe"),
            p("steam.exe", r"C:\Program Files (x86)\Steam\steam.exe"),
            p("chrome.exe", r"C:\Program Files\Google\Chrome\chrome.exe"),
            p("Discord.exe", r"C:\Users\me\AppData\Local\Discord\Discord.exe"),
            p("Discord.exe", r"C:\Users\me\AppData\Local\Discord\Discord.exe"),
            p("secret.exe", ""),
        ];
        let windows: HashSet<String> = ["chrome.exe".to_string()].into();
        assert_eq!(background_names(&procs, &windows, r"C:\Windows"), vec!["Discord.exe", "steam.exe"]);
    }

    #[test]
    fn downscale_keeps_aspect_and_colors() {
        let bgra = [10u8, 20, 30, 255].repeat(4000 * 2);
        let (rgb, w, h) = downscale(&bgra, 4000, 2, 2000);
        assert_eq!((w, h), (2000, 1));
        assert_eq!(&rgb[..3], &[30, 20, 10]);
    }

    #[test]
    fn own_command_line_is_readable() {
        let args = command_line(std::process::id()).unwrap();
        assert!(args[0].to_lowercase().contains("deepsecagent"));
    }

    /// cargo test -- --ignored: в сеансе пользователя помощник видит окна и снимает экран.
    #[test]
    #[ignore]
    fn real_desktop() {
        let apps = collect("apps");
        println!("apps: {} windows, background {}", apps["windows"].as_array().unwrap().len(), apps["background"]);
        let started = Instant::now();
        let shot = collect("screenshot");
        println!("screenshot: {:?} in {:?}, jpeg {} KB", shot["size"], started.elapsed(), shot["jpeg"].as_str().map_or(0, |s| s.len() * 3 / 4 / 1024));
        assert!(shot["jpeg"].is_string(), "{shot}");
    }
}
