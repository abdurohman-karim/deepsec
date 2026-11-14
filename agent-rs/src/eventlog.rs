//! Подписка в реальном времени на журнал Security через EvtSubscribe (нужны права администратора/SYSTEM).

use std::ffi::c_void;

use anyhow::Result;
use tokio::sync::mpsc::UnboundedSender;
use windows::Win32::System::EventLog::{
    EVT_HANDLE, EVT_SUBSCRIBE_NOTIFY_ACTION, EvtClose, EvtRender, EvtRenderEventXml, EvtSubscribe, EvtSubscribeActionDeliver,
    EvtSubscribeToFutureEvents,
};
use windows::core::{PCWSTR, w};

use crate::win::wide;

/// 4663 — доступ к объекту (наш SACL на tdata), 4624/4625 — входы, 4719 — изменена политика аудита,
/// 1102 — журнал очищен.
const QUERY: &str = "*[System[(EventID=4663 or EventID=4624 or EventID=4625 or EventID=4719 or EventID=1102)]]";

pub struct Subscription {
    handle: EVT_HANDLE,
    sender: *mut UnboundedSender<String>,
}

// Указатель на отправителя живёт, пока жива подписка; сам отправитель потокобезопасен
unsafe impl Send for Subscription {}

impl Subscription {
    /// События приходят из потока Windows — отправляем XML в канал агента.
    pub fn start(sender: UnboundedSender<String>) -> Result<Subscription> {
        let sender = Box::into_raw(Box::new(sender));
        let query = wide(QUERY);
        let handle = unsafe {
            EvtSubscribe(
                None,
                None,
                w!("Security"),
                PCWSTR(query.as_ptr()),
                None,
                Some(sender as *const c_void),
                Some(on_event),
                EvtSubscribeToFutureEvents.0,
            )
        };
        match handle {
            Ok(handle) => Ok(Subscription { handle, sender }),
            Err(e) => {
                drop(unsafe { Box::from_raw(sender) });
                Err(e.into())
            }
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        unsafe {
            let _ = EvtClose(self.handle);
            drop(Box::from_raw(self.sender));
        }
    }
}

unsafe extern "system" fn on_event(action: EVT_SUBSCRIBE_NOTIFY_ACTION, context: *const c_void, event: EVT_HANDLE) -> u32 {
    let sender = unsafe { &*(context as *const UnboundedSender<String>) };
    if action != EvtSubscribeActionDeliver {
        log::error!("Ошибка подписки на журнал Security: код {}", event.0 as usize);
        return 0;
    }
    match render_xml(event) {
        Some(xml) => {
            let _ = sender.send(xml);
        }
        None => log::error!("EvtRender не смог отрисовать событие"),
    }
    0
}

fn render_xml(event: EVT_HANDLE) -> Option<String> {
    let (mut used, mut count) = (0u32, 0u32);
    unsafe {
        // Первый вызов — узнать размер буфера (в байтах)
        let _ = EvtRender(None, event, EvtRenderEventXml.0, 0, None, &mut used, &mut count);
        let mut buffer = vec![0u16; (used as usize).div_ceil(2)];
        EvtRender(None, event, EvtRenderEventXml.0, used, Some(buffer.as_mut_ptr() as *mut c_void), &mut used, &mut count).ok()?;
        let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        Some(String::from_utf16_lossy(&buffer[..len]))
    }
}
