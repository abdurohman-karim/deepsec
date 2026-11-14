//! Локальный канал агента для окна DeepSec: http://127.0.0.1:47231 — только с этого компьютера.
//!
//! Окно работает от пользователя и без прав администратора, а обновляет агент (SYSTEM): окно просит его
//! проверить, скачать или установить обновление и показывает прогресс. Через канал можно только это — и
//! поставить только опубликованный релиз с совпавшим SHA-256, так что вреда от чужого запроса нет.
//! От веб-страниц канал закрыт: нужен свой заголовок, а запросы браузера с Origin отклоняются.

use std::io::Read;
use std::time::Duration;

use anyhow::{Result, anyhow};
use serde_json::{Value, json};
use tiny_http::{Header, Method, Response, Server};

use crate::protocol::{LOCAL_HEADER, LOCAL_PORT};
use crate::update::Updater;

fn has_header(request: &tiny_http::Request, name: &str, value: Option<&str>) -> bool {
    request
        .headers()
        .iter()
        .any(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name) && value.is_none_or(|v| h.value.as_str() == v))
}

fn handle(updater: &Updater, runtime: &tokio::runtime::Handle, method: &Method, path: &str, window: bool) -> (u16, Value) {
    if !window {
        return (403, json!({"error": "forbidden"}));
    }
    match (method, path) {
        (Method::Get, "/update") => (200, updater.snapshot()),
        (Method::Post, "/update/check") => {
            runtime.block_on(updater.check());
            (200, updater.snapshot())
        }
        (Method::Post, "/update/download") => {
            let _guard = runtime.enter(); // start() запускает задачу в рантайме агента
            updater.start(false);
            (200, updater.snapshot())
        }
        (Method::Post, "/update/install") => match runtime.block_on(updater.install(true)) {
            Ok(()) => (200, updater.snapshot()),
            Err(e) => {
                let mut snap = updater.snapshot();
                snap["error"] = format!("{e:#}").into();
                (409, snap)
            }
        },
        _ => (404, json!({"error": "not found"})),
    }
}

/// Держит канал, пока работает агент. Порт занят — окно просто не сможет обновлять, защита работает.
pub fn serve(updater: Updater, runtime: tokio::runtime::Handle) {
    let server = match Server::http(("127.0.0.1", LOCAL_PORT)) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("Локальный канал для окна DeepSec не открыт (порт {LOCAL_PORT}): {e}");
            return;
        }
    };
    for mut request in server.incoming_requests() {
        let mut body = Vec::new();
        let _ = request.as_reader().take(4096).read_to_end(&mut body);
        let window = has_header(&request, LOCAL_HEADER, Some("1")) && !has_header(&request, "Origin", None);
        let (code, value) = handle(&updater, &runtime, request.method(), request.url(), window);
        let response = Response::from_string(value.to_string())
            .with_status_code(code)
            .with_header(Header::from_bytes("Content-Type", "application/json; charset=utf-8").unwrap());
        let _ = request.respond(response);
    }
}

/// Запрос окна к агенту. Err — агент не запущен или канал недоступен.
pub fn call(path: &str, post: bool, timeout: Duration) -> Result<Value> {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(timeout)).http_status_as_error(false).build().into();
    let url = format!("http://127.0.0.1:{LOCAL_PORT}{path}");
    let mut response = if post {
        agent.post(&url).header(LOCAL_HEADER, "1").send_empty()
    } else {
        agent.get(&url).header(LOCAL_HEADER, "1").call()
    }
    .map_err(|e| anyhow!("{e}"))?;
    // 409 и т.п. — в теле тот же снимок состояния с ошибкой
    response.body_mut().read_json().map_err(|e| anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test(flavor = "multi_thread")]
    async fn channel_only_for_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let updater = Updater::new("0.7.0", dir.path(), "abdurohman-karim/deepsec", Arc::new(|| {}));
        let runtime = tokio::runtime::Handle::current();
        let snap = tokio::task::spawn_blocking(move || {
            let window = handle(&updater, &runtime, &Method::Get, "/update", true);
            let stranger = handle(&updater, &runtime, &Method::Get, "/update", false);
            let early = handle(&updater, &runtime, &Method::Post, "/update/install", true);
            (window, stranger, early)
        })
        .await
        .unwrap();
        let ((ok, state), (forbidden, _), (conflict, early)) = snap;
        assert_eq!((ok, state["version"].as_str()), (200, Some("0.7.0")));
        assert_eq!(forbidden, 403); // без заголовка окна или со страницы браузера
        assert!(conflict == 409 && early["error"].as_str().unwrap().contains("сначала скачайте"));
    }
}
