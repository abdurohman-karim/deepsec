//! Связь агента с сервером: постоянный WebSocket, переподключение, доставка инцидентов с подтверждением.
//!
//! TLS с закреплённым отпечатком: сертификат сервера самоподписанный, проверяем только его SHA-256 —
//! подменить сервер нельзя, а домен и удостоверяющий центр не нужны.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;

use crate::config::Config;
use crate::incidents::Incident;
use crate::protocol::{AUTH_HEADER, HEARTBEAT, NAME_HEADER, normalize_fingerprint};
use crate::state::Outbox;

/// (ok, текст для владельца, данные) — ответ на команду сервера.
pub type CommandResult = (bool, String, Value);
pub type CommandFuture = Pin<Box<dyn Future<Output = CommandResult> + Send>>;
pub type CommandHandler = Arc<dyn Fn(String, Value) -> CommandFuture + Send + Sync>;
pub type StatusFn = Arc<dyn Fn() -> Value + Send + Sync>;

/// Если от сервера три интервала подряд ничего не пришло (даже ping) — соединение мёртвое, переподключаемся.
const SILENCE_LIMIT: Duration = Duration::from_secs(HEARTBEAT * 3);

pub struct Link {
    cfg: Config,
    outbox: Mutex<Outbox>,
    wake: Notify,
    pub connected: AtomicBool,
}

impl Link {
    pub fn new(cfg: Config, outbox: Outbox) -> Link {
        Link { cfg, outbox: Mutex::new(outbox), wake: Notify::new(), connected: AtomicBool::new(false) }
    }

    pub fn send_incident(&self, inc: &Incident, armed: bool) {
        let message = json!({"type": "incident", "incident": inc.to_json(), "armed": armed});
        self.outbox.lock().unwrap().add(&inc.id, message);
        self.wake.notify_one();
    }

    pub fn push_status(&self) {
        self.wake.notify_one();
    }

    pub async fn run(self: Arc<Self>, handler: CommandHandler, status: StatusFn) {
        let mut delay = 1;
        loop {
            match self.session(&handler, &status).await {
                Ok(()) => delay = 1,
                Err(e) if e.downcast_ref::<FingerprintMismatch>().is_some() => {
                    log::error!("Отпечаток сертификата сервера не совпал — возможна подмена сервера!")
                }
                Err(e) => log::warn!("Нет связи с сервером: {e:#}"),
            }
            self.connected.store(false, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(delay)).await;
            delay = (delay * 2).min(60);
        }
    }

    async fn session(&self, handler: &CommandHandler, status: &StatusFn) -> Result<()> {
        let mut request = self.cfg.server_url.as_str().into_client_request()?;
        let headers = request.headers_mut();
        headers.insert(AUTH_HEADER, HeaderValue::from_str(&format!("Bearer {}", self.cfg.agent_token))?);
        headers.insert(NAME_HEADER, HeaderValue::from_str(&self.cfg.agent_name).unwrap_or(HeaderValue::from_static("PC")));
        let host = request.uri().host().context("в SERVER_URL нет адреса")?.trim_matches(['[', ']']).to_string();
        let port = request.uri().port_u16().unwrap_or(if request.uri().scheme_str() == Some("wss") { 443 } else { 80 });
        let tcp = tokio::time::timeout(Duration::from_secs(20), TcpStream::connect((host.as_str(), port)))
            .await
            .context("сервер не отвечает")??;
        tcp.set_nodelay(true)?;

        if request.uri().scheme_str() == Some("wss") {
            let fingerprint = normalize_fingerprint(&self.cfg.server_fingerprint);
            let config = rustls::ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedCert { fingerprint }))
                .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let tls = connector.connect(ServerName::try_from(host)?, tcp).await.map_err(unwrap_mismatch)?;
            let (ws, _) = tokio_tungstenite::client_async(request, tls).await?;
            self.serve(ws, handler, status).await
        } else {
            // ws:// — только для тестов на localhost
            let (ws, _) = tokio_tungstenite::client_async(request, tcp).await?;
            self.serve(ws, handler, status).await
        }
    }

    async fn serve<S>(&self, ws: tokio_tungstenite::WebSocketStream<S>, handler: &CommandHandler, status: &StatusFn) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        log::info!("Подключён к серверу {}", self.cfg.server_url);
        self.connected.store(true, Ordering::SeqCst);
        let (mut sink, mut stream) = ws.split();
        // Результаты команд приходят из задач, отправляет их этот же цикл — у WebSocket один писатель
        let (results_tx, mut results) = mpsc::unbounded_channel::<Value>();
        sink.send(text(json!({"type": "hello", "status": status()}))).await?;
        let mut sent: std::collections::HashSet<String> = Default::default();
        let mut heartbeat = tokio::time::interval(Duration::from_secs(HEARTBEAT));
        heartbeat.tick().await;

        loop {
            for (key, message) in self.outbox.lock().unwrap().items() {
                if sent.insert(key) {
                    results_tx.send(message).ok();
                }
            }
            tokio::select! {
                incoming = tokio::time::timeout(SILENCE_LIMIT, stream.next()) => {
                    let Some(msg) = incoming.context("сервер молчит — соединение потеряно")? else { bail!("сервер закрыл соединение") };
                    match msg? {
                        Message::Text(raw) => self.dispatch(&raw, handler, status, &results_tx),
                        Message::Close(_) => bail!("сервер закрыл соединение"),
                        _ => {} // ping/pong tungstenite обрабатывает сам
                    }
                }
                Some(message) = results.recv() => sink.send(text(message)).await?,
                _ = self.wake.notified() => sink.send(text(json!({"type": "status", "status": status()}))).await?,
                _ = heartbeat.tick() => sink.send(text(json!({"type": "status", "status": status()}))).await?,
            }
        }
    }

    fn dispatch(&self, raw: &str, handler: &CommandHandler, status: &StatusFn, results: &mpsc::UnboundedSender<Value>) {
        let Ok(data) = serde_json::from_str::<Value>(raw) else { return };
        match data["type"].as_str() {
            Some("ack") => self.outbox.lock().unwrap().ack(data["id"].as_str().unwrap_or_default()),
            Some("command") => {
                let (handler, status, results) = (handler.clone(), status.clone(), results.clone());
                let action = data["action"].as_str().unwrap_or_default().to_string();
                let args = if data["args"].is_object() { data["args"].clone() } else { json!({}) };
                let id = data["id"].clone();
                tokio::spawn(async move {
                    let started = std::time::Instant::now();
                    let (ok, text_, payload) = handler(action.clone(), args).await;
                    // Время и итог каждой команды: по ним видно, если ПК тормозит или помощник завис
                    let took = started.elapsed().as_secs_f64();
                    if ok {
                        log::info!("Команда {action} выполнена за {took:.1} с");
                    } else {
                        log::warn!("Команда {action} не удалась за {took:.1} с: {text_}");
                    }
                    let message = json!({"type": "result", "id": id, "ok": ok, "text": text_, "data": payload, "status": status()});
                    if results.send(message).is_err() {
                        log::warn!("Не удалось отправить результат команды — связь пропала");
                    }
                });
            }
            _ => {}
        }
    }
}

fn text(value: Value) -> Message {
    Message::text(value.to_string())
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

#[derive(Debug)]
struct FingerprintMismatch;

impl std::fmt::Display for FingerprintMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("отпечаток сертификата сервера не совпал")
    }
}

impl std::error::Error for FingerprintMismatch {}

fn unwrap_mismatch(e: std::io::Error) -> anyhow::Error {
    if e.to_string().contains("FingerprintMismatch") || e.to_string().contains("отпечаток") {
        anyhow::Error::new(FingerprintMismatch)
    } else {
        e.into()
    }
}

/// Принимает только сертификат с закреплённым SHA-256; подписи рукопожатия проверяются как обычно.
#[derive(Debug)]
struct PinnedCert {
    fingerprint: String,
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if hex::encode(Sha256::digest(end_entity.as_ref())) == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("отпечаток сертификата сервера не совпал".into()))
        }
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &provider().signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &provider().signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider().signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incidents::{Kind, Severity};
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    fn cfg(url: String, token: &str) -> Config {
        let mut c = crate::detector::tests::cfg();
        c.server_url = url;
        c.agent_token = token.into();
        c
    }

    /// Сквозной тест, как test_link.py: настоящий WebSocket на localhost.
    #[tokio::test(flavor = "multi_thread")]
    async fn incident_delivery_and_command_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/agent", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut headers = (String::new(), String::new());
            let ws = tokio_tungstenite::accept_hdr_async(tcp, |req: &Request, resp: Response| {
                headers = (
                    req.headers()[AUTH_HEADER].to_str().unwrap().to_string(),
                    req.headers()[NAME_HEADER].to_str().unwrap().to_string(),
                );
                Ok(resp)
            })
            .await
            .unwrap();
            let (mut sink, mut stream) = ws.split();
            let mut seen = Vec::new();
            while let Some(Ok(Message::Text(raw))) = stream.next().await {
                let data: Value = serde_json::from_str(&raw).unwrap();
                seen.push(data["type"].as_str().unwrap().to_string());
                match data["type"].as_str().unwrap() {
                    "incident" => {
                        sink.send(Message::text(json!({"type": "ack", "id": data["incident"]["id"]}).to_string())).await.unwrap();
                        sink.send(Message::text(json!({"type": "command", "id": "c1", "action": "lock", "args": {}}).to_string())).await.unwrap();
                    }
                    "result" => return (headers, seen, data),
                    _ => {}
                }
            }
            panic!("агент отключился");
        });

        let link = Arc::new(Link::new(cfg(url, "secret-token"), Outbox::new(None, 200)));
        // Инцидент случился, пока сети не было — должен дойти после подключения
        let inc = Incident::new(Kind::TdataAccess, Severity::Critical, "кража");
        link.send_incident(&inc, true);
        let handler: CommandHandler = Arc::new(|action, _args| Box::pin(async move { (true, format!("выполнено {action}"), Value::Null) }));
        let status: StatusFn = Arc::new(|| json!({"armed": true}));
        let task = tokio::spawn(link.clone().run(handler, status));
        let ((auth, name), seen, result) = tokio::time::timeout(Duration::from_secs(10), server).await.unwrap().unwrap();
        task.abort();
        assert_eq!((auth.as_str(), name.as_str()), ("Bearer secret-token", "HOME-PC"));
        assert_eq!(&seen[..2], ["hello", "incident"]);
        assert_eq!(result["text"], "выполнено lock");
        assert_eq!(result["status"]["armed"], true);
        assert!(link.outbox.lock().unwrap().items().is_empty()); // сервер подтвердил получение
    }

    #[test]
    fn pinned_certificate() {
        let der = CertificateDer::from(b"fake certificate".to_vec());
        let good = PinnedCert { fingerprint: hex::encode(Sha256::digest(b"fake certificate")) };
        let name = ServerName::try_from("203.0.113.10").unwrap();
        assert!(good.verify_server_cert(&der, &[], &name, &[], UnixTime::now()).is_ok());
        let bad = PinnedCert { fingerprint: "00".repeat(32) };
        assert!(bad.verify_server_cert(&der, &[], &name, &[], UnixTime::now()).is_err());
    }
}
