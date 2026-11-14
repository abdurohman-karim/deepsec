//! DeepSec — Windows-агент защиты сессий Telegram Desktop (Rust-версия Python-агента deepsec/).
//!
//! Команды и файлы те же, что у Python-агента, — установщик, задача планировщика и сервер не меняются:
//! run, setup, check, uninstall, version, ui, update, desktop, pet.

mod agent;
mod brand;
mod config;
mod control;
mod desktop;
mod detector;
mod eventlog;
mod incidents;
mod link;
mod logger;
mod monitors;
mod pet;
mod protocol;
mod response;
mod setup;
mod state;
mod trust;
mod update;
mod win;
mod window;
mod winacl;
mod winevent;

use std::time::Duration;

use clap::{Parser, Subcommand};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "DeepSecAgent", version = VERSION, about = "Windows-агент DeepSec (бот — на сервере)")]
struct Cli {
    /// Ждать Enter перед выходом (окно консоли не закроется).
    #[arg(long, global = true)]
    pause: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Запустить агента (обычно это делает планировщик от SYSTEM).
    Run,
    /// Установка: аудит, ловушки, подключение к серверу, автозапуск.
    Setup {
        /// IP или домен сервера.
        #[arg(long, default_value = "")]
        server: String,
        /// Порт агентов (LISTEN_PORT на сервере).
        #[arg(long, default_value = "")]
        port: String,
        /// SHA-256 отпечаток сертификата сервера.
        #[arg(long, default_value = "")]
        fingerprint: String,
        /// AGENT_TOKEN с сервера.
        #[arg(long, default_value = "")]
        token: String,
        /// Имя компьютера в боте.
        #[arg(long, default_value = "")]
        name: String,
        /// Не задавать вопросов (для установщика).
        #[arg(long)]
        yes: bool,
    },
    /// Диагностика: где tdata, кем подписан Telegram.exe.
    Check,
    /// Убрать задачу, правила брандмауэра, ловушки и настройки.
    Uninstall,
    /// Версия.
    Version,
    /// Окно DeepSec: состояние агента и обновление с прогрессом.
    Ui {
        /// Служебная: после обновления из окна.
        #[arg(long, default_value = "")]
        updated_from: String,
    },
    /// Поставить новую версию из релизов GitHub, сохранив настройки (от администратора).
    Update,
    /// Служебная: агент запускает её в сеансе пользователя.
    Desktop {
        #[arg(value_parser = ["screenshot", "apps", "close"])]
        what: String,
        /// Для close: PID и HWND окна.
        args: Vec<String>,
    },
    /// Пиксельный «Большой глаз» в углу экрана (агент запускает его по команде из бота).
    Pet {
        #[arg(value_parser = protocol::PET_MOODS)]
        mood: String,
        /// Своя надпись вместо стандартной.
        #[arg(long, default_value = "")]
        text: String,
        /// Через сколько минут исчезнуть.
        #[arg(long, default_value_t = 120.0)]
        minutes: f64,
    },
}

fn run() -> anyhow::Result<i32> {
    let cfg = config::Config::load()?;
    let _ = std::fs::create_dir_all(&cfg.data_dir);
    logger::init(cfg.data_dir.join("agent.log"), true);
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    loop {
        let agent = agent::Agent::new(cfg.clone());
        if let Err(e) = runtime.block_on(agent.run()) {
            log::error!("Агент упал — перезапуск через 10 секунд: {e:#}");
        }
        std::thread::sleep(Duration::from_secs(10));
    }
}

fn dispatch(command: Command) -> anyhow::Result<i32> {
    match command {
        Command::Run => run(),
        Command::Setup { server, port, fingerprint, token, name, yes } => {
            setup::setup(&setup::SetupOptions { server, port, fingerprint, token, name, yes })
        }
        Command::Check => setup::check(),
        Command::Uninstall => setup::uninstall(),
        Command::Update => setup::update_console(),
        Command::Version => {
            println!("{VERSION}");
            Ok(0)
        }
        Command::Ui { updated_from } => Ok(window::main(&updated_from)),
        Command::Desktop { what, args } => Ok(desktop::helper_main(&what, &args)),
        Command::Pet { mood, text, minutes } => Ok(pet::main(&mood, &text, minutes)),
    }
}

fn main() {
    let cli = Cli::parse();
    let code = match dispatch(cli.command) {
        Ok(code) => code,
        // Из установщика окно закроется — покажем причину по-человечески
        Err(e) => {
            if cli.pause {
                println!("\n⛔ Ошибка: {e:#}");
            } else {
                eprintln!("{e:#}");
            }
            1
        }
    };
    if cli.pause {
        println!("\nНажмите Enter, чтобы закрыть окно…");
        let _ = std::io::stdin().read_line(&mut String::new());
    }
    std::process::exit(code);
}
