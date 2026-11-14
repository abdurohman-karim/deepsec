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
    /// Версия.
    Version,
    /// Служебная: агент запускает её в сеансе пользователя.
    Desktop {
        #[arg(value_parser = ["screenshot", "apps", "close"])]
        what: String,
        /// Для close: PID и HWND окна.
        args: Vec<String>,
    },
    /// Окно DeepSec: состояние агента и обновление с прогрессом.
    Ui {
        /// Служебная: после обновления из окна.
        #[arg(long, default_value = "")]
        updated_from: String,
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

fn run() -> i32 {
    let cfg = match config::Config::load() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("{e:#}");
            return 1;
        }
    };
    let _ = std::fs::create_dir_all(&cfg.data_dir);
    logger::init(cfg.data_dir.join("agent.log"), true);
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio");
    loop {
        let agent = agent::Agent::new(cfg.clone());
        if let Err(e) = runtime.block_on(agent.run()) {
            log::error!("Агент упал — перезапуск через 10 секунд: {e:#}");
        }
        std::thread::sleep(Duration::from_secs(10));
    }
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Run => run(),
        Command::Version => {
            println!("{VERSION}");
            0
        }
        Command::Desktop { what, args } => desktop::helper_main(&what, &args),
        Command::Pet { mood, text, minutes } => pet::main(&mood, &text, minutes),
        Command::Ui { updated_from } => window::main(&updated_from),
    };
    if cli.pause {
        println!("\nНажмите Enter, чтобы закрыть окно…");
        let _ = std::io::stdin().read_line(&mut String::new());
    }
    std::process::exit(code);
}
