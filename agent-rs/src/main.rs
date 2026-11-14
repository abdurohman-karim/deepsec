//! DeepSec — Windows-агент защиты сессий Telegram Desktop (Rust-версия Python-агента deepsec/).
//!
//! Команды и файлы те же, что у Python-агента, — установщик, задача планировщика и сервер не меняются:
//! run, setup, check, uninstall, version, ui, update, desktop, pet.

mod config;
mod detector;
mod incidents;
mod monitors;
mod protocol;
mod state;
mod trust;
mod winevent;

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
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Run => {
            eprintln!("Rust-агент ещё в разработке — работает Python-агент из установщика");
            1
        }
        Command::Version => {
            println!("{VERSION}");
            0
        }
    };
    if cli.pause {
        println!("\nНажмите Enter, чтобы закрыть окно…");
        let _ = std::io::stdin().read_line(&mut String::new());
    }
    std::process::exit(code);
}
