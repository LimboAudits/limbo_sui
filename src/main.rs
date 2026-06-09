mod audit;
mod exploit;
mod git;
mod layer1;
mod layer3;
mod layer4;
mod report;
mod types;

use clap::{Parser, Subcommand};
use colored::*;
use dotenv::dotenv;

#[derive(Parser)]
#[command(
    name = "limbo",
    about = "Smart contract security auditor for Sui Move",
    version = "0.2.0",
    long_about = None,
    disable_version_flag = false,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Audit a Move contract or repository
    Audit {
        /// GitHub URL, local path, or .move file
        target: String,

        /// Output directory for limbo.report.md
        #[arg(short, long, default_value = ".")]
        output: String,

        /// Skip exploit verification (faster, less accurate)
        #[arg(long, default_value = "false")]
        no_exploit: bool,
    },
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    print_header();

    let cli = Cli::parse();

    match cli.command {
        Commands::Audit {
            target,
            output,
            no_exploit,
        } => {
            audit::run(target, output, no_exploit).await;
        }
    }
}

fn print_header() {
    println!();
    println!(
        "  {} {}",
        "◆ limbo".bold().white(),
        "v0.2.0".dimmed()
    );
    println!(
        "  {}",
        "Sui Move Security Auditor".dimmed()
    );
    println!(
        "  {}",
        "─────────────────────────────────────".dimmed()
    );
    println!();
}
