mod audit;
mod classifier;
mod git;
mod layer1;
mod layer2;
mod layer3;
mod layer4;
mod report;
mod types;

use clap::{Parser, Subcommand};
use colored::*;
use dotenv::dotenv;

#[derive(Parser)]
#[command(
    name = "limbo_sui",
    about = "Your Move contract won't leave the same.",
    version = "0.1.0",
    long_about = None
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

        /// Output directory for limbo.report.md (default: current dir)
        #[arg(short, long, default_value = ".")]
        output: String,
    },
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    print_banner();

    let cli = Cli::parse();

    match cli.command {
        Commands::Audit { target, output } => {
            audit::run(target, output).await;
        }
    }
}

fn print_banner() {
    println!();
    println!("{}", "  ██╗     ██╗███╗   ███╗██████╗  ██████╗ ".red().bold());
    println!("{}", "  ██║     ██║████╗ ████║██╔══██╗██╔═══██╗".red().bold());
    println!("{}", "  ██║     ██║██╔████╔██║██████╔╝██║   ██║".red().bold());
    println!("{}", "  ██║     ██║██║╚██╔╝██║██╔══██╗██║   ██║".red().bold());
    println!("{}", "  ███████╗██║██║ ╚═╝ ██║██████╔╝╚██████╔╝".red().bold());
    println!("{}", "  ╚══════╝╚═╝╚═╝     ╚═╝╚═════╝  ╚═════╝ ".red().bold());
    println!();
    println!("  {} {}", "limbo_sui".white().bold(), "v0.1.0".dimmed());
    println!("  {}", "Your Move contract won't leave the same.".dimmed());
    println!();
}
