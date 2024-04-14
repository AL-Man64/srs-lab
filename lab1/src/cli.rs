use clap::{Parser, Subcommand};

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Init {
        master_password: String,
    },
    Put {
        master_password: String,
        address: String,
        password: String,
    },
    Get {
        master_password: String,
        address: String,
    },
}
