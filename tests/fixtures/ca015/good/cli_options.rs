use clap::{Args, Parser};

// Command-line options: the shell already holds them and the process exits after use.
#[derive(Parser)]
struct CliOpts {
    admin_password: String,
}

#[derive(Args)]
struct AddArgs {
    password: String,
}
