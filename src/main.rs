use clap::Parser;

fn main() {
    let cli = boab::cli::Cli::parse();
    let code = boab::run(cli);
    std::process::exit(code);
}
