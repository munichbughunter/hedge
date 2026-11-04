mod config;

fn main() {
    match config::Config::load("hedge.toml") {
        Ok(cfg) => {
            println!("{:#?}", cfg)
        }
        Err(e) => {
            eprintln!("hedge: Configuration can not be loaded: {e}");
            std::process::exit(1);
        }
    }
}
