use crate::config::Config;
use clap::{Arg, ArgAction, Command};
use log::info;
use std::io;

mod api;
mod common;
mod config;
mod proxy;

//#[global_allocator]
//static ALLOC: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

fn main() -> io::Result<()> {
    let matches = Command::new("v2ray-rust")
        .version("v0.0.1")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .required(true)
                .help(".toml config file name"),
        )
        .arg(
            Arg::new("validate")
                .short('t')
                .long("test")
                .required(false)
                .action(ArgAction::SetTrue)
                .help("validate given toml config file"),
        )
        .author("Developed by @darsvador")
        .about("An opinionated lightweight implementation of V2Ray, in rust programming language")
        .get_matches();
    #[cfg(debug_assertions)]
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("v2ray_rust=debug,info"));
    #[cfg(not(debug_assertions))]
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let filename = matches.get_one::<String>("config").unwrap().to_string();
    if matches.get_flag("validate") {
        let _ = Config::read_from_file(filename)?;
        info!("A valid config file.");
        return Ok(());
    }
    let c = Config::read_from_file(filename)?;
    c.build_server()?.run()
}
