extern crate core;

use crate::config::Config;
use clap::{Arg, Command};
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
                .takes_value(true)
                .help(".toml config file name"),
        )
        .arg(
            Arg::new("validate")
                .short('t')
                .long("test")
                .required(false)
                .help("validate given toml config file"),
        )
        .author("Developed by @darsvador")
        .about("An opinionated lightweight implementation of V2Ray, in rust programming language")
        .get_matches();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let filename = matches.value_of("config").unwrap().to_string();
    if matches.is_present("validate") {
        let _ = Config::read_from_file(filename)?;
        info!("A valid config file.");
        return Ok(());
    }
    let c = Config::read_from_file(filename)?;
    c.build_server()?.run()
}
