use crate::common::new_error;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::path::Path;

pub mod tls;

// fn load_cert(path: &Path) -> io::Result<Vec<Certificate>> {
//     pemfile::certs(&mut BufReader::new(File::open(path)?))
//         .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid tls cert"))
// }
//
// fn load_key(path: &Path) -> io::Result<Vec<PrivateKey>> {
//     let pkcs8_key = pemfile::pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
//         .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid tls pkcs8 key"))?;
//     if pkcs8_key.len() != 0 {
//         return Ok(pkcs8_key);
//     }
//     let rsa_key = pemfile::rsa_private_keys(&mut BufReader::new(File::open(path)?))
//         .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid tls rsa key"))?;
//     if rsa_key.len() != 0 {
//         return Ok(rsa_key);
//     }
//     return Err(new_error("no valid key found"));
// }
