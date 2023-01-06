//! # nvd
//! Some functions about CPE and CVE
//!
//! # Usage
//! Add this to your *Cargo.toml*:
//! ```toml
//! [dependencies]
//! nvd = "0.1"
//! ```
//!
//! ### Examples
//! ```rust
//!
//! use std::{env, process};
//!
//! use nvd::{
//!     cpe::{download_cpe, make_cpe_dictionary, make_cpe_title},
//!     cve::{
//!         cpe23_uri_list_to_string, cpe_match, init_dir, load_db, make_db, sync_cve, Cpe23Uri,
//!         DATA_DIR,
//!     },
//! };
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     log_init();
//!     let args: Vec<String> = env::args().collect();
//!     if args.len() != 2 {
//!         log::error!("arguments error!");
//!         log::error!("eg: {} [cve|cpe]", args[0]);
//!         process::exit(1);
//!     }
//!     if "cve".eq(&args[1]) {
//!         cve().await?;
//!     } else if "cpe".eq(&args[1]) {
//!         cpe().await?;
//!     } else {
//!         log::error!("arguments error!");
//!         log::error!("eg: {} [cve|cpe]", args[0]);
//!     }
//!     Ok(())
//! }
//!
//! async fn cve() -> Result<(), Box<dyn std::error::Error>> {
//!     let path_dir = init_dir(DATA_DIR).await?;
//!     let _ = sync_cve(&path_dir).await?;
//!     let _ = make_db(&path_dir).await?;
//!     let db_list = load_db(&path_dir).await?;
//!     log::info!("db_list len: {}", db_list.len());
//!     let mut cpe23_uri_vec = Vec::new();
//!     let line = "cpe:2.3:a:vmware:rabbitmq:3.9.10:*:*:*:*:*:*:*";
//!     let cpe23_uri = Cpe23Uri::new(line);
//!     cpe23_uri_vec.push(cpe23_uri);
//!     log::info!("cpe23_uri: {}", cpe23_uri_list_to_string(&cpe23_uri_vec));
//!     cpe_match(&cpe23_uri_vec, &db_list).await?;
//!     Ok(())
//! }
//!
//! async fn cpe() -> Result<(), Box<dyn std::error::Error>> {
//!     download_cpe().await?;
//!     make_cpe_dictionary().await?;
//!     make_cpe_title().await?;
//!     Ok(())
//! }
//!
//! ```

pub mod cpe;
pub mod cve;
pub mod cve_api {
    include!(concat!(env!("OUT_DIR"), "/cve.api.rs"));
}
