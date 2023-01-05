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
//! use nvd::cve::{init_dir, init_log, load_db, make_db, sync_cve};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     init_log();
//!     let path_dir = init_dir("./data").await?;
//!     let _ = sync_cve(&path_dir).await?;
//!     let _ = make_db(&path_dir).await?;
//!     let db_list = load_db(&path_dir).await?;
//!     let mut cpe23_uri_vec = Vec::new();
//!     let line = "cpe:2.3:a:vmware:rabbitmq:3.9.10:*:*:*:*:*:*:*";
//!     let cpe23_uri = Cpe23Uri::new(line);
//!     cpe23_uri_vec.push(cpe23_uri);
//!     cpe_match(&cpe23_uri_vec, &db_list).await?;
//!     Ok(())
//! }
//! ```
pub mod cpe;
pub mod cve;
pub mod log;
pub mod cve_api {
    include!(concat!(env!("OUT_DIR"), "/cve.api.rs"));
}
