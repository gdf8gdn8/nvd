//! # nvd
//! Some functions about CPE and CVE
//!
//! ## cve
//! - [x] download cve file,
//! - [x] json to proto
//! - [x] load proto
//! - [ ] cpe match
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
//!     let _ = load_db(&path_dir).await?;
//!     Ok(())
//! }
//! ```
pub mod cve;
