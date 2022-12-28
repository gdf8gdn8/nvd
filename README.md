# nvd
Some functions about CPE and CVE

## cve
CVE 

# Usage
Add this to your *Cargo.toml*:
```toml
[dependencies]
nvd = "0.1"
```

### Examples
```rust
use nvd::cve::*;

init_log();
let path_dir = init_dir("./data").await?;
let _ = sync_cve(&path_dir).await?;
let _ = make_db(&path_dir).await?;
let db_list = load_db(&path_dir).await?;
log::info!("db_list len: {}", db_list.len());

```