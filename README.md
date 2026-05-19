# nvd
Some functions about CPE and CVE

# Usage
Add this to your *Cargo.toml*:
```toml
[dependencies]
nvd = "0.1"
```

### CLI

The `nvd` binary provides a `cve` subcommand for matching CVEs and a `cpe` subcommand for building the CPE dictionary.

```
# Match CVEs for a CPE URI (syncs + builds DB first)
nvd cve "cpe:2.3:a:vmware:rabbitmq:3.9.10:*:*:*:*:*:*:*"

# Skip data sync and reuse existing download cache
nvd cve --no-sync "cpe:2.3:a:qt:qt:4.8.7:*:*:*:*:*:*:*"

# Delete and regenerate the database from downloaded JSON
nvd cve --rebuild "cpe:2.3:a:vmware:rabbitmq:3.9.10:*:*:*:*:*:*:*"

# Show severity statistics after results
nvd cve --stat "cpe:2.3:a:vmware:rabbitmq:3.9.10:*:*:*:*:*:*:*"

# Filter by published date range
nvd cve --from-date 2023-01-01 --to-date 2023-12-31 "cpe:2.3:a:qt:qt:4.8.7:*:*:*:*:*:*:*"

# Sort results by severity (descending), id, or date
nvd cve --sort severity "cpe:2.3:a:vmware:rabbitmq:3.9.10:*:*:*:*:*:*:*"
nvd cve --sort id "cpe:2.3:a:vmware:rabbitmq:3.9.10:*:*:*:*:*:*:*"

# All flags can be combined
nvd cve --no-sync --rebuild --stat --sort severity --from-date 2023-06-01 "cpe:2.3:a:vmware:rabbitmq:3.9.10:*:*:*:*:*:*:*"

# Build CPE dictionary and title index
nvd cpe
```

### Library Examples
```rust
use std::{env, process};

use nvd::{
    cpe::{download_cpe, make_cpe_dictionary, make_cpe_title},
    cve::{
        cpe23_uri_list_to_string, cpe_match, init_dir, load_db, make_db, sync_cve, Cpe23Uri,
        DATA_DIR,
    },
    log::log_init,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    log_init();
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        log::error!("arguments error!");
        log::error!("eg: {} [cve|cpe]", args[0]);
        process::exit(1);
    }
    if "cve".eq(&args[1]) {
        cve().await?;
    } else if "cpe".eq(&args[1]) {
        cpe().await?;
    } else {
        log::error!("arguments error!");
        log::error!("eg: {} [cve|cpe]", args[0]);
    }
    Ok(())
}

async fn cve() -> Result<(), Box<dyn std::error::Error>> {
    let path_dir = init_dir(DATA_DIR).await?;
    let _ = sync_cve(&path_dir).await?;
    let _ = make_db(&path_dir).await?;
    let db_list = load_db(&path_dir).await?;
    log::info!("db_list len: {}", db_list.len());
    let mut cpe23_uri_vec = Vec::new();
    let line = "cpe:2.3:a:vmware:rabbitmq:3.9.10:*:*:*:*:*:*:*";
    let cpe23_uri = Cpe23Uri::new(line);
    cpe23_uri_vec.push(cpe23_uri);
    log::info!("cpe23_uri: {}", cpe23_uri_list_to_string(&cpe23_uri_vec));
    cpe_match(&cpe23_uri_vec, &db_list).await?;
    Ok(())
}

async fn cpe() -> Result<(), Box<dyn std::error::Error>> {
    download_cpe().await?;
    make_cpe_dictionary().await?;
    make_cpe_title().await?;
    Ok(())
}


```