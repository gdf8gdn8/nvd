use std::{
    fs::{self, File},
    io::{BufReader, Read, Write},
    path::{Path, PathBuf},
};

use chrono::{Datelike, Local};
use futures::future::join_all;
use sha2::{Digest, Sha256};

static DATA_DIR: &str = "./data";

pub async fn cpe_match() -> Result<(), Box<dyn std::error::Error>> {
    let _ = init_dir(DATA_DIR).await;
    Ok(())
}

async fn load_db() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

async fn sync_cve(path_dir: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let year_start = 2002;
    let year_now = Local::now().year();
    let file_count = year_now - year_start + 1;
    let mut future_list = Vec::with_capacity(file_count.try_into().unwrap());
    for year in year_start..(year_now + 1) {
        let future_download = download(year, path_dir.to_owned());
        future_list.push(future_download);
    }
    let _ = join_all(future_list).await;
    Ok(())
}

async fn download(year: i32, path_dir: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let url_meta = format!(
        "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.meta",
        year
    );
    let rsp = reqwest::get(&url_meta).await?;
    if rsp.status().is_success() {
        let meta = rsp.text().await?;
        let (_, sha256_lastest) = meta.trim_end().split_once("sha256:").unwrap();
        let file_name_gz = format!("nvdcve-1.1-{}.json.gz", year);
        let path_gz = path_dir.join(&file_name_gz);
        if path_gz.exists() {
            let file_gz = File::open(&path_gz).unwrap();
            let gz_decoder = flate2::read::GzDecoder::new(file_gz);
            let mut buf_reader = BufReader::new(gz_decoder);
            let mut buf = Vec::new();
            buf_reader.read_to_end(&mut buf).unwrap();
            let sha256_local = hex::encode_upper(Sha256::digest(buf));
            let sha256_local = sha256_local.as_str();
            if sha256_local == sha256_lastest {
                // no need to redownload
                log::debug!("no need to redownload, same sha256: {}", sha256_lastest);
                return Ok(());
            }
        }
        let url_gz = format!("https://nvd.nist.gov/feeds/json/cve/1.1/{}", file_name_gz);
        log::debug!("download: {}", &url_gz);
        let rsp = reqwest::get(url_gz).await?;
        let rsp_bytes = rsp.bytes().await?;
        let mut file_gz = File::create(path_gz).unwrap();
        file_gz.write_all(&rsp_bytes)?;
    } else {
        log::error!("get meta fail: {}", &url_meta);
    }
    Ok(())
}

async fn init_dir(data_dir: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = Path::new(data_dir);
    if !path.exists() {
        log::trace!("create {:?}", &path);
        fs::create_dir(path)?;
    } else {
        log::trace!("{:?} has been initialized", &path);
    }
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::{init_dir, sync_cve, DATA_DIR};

    fn init_log() {
        use chrono::Local;
        use tracing_subscriber::fmt::{format::Writer, time::FormatTime};
        struct LocalTimer;
        impl FormatTime for LocalTimer {
            fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
                write!(w, "{}", Local::now().format("%F %T%.3f"))
            }
        }
        let format = tracing_subscriber::fmt::format()
            .with_level(true)
            .with_target(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_timer(LocalTimer);
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(std::io::stdout)
            .with_ansi(true)
            .event_format(format)
            .init();
    }
    // cargo test cve::tests::test_init_dir
    #[tokio::test]
    async fn test_init_dir() -> Result<(), Box<dyn std::error::Error>> {
        init_log();
        let path_dir = init_dir(DATA_DIR).await?;
        log::info!("dir {:?} initialized", path_dir);
        Ok(())
    }
    // cargo test cve::tests::test_sync_cve
    #[tokio::test]
    async fn test_sync_cve() -> Result<(), Box<dyn std::error::Error>> {
        init_log();
        let path_dir = init_dir(DATA_DIR).await?;
        let _ = sync_cve(path_dir).await?;
        Ok(())
    }
    // cargo test cve::tests::it_works_async
    #[tokio::test]
    async fn it_works_async() -> Result<(), Box<dyn std::error::Error>> {
        use sha2::{Digest, Sha256};
        use std::fs::File;
        use std::io::BufReader;
        use std::io::Read;

        init_log();
        // 3B031264935B91768D8D6C9977FABF0D0F0E12E057435F93CE664326A62D66A5

        let file_gz = File::open("./data/nvdcve-1.1-2022.json.gz").unwrap();
        let gz_decoder = flate2::read::GzDecoder::new(file_gz);
        let mut buf_reader = BufReader::new(gz_decoder);
        let mut buf = Vec::new();
        buf_reader.read_to_end(&mut buf).unwrap();
        let sha256_local = hex::encode_upper(Sha256::digest(buf));
        log::info!("GzDecoder sha256_local: {}", sha256_local);

        Ok(())
    }

    // cargo test cve::tests::test_it_works
    #[test]
    fn test_it_works() {
        // 68a85d83abdd0fb34a31d1c49bb0ecfa380597046528ce624c514ea311b7f59f
        use sha2::{Digest, Sha256};
        use std::fs::File;
        use std::io::BufReader;
        use std::io::Read;

        init_log();

        let file_gz = File::open("./data/nvdcve-1.1-2022.json.gz").unwrap();
        let gz_decoder = flate2::read::GzDecoder::new(file_gz);
        let mut buf_reader = BufReader::new(gz_decoder);
        let mut buf = Vec::new();
        buf_reader.read_to_end(&mut buf).unwrap();
        let sha256_local = hex::encode_upper(Sha256::digest(buf));
        log::info!("GzDecoder sha256_local: {}", sha256_local);
    }
}
