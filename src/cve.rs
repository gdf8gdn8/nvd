use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use chrono::{Datelike, Local};
use futures::future::join_all;

static DATA_DIR: &str = "./data";

pub async fn cpe_match() -> Result<(), Box<dyn std::error::Error>> {
    let _ = init_dir(DATA_DIR).await;
    Ok(())
}

async fn load_db() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

async fn sync_db(path_dir: PathBuf) -> Result<Vec<File>, Box<dyn std::error::Error>> {
    let year_start = 2002;
    let year_now = Local::now().year();
    let file_count = year_now - year_start + 1;
    let mut future_list = Vec::with_capacity(file_count.try_into().unwrap());
    let mut file_list = Vec::with_capacity(file_count.try_into().unwrap());
    for year in year_start..(year_now + 1) {
        let file_name = format!("nvdcve-1.1-{}.json.gz", year);
        let url = format!("https://nvd.nist.gov/feeds/json/cve/1.1/{}", file_name);
        let file_gz = File::create(path_dir.join(file_name)).unwrap();
        file_list.push(file_gz.try_clone().unwrap());
        let future_download = download(url, file_gz);
        future_list.push(future_download);
    }
    let _ = join_all(future_list).await;
    Ok(file_list)
}

async fn download(url: String, mut file_local: File) -> Result<(), Box<dyn std::error::Error>> {
    let rsp = reqwest::get(url).await?;
    let rsp_bytes = rsp.bytes().await?;
    file_local.write_all(&rsp_bytes)?;
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
    use super::*;
    use chrono::Local;
    use tracing_subscriber::fmt::{format::Writer, time::FormatTime};

    fn init_log() {
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
    // cargo test cve::tests::test_sync_db
    #[tokio::test]
    async fn test_sync_db() -> Result<(), Box<dyn std::error::Error>> {
        init_log();
        let path_dir = init_dir(DATA_DIR).await?;
        let file_list = sync_db(path_dir).await?;
        log::info!("file_list {:?}", file_list);
        Ok(())
    }
}
