use std::{
    fs::{self, File},
    io::{BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use self::cve_api::{Configurations, CpeMatch, Cve, CveDataMeta, CveItem, Node, NvdCve};
use chrono::{Datelike, Local};
use futures::future::join_all;
use prost::Message;
use sha2::{Digest, Sha256};
use tokio::time::{sleep, Duration};
use tracing_subscriber::fmt::{format::Writer, time::FormatTime};

mod cve_api {
    include!(concat!(env!("OUT_DIR"), "/cve.api.rs"));
}
static DATA_DIR: &str = "./data";

// cargo run --bin cve
#[allow(dead_code)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_log();
    let path_dir = init_dir(DATA_DIR).await?;
    let _ = sync_cve(&path_dir).await?;
    let _ = make_db(&path_dir).await?;
    let db_list = load_db(&path_dir).await?;
    log::info!("db_list len: {}", db_list.len());
    cpe_match().await?;
    Ok(())
}
impl NvdCve {
    #[allow(dead_code)]
    fn new(json: &serde_json::Value) -> NvdCve {
        let cve_items = &json["CVE_Items"];
        let cve_items = CveItem::new(&cve_items);
        NvdCve { cve_items }
    }
}

impl CveItem {
    fn new(json: &serde_json::Value) -> Vec<CveItem> {
        let json = json.as_array().unwrap();
        let mut cve_items = Vec::new();
        for cve_item in json.iter() {
            let cve = &cve_item["cve"];
            let cve = Some(Cve::new(cve));
            let configurations = &cve_item["configurations"];
            let configurations = Some(Configurations::new(configurations));
            let cve_item = CveItem {
                cve,
                configurations,
            };
            cve_items.push(cve_item);
        }
        cve_items
    }
}

impl Cve {
    fn new(json: &serde_json::Value) -> Cve {
        let cve_data_meta = &json["CVE_data_meta"];
        let cve_data_meta = Some(CveDataMeta::new(cve_data_meta));
        Cve { cve_data_meta }
    }
}

impl CveDataMeta {
    fn new(json: &serde_json::Value) -> CveDataMeta {
        let id = json["ID"].as_str().unwrap().to_owned();
        CveDataMeta { id }
    }
}

impl Configurations {
    fn new(json: &serde_json::Value) -> Configurations {
        let nodes = &json["nodes"];
        let nodes = Node::new(nodes);
        Configurations { nodes }
    }
}

impl Node {
    fn new(json: &serde_json::Value) -> Vec<Node> {
        let json = json.as_array().unwrap();
        let mut node_vec = Vec::new();
        for node in json {
            let operator = node["operator"].as_str().unwrap().to_owned();
            let children = &node["children"];
            let children = Node::new(children);
            let cpe_match = &node["cpe_match"];
            let cpe_match = CpeMatch::new(cpe_match);
            node_vec.push(Node {
                operator,
                children,
                cpe_match,
            });
        }
        node_vec
    }
}

impl CpeMatch {
    fn new(json: &serde_json::Value) -> Vec<CpeMatch> {
        let json = json.as_array().unwrap();
        let mut cpe_match_vec = Vec::new();
        for cpe_match in json {
            let cpe23_uri = cpe_match["cpe23Uri"].as_str().unwrap().to_owned();
            let version_start_excluding = cpe_match["versionStartExcluding"]
                .as_str()
                .to_owned()
                .map(|s| s.to_string());
            let version_end_excluding = cpe_match["versionEndExcluding"]
                .as_str()
                .to_owned()
                .map(|s| s.to_string());
            let version_start_including = cpe_match["versionStartIncluding"]
                .as_str()
                .to_owned()
                .map(|s| s.to_string());
            let version_end_including = cpe_match["versionEndIncluding"]
                .as_str()
                .to_owned()
                .map(|s| s.to_string());
            cpe_match_vec.push(CpeMatch {
                cpe23_uri,
                version_start_excluding,
                version_end_excluding,
                version_start_including,
                version_end_including,
            });
        }
        cpe_match_vec
    }
}
pub async fn cpe_match() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}
async fn make_db(path_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let num_cpus = num_cpus::get_physical();
    let thread_counter = Arc::new(Mutex::new(0));
    for entry in fs::read_dir(path_dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_name_json = &path.file_name().unwrap().to_str().unwrap();
        if path.is_file() && file_name_json.ends_with(".json.gz") {
            let thread_counter = Arc::clone(&thread_counter);
            loop {
                let mut thread_count = thread_counter.lock().unwrap();
                if *thread_count >= num_cpus {
                    drop(thread_count);
                    sleep(Duration::from_millis(100)).await;
                } else {
                    *thread_count += 1;
                    drop(thread_count);
                    break;
                }
            }
            let path_dir = path_dir.to_owned();
            tokio::spawn(async move {
                json_to_proto(&path, &path_dir, thread_counter).await;
            });
        }
    }
    let thread_counter = Arc::clone(&thread_counter);
    loop {
        let thread_count = thread_counter.lock().unwrap();
        if *thread_count > 0 {
            drop(thread_count);
            sleep(Duration::from_millis(1000)).await;
        } else {
            drop(thread_count);
            break;
        }
    }
    Ok(())
}

async fn json_to_proto(path_json_gz: &Path, path_dir: &Path, thread_counter: Arc<Mutex<usize>>) {
    let file_name_json = path_json_gz.file_name().unwrap().to_str().unwrap();
    let file_name_proto = file_name_json.replace(".json.", ".proto.");
    let path_proto = path_dir.join(&file_name_proto);
    log::info!("convert {} to {}", file_name_json, file_name_proto);
    let file_gz = File::open(&path_json_gz).unwrap();
    let gz_decoder = flate2::read::GzDecoder::new(file_gz);
    let json = serde_json::from_reader(gz_decoder).unwrap();
    let nvd_cve = NvdCve::new(&json);
    let mut buf: Vec<u8> = Vec::new();
    nvd_cve.encode(&mut buf).unwrap();
    let file_proto = File::create(path_proto).unwrap();
    let mut gz_encoder = flate2::write::GzEncoder::new(file_proto, flate2::Compression::default());
    gz_encoder.write_all(&buf).unwrap();
    let mut thread_count = thread_counter.lock().unwrap();
    *thread_count -= 1;
    drop(thread_count);
}

async fn load_db(path_dir: &PathBuf) -> Result<Vec<NvdCve>, Box<dyn std::error::Error>> {
    let mut db_list = Vec::new();
    for entry in fs::read_dir(path_dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_name_json = &path.file_name().unwrap().to_str().unwrap();
        if path.is_file() && file_name_json.ends_with(".proto.gz") {
            let gz_file = File::open(path).unwrap();
            let gz_decoder = flate2::read::GzDecoder::new(gz_file);
            let mut reader = BufReader::new(gz_decoder);
            let mut buf = Vec::new();
            reader.read_to_end(&mut buf).unwrap();
            let nvd_cve: NvdCve = prost::Message::decode(buf.as_slice()).unwrap();
            db_list.push(nvd_cve);
        }
    }
    Ok(db_list)
}

async fn sync_cve(path_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
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
                // not need to redownload
                log::info!("{} is lastest", file_name_gz);
                return Ok(());
            }
        }
        let url_gz = format!("https://nvd.nist.gov/feeds/json/cve/1.1/{}", file_name_gz);
        log::info!("download: {}", &url_gz);
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
        log::info!("create {:?}", &path);
        fs::create_dir(path)?;
    } else {
        log::info!("{:?} has been initialized", &path);
    }
    Ok(path.to_path_buf())
}
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
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stdout)
        .with_ansi(true)
        .event_format(format)
        .init();
}
#[cfg(test)]
mod tests {

    use super::{init_dir, init_log, load_db, make_db, sync_cve, DATA_DIR};

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
        let _ = sync_cve(&path_dir).await?;
        Ok(())
    }
    // cargo test cve::tests::test_make_db
    #[tokio::test]
    async fn test_make_db() -> Result<(), Box<dyn std::error::Error>> {
        init_log();
        let path_dir = init_dir(DATA_DIR).await?;
        let _ = make_db(&path_dir).await?;
        Ok(())
    }
    // cargo test cve::tests::test_load_db
    #[tokio::test]
    async fn test_load_db() -> Result<(), Box<dyn std::error::Error>> {
        init_log();
        let path_dir = init_dir(DATA_DIR).await?;
        let db_list = load_db(&path_dir).await?;
        log::info!("db_list len: {}", db_list.len());
        Ok(())
    }

    // cargo test cve::tests::it_works
    #[test]
    fn it_works() {
        use super::cve_api::NvdCve;
        use std::fs::File;

        let file_gz = File::open("./data/nvdcve-1.1-2022.json.gz").unwrap();
        let gz_decoder = flate2::read::GzDecoder::new(file_gz);
        let json = serde_json::from_reader(gz_decoder).unwrap();
        let _ = NvdCve::new(&json);
    }
}
