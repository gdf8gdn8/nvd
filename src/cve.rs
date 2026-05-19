use crate::cve_api::{
    BaseMetricV2,
    BaseMetricV3,
    Configurations,
    CpeMatch,
    Cve,
    CveDataMeta,
    CveItem,
    CveItemBytes,
    CvssV2,
    CvssV3,
    Description,
    DescriptionData,
    Impact,
    Node,
    NvdCve,
    ProblemTypeData,
    Problemtype,
};
use crate::format::DbFormat;
use chrono::{
    Datelike,
    Local,
};
use futures::future::join_all;
use prost::Message;
use redb::ReadableTable;
use sha2::{
    Digest,
    Sha256,
};
use std::io::{
    BufReader,
    Read,
    Write,
};
use std::path::{
    Path,
    PathBuf,
};
use std::sync::Arc;
use tokio::fs::{
    self,
    File,
};
use tokio::io::AsyncWriteExt;
use tokio::task::JoinHandle;
use tokio::time::{
    sleep,
    Duration,
};

pub static DATA_DIR: &str = "./data";

impl NvdCve {
    #[allow(dead_code)]
    fn new(json: &serde_json::Value) -> NvdCve {
        let vulnerabilities = &json["vulnerabilities"];
        let cve_item_bytes_list = CveItem::new(vulnerabilities);
        NvdCve {
            cve_item_bytes_list,
        }
    }

    fn get_items(&self) -> Vec<Vec<u8>> {
        self.cve_item_bytes_list
            .iter()
            .map(|b| b.cve_item_bytes.clone())
            .collect()
    }

    #[allow(dead_code)]
    fn from_items(items: Vec<Vec<u8>>) -> NvdCve {
        NvdCve {
            cve_item_bytes_list: items
                .into_iter()
                .map(|b| CveItemBytes { cve_item_bytes: b })
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Cpe23Uri {
    pub part: String,
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub update: String,
    pub edition: String,
    pub language: String,
    pub sw_edition: String,
    pub target_sw: String,
    pub target_hw: String,
    pub other: String,
}

impl Cpe23Uri {
    /// Parse a CPE 2.3 URI string into its component fields.
    ///
    /// Missing or malformed fields default to `"*"`.
    pub fn new(cpe23uri: &str) -> Cpe23Uri {
        let parts: Vec<&str> = cpe23uri.split(":").collect();
        let get = |i: usize| parts.get(i).copied().unwrap_or("*").to_owned();
        Cpe23Uri {
            part: get(2),
            vendor: get(3),
            product: get(4),
            version: get(5),
            update: get(6),
            edition: get(7),
            language: get(8),
            sw_edition: get(9),
            target_sw: get(10),
            target_hw: get(11),
            other: get(12),
        }
    }

    /// Reconstruct a CPE 2.3 URI string from the parsed component fields.
    pub fn to_string(&self) -> String {
        format!(
            "cpe:2.3:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.part,
            self.vendor,
            self.product,
            self.version,
            self.update,
            self.edition,
            self.language,
            self.sw_edition,
            self.target_sw,
            self.target_hw,
            self.other
        )
    }
}

impl CveItem {
    fn new(json: &serde_json::Value) -> Vec<CveItemBytes> {
        let json = match json.as_array() {
            Some(arr) => arr,
            None => return vec![],
        };
        let mut cve_item_bytes_list = Vec::new();
        for vuln in json.iter() {
            let cve_val = &vuln["cve"];
            let cve = Some(Cve::new(cve_val));
            let configurations = &cve_val["configurations"];
            let configurations = Some(Configurations::new(configurations));
            let metrics = &cve_val["metrics"];
            let impact = Some(Impact::new(metrics));
            let cve_item = CveItem {
                cve,
                configurations,
                impact,
                last_modified_date: cve_val["lastModified"].as_str().unwrap_or("").to_owned(),
                published_date: cve_val["published"].as_str().unwrap_or("").to_owned(),
            };
            let mut buf: Vec<u8> = Vec::new();
            if cve_item.encode(&mut buf).is_err() {
                continue;
            }
            cve_item_bytes_list.push(CveItemBytes {
                cve_item_bytes: buf,
            });
        }
        cve_item_bytes_list
    }
}
impl Problemtype {
    fn new(json: &serde_json::Value) -> Problemtype {
        let problemtype_data = match json.as_array() {
            Some(arr) => arr.iter().map(ProblemTypeData::new).collect(),
            None => vec![],
        };
        Problemtype { problemtype_data }
    }
}
impl ProblemTypeData {
    fn new(json: &serde_json::Value) -> ProblemTypeData {
        let description = json["description"].as_array().map_or(vec![], |arr| {
            arr.iter()
                .filter_map(|x| x["value"].as_str().map(String::from))
                .collect()
        });
        ProblemTypeData { description }
    }
}
impl DescriptionData {
    fn new(json: &serde_json::Value) -> DescriptionData {
        let value = match json.as_array() {
            Some(arr) => arr
                .iter()
                .filter_map(|x| x["value"].as_str().map(String::from))
                .collect(),
            None => vec![],
        };
        DescriptionData { value }
    }
}
impl Description {
    fn new(json: &serde_json::Value) -> Description {
        let description_data = Some(DescriptionData::new(json));
        Description { description_data }
    }
}
impl Cve {
    fn new(json: &serde_json::Value) -> Cve {
        let id = json["id"].as_str().unwrap_or("").to_owned();
        Cve {
            cve_data_meta: Some(CveDataMeta { id }),
            problemtype: Some(Problemtype::new(&json["weaknesses"])),
            description: Some(Description::new(&json["descriptions"])),
        }
    }
}

impl Configurations {
    fn new(json: &serde_json::Value) -> Configurations {
        let nodes = match json.as_array() {
            Some(arr) => arr
                .iter()
                .flat_map(|config| {
                    let inner = Node::new(&config["nodes"]);
                    inner
                })
                .collect(),
            None => vec![],
        };
        Configurations { nodes }
    }
}
impl BaseMetricV2 {
    pub fn new(json: &serde_json::Value) -> BaseMetricV2 {
        let cvss_data = &json["cvssData"];
        let base_severity = json["baseSeverity"]
            .as_str()
            .unwrap_or("UNKNOWN")
            .to_owned();
        let exploitability_score = json["exploitabilityScore"].as_f64().unwrap_or(0.0) as f32;
        let impact_score = json["impactScore"].as_f64().unwrap_or(0.0) as f32;
        let obtain_all_privilege = json["obtainAllPrivilege"].as_bool().unwrap_or(false);
        let obtain_user_privilege = json["obtainUserPrivilege"].as_bool().unwrap_or(false);
        let obtain_other_privilege = json["obtainOtherPrivilege"].as_bool().unwrap_or(false);
        let user_interaction_required = json["userInteractionRequired"].as_bool().unwrap_or(false);
        let cvss_v2 = Some(CvssV2::new(cvss_data));
        BaseMetricV2 {
            severity: base_severity,
            exploitability_score,
            impact_score,
            obtain_all_privilege,
            obtain_user_privilege,
            obtain_other_privilege,
            user_interaction_required,
            cvss_v2,
        }
    }
}
impl CvssV2 {
    fn new(json: &serde_json::Value) -> CvssV2 {
        CvssV2 {
            version: json["version"].as_str().unwrap_or("").to_owned(),
            vector_string: json["vectorString"].as_str().unwrap_or("").to_owned(),
            access_vector: json["accessVector"].as_str().unwrap_or("").to_owned(),
            access_complexity: json["accessComplexity"].as_str().unwrap_or("").to_owned(),
            confidentiality_impact: json["confidentialityImpact"]
                .as_str()
                .unwrap_or("")
                .to_owned(),
            integrity_impact: json["integrityImpact"].as_str().unwrap_or("").to_owned(),
            availability_impact: json["availabilityImpact"].as_str().unwrap_or("").to_owned(),
            base_score: json["baseScore"].as_f64().unwrap_or(0.0) as f32,
        }
    }
}
impl CvssV3 {
    fn new(json: &serde_json::Value) -> CvssV3 {
        CvssV3 {
            version: json["version"].as_str().unwrap_or("").to_owned(),
            vector_string: json["vectorString"].as_str().unwrap_or("").to_owned(),
            attack_vector: json["attackVector"].as_str().unwrap_or("").to_owned(),
            attack_complexity: json["attackComplexity"].as_str().unwrap_or("").to_owned(),
            privileges_required: json["privilegesRequired"].as_str().unwrap_or("").to_owned(),
            user_interaction: json["userInteraction"].as_str().unwrap_or("").to_owned(),
            scope: json["scope"].as_str().unwrap_or("").to_owned(),
            confidentiality_impact: json["confidentialityImpact"]
                .as_str()
                .unwrap_or("")
                .to_owned(),
            integrity_impact: json["integrityImpact"].as_str().unwrap_or("").to_owned(),
            availability_impact: json["availabilityImpact"].as_str().unwrap_or("").to_owned(),
            base_score: json["baseScore"].as_f64().unwrap_or(0.0) as f32,
            base_severity: json["baseSeverity"].as_str().unwrap_or("").to_owned(),
        }
    }
}
impl BaseMetricV3 {
    fn new(json: &serde_json::Value) -> BaseMetricV3 {
        let cvss_data = &json["cvssData"];
        let exploitability_score = json["exploitabilityScore"].as_f64().unwrap_or(0.0) as f32;
        let impact_score = json["impactScore"].as_f64().unwrap_or(0.0) as f32;
        let cvss_v3 = Some(CvssV3::new(cvss_data));
        BaseMetricV3 {
            cvss_v3,
            exploitability_score,
            impact_score,
        }
    }
}
impl Impact {
    fn new(json: &serde_json::Value) -> Impact {
        let base_metric_v2 = json["cvssMetricV2"]
            .as_array()
            .and_then(|a| a.first())
            .map(BaseMetricV2::new);
        let base_metric_v3 = json["cvssMetricV31"]
            .as_array()
            .and_then(|a| a.first())
            .map(BaseMetricV3::new)
            .or_else(|| {
                json["cvssMetricV30"]
                    .as_array()
                    .and_then(|a| a.first())
                    .map(BaseMetricV3::new)
            });
        Impact {
            base_metric_v2,
            base_metric_v3,
        }
    }
}
impl Node {
    fn new(json: &serde_json::Value) -> Vec<Node> {
        let json = match json.as_array() {
            Some(arr) => arr,
            None => return vec![],
        };
        let mut node_vec = Vec::new();
        for node in json {
            let operator = node["operator"].as_str().unwrap_or("OR").to_owned();
            let cpe_match = &node["cpeMatch"];
            let cpe_match = CpeMatch::new(cpe_match);
            node_vec.push(Node {
                operator,
                children: vec![],
                cpe_match,
            });
        }
        node_vec
    }
}

impl CpeMatch {
    fn new(json: &serde_json::Value) -> Vec<CpeMatch> {
        let json = match json.as_array() {
            Some(arr) => arr,
            None => return vec![],
        };
        let mut cpe_match_vec = Vec::new();
        for cpe_match in json {
            let cpe23_uri = cpe_match["criteria"].as_str().unwrap_or("").to_owned();
            let version_start_excluding = cpe_match["versionStartExcluding"]
                .as_str()
                .map(String::from);
            let version_end_excluding = cpe_match["versionEndExcluding"].as_str().map(String::from);
            let version_start_including = cpe_match["versionStartIncluding"]
                .as_str()
                .map(String::from);
            let version_end_including = cpe_match["versionEndIncluding"].as_str().map(String::from);
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

pub fn cpe23_uri_list_to_string(cpe23_uri_list: &Vec<Cpe23Uri>) -> String {
    let mut cpe23_uri_string_list: Vec<String> = Vec::new();
    for cpe23_uri in cpe23_uri_list {
        cpe23_uri_string_list.push(cpe23_uri.to_string());
    }
    cpe23_uri_string_list.sort();
    cpe23_uri_string_list.into_iter().collect::<String>()
}
/// Check whether the non-version CPE fields of `input` match `rule`.
///
/// `*` in a rule field acts as a wildcard (matches anything). The `part`,
/// `vendor`, and `product` fields must match exactly.
fn field_matches(input: &Cpe23Uri, rule: &Cpe23Uri) -> bool {
    input.part == rule.part
        && input.vendor == rule.vendor
        && input.product == rule.product
        && (rule.update == "*" || input.update == rule.update)
        && (rule.edition == "*" || input.edition == rule.edition)
        && (rule.language == "*" || input.language == rule.language)
        && (rule.sw_edition == "*" || input.sw_edition == rule.sw_edition)
        && (rule.target_sw == "*" || input.target_sw == rule.target_sw)
        && (rule.target_hw == "*" || input.target_hw == rule.target_hw)
        && (rule.other == "*" || input.other == rule.other)
}

/// Compare two dot-separated version strings numerically.
///
/// Splits each component on `.`, parses as `u32`, and compares
/// element-by-element. Shorter sequences are treated as less-than
/// longer ones when the common prefix is equal.
fn cmp_ver(a: &str, b: &str) -> std::cmp::Ordering {
    let a_parts: Vec<u32> = a.split('.').filter_map(|s| s.parse().ok()).collect();
    let b_parts: Vec<u32> = b.split('.').filter_map(|s| s.parse().ok()).collect();
    for i in 0..a_parts.len().min(b_parts.len()) {
        match a_parts[i].cmp(&b_parts[i]) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    a_parts.len().cmp(&b_parts.len())
}

/// Check whether the input version matches the version rules in a CPE match.
///
/// Handles exact version, `*` wildcard, `-` (N/A), and numeric range
/// matching (`versionStartIncluding`, `versionStartExcluding`,
/// `versionEndIncluding`, `versionEndExcluding`).
fn version_matches(input: &str, rule: &Cpe23Uri, cpe_match: &CpeMatch) -> bool {
    if rule.version == "-" {
        return true;
    }
    if rule.version != "*" {
        return input == rule.version || input == "*";
    }
    let v = input;
    if v == "*" {
        return true;
    }
    if let Some(end) = &cpe_match.version_end_including {
        if let Some(start) = &cpe_match.version_start_including {
            return cmp_ver(v, start.as_str()) != std::cmp::Ordering::Less
                && cmp_ver(v, end.as_str()) != std::cmp::Ordering::Greater;
        }
        if let Some(start) = &cpe_match.version_start_excluding {
            return cmp_ver(v, start.as_str()) == std::cmp::Ordering::Greater
                && cmp_ver(v, end.as_str()) != std::cmp::Ordering::Greater;
        }
        return cmp_ver(v, end.as_str()) != std::cmp::Ordering::Greater;
    }
    if let Some(end) = &cpe_match.version_end_excluding {
        if let Some(start) = &cpe_match.version_start_including {
            return cmp_ver(v, start.as_str()) != std::cmp::Ordering::Less
                && cmp_ver(v, end.as_str()) == std::cmp::Ordering::Less;
        }
        if let Some(start) = &cpe_match.version_start_excluding {
            return cmp_ver(v, start.as_str()) == std::cmp::Ordering::Greater
                && cmp_ver(v, end.as_str()) == std::cmp::Ordering::Less;
        }
        return cmp_ver(v, end.as_str()) == std::cmp::Ordering::Less;
    }
    if let Some(start) = &cpe_match.version_start_including {
        return cmp_ver(v, start.as_str()) != std::cmp::Ordering::Less;
    }
    if let Some(start) = &cpe_match.version_start_excluding {
        return cmp_ver(v, start.as_str()) == std::cmp::Ordering::Greater;
    }
    true
}

fn match_node(cpe23_uri_list: &Vec<Cpe23Uri>, node: &Node) -> bool {
    let cpe_match_list = &node.cpe_match;
    if !cpe_match_list.is_empty() {
        let mut match_count = 0;
        'rule: for cpm in cpe_match_list {
            let rule_uri = Cpe23Uri::new(&cpm.cpe23_uri);
            for input in cpe23_uri_list {
                if !field_matches(input, &rule_uri) {
                    continue;
                }
                if version_matches(&input.version, &rule_uri, cpm) {
                    if node.operator == "OR" {
                        return true;
                    }
                    match_count += 1;
                    continue 'rule;
                }
            }
        }
        if match_count == cpe_match_list.len() {
            return true;
        }
    }

    let children = &node.children;
    if !children.is_empty() {
        let mut match_count = 0;
        for child in children {
            if match_node(cpe23_uri_list, child) {
                if node.operator == "OR" {
                    return true;
                }
                match_count += 1;
            }
        }
        if match_count == children.len() {
            return true;
        }
    }
    false
}

/// A single CPE → CVE match result.
#[derive(Debug)]
pub struct CveMatchResult {
    /// CVE identifier, e.g. `"CVE-2023-46118"`.
    pub id: String,
    /// Human-readable severity (`"LOW"`, `"MEDIUM"`, `"HIGH"`, `"CRITICAL"`, or empty).
    pub severity: String,
    /// CWE problem type description.
    pub problem_type: String,
    /// English description of the vulnerability.
    pub description: String,
    /// ISO-8601 publication date string, e.g. `"2023-01-01T00:00:00.000"`.
    pub published_date: String,
}

/// Match a list of CPE 2.3 URIs against the loaded CVE database.
///
/// The function spawns one async task per `NvdCve` chunk, limited by
/// `num_cpus`. Each task decodes the protobuf-encoded `CveItem` and checks
/// every configuration node against the supplied CPE URIs.
pub async fn cpe_match(
    cpe23_uri_list: &Vec<Cpe23Uri>,
    db_list: &[NvdCve],
) -> Result<Vec<CveMatchResult>, Box<dyn std::error::Error>> {
    let num_cpus = num_cpus::get_physical();
    log::info!("num_cpus: {}", num_cpus);
    let mut results: Vec<CveMatchResult> = Vec::new();
    let shared_uri_list = Arc::new(cpe23_uri_list.to_owned());
    let mut handle_list: Vec<JoinHandle<Vec<CveMatchResult>>> = Vec::new();
    for nvdcve in db_list {
        while handle_list.len() >= num_cpus {
            for i in 0..handle_list.len() {
                if handle_list[i].is_finished() {
                    if let Ok(r) = handle_list.swap_remove(i).await {
                        results.extend(r);
                    }
                    break;
                }
            }
            sleep(Duration::from_millis(100)).await;
        }
        let ul = Arc::clone(&shared_uri_list);
        let nvdcve = nvdcve.to_owned();
        handle_list.push(tokio::spawn(async move {
            let mut r = Vec::new();
            for cve_item_bytes in &nvdcve.cve_item_bytes_list {
                let cve_item = match <CveItem as prost::Message>::decode(
                    cve_item_bytes.cve_item_bytes.as_slice(),
                ) {
                    Ok(ci) => ci,
                    Err(_) => continue,
                };
                if let Some(config) = &cve_item.configurations {
                    for node in &config.nodes {
                        if match_node(ul.as_ref(), node) {
                            let cve = cve_item.cve.as_ref();
                            let id = cve
                                .and_then(|c| c.cve_data_meta.as_ref())
                                .map(|m| m.id.clone())
                                .unwrap_or_default();
                            let severity = cve_item
                                .impact
                                .as_ref()
                                .and_then(|i| {
                                    i.base_metric_v3
                                        .as_ref()
                                        .and_then(|v| v.cvss_v3.as_ref())
                                        .map(|c| c.base_severity.clone())
                                        .or_else(|| {
                                            i.base_metric_v2.as_ref().map(|v| v.severity.clone())
                                        })
                                })
                                .unwrap_or_default();
                            let problem_type = cve
                                .and_then(|c| c.problemtype.as_ref())
                                .and_then(|p| p.problemtype_data.first())
                                .and_then(|d| d.description.first())
                                .cloned()
                                .unwrap_or_default();
                            let description = cve
                                .and_then(|c| c.description.as_ref())
                                .and_then(|d| d.description_data.as_ref())
                                .and_then(|dd| dd.value.first())
                                .cloned()
                                .unwrap_or_default();
                            r.push(CveMatchResult {
                                id,
                                severity,
                                problem_type,
                                description,
                                published_date: cve_item.published_date.clone(),
                            });
                            break;
                        }
                    }
                }
            }
            r
        }));
    }
    for handle in handle_list {
        if let Ok(r) = handle.await {
            results.extend(r);
        }
    }
    Ok(results)
}

/// Convert all `.json.gz` files in `path_dir` to the chosen database format.
///
/// Skips files whose output already exists. Parallelism is capped at
/// `num_cpus` concurrent conversions.  For `DbFormat::RkyvMmapRedb`, all years
/// are collected into a single database file.
pub async fn make_db(
    path_dir: &PathBuf,
    format: DbFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    if format == DbFormat::RkyvMmapRedb {
        return make_db_rmr(path_dir).await;
    }
    let num_cpus = num_cpus::get_physical();
    let mut handle_list: Vec<JoinHandle<()>> = Vec::new();
    let mut entries = fs::read_dir(path_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let file_name_json = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name.to_owned(),
            None => continue,
        };
        if !path.is_file()
            || !file_name_json.starts_with("nvdcve-2.0-")
            || !file_name_json.ends_with(".json.gz")
        {
            continue;
        }
        let file_name_out = file_name_json.replace(".json.gz", format.ext());
        if path_dir.join(&file_name_out).exists() {
            log::info!("{} already converted", file_name_json);
            continue;
        }
        log::trace!("json file: {}", file_name_json);
        while handle_list.len() >= num_cpus {
            for i in 0..handle_list.len() {
                if handle_list[i].is_finished() {
                    handle_list.remove(i);
                    break;
                }
            }
            sleep(Duration::from_millis(100)).await;
        }
        let path_dir = path_dir.to_owned();
        let path_json = path.clone();
        let handle = tokio::spawn(async move {
            let _ = json_to_proto(&path_json, &path_dir, format).await;
        });
        handle_list.push(handle);
        log::trace!("make a new thread to work");
    }
    for handle in handle_list {
        handle.await?;
    }
    Ok(())
}

async fn json_to_proto(
    path_json_gz: &Path,
    path_dir: &Path,
    format: DbFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_name_json = match path_json_gz.file_name().and_then(|n| n.to_str()) {
        Some(name) => name,
        None => return Ok(()),
    };
    let file_name_out = file_name_json.replace(".json.gz", format.ext());
    let path_out = path_dir.join(&file_name_out);
    log::info!("convert {} to {}", file_name_json, file_name_out);
    let file_gz = File::open(&path_json_gz).await?;
    let file_gz = file_gz.into_std().await;
    let gz_decoder = flate2::read::GzDecoder::new(file_gz);
    let json: serde_json::Value = match serde_json::from_reader(gz_decoder) {
        Ok(v) => v,
        Err(e) => {
            log::error!("failed to parse {}: {}", file_name_json, e);
            return Ok(());
        }
    };
    let nvd_cve = NvdCve::new(&json);
    let items = nvd_cve.get_items();
    let buf = format.encode_items(&items);
    let file_out = File::create(path_out).await?;
    let file_out = file_out.into_std().await;
    if format.uses_zstd() {
        let mut encoder = zstd::stream::write::Encoder::new(file_out, 0)?;
        encoder.write_all(&buf)?;
        encoder.finish()?;
    } else {
        use std::io::Write;
        let mut f = file_out;
        f.write_all(&buf)?;
    }
    Ok(())
}

/// Build a single redb database from all JSON files, using rkyv-encoded
/// batches (up to 8000 items per batch).  The file extension is `.rmr`.
///
/// This is the "complete combination" format: rkyv serialisation + redb
/// storage + memory-map friendly layout.
async fn make_db_rmr(path_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let db_path = path_dir.join("nvdcve.rmr");
    if db_path.exists() {
        log::info!("rkyv_mmap_redb database already exists, skipping");
        return Ok(());
    }
    let db = redb::Database::create(&db_path)?;
    let txn = db.begin_write()?;
    {
        let table_def: redb::TableDefinition<u64, &[u8]> = redb::TableDefinition::new("batches");
        let mut table = txn.open_table(table_def)?;
        let mut batch: Vec<Vec<u8>> = Vec::new();
        let mut key: u64 = 0;
        let mut entries = fs::read_dir(path_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let file_name = match path.file_name().and_then(|n| n.to_str()) {
                Some(name) => name.to_owned(),
                None => continue,
            };
            if !path.is_file()
                || !file_name.starts_with("nvdcve-2.0-")
                || !file_name.ends_with(".json.gz")
            {
                continue;
            }
            log::info!("processing {} for rkyv_mmap_redb", file_name);
            let file_gz = std::fs::File::open(&path)?;
            let gz_decoder = flate2::read::GzDecoder::new(file_gz);
            let json: serde_json::Value = match serde_json::from_reader(gz_decoder) {
                Ok(v) => v,
                Err(e) => {
                    log::error!("failed to parse {}: {}", file_name, e);
                    continue;
                }
            };
            let nvd_cve = NvdCve::new(&json);
            for item in nvd_cve.get_items() {
                batch.push(item);
                if batch.len() >= 8000 {
                    let rkyv_bytes = crate::format::encode_rkyv(&batch);
                    table.insert(key, rkyv_bytes.as_slice())?;
                    key += 1;
                    batch.clear();
                }
            }
        }
        if !batch.is_empty() {
            let rkyv_bytes = crate::format::encode_rkyv(&batch);
            table.insert(key, rkyv_bytes.as_slice())?;
        }
    }
    txn.commit()?;
    Ok(())
}

/// Load all database files in `path_dir` matching `format`'s extension.
///
/// Files are decompressed (zstd), decoded, and split into ~8 000-item
/// `NvdCve` chunks for parallel matching.
pub async fn load_db(
    path_dir: &PathBuf,
    format: DbFormat,
) -> Result<Vec<NvdCve>, Box<dyn std::error::Error>> {
    if format == DbFormat::RkyvMmapRedb {
        return load_db_rmr(path_dir).await;
    }
    let mut db_list: Vec<NvdCve> = Vec::new();
    let mut all_items: Vec<Vec<u8>> = Vec::new();
    let mut entries = fs::read_dir(path_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name.to_owned(),
            None => continue,
        };
        if path.is_file()
            && file_name.starts_with("nvdcve-2.0-")
            && file_name.ends_with(format.ext())
        {
            let file = File::open(path).await?;
            let mut file = file.into_std().await;
            let mut buf = Vec::new();
            if format.uses_zstd() {
                if zstd::stream::read::Decoder::new(file)
                    .and_then(|mut r| r.read_to_end(&mut buf))
                    .is_err()
                {
                    log::error!("failed to read {}", file_name);
                    continue;
                }
            } else {
                if file.read_to_end(&mut buf).is_err() {
                    log::error!("failed to read {}", file_name);
                    continue;
                }
            }
            match format.decode_items(&buf) {
                Ok(items) => all_items.extend(items),
                Err(e) => log::error!("failed to decode {}: {}", file_name, e),
            }
        }
    }
    let count_max = 8_000;
    let mut count = 0;
    let mut cve_item_bytes_list = Vec::new();
    for item in all_items {
        cve_item_bytes_list.push(CveItemBytes {
            cve_item_bytes: item,
        });
        count += 1;
        if count >= count_max {
            let nvdcve = NvdCve {
                cve_item_bytes_list: cve_item_bytes_list.to_owned(),
            };
            db_list.push(nvdcve);
            cve_item_bytes_list.clear();
            count = 0;
        }
    }
    if count > 0 {
        let nvdcve = NvdCve {
            cve_item_bytes_list,
        };
        db_list.push(nvdcve);
    }
    Ok(db_list)
}

/// Load all CVE items from a single `.rmr` database (rkyv + mmap + redb).
///
/// Opens the redb database, iterates batch entries (each batch is an
/// rkyv-encoded `Vec<Vec<u8>>`), decodes each batch with rkyv, and
/// assembles the items into ~8 000-item NvdCve chunks.
async fn load_db_rmr(path_dir: &PathBuf) -> Result<Vec<NvdCve>, Box<dyn std::error::Error>> {
    let db_path = path_dir.join("nvdcve.rmr");
    let db = redb::Database::open(&db_path)?;
    let txn = db.begin_read()?;
    let table_def: redb::TableDefinition<u64, &[u8]> = redb::TableDefinition::new("batches");
    let table = txn.open_table(table_def)?;
    let mut all_items: Vec<Vec<u8>> = Vec::new();
    for entry in table.iter()? {
        let (_key, value) = entry?;
        let batch = crate::format::decode_rkyv(value.value())?;
        all_items.extend(batch);
    }
    let mut db_list: Vec<NvdCve> = Vec::new();
    let count_max = 8_000;
    let mut count = 0;
    let mut cve_item_bytes_list = Vec::new();
    for item in all_items {
        cve_item_bytes_list.push(CveItemBytes {
            cve_item_bytes: item,
        });
        count += 1;
        if count >= count_max {
            let nvdcve = NvdCve {
                cve_item_bytes_list: cve_item_bytes_list.to_owned(),
            };
            db_list.push(nvdcve);
            cve_item_bytes_list.clear();
            count = 0;
        }
    }
    if count > 0 {
        let nvdcve = NvdCve {
            cve_item_bytes_list,
        };
        db_list.push(nvdcve);
    }
    Ok(db_list)
}

/// Download (or verify) all NVD CVE `.json.gz` files for years 2002–current.
///
/// Each year's file is downloaded if the local SHA-256 does not match the
/// latest published meta hash.
pub async fn sync_cve(path_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let year_start = 2002;
    let year_now = Local::now().year();
    let mut future_list = Vec::new();
    for year in year_start..(year_now + 1) {
        future_list.push(download(year, path_dir.to_owned()));
    }
    join_all(future_list).await;
    Ok(())
}

async fn download(year: i32, path_dir: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let url_meta = format!(
        "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{}.meta",
        year
    );
    let rsp = reqwest::get(&url_meta).await?;
    log::info!("download {} {}", url_meta, rsp.status());
    if !rsp.status().is_success() {
        log::error!("get meta fail: {}", &url_meta);
        return Ok(());
    }
    let meta = rsp.text().await?;
    let sha256_lastest = match meta.trim_end().split_once("sha256:") {
        Some((_, hash)) => hash,
        None => {
            log::error!("no sha256 in meta for year {}", year);
            return Ok(());
        }
    };
    let file_name_gz = format!("nvdcve-2.0-{}.json.gz", year);
    let path_gz = path_dir.join(&file_name_gz);
    if path_gz.exists() {
        let file_gz = File::open(&path_gz).await?;
        let file_gz = file_gz.into_std().await;
        let gz_decoder = flate2::read::GzDecoder::new(file_gz);
        let mut buf_reader = BufReader::new(gz_decoder);
        let mut buf = Vec::new();
        if buf_reader.read_to_end(&mut buf).is_ok() {
            let sha256_local = hex::encode_upper(Sha256::digest(buf));
            if sha256_local == sha256_lastest {
                log::info!("{} is lastest", file_name_gz);
                return Ok(());
            }
        }
    }
    let url_gz = format!("https://nvd.nist.gov/feeds/json/cve/2.0/{}", file_name_gz);
    log::info!("download: {}", &url_gz);
    let rsp = reqwest::get(url_gz).await?;
    let rsp_bytes = rsp.bytes().await?;
    let mut file_gz = File::create(path_gz).await?;
    file_gz.write_all(&rsp_bytes).await?;
    Ok(())
}

/// Ensure `data_dir` exists, creating it if necessary.
pub async fn init_dir(data_dir: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = Path::new(data_dir);
    if !path.exists() {
        log::info!("create {:?}", &path);
        fs::create_dir(path).await?;
    } else {
        log::info!("{:?} has been initialized", &path);
    }
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::{
        cpe_match,
        init_dir,
        load_db,
        make_db,
        sync_cve,
        Cpe23Uri,
        DATA_DIR,
    };
    use crate::format::DbFormat;
    use dev_util::log::log_init;

    // cargo test cve::tests::test_init_dir
    #[tokio::test]
    async fn test_init_dir() -> Result<(), Box<dyn std::error::Error>> {
        log_init();
        let path_dir = init_dir(DATA_DIR).await?;
        log::info!("dir {:?} initialized", path_dir);
        Ok(())
    }
    // cargo test cve::tests::test_sync_cve
    #[tokio::test]
    async fn test_sync_cve() -> Result<(), Box<dyn std::error::Error>> {
        log_init();
        let path_dir = init_dir(DATA_DIR).await?;
        sync_cve(&path_dir).await?;
        Ok(())
    }
    // cargo test cve::tests::test_make_db
    #[tokio::test(flavor = "multi_thread")]
    async fn test_make_db() -> Result<(), Box<dyn std::error::Error>> {
        log_init();
        let path_dir = init_dir(DATA_DIR).await?;
        make_db(&path_dir, DbFormat::Protobuf).await?;
        Ok(())
    }
    // cargo test cve::tests::test_load_db
    #[tokio::test]
    async fn test_load_db() -> Result<(), Box<dyn std::error::Error>> {
        log_init();
        let path_dir = init_dir(DATA_DIR).await?;
        let db_list = load_db(&path_dir, DbFormat::Protobuf).await?;
        log::info!("db_list len: {}", db_list.len());
        Ok(())
    }

    // cargo test cve::tests::test_cpe_match
    #[tokio::test(flavor = "multi_thread")]
    async fn test_cpe_match() -> Result<(), Box<dyn std::error::Error>> {
        log_init();
        let path_dir = init_dir(DATA_DIR).await?;
        let db_list = load_db(&path_dir, DbFormat::Protobuf).await?;
        log::info!("db_list len: {}", db_list.len());
        let mut cpe23_uri_vec = Vec::new();
        let line = "cpe:2.3:a:vmware:rabbitmq:3.9.10:*:*:*:*:*:*:*";
        println!("cpe23_uri: {}", line);
        let cpe23_uri = Cpe23Uri::new(line);
        cpe23_uri_vec.push(cpe23_uri);
        let results = cpe_match(&cpe23_uri_vec, &db_list).await?;
        println!("results count: {}", results.len());
        for r in results.iter().take(5) {
            println!(
                "match: {} sev: {} type: {} desc: {}",
                r.id, r.severity, r.problem_type, r.description
            );
        }
        Ok(())
    }

    #[test]
    fn test_cmp_ver() {
        use super::cmp_ver;
        use std::cmp::Ordering;
        assert_eq!(cmp_ver("3.9.10", "3.11.24"), Ordering::Less);
        assert_eq!(cmp_ver("3.11.24", "3.9.10"), Ordering::Greater);
        assert_eq!(cmp_ver("3.9.10", "3.9.10"), Ordering::Equal);
        assert_eq!(cmp_ver("16.0.0", "15.5.7"), Ordering::Greater);
        assert_eq!(cmp_ver("1.0.0", "1.0"), Ordering::Greater);
        assert_eq!(cmp_ver("5.1", "5.1.0"), Ordering::Less);
        assert_eq!(cmp_ver("0", "0.0.0"), Ordering::Less);
    }

    #[test]
    fn test_field_matches() {
        use super::{
            field_matches,
            Cpe23Uri,
        };
        let input = Cpe23Uri::new("cpe:2.3:a:vmware:rabbitmq:3.9.10:*:*:*:*:*:*:*");
        let rule = Cpe23Uri::new("cpe:2.3:a:vmware:rabbitmq:*:*:*:*:*:*:*:*");
        assert!(field_matches(&input, &rule));

        let rule_diff_vendor = Cpe23Uri::new("cpe:2.3:a:apache:rabbitmq:*:*:*:*:*:*:*:*");
        assert!(!field_matches(&input, &rule_diff_vendor));

        let rule_sw = Cpe23Uri::new("cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*");
        let input_sw = Cpe23Uri::new("cpe:2.3:a:gitlab:gitlab:*:*:*:*:enterprise:*:*:*");
        assert!(!field_matches(&input_sw, &rule_sw));
        let input_sw_match = Cpe23Uri::new("cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*");
        assert!(field_matches(&input_sw_match, &rule_sw));
    }

    #[test]
    fn test_version_matches() {
        use super::{
            version_matches,
            Cpe23Uri,
        };
        use crate::cve_api::CpeMatch;

        let rule = Cpe23Uri::new("cpe:2.3:a:vmware:rabbitmq:*:*:*:*:*:*:*:*");

        let no_range = CpeMatch {
            cpe23_uri: "cpe:2.3:a:vmware:rabbitmq:*:*:*:*:*:*:*:*".into(),
            version_start_excluding: None,
            version_end_excluding: None,
            version_start_including: None,
            version_end_including: None,
        };
        assert!(version_matches("3.9.10", &rule, &no_range));
        assert!(version_matches("*", &rule, &no_range));

        let end_excl = CpeMatch {
            cpe23_uri: "cpe:2.3:a:vmware:rabbitmq:*:*:*:*:*:*:*:*".into(),
            version_start_excluding: None,
            version_end_excluding: Some("3.11.24".into()),
            version_start_including: None,
            version_end_including: None,
        };
        assert!(version_matches("3.9.10", &rule, &end_excl));
        assert!(!version_matches("4.0.0", &rule, &end_excl));

        let range = CpeMatch {
            cpe23_uri: "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*".into(),
            version_start_including: Some("11.4.0".into()),
            version_end_excluding: Some("15.5.7".into()),
            version_start_excluding: None,
            version_end_including: None,
        };
        assert!(version_matches("12.0.0", &rule, &range));
        assert!(!version_matches("10.0.0", &rule, &range));
        assert!(!version_matches("16.0.0", &rule, &range));
        assert!(version_matches("11.4.0", &rule, &range));
        assert!(version_matches("*", &rule, &range));

        let exact_rule = Cpe23Uri::new("cpe:2.3:a:gitlab:gitlab:16.0.0:*:*:*:*:*:*:*");
        assert!(version_matches("16.0.0", &exact_rule, &no_range));
        assert!(!version_matches("15.0.0", &exact_rule, &no_range));
        assert!(version_matches("*", &exact_rule, &no_range));

        let na_rule = Cpe23Uri::new("cpe:2.3:a:vmware:rabbitmq:-:*:*:*:*:*:*:*");
        assert!(version_matches("any", &na_rule, &no_range));
    }

    // cargo test cve::tests::it_works
    #[test]
    fn it_works() {
        use tokio::runtime::Builder;
        let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
        log_init();
        let path_dir = runtime.block_on(init_dir(DATA_DIR)).unwrap();
        let db_list = runtime
            .block_on(load_db(&path_dir, DbFormat::Protobuf))
            .unwrap();
        log::info!("{}", db_list.len());
        let mut cpe23_uri_vec = Vec::new();
        let line = "cpe:2.3:a:vmware:rabbitmq:3.9.10:*:*:*:*:*:*:*";
        let cpe23_uri = Cpe23Uri::new(line);
        cpe23_uri_vec.push(cpe23_uri);
        let results = runtime
            .block_on(cpe_match(&cpe23_uri_vec, &db_list))
            .unwrap();
        println!("results count: {}", results.len());
        for r in results.iter().take(5) {
            println!(
                "match: {} sev: {} type: {} desc: {}",
                r.id, r.severity, r.problem_type, r.description
            );
        }
    }
}
