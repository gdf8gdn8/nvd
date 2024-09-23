use std::{
    io::{BufReader, Read, Write},
    path::{Path, PathBuf},
};

use crate::cve_api::{
    BaseMetricV2, BaseMetricV3, Configurations, CpeMatch, Cve, CveDataMeta, CveItem, CveItemBytes,
    CvssV2, CvssV3, Description, DescriptionData, Impact, Node, NvdCve, ProblemTypeData,
    Problemtype,
};
use chrono::{Datelike, Local};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use futures::future::join_all;
use prost::Message;
use sha2::{Digest, Sha256};
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
    task::JoinHandle,
    time::{sleep, Duration},
};

pub static DATA_DIR: &str = "./data";

impl NvdCve {
    #[allow(dead_code)]
    fn new(json: &serde_json::Value) -> NvdCve {
        let cve_items = &json["CVE_Items"];
        let cve_item_bytes_list = CveItem::new(cve_items);
        NvdCve {
            cve_item_bytes_list,
        }
    }
}

impl CveItem {
    fn new(json: &serde_json::Value) -> Vec<CveItemBytes> {
        let json = json.as_array().unwrap();
        let mut cve_item_bytes_list = Vec::new();
        for cve_item in json.iter() {
            let cve = &cve_item["cve"];
            let cve = Some(Cve::new(cve));
            let configurations = &cve_item["configurations"];
            let configurations = Some(Configurations::new(configurations));
            let impact = &cve_item["impact"];
            let impact = Some(Impact::new(impact));
            let last_modified_date = &cve_item["lastModifiedDate"];
            let cve_item = CveItem {
                cve,
                configurations,
                impact,
                last_modified_date: last_modified_date.to_string(),
                published_date: cve_item["publishedDate"].to_string(),
            };
            // CveItem序列化成proto后，再gz压缩
            let mut buf: Vec<u8> = Vec::new();
            cve_item.encode(&mut buf).unwrap();
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&buf).unwrap();
            let buf = encoder.finish().unwrap();
            let cve_item_bytes = CveItemBytes {
                cve_item_bytes: buf,
            };
            cve_item_bytes_list.push(cve_item_bytes);
        }
        cve_item_bytes_list
    }
}
impl Problemtype {
    fn new(json: &serde_json::Value) -> Problemtype {
        let problemtype_data = if json["problemtype_data"].is_null() {
            vec![]
        } else {
            json["problemtype_data"].as_array().unwrap().to_owned()
        };
        // log::info!("{:?}", json);
        let problemtype_data = problemtype_data
            .iter()
            .map(ProblemTypeData::new)
            .collect::<Vec<ProblemTypeData>>();
        Problemtype { problemtype_data }
    }
}
impl ProblemTypeData {
    fn new(json: &serde_json::Value) -> ProblemTypeData {
        let description = json["description"].as_array().unwrap().to_owned();
        let description = description
            .iter()
            .map(|x| x["value"].as_str().unwrap().to_owned())
            .collect::<Vec<String>>();
        ProblemTypeData { description }
    }
}
impl DescriptionData {
    fn new(json: &serde_json::Value) -> DescriptionData {
        let description = if json.is_null() {
            vec![]
        } else {
            json.as_array().unwrap().to_owned()
        };
        let description = description
            .iter()
            .map(|x| x["value"].as_str().unwrap().to_owned())
            .collect::<Vec<String>>();
        // let value = json["value"].as_str().unwrap().to_owned();
        DescriptionData { value: description }
    }
}
impl Description {
    fn new(json: &serde_json::Value) -> Description {
        let description_data = &json["description_data"];
        let description_data = Some(DescriptionData::new(description_data));
        Description { description_data }
    }
}
impl Cve {
    fn new(json: &serde_json::Value) -> Cve {
        let cve_data_meta = &json["CVE_data_meta"];
        let cve_data_meta = Some(CveDataMeta::new(cve_data_meta));
        let problemtype = &json["problemtype"];
        let problemtype = Some(Problemtype::new(problemtype));
        let description = &json["description"];
        let description = Some(Description::new(description));
        Cve {
            cve_data_meta,
            problemtype,
            description: description.to_owned(),
        }
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
impl BaseMetricV2 {
    pub fn new(json: &serde_json::Value) -> BaseMetricV2 {
        // log::info!("{:#?}", json);
        let severity = &json["severity"].as_str().unwrap_or("UNKNOWN").to_owned();
        let exploitability_score = json["exploitabilityScore"].as_f64().unwrap_or(0.0) as f32;
        let impact_score = json["impactScore"].as_f64().unwrap_or(0.0) as f32;
        let obtain_all_privilege = &json["obtainAllPrivilege"].as_bool().unwrap_or(false);
        let obtain_user_privilege = &json["obtainUserPrivilege"].as_bool().unwrap_or(false);
        let obtain_other_privilege = &json["obtainOtherPrivilege"].as_bool().unwrap_or(false);
        let user_interaction_required = &json["userInteractionRequired"].as_bool().unwrap_or(false);
        let cvvss = &json["cvss-V2"];
        let cvss_v2 = Some(CvssV2::new(cvvss));
        BaseMetricV2 {
            severity: severity.clone(),
            exploitability_score,
            impact_score,
            obtain_all_privilege: *obtain_all_privilege,
            obtain_user_privilege: *obtain_user_privilege,
            obtain_other_privilege: *obtain_other_privilege,
            user_interaction_required: *user_interaction_required,
            cvss_v2,
        }
    }
}
impl CvssV2 {
    fn new(json: &serde_json::Value) -> CvssV2 {
        let version = &json["version"].as_str().unwrap_or("").to_owned();
        let vector_string = &json["vectorString"].as_str().unwrap_or("").to_owned();
        let access_vector = &json["accessVector"].as_str().unwrap_or("").to_owned();
        let access_complexity = &json["accessComplexity"].as_str().unwrap_or("").to_owned();
        let confidentiality_impact = &json["confidentialityImpact"]
            .as_str()
            .unwrap_or("")
            .to_owned();
        let integrity_impact = &json["integrityImpact"].as_str().unwrap_or("").to_owned();
        let availability_impact = &json["availabilityImpact"].as_str().unwrap_or("").to_owned();
        let base_score = json["baseScore"].as_f64().unwrap_or(0.0) as f32;
        CvssV2 {
            version: version.clone(),
            vector_string: vector_string.clone(),
            access_vector: access_vector.clone(),
            access_complexity: access_complexity.clone(),
            confidentiality_impact: confidentiality_impact.clone(),
            integrity_impact: integrity_impact.clone(),
            availability_impact: availability_impact.clone(),
            base_score,
        }
    }
}
impl CvssV3 {
    fn new(json: &serde_json::Value) -> CvssV3 {
        let version = &json["version"].as_str().unwrap_or("").to_owned();
        let vector_string = &json["vectorString"].as_str().unwrap_or("").to_owned();
        let attack_vector = &json["attackVector"].as_str().unwrap_or("").to_owned();
        let attack_complexity = &json["attackComplexity"].as_str().unwrap_or("").to_owned();
        let privileges_required = &json["privilegesRequired"].as_str().unwrap_or("").to_owned();
        let user_interaction = &json["userInteraction"].as_str().unwrap_or("").to_owned();
        let scope = &json["scope"].as_str().unwrap_or("").to_owned();
        let confidentiality_impact = &json["confidentialityImpact"]
            .as_str()
            .unwrap_or("")
            .to_owned();
        let integrity_impact = &json["integrityImpact"].as_str().unwrap_or("").to_owned();
        let availability_impact = &json["availabilityImpact"].as_str().unwrap_or("").to_owned();
        let base_score = json["baseScore"].as_f64().unwrap_or(0.0) as f32;
        let base_severity = &json["baseSeverity"].as_str().unwrap_or("").to_owned();
        CvssV3 {
            version: version.clone(),
            vector_string: vector_string.clone(),
            attack_vector: attack_vector.clone(),
            attack_complexity: attack_complexity.clone(),
            privileges_required: privileges_required.clone(),
            user_interaction: user_interaction.clone(),
            scope: scope.clone(),
            confidentiality_impact: confidentiality_impact.clone(),
            integrity_impact: integrity_impact.clone(),
            availability_impact: availability_impact.clone(),
            base_score,
            base_severity: base_severity.clone(),
        }
    }
}
impl BaseMetricV3 {
    fn new(json: &serde_json::Value) -> BaseMetricV3 {
        // log::info!("{:#?}", json);
        let exploitability_score = json["exploitabilityScore"].as_f64().unwrap_or(0.0) as f32;
        let impact_score = json["impactScore"].as_f64().unwrap_or(0.0) as f32;
        let cvss_v3 = &json["cvssV3"];
        let cvss_v3 = Some(CvssV3::new(cvss_v3));
        BaseMetricV3 {
            cvss_v3,
            exploitability_score,
            impact_score,
        }
    }
}
impl Impact {
    fn new(json: &serde_json::Value) -> Impact {
        // log::info!("{:#?}", json);
        let base_metric_v2 = &json["baseMetricV2"];
        let base_metric_v2 = if base_metric_v2.is_null() {
            None
        } else {
            Some(BaseMetricV2::new(base_metric_v2))
        };
        let base_metric_v3 = &json["baseMetricV3"];
        let base_metric_v3 = if base_metric_v3.is_null() {
            None
        } else {
            Some(BaseMetricV3::new(base_metric_v3))
        };
        Impact {
            base_metric_v2,
            base_metric_v3,
        }
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

pub async fn cpe_match(
    cpe23_uri_list: &Vec<Cpe23Uri>,
    cve_db_list: &Vec<NvdCve>,
) -> Result<(), Box<dyn std::error::Error>> {
    let num_cpus = num_cpus::get();
    let mut handle_list: Vec<JoinHandle<()>> = Vec::new();
    for nvdcve in cve_db_list {
        // sleep放在这里，性能更好
        'sleep: while handle_list.len() >= num_cpus {
            for i in 0..handle_list.len() {
                if handle_list[i].is_finished() {
                    handle_list.remove(i);
                    // log::info!("解压缩比match慢,cpe match需要等解压缩");
                    break 'sleep;
                }
            }
            // log::info!("解压缩比match快,需要等cpe match");
            sleep(Duration::from_millis(1)).await;
        }
        let cpe23_uri_list = cpe23_uri_list.to_owned();
        let nvdcve = nvdcve.to_owned();
        let handle = tokio::spawn(async move {
            for cve_items_bytes in nvdcve.cve_item_bytes_list {
                let mut decoder = GzDecoder::new(&cve_items_bytes.cve_item_bytes[..]);
                let mut buf = Vec::new();
                match decoder.read_to_end(&mut buf) {
                    Ok(_) => {
                        let cve_item: CveItem = prost::Message::decode(buf.as_slice()).unwrap();
                        let cve_id = &cve_item
                            .cve
                            .as_ref()
                            .unwrap()
                            .cve_data_meta
                            .as_ref()
                            .unwrap()
                            .id;
                        let severity: String = if let Some(impact) = &cve_item.impact {
                            if let Some(_base_metric_v3) = &impact.base_metric_v3 {
                                if let Some(cvss_v3) = &_base_metric_v3.cvss_v3 {
                                    cvss_v3.base_severity.to_string()
                                } else {
                                    String::new()
                                }
                            } else if let Some(_base_metric_v2) = &impact.base_metric_v2 {
                                _base_metric_v2.severity.to_string()
                            } else {
                                String::new()
                            }
                        } else {
                            String::new()
                        };
                        let problem_type = if let Some(problemtype) =
                            &cve_item.cve.as_ref().unwrap().problemtype
                        {
                            problemtype
                                .problemtype_data
                                .iter()
                                .map(|x| x.description.join(","))
                                .collect::<Vec<String>>()
                                .join(",")
                        } else {
                            String::new()
                        };
                        let description = if let Some(description) =
                            &cve_item.cve.as_ref().unwrap().description
                        {
                            description
                                .description_data
                                .iter()
                                .map(|x| x.value.join(","))
                                .collect::<Vec<String>>()
                                .join(",")
                        } else {
                            String::new()
                        };
                        for node in cve_item.configurations.unwrap().nodes {
                            if match_node(&cpe23_uri_list, &node) {
                                // log::info!("{:#?}", &cve_item2);
                                println!(
                                    "matched :{:>20} severity: {:>10} problem_type: {} ",
                                    cve_id, severity, problem_type
                                );
                            }
                        }
                    }
                    Err(err) => {
                        log::error!("{}", err);
                        log::info!("size: {}", cve_items_bytes.cve_item_bytes.len());
                    }
                };
            }
        });
        handle_list.push(handle);
    }
    for handle in handle_list {
        handle.await?;
    }
    log::info!("match finish.");
    Ok(())
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
    pub fn new(cpe23uri: &str) -> Cpe23Uri {
        let cpe23uri_vec: Vec<&str> = cpe23uri.split(":").collect();
        Cpe23Uri {
            part: cpe23uri_vec[2].to_owned(),
            vendor: cpe23uri_vec[3].to_owned(),
            product: cpe23uri_vec[4].to_owned(),
            version: cpe23uri_vec[5].to_owned(),
            update: cpe23uri_vec[6].to_owned(),
            edition: cpe23uri_vec[7].to_owned(),
            language: cpe23uri_vec[8].to_owned(),
            sw_edition: cpe23uri_vec[9].to_owned(),
            target_sw: cpe23uri_vec[10].to_owned(),
            target_hw: cpe23uri_vec[11].to_owned(),
            other: cpe23uri_vec[12].to_owned(),
        }
    }
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

pub fn cpe23_uri_list_to_string(cpe23_uri_list: &Vec<Cpe23Uri>) -> String {
    let mut cpe23_uri_string_list: Vec<String> = Vec::new();
    for cpe23_uri in cpe23_uri_list {
        cpe23_uri_string_list.push(cpe23_uri.to_string());
    }
    cpe23_uri_string_list.sort();
    cpe23_uri_string_list.into_iter().collect::<String>()
}
fn match_node(cpe23_uri_list: &Vec<Cpe23Uri>, node: &Node) -> bool {
    // log::info!("match {}", cpe23_uri_list_to_string(cpe23_uri_list));
    let operator = &node.operator;
    let is_or = matches!(operator.as_str(), "OR");
    // children存在是match_cpe为空，反之亦然
    let cpe_match_list = &node.cpe_match;
    if !cpe_match_list.is_empty() {
        let mut match_count = 0;
        for cpe_match in cpe_match_list {
            let cpe23_uri = &cpe_match.cpe23_uri;
            let cpe23_uri = Cpe23Uri::new(cpe23_uri);
            let version_start_including = &cpe_match.version_start_including;
            let version_end_including = &cpe_match.version_end_including;
            let version_start_excluding = &cpe_match.version_start_excluding;
            let version_end_excluding = &cpe_match.version_end_excluding;
            'cpe23_uri_list: for cpe23_uri_input in cpe23_uri_list {
                // part, vendor, product严格匹配
                if cpe23_uri_input.part != cpe23_uri.part {
                    continue 'cpe23_uri_list;
                }
                if cpe23_uri_input.vendor != cpe23_uri.vendor {
                    continue 'cpe23_uri_list;
                }
                if cpe23_uri_input.product != cpe23_uri.product {
                    continue 'cpe23_uri_list;
                }
                // 规则中部位“*”的情况下，要严格匹配
                if cpe23_uri.update != "*" && cpe23_uri_input.update != cpe23_uri.update {
                    continue 'cpe23_uri_list;
                }
                if cpe23_uri.edition != "*" && cpe23_uri_input.edition != cpe23_uri.edition {
                    continue 'cpe23_uri_list;
                }
                if cpe23_uri.language != "*" && cpe23_uri_input.language != cpe23_uri.language {
                    continue 'cpe23_uri_list;
                }
                if cpe23_uri.sw_edition != "*" && cpe23_uri_input.sw_edition != cpe23_uri.sw_edition
                {
                    continue 'cpe23_uri_list;
                }
                if cpe23_uri.target_sw != "*" && cpe23_uri_input.target_sw != cpe23_uri.target_sw {
                    continue 'cpe23_uri_list;
                }
                if cpe23_uri.target_hw != "*" && cpe23_uri_input.target_hw != cpe23_uri.target_hw {
                    continue 'cpe23_uri_list;
                }
                if cpe23_uri.other != "*" && cpe23_uri_input.other != cpe23_uri.other {
                    continue 'cpe23_uri_list;
                }
                // 版本号为“-”，匹配所有版本
                if cpe23_uri.version == "-" {
                    if is_or {
                        return true;
                    } else {
                        match_count += 1;
                        continue 'cpe23_uri_list;
                    }
                }
                // 版本号部位“-”和“*”，精确匹配版本
                if cpe23_uri.version != "*" && cpe23_uri_input.version == cpe23_uri.version {
                    if is_or {
                        return true;
                    } else {
                        match_count += 1;
                        continue 'cpe23_uri_list;
                    }
                }
                // 版本号为“*”，需要匹配start和end
                let input_version = cpe23_uri_input.version.as_str();
                if cpe23_uri.version == "*" {
                    // 比较版本
                    match &version_start_including {
                        Some(start_including) => {
                            // 包含开始版本
                            match &version_end_including {
                                Some(end_including) => {
                                    // 包含开始版本,包含结束版本--[start, end]
                                    if input_version.ge(start_including.as_str())
                                        && input_version.le(end_including.as_str())
                                    {
                                        if is_or {
                                            return true;
                                        } else {
                                            match_count += 1;
                                        }
                                    }
                                }
                                None => {
                                    match &version_end_excluding {
                                        Some(end_excluding) => {
                                            // 包含开始版本,不包含结束版本--[start, end)
                                            if input_version.ge(start_including.as_str())
                                                && input_version.lt(end_excluding.as_str())
                                            {
                                                if is_or {
                                                    return true;
                                                } else {
                                                    match_count += 1;
                                                }
                                            }
                                        }
                                        None => {
                                            // 包含开始版本,没有结束版本--[start, ∞)
                                            if input_version.ge(start_including.as_str()) {
                                                if is_or {
                                                    return true;
                                                } else {
                                                    match_count += 1;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        None => {
                            match &version_start_excluding {
                                Some(start_excluding) => {
                                    // 不包含开始版本
                                    match &version_end_including {
                                        Some(end_including) => {
                                            // 不包含开始版本,包含结束版本--(start, end]
                                            if input_version.gt(start_excluding.as_str())
                                                && input_version.le(end_including.as_str())
                                            {
                                                if is_or {
                                                    return true;
                                                } else {
                                                    match_count += 1;
                                                }
                                            }
                                        }
                                        None => {
                                            match &version_end_excluding {
                                                Some(end_excluding) => {
                                                    // 不包含开始版本,不包含结束版本--(start, end)
                                                    if input_version.gt(start_excluding.as_str())
                                                        && input_version.lt(end_excluding.as_str())
                                                    {
                                                        if is_or {
                                                            return true;
                                                        } else {
                                                            match_count += 1;
                                                        }
                                                    }
                                                }
                                                None => {
                                                    // 不包含开始版本,没有结束版本--(start, ∞)
                                                    if input_version.gt(start_excluding.as_str()) {
                                                        if is_or {
                                                            return true;
                                                        } else {
                                                            match_count += 1;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                None => {
                                    // 没有开始版本
                                    match &version_end_including {
                                        Some(end_including) => {
                                            // 没有开始版本,包含结束版本--(∞, end]
                                            if input_version.le(end_including.as_str()) {
                                                if is_or {
                                                    return true;
                                                } else {
                                                    match_count += 1;
                                                }
                                            }
                                        }
                                        None => {
                                            match &version_end_excluding {
                                                Some(end_excluding) => {
                                                    // 没有开始版本,不包含结束版本--(∞, end)
                                                    if input_version.lt(end_excluding.as_str()) {
                                                        if is_or {
                                                            return true;
                                                        } else {
                                                            match_count += 1;
                                                        }
                                                    }
                                                }
                                                None => {
                                                    // 没有开始版本,没有结束版本--(∞, ∞)
                                                    if is_or {
                                                        return true;
                                                    } else {
                                                        match_count += 1;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        // 如果是and，需要所有都匹配上
        if match_count == cpe_match_list.len() {
            return true;
        }
    }

    let children = &node.children;
    if !children.is_empty() {
        let mut match_count = 0;
        for child in children {
            if match_node(cpe23_uri_list, child) {
                if is_or {
                    return true;
                } else {
                    match_count += 1;
                }
            }
        }
        // 如果是and，需要所有都匹配上
        if match_count == children.len() {
            return true;
        }
    }
    false
}

pub async fn make_db(path_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let num_cpus = num_cpus::get_physical();
    let mut handle_list: Vec<JoinHandle<()>> = Vec::new();
    let mut entries = fs::read_dir(path_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let file_name_json = &path.file_name().unwrap().to_str().unwrap();
        if path.is_file()
            && file_name_json.starts_with("nvdcve-1.1-")
            && file_name_json.ends_with(".json.gz")
        {
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
            let handle = tokio::spawn(async move {
                let _ = json_to_proto(&path, &path_dir).await;
            });
            handle_list.push(handle);
            log::trace!("make a new thread to work");
        }
    }
    for handle in handle_list {
        handle.await?;
    }
    Ok(())
}

async fn json_to_proto(
    path_json_gz: &Path,
    path_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_name_json = path_json_gz.file_name().unwrap().to_str().unwrap();
    let file_name_proto = file_name_json.replace(".json.", ".proto.");
    let path_proto = path_dir.join(&file_name_proto);
    log::info!("convert {} to {}", file_name_json, file_name_proto);
    let file_gz = File::open(&path_json_gz).await?;
    let file_gz = file_gz.into_std().await;
    let gz_decoder = flate2::read::GzDecoder::new(file_gz);
    let json = serde_json::from_reader(gz_decoder).unwrap();
    let nvd_cve = NvdCve::new(&json);
    let mut buf: Vec<u8> = Vec::new();
    nvd_cve.encode(&mut buf).unwrap();
    let file_proto = File::create(path_proto).await?;
    let file_proto = file_proto.into_std().await;
    let mut gz_encoder = flate2::write::GzEncoder::new(file_proto, flate2::Compression::default());
    gz_encoder.write_all(&buf).unwrap();
    Ok(())
}

pub async fn load_db(path_dir: &PathBuf) -> Result<Vec<NvdCve>, Box<dyn std::error::Error>> {
    let mut db_list: Vec<NvdCve> = Vec::new();
    let mut nvdcve_vec = Vec::new();
    let mut entries = fs::read_dir(path_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let file_name_json = &path.file_name().unwrap().to_str().unwrap();
        if path.is_file()
            && file_name_json.starts_with("nvdcve-1.1-")
            && file_name_json.ends_with(".proto.gz")
        {
            let file_gz = File::open(path).await?;
            let file_gz = file_gz.into_std().await;
            let gz_decoder = flate2::read::GzDecoder::new(file_gz);
            let mut reader = BufReader::new(gz_decoder);
            let mut buf = Vec::new();
            reader.read_to_end(&mut buf).unwrap();
            let nvd_cve: NvdCve = prost::Message::decode(buf.as_slice()).unwrap();
            nvdcve_vec.push(nvd_cve);
        }
    }
    // 平均分配db
    let count_max = 8_000;
    let mut count = 0;
    let mut cve_item_bytes_list = Vec::new();
    for nvdcve in nvdcve_vec {
        for cve_item_bytes in nvdcve.cve_item_bytes_list {
            cve_item_bytes_list.push(cve_item_bytes);
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
    }
    if count > 0 {
        let nvdcve = NvdCve {
            cve_item_bytes_list,
        };
        db_list.push(nvdcve);
    }
    Ok(db_list)
}

pub async fn sync_cve(path_dir: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
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
            let file_gz = File::open(&path_gz).await?;
            let file_gz = file_gz.into_std().await;
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
        let mut file_gz = File::create(path_gz).await?;
        file_gz.write_all(&rsp_bytes).await?;
    } else {
        log::error!("get meta fail: {}", &url_meta);
    }
    Ok(())
}

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
    use dev_util::log::log_init;

    use super::{cpe_match, init_dir, load_db, make_db, sync_cve, Cpe23Uri, DATA_DIR};

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
        make_db(&path_dir).await?;
        Ok(())
    }
    // cargo test cve::tests::test_load_db
    #[tokio::test]
    async fn test_load_db() -> Result<(), Box<dyn std::error::Error>> {
        log_init();
        let path_dir = init_dir(DATA_DIR).await?;
        let db_list = load_db(&path_dir).await?;
        log::info!("db_list len: {}", db_list.len());
        Ok(())
    }

    // cargo test cve::tests::test_cpe_match
    #[tokio::test(flavor = "multi_thread")]
    async fn test_cpe_match() -> Result<(), Box<dyn std::error::Error>> {
        log_init();
        let path_dir = init_dir(DATA_DIR).await?;
        let db_list = load_db(&path_dir).await?;
        log::info!("db_list len: {}", db_list.len());
        let mut cpe23_uri_vec = Vec::new();
        let line = "cpe:2.3:a:vmware:rabbitmq:3.9.10:*:*:*:*:*:*:*";
        println!("cpe23_uri: {}", line);
        let cpe23_uri = Cpe23Uri::new(line);
        cpe23_uri_vec.push(cpe23_uri);
        cpe_match(&cpe23_uri_vec, &db_list).await?;
        Ok(())
    }

    // cargo test cve::tests::it_works
    #[test]
    fn it_works() {
        use tokio::runtime::Builder;
        let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
        log_init();
        let path_dir = runtime.block_on(init_dir(DATA_DIR)).unwrap();
        let db_list = runtime.block_on(load_db(&path_dir)).unwrap();
        log::info!("{}", db_list.len());
        let mut cpe23_uri_vec = Vec::new();
        let line = "cpe:2.3:a:vmware:rabbitmq:3.9.10:*:*:*:*:*:*:*";
        let cpe23_uri = Cpe23Uri::new(line);
        cpe23_uri_vec.push(cpe23_uri);
        runtime
            .block_on(cpe_match(&cpe23_uri_vec, &db_list))
            .unwrap();
    }
}
