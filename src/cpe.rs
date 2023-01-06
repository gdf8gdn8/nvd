use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write},
    path::Path,
};

use flate2::{read::GzDecoder, write::GzEncoder, Compression};

use prost::Message;
use xml::{reader::XmlEvent, EventReader};

use crate::cve_api::{Cpe23, Cpe23Dictionary, Cpe23Title};

#[allow(dead_code)]
pub async fn download_cpe() -> Result<(), Box<dyn std::error::Error>> {
    let cpe_file_name = "official-cpe-dictionary_v2.3.xml.gz";
    let path = Path::new("./data");
    if !path.exists() {
        fs::create_dir(path).unwrap();
    }
    let path = path.join(cpe_file_name);
    let mut file = File::create(&path).unwrap();
    let url = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz";
    let rsp = reqwest::get(url).await?;
    let rsp_bytes = rsp.bytes().await?;
    let _ = file.write_all(&rsp_bytes);
    log::info!("{} downloaded successfully", cpe_file_name);
    Ok(())
}

pub async fn make_cpe_dictionary() -> Result<(), Box<dyn std::error::Error>> {
    let path_xml_gz = Path::new("./data/official-cpe-dictionary_v2.3.xml.gz");
    let file_xml_gz = File::open(path_xml_gz).unwrap();
    let gz_decoder = flate2::read::GzDecoder::new(file_xml_gz);
    let buf_reader = BufReader::new(gz_decoder);
    let event_reader = EventReader::new(buf_reader);
    let mut find_title = false;
    let mut find_uri = false;
    let mut cpe23_title = String::new();
    let mut cpe23_uri = String::new();
    let mut cpe_dictionary = Cpe23Dictionary::default();
    for event in event_reader {
        match event {
            Ok(XmlEvent::StartElement {
                name,
                attributes,
                namespace: _,
            }) => {
                if "title".eq(&name.local_name) {
                    for attribute in &attributes {
                        if "lang".eq(&attribute.name.local_name) {
                            if "en-US".eq(&attribute.value) {
                                find_title = true;
                                find_uri = false;
                            }
                        }
                    }
                } else if "cpe23-item".eq(&name.local_name) {
                    for attribute in &attributes {
                        if "name".eq(&attribute.name.local_name) {
                            find_uri = true;
                            cpe23_uri = attribute.value.to_owned();
                        }
                    }
                }
            }
            Ok(XmlEvent::Characters(characters)) => {
                if find_title {
                    cpe23_title = characters;
                    find_title = false;
                }
            }
            _ => {}
        };
        if find_uri {
            let cpe23 = Cpe23 {
                cpe23_uri: cpe23_uri.to_owned(),
                cpe23_title: cpe23_title.to_owned(),
            };
            cpe_dictionary.cpe23_list.push(cpe23);
        }
    }
    log::info!("dictionary size: {}", cpe_dictionary.cpe23_list.len());
    let path_proto_gz = "./data/cpe_dictionary.proto.gz";
    let file_proto_gz = File::create(path_proto_gz).unwrap();
    let buf_writer = BufWriter::new(file_proto_gz);
    let mut gz_encoder = GzEncoder::new(buf_writer, Compression::default());
    let mut buf: Vec<u8> = Vec::new();
    cpe_dictionary.encode(&mut buf).unwrap();
    drop(cpe_dictionary);
    gz_encoder.write_all(&buf).unwrap();
    Ok(())
}

pub async fn make_cpe_title() -> Result<(), Box<dyn std::error::Error>> {
    let path_proto_gz = "./data/cpe_dictionary.proto.gz";
    let file_proto_gz = File::open(path_proto_gz).unwrap();
    let buf_reader = BufReader::new(file_proto_gz);
    let gz_decoder = GzDecoder::new(buf_reader);
    let mut buf_reader = BufReader::new(gz_decoder);
    let mut buf = Vec::new();
    buf_reader.read_to_end(&mut buf).unwrap();
    let cpe23_dictionary: Cpe23Dictionary = prost::Message::decode(buf.as_slice()).unwrap();
    let mut cpe23_title = Cpe23Title::default();
    for cpe23 in cpe23_dictionary.cpe23_list {
        // cpe:2.3:a:10web:slider:1.1.71:*:*:*:*:wordpress:*:*
        let cpe23uri_vec: Vec<&str> = cpe23.cpe23_uri.split(":").collect();

        // if !"*".eq(cpe23uri_vec[10]) || !"*".eq(cpe23uri_vec[11]) {
        //     log::info!("{:?}", cpe23);
        // }

        // part:vendor:product
        let key = format!(
            "{}:{}:{}",
            cpe23uri_vec[2], cpe23uri_vec[3], cpe23uri_vec[4]
        );
        let version = cpe23uri_vec[5];
        let mut value = cpe23.cpe23_title;
        if !"*".eq(version) {
            // 抹掉version和update
            let offset = value.find(&format!(" {}", version)).unwrap_or(value.len());
            value.replace_range(offset..value.len(), "");
        }
        // if !"*".eq(cpe23uri_vec[10]) || !"*".eq(cpe23uri_vec[11]) {
        //     log::info!("{key}--{value}");
        // }
        cpe23_title.cpe23_title_map.insert(key.to_owned(), value);
    }
    log::info!("cpe23 title size: {}", cpe23_title.cpe23_title_map.len());
    let path_proto_gz = "./data/cpe23_title.proto.gz";
    let file_proto_gz = File::create(path_proto_gz).unwrap();
    let buf_writer = BufWriter::new(file_proto_gz);
    let mut gz_encoder = GzEncoder::new(buf_writer, Compression::default());
    let mut buf: Vec<u8> = Vec::new();
    cpe23_title.encode(&mut buf).unwrap();
    drop(cpe23_title);
    gz_encoder.write_all(&buf).unwrap();
    Ok(())
}

#[cfg(test)]
mod tests {
    use dev_util::log::log_init;

    use super::*;

    // cargo test cve::tests::test_download_cpe
    #[tokio::test]
    async fn test_download_cpe() -> Result<(), Box<dyn std::error::Error>> {
        log_init();
        download_cpe().await
    }

    // cargo test cve::tests::test_make_cpe_dictionary
    #[tokio::test]
    async fn test_make_cpe_dictionary() -> Result<(), Box<dyn std::error::Error>> {
        log_init();
        make_cpe_dictionary().await
    }

    // cargo test cve::tests::test_make_cpe_title
    #[tokio::test]
    async fn test_make_cpe_title() -> Result<(), Box<dyn std::error::Error>> {
        log_init();
        make_cpe_title().await
    }
}
