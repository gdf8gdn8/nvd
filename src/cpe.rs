use std::{
    fs::{self, File},
    io::{BufReader, BufWriter, Write},
    path::Path,
};

use flate2::{write::GzEncoder, Compression};
use nvd::{
    cve_api::{Cpe23, Cpe23Dictionary},
    init_log,
};
use prost::Message;
use xml::{reader::XmlEvent, EventReader};

// cargo run --release --bin cpe
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_log();
    make_cpe_dictionary().await;
    Ok(())
}

#[allow(dead_code)]
async fn download_cpe() -> Result<(), Box<dyn std::error::Error>> {
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

async fn make_cpe_dictionary() {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    // cargo test tests::test_download_cpe
    #[tokio::test]
    async fn test_download_cpe() {
        init_log();
        let future_download_cpe = download_cpe();
        let _ = tokio::join!(future_download_cpe);
    }

    // cargo test tests::test_it_works
    #[tokio::test]
    async fn test_it_works() {
        init_log();
        make_cpe_dictionary().await;
    }
}
