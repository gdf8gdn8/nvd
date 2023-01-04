use std::{
    fs::{self, File},
    io::Write,
    path::Path,
};

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

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use xml::{reader::XmlEvent, EventReader};

    use crate::cve::init_log;

    use super::*;

    // cargo test cpe::tests::test_download_cpe
    #[tokio::test]
    async fn test_download_cpe() {
        init_log();
        let future_download_cpe = download_cpe();
        let _ = tokio::join!(future_download_cpe);
    }

    // cargo test cpe::tests::test_it_works
    #[tokio::test]
    async fn test_it_works() {
        init_log();
        let path_gz = Path::new("./data/official-cpe-dictionary_v2.3.xml.gz");
        let file_gz = File::open(path_gz).unwrap();
        let gz_decoder = flate2::read::GzDecoder::new(file_gz);
        let buf_reader = BufReader::new(gz_decoder);
        let event_reader = EventReader::new(buf_reader);
        let mut find_title = false;
        let mut find_uri = false;
        let mut cpe23_title = String::new();
        let mut cpe23_uri = String::new();
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
                log::info!("{cpe23_uri}, {cpe23_title}");
            }
        }
    }
}
