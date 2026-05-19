use std::str::FromStr;

use chrono::NaiveDate;
use clap::Parser;
use dev_util::log::{log_init_with_level, Level};
use indicatif::{ProgressBar, ProgressStyle};
use nvd::{
    cpe::{download_cpe, make_cpe_dictionary, make_cpe_title},
    cve::{
        cpe23_uri_list_to_string, cpe_match, init_dir, load_db, make_db, sync_cve, Cpe23Uri,
        DATA_DIR,
    },
};

#[derive(Clone, Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Debug, Parser)]
enum Commands {
    Cve(Cve),
    Cpe,
}

#[derive(Clone, Debug, Parser)]
struct Cve {
    cve: String,
    #[arg(long, default_value_t = false)]
    no_sync: bool,
    #[arg(long)]
    stat: bool,
    #[arg(long)]
    from_date: Option<String>,
    #[arg(long)]
    to_date: Option<String>,
    #[arg(long)]
    sort: Option<String>,
    #[arg(long, default_value_t = false)]
    rebuild: bool,
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    log_init_with_level(Level::WARN);
    let cli = Cli::parse();
    match &cli.command {
        Commands::Cve(args) => {
            cve(
                args.cve.as_str(),
                args.no_sync,
                args.stat,
                args.from_date.as_deref(),
                args.to_date.as_deref(),
                args.sort.as_deref(),
                args.rebuild,
            )
            .await?;
        }
        Commands::Cpe => {
            cpe().await?;
        }
    }
    // if args.len() != 2 {
    //     log::error!("arguments error!");
    //     log::error!("eg: {} [cve|cpe]", args[0]);
    //     process::exit(1);
    // }
    // if "cve".eq(&args[1]) {
    //     cve("cpe:2.3:a:qt:qt:4.8.7:*:*:*:*:*:*:*").await?;
    // } else if "cpe".eq(&args[1]) {
    //     cpe().await?;
    // } else {
    //     log::error!("arguments error!");
    //     log::error!("eg: {} [cve|cpe]", args[0]);
    // }
    Ok(())
}

fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ")
            .template("{spinner:.green} {msg}").unwrap(),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb
}

async fn cve(
    line: &str,
    no_sync: bool,
    stat: bool,
    from_date: Option<&str>,
    to_date: Option<&str>,
    sort: Option<&str>,
    rebuild: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let pb = spinner("Initializing data directory…");
    let path_dir = init_dir(DATA_DIR).await?;
    if !no_sync {
        pb.set_message("Syncing CVE data…");
        sync_cve(&path_dir).await?;
    }
    if rebuild {
        pb.set_message("Removing old database…");
        let mut entries = tokio::fs::read_dir(&path_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()).map_or(false, |n| n.ends_with(".proto.zst")) {
                tokio::fs::remove_file(&path).await?;
            }
        }
    }
    pb.set_message("Building database…");
    make_db(&path_dir).await?;
    pb.set_message("Loading database…");
    let db_list = load_db(&path_dir).await?;
    pb.finish_and_clear();
    log::info!("db_list len: {}", db_list.len());
    let mut cpe23_uri_vec = Vec::new();
    let cpe23_uri = Cpe23Uri::new(line);
    cpe23_uri_vec.push(cpe23_uri);
    log::info!("cpe23_uri: {}", cpe23_uri_list_to_string(&cpe23_uri_vec));
    let pb = spinner("Matching CPE…");
    let mut results = cpe_match(&cpe23_uri_vec, &db_list).await?;
    pb.finish_and_clear();

    // filter by date
    let from = from_date
        .and_then(|d| NaiveDate::from_str(d).ok())
        .map(|d| d.and_hms_opt(0, 0, 0).unwrap());
    let to = to_date
        .and_then(|d| NaiveDate::from_str(d).ok())
        .map(|d| d.and_hms_opt(23, 59, 59).unwrap());
    if from.is_some() || to.is_some() {
        results = results
            .into_iter()
            .filter(|r| {
                let pub_date = NaiveDate::from_str(&r.published_date[..10])
                    .ok()
                    .map(|d| d.and_hms_opt(0, 0, 0).unwrap());
                let after = from.map_or(true, |f| pub_date.map_or(true, |p| p >= f));
                let before = to.map_or(true, |t| pub_date.map_or(true, |p| p <= t));
                after && before
            })
            .collect();
    }

    // sort
    if let Some(sort_field) = sort {
        match sort_field {
            "id" => results.sort_by(|a, b| a.id.cmp(&b.id)),
            "severity" => {
                let rank = |s: &str| -> u8 {
                    match s {
                        "CRITICAL" => 4,
                        "HIGH" => 3,
                        "MEDIUM" => 2,
                        "LOW" => 1,
                        _ => 0,
                    }
                };
                results.sort_by(|a, b| rank(&b.severity).cmp(&rank(&a.severity)));
            }
            "date" => results.sort_by(|a, b| a.published_date.cmp(&b.published_date)),
            _ => {}
        }
    }

    // print
    for r in &results {
        println!(
            "matched :{:>20} severity: {:>10} problem_type: {} description: {}",
            r.id, r.severity, r.problem_type, r.description
        );
    }

    // statistics
    if stat {
        let total = results.len();
        let mut sev: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
        for r in &results {
            let s = if r.severity.is_empty() { "UNKNOWN" } else { &r.severity };
            *sev.entry(s).or_insert(0) += 1;
        }
        println!("\n--- statistics ---");
        println!("total: {}", total);
        for (s, n) in &sev {
            println!("  {}: {}", s, n);
        }
    }

    Ok(())
}

async fn cpe() -> Result<(), Box<dyn std::error::Error>> {
    let pb = spinner("Downloading CPE dictionary…");
    download_cpe().await?;
    pb.set_message("Building CPE dictionary…");
    make_cpe_dictionary().await?;
    pb.set_message("Building CPE title index…");
    make_cpe_title().await?;
    pb.finish_with_message("Done!");
    Ok(())
}
