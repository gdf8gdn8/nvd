use chrono::NaiveDate;
use clap::Parser;
use dev_util::log::{
    log_init_with_level,
    Level,
};
use indicatif::{
    ProgressBar,
    ProgressStyle,
};
use nvd::cpe::{
    download_cpe,
    make_cpe_dictionary,
    make_cpe_title,
};
use nvd::cve::{
    cpe23_uri_list_to_string,
    cpe_match,
    init_dir,
    load_db,
    make_db,
    sync_cve,
    Cpe23Uri,
    DATA_DIR,
};
use nvd::format::DbFormat;
use std::str::FromStr;
use tabled::settings::Style;

#[derive(Clone, Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Debug, Parser)]
struct Cpe {
    /// Enable verbose (DEBUG) logging
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
    /// Database serialisation format
    #[arg(short, long, default_value = "protobuf")]
    format: DbFormat,
}

#[derive(Clone, Debug, Parser)]
enum Commands {
    Cve(Cve),
    Cpe(Cpe),
}

#[derive(Clone, Debug, Parser)]
struct Cve {
    /// CPE 2.3 URI to match, e.g. `cpe:2.3:a:vmware:rabbitmq:3.9.10:*:*:*:*:*:*:*`
    cve: String,
    /// Skip the sync step (don't download/verify JSON feeds)
    #[arg(long, default_value_t = false)]
    no_sync: bool,
    /// Print severity statistics instead of individual results
    #[arg(long)]
    stat: bool,
    /// Only show CVEs published on or after this date (YYYY-MM-DD)
    #[arg(long)]
    from_date: Option<String>,
    /// Only show CVEs published on or before this date (YYYY-MM-DD)
    #[arg(long)]
    to_date: Option<String>,
    /// Sort results by one of: `id`, `severity`, `date`
    #[arg(long)]
    sort: Option<String>,
    /// Delete all cached database files before rebuilding
    #[arg(long, default_value_t = false)]
    rebuild: bool,
    /// Enable verbose (DEBUG) logging
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
    /// Database serialisation format
    // #[arg(short, long, default_value = "protobuf")]
    #[arg(short, long, default_value = "turso")]
    format: DbFormat,
    /// Display results in a formatted table
    #[arg(long, default_value_t = false)]
    table: bool,
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
                args.verbose,
                args.format,
                args.table,
            )
            .await?;
        }
        Commands::Cpe(args) => {
            cpe(args.verbose, args.format).await?;
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
            .template("{spinner:.green} {msg}")
            .unwrap(),
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
    verbose: bool,
    format: DbFormat,
    table: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if verbose {
        log_init_with_level(Level::DEBUG);
    } else {
        log_init_with_level(Level::WARN);
    }
    let pb = spinner("Initializing data directory…");
    let path_dir = init_dir(DATA_DIR).await?;
    if !no_sync {
        pb.set_message("Syncing CVE data…");
        sync_cve(&path_dir).await?;
    }
    if rebuild {
        pb.set_message("Removing old database…");
        let mut entries = tokio::fs::read_dir(&path_dir).await?;
        let exts = DbFormat::all_extensions();
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if exts.iter().any(|e| name.ends_with(e)) {
                tokio::fs::remove_file(&path).await?;
            }
        }
    }
    pb.set_message("Building database…");
    make_db(&path_dir, format).await?;
    pb.set_message("Loading database…");
    let db_list = load_db(&path_dir, format).await?;
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
                let date_str = r.published_date.trim_matches('"');
                let pub_date = date_str
                    .get(..10)
                    .and_then(|s| NaiveDate::from_str(s).ok())
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
            "date" => results.sort_by(|a, b| {
                a.published_date
                    .trim_matches('"')
                    .cmp(b.published_date.trim_matches('"'))
            }),
            _ => log::warn!("unknown sort field: {}", sort_field),
        }
    }

    // print
    if table {
        use tabled::builder::Builder;
        let mut builder = Builder::default();
        builder.push_record(["ID", "Date", "Severity", "Problem Type", "Description"]);
        for r in &results {
            let date_str = r.published_date.trim_matches('"');
            let date_short = date_str.get(..10).unwrap_or(date_str);
            builder.push_record([
                r.id.as_str(),
                date_short,
                r.severity.as_str(),
                r.problem_type.as_str(),
                r.description.as_str(),
            ]);
        }
        let mut table = builder.build();
        table.with(Style::rounded());
        println!("{table}");
    } else {
        for r in &results {
            let date_str = r.published_date.trim_matches('"');
            let date_short = date_str.get(..10).unwrap_or(date_str);
            println!(
                "matched :{:>20} date: {} severity: {:>10} problem_type: {} description: {}",
                r.id, date_short, r.severity, r.problem_type, r.description
            );
        }
    }

    // statistics
    if stat {
        let total = results.len();
        let mut sev: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
        for r in &results {
            let s = if r.severity.is_empty() {
                "UNKNOWN"
            } else {
                &r.severity
            };
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

async fn cpe(verbose: bool, _format: DbFormat) -> Result<(), Box<dyn std::error::Error>> {
    if verbose {
        log_init_with_level(Level::DEBUG);
    } else {
        log_init_with_level(Level::WARN);
    }
    let pb = spinner("Downloading CPE dictionary…");
    download_cpe().await?;
    pb.set_message("Building CPE dictionary…");
    make_cpe_dictionary().await?;
    pb.set_message("Building CPE title index…");
    make_cpe_title().await?;
    pb.finish_with_message("Done!");
    Ok(())
}
