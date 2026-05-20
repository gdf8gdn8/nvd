use criterion::{
    criterion_group,
    criterion_main,
    Criterion,
};
use nvd::cve::{
    cpe_match,
    init_dir,
    load_db,
    Cpe23Uri,
    DATA_DIR,
};
use nvd::format::DbFormat;
use std::hint::black_box;
use tokio::runtime::Builder;

fn bench_load_db(c: &mut Criterion) {
    let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
    let path_dir = runtime.block_on(init_dir(DATA_DIR)).unwrap();

    for format in &[
        DbFormat::Protobuf,
        DbFormat::MessagePack,
        DbFormat::RkyvMmapRedb,
        DbFormat::FlatBuffers,
        DbFormat::CapnProto,
        DbFormat::Turso,
    ] {
        let label = format!("load_db_{:?}", format);
        c.bench_function(&label, |b| {
            b.iter(|| {
                runtime
                    .block_on(load_db(black_box(&path_dir), *format))
                    .unwrap()
            })
        });
    }
}

fn bench_cpe_match(c: &mut Criterion) {
    let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
    let path_dir = runtime.block_on(init_dir(DATA_DIR)).unwrap();
    let db_list = runtime
        .block_on(load_db(&path_dir, DbFormat::Protobuf))
        .unwrap();
    let mut cpe23_uri_vec = Vec::new();
    let line = "cpe:2.3:a:vmware:rabbitmq:3.9.10:*:*:*:*:*:*:*";
    let cpe23_uri = Cpe23Uri::new(line);
    cpe23_uri_vec.push(cpe23_uri);
    c.bench_function("cpe_match", |b| {
        b.iter(|| {
            runtime
                .block_on(cpe_match(black_box(&cpe23_uri_vec), black_box(&db_list)))
                .unwrap()
        })
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(20).measurement_time(std::time::Duration::from_secs(30));
    targets = bench_load_db, bench_cpe_match
);
criterion_main!(benches);
