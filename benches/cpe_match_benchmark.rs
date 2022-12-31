use criterion::{black_box, criterion_group, criterion_main, Criterion};
use nvd::cve::{
    cpe_match,
    init_dir,
    load_db,
    // make_db, sync_cve,
    Cpe23Uri,
    DATA_DIR,
};
use tokio::runtime::Builder;
pub fn criterion_benchmark(c: &mut Criterion) {
    let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
    let path_dir = runtime.block_on(init_dir(DATA_DIR)).unwrap();
    // runtime.block_on(sync_cve(&path_dir)).unwrap();
    // runtime.block_on(make_db(&path_dir)).unwrap();
    let db_list = runtime.block_on(load_db(&path_dir)).unwrap();
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
criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
