use criterion::async_executor::FuturesExecutor;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use futures::executor::block_on;
use nvd::cve::{cpe_match, init_dir, load_db, Cpe23Uri, DATA_DIR};
pub fn criterion_benchmark(c: &mut Criterion) {
    let path_dir = init_dir(DATA_DIR);
    let path_dir = block_on(path_dir).unwrap();
    let db_list = load_db(&path_dir);
    let db_list = block_on(db_list).unwrap();
    let mut cpe23_uri_vec = Vec::new();
    let line = "cpe:2.3:a:vmware:rabbitmq:3.9.10:*:*:*:*:*:*:*";
    let cpe23_uri = Cpe23Uri::new(line);
    cpe23_uri_vec.push(cpe23_uri);

    c.bench_function("cpe_match", move |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            // cpe_match(black_box(&cpe23_uri_vec), black_box(&db_list)).await
            // cpe_match(&cpe23_uri_vec, &db_list).await
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
