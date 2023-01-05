pub fn log_init() {
    struct LocalTimer;
    impl tracing_subscriber::fmt::time::FormatTime for LocalTimer {
        fn format_time(
            &self,
            w: &mut tracing_subscriber::fmt::format::Writer<'_>,
        ) -> std::fmt::Result {
            write!(w, "{}", chrono::Local::now().format("%F %T%.3f"))
        }
    }
    let format = tracing_subscriber::fmt::format()
        .with_level(true)
        .with_target(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_thread_names(false)
        .with_timer(LocalTimer);
    match tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_writer(std::io::stdout)
        .with_ansi(true)
        .event_format(format)
        .try_init()
    {
        Ok(_) => {}
        Err(_) => {}
    };
}
