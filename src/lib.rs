pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;
    fn init_log() {
        struct LocalTimer;
        impl FormatTime for LocalTimer {
            fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
                write!(w, "{}", Local::now().format("%F %T%.3f"))
            }
        }
        let format = tracing_subscriber::fmt::format()
            .with_level(true)
            .with_target(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_timer(LocalTimer);
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(std::io::stdout)
            .with_ansi(true)
            .event_format(format)
            .init();
    }
    #[test]
    fn it_works() {
        init_log();
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
