use tracing_subscriber::fmt::format::FmtSpan;

const LOG_LEVEL: tracing::Level = if cfg!(debug_assertions) {
    tracing::Level::TRACE
} else {
    tracing::Level::INFO
};

pub fn init() -> anyhow::Result<()> {
    let subscriber = tracing_subscriber::fmt::Subscriber::builder()
        .with_max_level(LOG_LEVEL)
        .with_span_events(FmtSpan::CLOSE)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    Ok(())
}
