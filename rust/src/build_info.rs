pub const GIT_REVISION: &str = env!("FORGEPROXY_GIT_REVISION");
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("FORGEPROXY_GIT_REVISION"),
    ")"
);
