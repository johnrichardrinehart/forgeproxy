use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Context;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{debug, error, info};

// ── CLI (all fields optional — defaults live in `resolve()`) ──────────────────

#[derive(Parser, Debug)]
#[command(
    name = "ghe-key-lookup",
    about = "Map SSH key fingerprints to GHE users"
)]
struct Cli {
    /// Path to a TOML configuration file; CLI flags take precedence over
    /// any value set in the file.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Address:port to listen on [default: 0.0.0.0:3000]
    #[arg(long)]
    listen: Option<String>,

    /// Path to the SSH private key for the GHE admin console
    #[arg(short = 'i', long)]
    identity_file: Option<String>,

    /// SSH username for the GHE admin console [default: admin]
    #[arg(long)]
    ssh_user: Option<String>,

    /// Hostname (or IP) of the GHE admin SSH endpoint, e.g. ghe.example.com
    #[arg(long)]
    ssh_target_endpoint: Option<String>,

    /// Base URL for response url fields, e.g. https://ghe.example.com
    /// [default: https://<ssh-target-endpoint>]
    /// Override only when the HTTPS hostname differs from the SSH target.
    #[arg(long)]
    ghe_url: Option<String>,

    /// SSH port for the GHE admin console [default: 122]
    #[arg(long)]
    ssh_port: Option<u16>,

    /// Path for the SSH ControlMaster socket; enables connection reuse so that
    /// subsequent requests skip TCP+auth overhead.
    /// Leave unset or empty to open a fresh connection per request [default: ""]
    #[arg(long)]
    ssh_control_path: Option<String>,

    /// How long the ControlMaster process lingers after the last client
    /// disconnects: "yes" = indefinite, "no" = exit immediately, or seconds.
    /// Only used when --ssh-control-path is set [default: yes]
    #[arg(long)]
    ssh_control_persist: Option<String>,

    /// Seconds to cache a positive result (key found) [default: 300]
    #[arg(long)]
    cache_ttl_pos: Option<u64>,

    /// Seconds to cache a negative result (key not found); 0 disables [default: 30]
    #[arg(long)]
    cache_ttl_neg: Option<u64>,
}

// ── Config file (TOML) ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    listen: Option<String>,
    identity_file: Option<String>,
    ssh_user: Option<String>,
    ssh_target_endpoint: Option<String>,
    ghe_url: Option<String>,
    ssh_port: Option<u16>,
    ssh_control_path: Option<String>,
    ssh_control_persist: Option<String>,
    cache_ttl_pos: Option<u64>,
    cache_ttl_neg: Option<u64>,
}

// ── Resolved config ───────────────────────────────────────────────────────────

#[derive(Debug)]
struct ResolvedConfig {
    listen: String,
    identity_file: String,
    ssh_user: String,
    /// Hostname of the GHE SSH admin endpoint.
    ssh_target_endpoint: String,
    /// Base URL for response url fields, e.g. "https://ghe.example.com".
    /// Defaults to https://<ssh_target_endpoint>.
    ghe_url: String,
    ssh_port: u16,
    ssh_control_path: String,
    ssh_control_persist: String,
    cache_ttl_pos: u64,
    cache_ttl_neg: u64,
}

/// Merge: CLI flags > config-file values > hardcoded defaults.
fn resolve(cli: Cli, file: ConfigFile) -> anyhow::Result<ResolvedConfig> {
    let ssh_target_endpoint = cli.ssh_target_endpoint
        .or(file.ssh_target_endpoint)
        .context("ssh_target_endpoint is required: pass --ssh-target-endpoint or set it in the config file")?;

    // ghe_url defaults to https://<ssh_target_endpoint> when absent.
    let ghe_url = cli
        .ghe_url
        .or(file.ghe_url)
        .unwrap_or_else(|| format!("https://{}", ssh_target_endpoint));

    Ok(ResolvedConfig {
        listen: cli
            .listen
            .or(file.listen)
            .unwrap_or_else(|| "0.0.0.0:3000".to_owned()),

        identity_file: cli.identity_file.or(file.identity_file).context(
            "identity_file is required: pass --identity-file or set it in the config file",
        )?,

        ssh_user: cli
            .ssh_user
            .or(file.ssh_user)
            .unwrap_or_else(|| "admin".to_owned()),

        ssh_target_endpoint,
        ghe_url,

        ssh_port: cli.ssh_port.or(file.ssh_port).unwrap_or(122),

        ssh_control_path: cli
            .ssh_control_path
            .or(file.ssh_control_path)
            .unwrap_or_default(),

        ssh_control_persist: cli
            .ssh_control_persist
            .or(file.ssh_control_persist)
            .unwrap_or_else(|| "yes".to_owned()),

        cache_ttl_pos: cli.cache_ttl_pos.or(file.cache_ttl_pos).unwrap_or(300),

        cache_ttl_neg: cli.cache_ttl_neg.or(file.cache_ttl_neg).unwrap_or(30),
    })
}

// ── Cache ─────────────────────────────────────────────────────────────────────

#[derive(Clone)]
enum CacheValue {
    Hit(Vec<KeyRow>),
    Miss,
}

struct CacheEntry {
    value: CacheValue,
    expires_at: Instant,
}

type Cache = Mutex<HashMap<String, CacheEntry>>;

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    config: Arc<ResolvedConfig>,
    cache: Arc<Cache>,
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize)]
struct KeyRow {
    id: u64,
    key: String,
    title: String,
    /// Full URL to this key on the GHE instance, e.g.
    /// https://ghe.example.com/user/keys/42
    url: String,
    created_at: String,
    /// True when `verified_at` is non-NULL in the database.
    verified: bool,
    read_only: bool,
    /// Maps to `accessed_at` in the database.
    last_used: Option<String>,
    user_id: u64,
    repository_id: Option<u64>,
    login: String,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

#[derive(Deserialize)]
struct LookupQuery {
    fingerprint: String,
}

async fn lookup_key(
    State(state): State<AppState>,
    Query(params): Query<LookupQuery>,
) -> impl IntoResponse {
    let fp = params
        .fingerprint
        .strip_prefix("SHA256:")
        .unwrap_or(&params.fingerprint)
        .to_owned();

    if !fp
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"message": "Invalid fingerprint format"})),
        )
            .into_response();
    }

    if let Some(cached) = cache_get(&state.cache, &fp) {
        debug!(fingerprint = %fp, "cache hit");
        return respond(cached);
    }

    match ssh_query(&state.config, &fp).await {
        Err(e) => {
            error!("SSH query failed: {e:#}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"message": "Internal server error"})),
            )
                .into_response()
        }
        Ok(rows) => {
            let value = if rows.is_empty() {
                cache_insert(
                    &state.cache,
                    fp,
                    CacheValue::Miss,
                    Duration::from_secs(state.config.cache_ttl_neg),
                );
                CacheValue::Miss
            } else {
                cache_insert(
                    &state.cache,
                    fp,
                    CacheValue::Hit(rows.clone()),
                    Duration::from_secs(state.config.cache_ttl_pos),
                );
                CacheValue::Hit(rows)
            };
            respond(value)
        }
    }
}

fn respond(value: CacheValue) -> axum::response::Response {
    match value {
        CacheValue::Hit(rows) => (StatusCode::OK, Json(rows)).into_response(),
        CacheValue::Miss => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"message": "Not Found"})),
        )
            .into_response(),
    }
}

// ── Cache helpers ─────────────────────────────────────────────────────────────

fn cache_get(cache: &Cache, key: &str) -> Option<CacheValue> {
    let mut map = cache.lock().expect("cache lock poisoned");
    match map.get(key) {
        Some(entry) if entry.expires_at > Instant::now() => Some(entry.value.clone()),
        Some(_) => {
            map.remove(key);
            None
        }
        None => None,
    }
}

fn cache_insert(cache: &Cache, key: String, value: CacheValue, ttl: Duration) {
    if ttl.is_zero() {
        return;
    }
    let mut map = cache.lock().expect("cache lock poisoned");
    map.insert(
        key,
        CacheEntry {
            value,
            expires_at: Instant::now() + ttl,
        },
    );
}

// ── SSH + SQL ─────────────────────────────────────────────────────────────────

fn build_ssh_args(cfg: &ResolvedConfig, remote_cmd: &str) -> Vec<String> {
    let mut args = vec![
        "-i".to_owned(),
        cfg.identity_file.clone(),
        "-p".to_owned(),
        cfg.ssh_port.to_string(),
        "-o".to_owned(),
        "StrictHostKeyChecking=no".to_owned(),
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-o".to_owned(),
        "ConnectTimeout=10".to_owned(),
    ];

    if !cfg.ssh_control_path.is_empty() {
        args.extend([
            "-o".to_owned(),
            "ControlMaster=auto".to_owned(),
            "-o".to_owned(),
            format!("ControlPath={}", cfg.ssh_control_path),
            "-o".to_owned(),
            format!("ControlPersist={}", cfg.ssh_control_persist),
        ]);
    }

    args.push(format!("{}@{}", cfg.ssh_user, cfg.ssh_target_endpoint));
    args.push(remote_cmd.to_owned());
    args
}

async fn ssh_query(cfg: &ResolvedConfig, fingerprint: &str) -> anyhow::Result<Vec<KeyRow>> {
    // `verified_at IS NOT NULL` produces 1/0 in MySQL TSV output, which the
    // parser maps to bool.  `accessed_at` is the actual column name for what
    // the GHE API surface calls `last_used`.
    let sql = format!(
        "SELECT pk.id, pk.key, pk.title, pk.created_at, \
         (pk.verified_at IS NOT NULL) AS verified, \
         pk.read_only, pk.accessed_at, pk.user_id, pk.repository_id, u.login \
         FROM users u \
         LEFT JOIN public_keys pk ON u.id = pk.user_id \
         WHERE pk.fingerprint_sha256 = '{fingerprint}';"
    );

    let remote_cmd = format!("echo \"{}\" | /usr/local/bin/ghe-dbconsole -y", sql);
    let args = build_ssh_args(cfg, &remote_cmd);

    let output = Command::new("ssh")
        .args(&args)
        .output()
        .await
        .context("failed to spawn ssh")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ssh exited with {}: {}", output.status, stderr.trim());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_mysql_output(&stdout, &cfg.ghe_url)
}

// ── Output parser ─────────────────────────────────────────────────────────────

/// Parse MySQL TSV output into `KeyRow`s.
///
/// `ghe_url` is used to build the response `url` field as
/// `<ghe_url>/user/keys/<id>`.
fn parse_mysql_output(stdout: &str, ghe_url: &str) -> anyhow::Result<Vec<KeyRow>> {
    let mut rows = Vec::new();
    let mut header_seen = false;

    for line in stdout.lines() {
        if line.starts_with("mysql:") {
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        if !header_seen {
            header_seen = true;
            continue;
        }

        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 10 {
            continue;
        }

        let id: u64 = cols[0].parse().context("id")?;
        let key = cols[1].to_owned();
        let title = cols[2].to_owned();
        let created_at = cols[3].to_owned();
        // col[4] is `(verified_at IS NOT NULL)` — MySQL outputs "1" or "0"
        let verified = cols[4] == "1";
        let read_only = cols[5] == "1";
        // col[6] is `accessed_at`, exposed as `last_used` in the response
        let last_used = match cols[6] {
            "NULL" | "" => None,
            v => Some(v.to_owned()),
        };
        let user_id: u64 = cols[7].parse().context("user_id")?;
        let repository_id = match cols[8] {
            "NULL" | "" => None,
            v => Some(v.parse::<u64>().context("repository_id")?),
        };
        let login = cols[9].to_owned();

        let url = format!("{}/user/keys/{}", ghe_url.trim_end_matches('/'), id);

        rows.push(KeyRow {
            id,
            key,
            title,
            url,
            created_at,
            verified,
            read_only,
            last_used,
            user_id,
            repository_id,
            login,
        });
    }

    Ok(rows)
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    let config_file = match &cli.config {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading config file {}", path.display()))?;
            toml::from_str::<ConfigFile>(&text)
                .with_context(|| format!("parsing config file {}", path.display()))?
        }
        None => ConfigFile::default(),
    };

    let config = resolve(cli, config_file)?;

    info!(
        listen = %config.listen,
        ssh_target_endpoint = %config.ssh_target_endpoint,
        ghe_url = %config.ghe_url,
        cache_ttl_pos = config.cache_ttl_pos,
        cache_ttl_neg = config.cache_ttl_neg,
        "starting ghe-key-lookup",
    );

    let addr: std::net::SocketAddr = config.listen.parse().context("invalid listen address")?;

    let state = AppState {
        config: Arc::new(config),
        cache: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v3/users/keys/lookup", get(lookup_key))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("listening on {addr}");
    axum::serve(listener, app).await?;

    Ok(())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_OUTPUT: &str = "\
id\tkey\ttitle\tcreated_at\tverified\tread_only\tlast_used\tuser_id\trepository_id\tlogin
42\tssh-rsa AAAAB3Nza...\tmy-laptop\t2024-01-15 10:00:00\t1\t0\t2024-03-01 09:00:00\t7\tNULL\toctocat
";

    #[test]
    fn parse_normal_row() {
        let rows = parse_mysql_output(SAMPLE_OUTPUT, "https://ghe.example.com").unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.id, 42);
        assert_eq!(row.login, "octocat");
        assert_eq!(row.user_id, 7);
        assert!(row.verified);
        assert!(!row.read_only);
        assert_eq!(row.last_used.as_deref(), Some("2024-03-01 09:00:00"));
        assert!(row.repository_id.is_none());
        assert_eq!(row.url, "https://ghe.example.com/user/keys/42");
    }

    #[test]
    fn parse_empty_result() {
        let header_only = "id\tkey\ttitle\tcreated_at\tverified\tread_only\tlast_used\tuser_id\trepository_id\tlogin\n";
        let rows = parse_mysql_output(header_only, "https://ghe.example.com").unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn parse_unverified_key() {
        // verified_at IS NOT NULL returns "0" when verified_at is NULL
        let output = "\
id\tkey\ttitle\tcreated_at\tverified\tread_only\tlast_used\tuser_id\trepository_id\tlogin
5\tssh-ed25519 AAAAC3Nza...\tlaptop\t2024-01-01 00:00:00\t0\t0\tNULL\t2\tNULL\toctocat
";
        let rows = parse_mysql_output(output, "https://ghe.example.com").unwrap();
        assert!(!rows[0].verified);
        assert!(rows[0].last_used.is_none());
    }

    #[test]
    fn parse_with_mysql_warning_lines() {
        let output = "\
mysql: [Warning] Using a password on the command line interface can be insecure.
id\tkey\ttitle\tcreated_at\tverified\tread_only\tlast_used\tuser_id\trepository_id\tlogin
1\tssh-ed25519 AAAAC3Nza...\twork\t2024-06-01 00:00:00\t1\t0\tNULL\t3\tNULL\tmonalisa
";
        let rows = parse_mysql_output(output, "https://ghe.example.com").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].login, "monalisa");
        assert!(rows[0].last_used.is_none());
    }

    #[test]
    fn strip_sha256_prefix() {
        let fp = "SHA256:V6EXcETU79VFRabcdef";
        let stripped = fp.strip_prefix("SHA256:").unwrap_or(fp);
        assert_eq!(stripped, "V6EXcETU79VFRabcdef");

        let fp2 = "V6EXcETU79VFRabcdef";
        assert_eq!(
            fp2.strip_prefix("SHA256:").unwrap_or(fp2),
            "V6EXcETU79VFRabcdef"
        );
    }

    // ── resolve() tests ───────────────────────────────────────────────────────

    fn minimal_file() -> ConfigFile {
        ConfigFile {
            identity_file: Some("/run/secrets/key".to_owned()),
            ssh_target_endpoint: Some("ghe.example.com".to_owned()),
            ..Default::default()
        }
    }

    fn empty_cli() -> Cli {
        Cli::parse_from(["ghe-key-lookup"])
    }

    #[test]
    fn resolve_all_from_file() {
        let resolved = resolve(empty_cli(), minimal_file()).unwrap();
        assert_eq!(resolved.ssh_target_endpoint, "ghe.example.com");
        // ghe_url defaults to https://<ssh_target_endpoint>
        assert_eq!(resolved.ghe_url, "https://ghe.example.com");
        assert_eq!(resolved.listen, "0.0.0.0:3000");
        assert_eq!(resolved.cache_ttl_pos, 300);
    }

    #[test]
    fn resolve_ghe_url_defaults_to_https_ssh_target() {
        let resolved = resolve(empty_cli(), minimal_file()).unwrap();
        assert_eq!(
            resolved.ghe_url,
            format!("https://{}", resolved.ssh_target_endpoint)
        );
    }

    #[test]
    fn resolve_ghe_url_override() {
        let cli = Cli::parse_from([
            "ghe-key-lookup",
            "--ghe-url",
            "https://ghe.corp.example.com",
        ]);
        let resolved = resolve(cli, minimal_file()).unwrap();
        assert_eq!(resolved.ssh_target_endpoint, "ghe.example.com");
        assert_eq!(resolved.ghe_url, "https://ghe.corp.example.com");
    }

    #[test]
    fn resolve_cli_overrides_file() {
        let file = ConfigFile {
            cache_ttl_pos: Some(600),
            ..minimal_file()
        };
        let cli = Cli::parse_from(["ghe-key-lookup", "--cache-ttl-pos", "999"]);
        assert_eq!(resolve(cli, file).unwrap().cache_ttl_pos, 999);
    }

    #[test]
    fn resolve_file_used_when_cli_absent() {
        let file = ConfigFile {
            cache_ttl_pos: Some(600),
            ..minimal_file()
        };
        assert_eq!(resolve(empty_cli(), file).unwrap().cache_ttl_pos, 600);
    }

    #[test]
    fn resolve_required_field_missing_errors() {
        let file = ConfigFile {
            ssh_target_endpoint: Some("ghe.example.com".to_owned()),
            ..Default::default() // no identity_file
        };
        assert!(resolve(empty_cli(), file).is_err());
    }

    #[test]
    fn resolve_toml_roundtrip() {
        let toml_str = r#"
            identity_file        = "/run/secrets/key"
            ssh_target_endpoint  = "ghe.example.com"
            ghe_url              = "https://ghe.corp.example.com"
            cache_ttl_pos        = 600
            ssh_control_path     = "/run/ghe-key-lookup/ctrl"
            ssh_control_persist  = "120"
        "#;
        let file: ConfigFile = toml::from_str(toml_str).unwrap();
        let resolved = resolve(empty_cli(), file).unwrap();
        assert_eq!(resolved.ssh_target_endpoint, "ghe.example.com");
        assert_eq!(resolved.ghe_url, "https://ghe.corp.example.com");
        assert_eq!(resolved.cache_ttl_pos, 600);
        assert_eq!(resolved.ssh_control_path, "/run/ghe-key-lookup/ctrl");
    }

    #[test]
    fn resolve_toml_unknown_field_errors() {
        let toml_str = r#"
            identity_file       = "/run/secrets/key"
            ssh_target_endpoint = "ghe.example.com"
            typo_field          = "oops"
        "#;
        assert!(toml::from_str::<ConfigFile>(toml_str).is_err());
    }

    // ── SSH arg tests ─────────────────────────────────────────────────────────

    fn base_config() -> ResolvedConfig {
        ResolvedConfig {
            listen: "0.0.0.0:3000".to_owned(),
            identity_file: "/run/secrets/key".to_owned(),
            ssh_user: "admin".to_owned(),
            ssh_target_endpoint: "ghe.example.com".to_owned(),
            ghe_url: "https://ghe.example.com".to_owned(),
            ssh_port: 122,
            ssh_control_path: "".to_owned(),
            ssh_control_persist: "yes".to_owned(),
            cache_ttl_pos: 300,
            cache_ttl_neg: 30,
        }
    }

    #[test]
    fn ssh_args_no_control_master() {
        let cfg = base_config();
        let args = build_ssh_args(&cfg, "echo hi");
        assert!(!args.iter().any(|a| a.starts_with("ControlMaster")));
        assert!(!args.iter().any(|a| a.starts_with("ControlPath")));
        assert!(!args.iter().any(|a| a.starts_with("ControlPersist")));
        assert!(args.contains(&"-i".to_owned()));
        assert!(args.contains(&"admin@ghe.example.com".to_owned()));
        assert_eq!(args.last().unwrap(), "echo hi");
    }

    #[test]
    fn ssh_args_uses_ssh_target_endpoint() {
        let cfg = ResolvedConfig {
            ssh_target_endpoint: "ghe-internal.corp.net".to_owned(),
            ghe_url: "https://ghe.example.com".to_owned(),
            ..base_config()
        };
        let args = build_ssh_args(&cfg, "echo hi");
        assert!(args.contains(&"admin@ghe-internal.corp.net".to_owned()));
        assert!(!args.iter().any(|a| a == "admin@ghe.example.com"));
    }

    #[test]
    fn ssh_args_with_control_master() {
        let cfg = ResolvedConfig {
            ssh_control_path: "/run/ghe-key-lookup/ssh-control".to_owned(),
            ssh_control_persist: "120".to_owned(),
            ..base_config()
        };
        let args = build_ssh_args(&cfg, "echo hi");
        let joined = args.join(" ");
        assert!(joined.contains("ControlMaster=auto"));
        assert!(joined.contains("ControlPath=/run/ghe-key-lookup/ssh-control"));
        assert!(joined.contains("ControlPersist=120"));
    }

    #[test]
    fn ssh_args_control_persist_defaults_to_yes() {
        let cfg = ResolvedConfig {
            ssh_control_path: "/run/ghe-key-lookup/ssh-control".to_owned(),
            ..base_config()
        };
        let args = build_ssh_args(&cfg, "echo hi");
        assert!(args.iter().any(|a| a == "ControlPersist=yes"));
    }

    // ── Cache tests ───────────────────────────────────────────────────────────

    fn make_cache() -> Arc<Cache> {
        Arc::new(Mutex::new(HashMap::new()))
    }

    #[test]
    fn cache_miss_on_empty() {
        assert!(cache_get(&make_cache(), "abc123").is_none());
    }

    #[test]
    fn cache_hit_within_ttl() {
        let cache = make_cache();
        cache_insert(
            &cache,
            "abc123".to_owned(),
            CacheValue::Miss,
            Duration::from_secs(60),
        );
        assert!(matches!(
            cache_get(&cache, "abc123"),
            Some(CacheValue::Miss)
        ));
    }

    #[test]
    fn cache_miss_after_ttl_expires() {
        let cache = make_cache();
        cache_insert(
            &cache,
            "abc123".to_owned(),
            CacheValue::Miss,
            Duration::from_secs(1),
        );
        {
            let mut map = cache.lock().unwrap();
            map.get_mut("abc123").unwrap().expires_at = Instant::now() - Duration::from_secs(1);
        }
        assert!(cache_get(&cache, "abc123").is_none());
        assert!(cache.lock().unwrap().get("abc123").is_none());
    }

    #[test]
    fn cache_zero_ttl_skips_insert() {
        let cache = make_cache();
        cache_insert(
            &cache,
            "abc123".to_owned(),
            CacheValue::Miss,
            Duration::ZERO,
        );
        assert!(cache_get(&cache, "abc123").is_none());
    }

    #[test]
    fn cache_positive_hit_stores_rows() {
        let rows = parse_mysql_output(SAMPLE_OUTPUT, "https://ghe.example.com").unwrap();
        let cache = make_cache();
        cache_insert(
            &cache,
            "abc123".to_owned(),
            CacheValue::Hit(rows),
            Duration::from_secs(300),
        );
        match cache_get(&cache, "abc123") {
            Some(CacheValue::Hit(cached)) => assert_eq!(cached[0].login, "octocat"),
            _ => panic!("expected a cache hit"),
        }
    }
}
