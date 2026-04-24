//! SSH upstream proxy.
//!
//! When a requested repository is not available in the local bare-repo cache,
//! this module proxies the `git-upload-pack` exchange to the upstream forge
//! using the HTTP smart protocol (RFC 7230 / git's dumb-vs-smart HTTP spec).
//!
//! Two-phase exchange:
//!   1. `fetch_ref_advertisement` — `GET /info/refs?service=git-upload-pack`
//!      strips the HTTP service-line preamble and returns pkt-line data
//!      suitable for forwarding to an SSH git client.
//!   2. `post_upload_pack_stream` — `POST /git-upload-pack` with the
//!      accumulated want/have/done bytes from the client; returns a stream of
//!      packfile chunks.
//!
//! Only PAT (token / HTTPS) credential mode is supported for the upstream
//! proxy path.  SSH credential mode requires a bidirectional subprocess pipe
//! that has not yet been implemented.

use anyhow::{Context, Result, bail};
use futures::Stream;
use tracing::{debug, info, instrument};

use crate::AppState;
use crate::config::{Config, CredentialMode};
use crate::metrics::{ClonePhase, CloneUpstreamBytesLabels, Protocol};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Phase 1: Fetch the ref advertisement from the upstream forge.
///
/// Returns pkt-line-formatted bytes ready to send directly to a git SSH
/// client.  The HTTP service-line preamble (`001e# service=…\n0000`) is
/// stripped; it is only present in the HTTP transport, not SSH.
///
/// `authenticated` controls whether a token is injected into the upstream URL.
/// Pass `false` for anonymous SSH sessions so private repos are rejected
/// naturally by the forge rather than being served under the admin token.
///
/// Supports PAT (HTTPS) credential mode.  SSH credential mode returns an
/// error — configure a PAT for uncached repository proxying.
#[instrument(
    skip(state),
    fields(
        %owner_repo,
        username = %metric_username,
        git_protocol = git_protocol.unwrap_or(""),
        forge_backend = %state.config().backend_type.as_label(),
        authenticated
    )
)]
pub async fn fetch_ref_advertisement(
    state: &AppState,
    owner_repo: &str,
    authenticated: bool,
    git_protocol: Option<&str>,
    metric_username: &str,
    inject_bundle_uri: bool,
) -> Result<Vec<u8>> {
    let (owner, repo) = split_owner_repo(owner_repo)?;
    let (clone_url, _) =
        resolve_upstream_url_and_creds(state.config().as_ref(), owner, repo, authenticated).await?;

    match credential_mode(state.config().as_ref(), owner) {
        CredentialMode::Pat => {
            let url = format!("{clone_url}/info/refs?service=git-upload-pack");
            let redacted_url = crate::git::commands::redact_url_secret(
                &url,
                state.config().upstream.log_secret_unmask_chars,
            );
            debug!(url = %redacted_url, "fetching ref advertisement via HTTP GET");

            let mut req = state
                .http_client
                .get(&url)
                .header("Accept", "application/x-git-upload-pack-advertisement");
            if let Some(protocol) = git_protocol {
                req = req.header("Git-Protocol", protocol);
            }
            let resp = req.send().await.context("HTTP GET /info/refs failed")?;

            if !resp.status().is_success() {
                bail!("upstream returned {} for ref advertisement", resp.status());
            }

            let body = resp
                .bytes()
                .await
                .context("failed to read ref advertisement body")?;

            let stripped = strip_http_service_line(&body);
            let stripped = if !inject_bundle_uri {
                info!(
                    %owner_repo,
                    "forwarding SSH ref advertisement without bundle-uri injection"
                );
                stripped.to_vec()
            } else {
                let (stripped, bundle_uri_result) =
                    crate::http::protocolv2::inject_bundle_uri_with_result(stripped, "");
                crate::metrics::inc_bundle_uri_advertisement(
                    &state.metrics,
                    owner_repo,
                    bundle_uri_result.as_metric_label(),
                );
                stripped
            };

            state
                .metrics
                .metrics
                .clone_upstream_bytes
                .get_or_create(&CloneUpstreamBytesLabels {
                    protocol: Protocol::Ssh,
                    phase: ClonePhase::InfoRefs,
                    username: metric_username.to_string(),
                    repo: owner_repo.to_string(),
                })
                .inc_by(stripped.len() as u64);

            info!(
                %owner_repo,
                bytes = stripped.len(),
                "fetched ref advertisement from upstream"
            );

            Ok(stripped)
        }

        CredentialMode::Ssh => {
            bail!(
                "SSH credential mode is not supported for the uncached upstream proxy; \
                 configure PAT (token) credentials instead"
            )
        }
    }
}

/// Phase 2: POST want/have/done to the upstream and return a byte stream.
///
/// `want_have` is the accumulated bytes the git client sent after receiving
/// the ref advertisement (want/have/done pkt-lines).  Supports PAT mode only.
///
/// `authenticated` must match the value used for phase 1 — it controls
/// whether a token is embedded in the upstream URL.
#[instrument(
    skip(state, want_have),
    fields(
        %owner_repo,
        username = %metric_username,
        git_protocol = git_protocol.unwrap_or(""),
        forge_backend = %state.config().backend_type.as_label(),
        input_bytes = want_have.len(),
        authenticated
    )
)]
pub async fn post_upload_pack_stream(
    state: &AppState,
    owner_repo: &str,
    want_have: &[u8],
    authenticated: bool,
    git_protocol: Option<&str>,
    metric_username: &str,
) -> Result<impl Stream<Item = reqwest::Result<bytes::Bytes>>> {
    let (owner, repo) = split_owner_repo(owner_repo)?;
    let (clone_url, _) =
        resolve_upstream_url_and_creds(state.config().as_ref(), owner, repo, authenticated).await?;

    match credential_mode(state.config().as_ref(), owner) {
        CredentialMode::Pat => {
            let url = format!("{clone_url}/git-upload-pack");
            let redacted_url = crate::git::commands::redact_url_secret(
                &url,
                state.config().upstream.log_secret_unmask_chars,
            );
            debug!(
                url = %redacted_url,
                input_bytes = want_have.len(),
                "posting want/have to upstream"
            );

            let mut req = state
                .http_client
                .post(&url)
                .header("Content-Type", "application/x-git-upload-pack-request")
                .header("Accept", "application/x-git-upload-pack-result");
            if let Some(protocol) = git_protocol {
                req = req.header("Git-Protocol", protocol);
            }
            let resp = req
                .body(want_have.to_vec())
                .send()
                .await
                .context("HTTP POST /git-upload-pack failed")?;

            if !resp.status().is_success() {
                bail!(
                    "upstream returned {} for git-upload-pack POST",
                    resp.status()
                );
            }

            info!(%owner_repo, "upstream proxy POST started, streaming response");
            Ok(resp.bytes_stream())
        }

        CredentialMode::Ssh => {
            bail!(
                "SSH credential mode is not supported for the uncached upstream proxy; \
                 configure PAT (token) credentials instead"
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Split an `owner/repo` slug into its two components.
pub(crate) fn split_owner_repo(slug: &str) -> Result<(&str, &str)> {
    let mut parts = slug.splitn(2, '/');
    let owner = parts.next().context("missing owner in repo slug")?;
    let repo = parts.next().context("missing repo in repo slug")?;
    if owner.is_empty() || repo.is_empty() {
        bail!("invalid owner/repo slug: {slug:?}");
    }
    Ok((owner, repo))
}

/// Return the effective credential mode for the given owner.
fn credential_mode(config: &Config, owner: &str) -> CredentialMode {
    config
        .upstream_credentials
        .orgs
        .get(owner)
        .map(|oc| oc.mode)
        .unwrap_or(CredentialMode::Pat)
}

/// Resolve the upstream clone URL and any environment variables needed for
/// credential injection.
///
/// For PAT mode: HTTPS URL with embedded token (or bare HTTPS when
/// `authenticated` is `false` — anonymous SSH sessions must not receive a
/// token, so private repos are rejected by the forge rather than silently
/// served under the admin token).
/// For SSH mode: `git@host:owner/repo.git` URL.
async fn resolve_upstream_url_and_creds(
    config: &Config,
    owner: &str,
    repo: &str,
    authenticated: bool,
) -> Result<(String, Vec<(String, String)>)> {
    match credential_mode(config, owner) {
        CredentialMode::Pat => {
            let token = if authenticated {
                if let Some(key_name) = config
                    .upstream_credentials
                    .orgs
                    .get(owner)
                    .filter(|oc| oc.mode == CredentialMode::Pat)
                    .map(|oc| oc.keyring_key_name.as_str())
                {
                    crate::credentials::keyring::resolve_secret(key_name)
                        .await
                        .unwrap_or_default()
                } else {
                    String::new()
                }
            } else {
                // Anonymous SSH session — do not inject a token.  The forge
                // will reject the request if the repo is private, which is the
                // correct behaviour.
                String::new()
            };

            let url = if token.is_empty() {
                format!("{}/{}/{}.git", config.upstream.git_url_base(), owner, repo)
            } else {
                format!(
                    "{}/{}/{}.git",
                    authenticated_git_base_url(config, &format!("x-access-token:{token}")),
                    owner,
                    repo,
                )
            };

            Ok((url, vec![]))
        }

        CredentialMode::Ssh => {
            let url = format!("git@{}:{}/{}.git", config.upstream.hostname, owner, repo);
            Ok((url, vec![]))
        }
    }
}

fn authenticated_git_base_url(config: &Config, userinfo: &str) -> String {
    let base = config.upstream.git_url_base();
    if let Ok(mut parsed) = url::Url::parse(&base) {
        if let Some((username, password)) = userinfo.split_once(':') {
            let _ = parsed.set_username(username);
            let _ = parsed.set_password(Some(password));
        } else {
            let _ = parsed.set_username(userinfo);
        }
        parsed.to_string().trim_end_matches('/').to_string()
    } else {
        base
    }
}

/// Strip the HTTP service-line preamble from a git smart-HTTP response.
///
/// The HTTP transport prepends the following before the pkt-line ref
/// advertisement:
///
/// ```text
/// 001e# service=git-upload-pack\n   ← pkt-line (30 bytes)
/// 0000                               ← flush
/// ```
///
/// The SSH transport does not include this preamble, so we must strip it
/// before forwarding to an SSH client.
fn strip_http_service_line(data: &[u8]) -> &[u8] {
    if data.len() < 4 {
        return data;
    }
    let len_str = match std::str::from_utf8(&data[..4]) {
        Ok(s) => s,
        Err(_) => return data,
    };
    let pkt_len = match usize::from_str_radix(len_str, 16) {
        Ok(n) => n,
        Err(_) => return data,
    };
    // pkt_len includes the 4-byte length prefix itself.
    if pkt_len < 4 || pkt_len > data.len() {
        return data;
    }
    if !data[4..pkt_len].starts_with(b"# service=") {
        return data;
    }
    // Skip past the service pkt-line and the following 0000 flush.
    let after_service = &data[pkt_len..];
    after_service.strip_prefix(b"0000").unwrap_or(after_service)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_owner_repo_valid() {
        let (owner, repo) = split_owner_repo("acme/widgets").unwrap();
        assert_eq!(owner, "acme");
        assert_eq!(repo, "widgets");
    }

    #[test]
    fn split_owner_repo_with_subpath() {
        let (owner, repo) = split_owner_repo("org/deep/nested").unwrap();
        assert_eq!(owner, "org");
        assert_eq!(repo, "deep/nested");
    }

    #[test]
    fn split_owner_repo_invalid() {
        assert!(split_owner_repo("noslash").is_err());
        assert!(split_owner_repo("/repo").is_err());
        assert!(split_owner_repo("owner/").is_err());
    }

    #[test]
    fn strip_service_line_valid() {
        // "# service=git-upload-pack\n" = 26 bytes; pkt_len = 30 = 0x1e.
        let mut data = b"001e# service=git-upload-pack\n".to_vec();
        data.extend_from_slice(b"0000");
        data.extend_from_slice(b"001fsome-ref-advertisement-data");

        let result = strip_http_service_line(&data);
        assert_eq!(result, b"001fsome-ref-advertisement-data");
    }

    #[test]
    fn strip_service_line_passthrough_if_no_service() {
        // First pkt-line does not start with "# service=" — pass through.
        let data = b"0012not a service line\n";
        assert_eq!(strip_http_service_line(data), data.as_ref());
    }

    #[test]
    fn strip_service_line_empty() {
        assert_eq!(strip_http_service_line(b""), b"");
    }

    #[test]
    fn strip_service_line_too_short() {
        assert_eq!(strip_http_service_line(b"001"), b"001");
    }

    #[tokio::test]
    async fn missing_org_credential_does_not_fall_back_to_admin_token() {
        let config = crate::config::parse_config_str(include_str!("../../../config.example.yaml"))
            .expect("example config should parse");

        let (url, env_vars) =
            resolve_upstream_url_and_creds(&config, "unknown-org", "widgets", true)
                .await
                .expect("missing org should still produce a direct upstream URL");

        assert_eq!(
            url,
            "https://ghe.internal.example.com/unknown-org/widgets.git"
        );
        assert!(env_vars.is_empty());
    }
}
