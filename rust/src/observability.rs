use tracing::field::display;
use uuid::Uuid;

use crate::config::Config;

#[derive(Clone, Debug)]
pub struct GitRequestObservation {
    pub owner: String,
    pub repo: String,
    pub owner_repo: String,
    pub username: String,
    pub git_protocol: String,
    pub client_fingerprint: String,
    pub forge_backend: String,
    pub git_request_id: String,
    pub git_session_id: String,
}

impl GitRequestObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &Config,
        owner: &str,
        repo: &str,
        username: &str,
        git_protocol: Option<&str>,
        client_fingerprint: &str,
        transport: &str,
        git_session_id: Option<String>,
    ) -> Self {
        Self {
            owner: owner.to_string(),
            repo: repo.to_string(),
            owner_repo: format!("{owner}/{repo}"),
            username: username.to_string(),
            git_protocol: git_protocol.unwrap_or("").to_string(),
            client_fingerprint: client_fingerprint.to_string(),
            forge_backend: config.backend_type.as_label().to_string(),
            git_request_id: format!("{transport}-{}", Uuid::new_v4().simple()),
            git_session_id: git_session_id
                .unwrap_or_else(|| format!("{transport}-{}", Uuid::new_v4().simple())),
        }
    }

    pub fn record_span(&self, span: &tracing::Span, git_phase: &str) {
        span.record("owner_repo", display(&self.owner_repo));
        span.record("username", display(&self.username));
        span.record("forge_backend", display(&self.forge_backend));
        span.record("git_protocol", display(&self.git_protocol));
        span.record("git_request_id", display(&self.git_request_id));
        span.record("git_session_id", display(&self.git_session_id));
        span.record("git_phase", display(git_phase));
        span.record("client_fingerprint", display(&self.client_fingerprint));
    }

    pub fn make_span(&self, request_name: &'static str, git_phase: &str) -> tracing::Span {
        tracing::info_span!(
            "git_request",
            request_name = %request_name,
            owner = %self.owner,
            repo = %self.repo,
            owner_repo = %self.owner_repo,
            username = %self.username,
            forge_backend = %self.forge_backend,
            git_protocol = %self.git_protocol,
            git_request_id = %self.git_request_id,
            git_session_id = %self.git_session_id,
            git_phase = %git_phase,
            client_fingerprint = %self.client_fingerprint,
        )
    }
}
