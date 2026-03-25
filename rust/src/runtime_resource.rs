use std::net::UdpSocket;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use opentelemetry::KeyValue;
use serde::{Deserialize, Serialize};

const AWS_IMDS_BASE: &str = "http://169.254.169.254";
const AZURE_IMDS_BASE: &str = "http://169.254.169.254";
const GCP_IMDS_BASE: &str = "http://metadata.google.internal";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeResourceAttributes {
    #[serde(default)]
    pub service_name: String,
    #[serde(default)]
    pub service_namespace: String,
    #[serde(default)]
    pub service_version: String,
    pub service_instance_id: Option<String>,
    pub service_machine_id: Option<String>,
    pub service_ip_address: Option<String>,
    pub cloud_provider: Option<String>,
    pub cloud_platform: Option<String>,
    pub cloud_region: Option<String>,
}

impl RuntimeResourceAttributes {
    pub fn for_forgeproxy(version: &str) -> Self {
        Self {
            service_name: "forgeproxy".to_string(),
            service_namespace: "forgeproxy".to_string(),
            service_version: version.to_string(),
            ..Self::default()
        }
    }

    pub fn to_otel_resource_attributes(&self) -> Vec<KeyValue> {
        let mut attributes = vec![
            KeyValue::new("service.name", self.service_name.clone()),
            KeyValue::new("service.namespace", self.service_namespace.clone()),
            KeyValue::new("service.version", self.service_version.clone()),
        ];

        if let Some(value) = &self.service_instance_id {
            attributes.push(KeyValue::new("service.instance.id", value.clone()));
        }
        if let Some(value) = &self.service_machine_id {
            attributes.push(KeyValue::new("service.machine_id", value.clone()));
        }
        if let Some(value) = &self.service_ip_address {
            attributes.push(KeyValue::new("service.ip_address", value.clone()));
        }
        if let Some(value) = &self.cloud_provider {
            attributes.push(KeyValue::new("cloud.provider", value.clone()));
        }
        if let Some(value) = &self.cloud_platform {
            attributes.push(KeyValue::new("cloud.platform", value.clone()));
        }
        if let Some(value) = &self.cloud_region {
            attributes.push(KeyValue::new("cloud.region", value.clone()));
        }

        attributes
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeResourceDetection {
    pub attributes: RuntimeResourceAttributes,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
struct CloudMetadata {
    provider: &'static str,
    platform: &'static str,
    instance_id: String,
    region: Option<String>,
    local_ip_address: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AwsInstanceIdentityDocument {
    #[serde(rename = "instanceId")]
    instance_id: String,
    region: String,
    #[serde(rename = "privateIp")]
    private_ip: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AzureComputeMetadata {
    #[serde(rename = "vmId")]
    vm_id: String,
    location: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AzureInstanceMetadata {
    compute: AzureComputeMetadata,
}

pub async fn detect_runtime_resource_attributes(service_version: &str) -> RuntimeResourceDetection {
    let mut warnings = Vec::new();
    let mut attributes = RuntimeResourceAttributes::for_forgeproxy(service_version);

    attributes.service_machine_id = read_machine_id()
        .map_err(|error| {
            warnings.push(format!(
                "failed to read /etc/machine-id for runtime resource attributes: {error}"
            ));
        })
        .ok();

    let client = match build_metadata_client() {
        Ok(client) => Some(client),
        Err(error) => {
            warnings.push(format!(
                "failed to build metadata HTTP client for runtime resource detection: {error}"
            ));
            None
        }
    };

    let cloud = if let Some(client) = client.as_ref() {
        match detect_cloud_metadata(client).await {
            Ok(cloud) => cloud,
            Err(error) => {
                warnings.push(format!(
                    "cloud metadata detection failed during forgeproxy startup: {error}"
                ));
                None
            }
        }
    } else {
        None
    };

    if let Some(cloud) = cloud {
        attributes.cloud_provider = Some(cloud.provider.to_string());
        attributes.cloud_platform = Some(cloud.platform.to_string());
        attributes.cloud_region = cloud.region;
        attributes.service_instance_id = Some(cloud.instance_id);
        attributes.service_ip_address = cloud
            .local_ip_address
            .or_else(detect_best_effort_local_ip_address);
    } else {
        attributes.service_instance_id = attributes.service_machine_id.clone();
        attributes.service_ip_address = detect_best_effort_local_ip_address();
        warnings.push(
            "cloud environment metadata was indeterminate during startup; using best-effort local identifiers"
                .to_string(),
        );
    }

    if attributes.service_instance_id.is_none() {
        warnings.push(
            "runtime resource detection could not determine a stable service.instance.id"
                .to_string(),
        );
    }
    if attributes.service_ip_address.is_none() {
        warnings
            .push("runtime resource detection could not determine service.ip_address".to_string());
    }

    RuntimeResourceDetection {
        attributes,
        warnings,
    }
}

pub async fn load_or_detect_runtime_resource_attributes(
    path: &Path,
    service_version: &str,
) -> RuntimeResourceDetection {
    match load_runtime_resource_attributes(path) {
        Ok(attributes) => RuntimeResourceDetection {
            attributes,
            warnings: Vec::new(),
        },
        Err(error) => {
            let mut detection = detect_runtime_resource_attributes(service_version).await;
            detection.warnings.insert(
                0,
                format!(
                    "failed to load runtime resource attributes from {}: {error}",
                    path.display()
                ),
            );
            detection
        }
    }
}

pub fn load_runtime_resource_attributes(path: &Path) -> Result<RuntimeResourceAttributes> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("read runtime resource attributes from {}", path.display()))?;
    let attributes: RuntimeResourceAttributes =
        serde_json::from_str(&contents).context("parse runtime resource attributes JSON")?;

    if attributes.service_name.is_empty() {
        bail!("runtime resource attributes missing service_name");
    }

    Ok(attributes)
}

pub async fn write_runtime_resource_attributes_file(
    path: &Path,
    service_version: &str,
) -> Result<RuntimeResourceDetection> {
    let detection = detect_runtime_resource_attributes(service_version).await;
    let parent = path.parent().with_context(|| {
        format!(
            "runtime resource attribute path {} has no parent",
            path.display()
        )
    })?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create runtime resource directory {}", parent.display()))?;
    let contents = serde_json::to_string_pretty(&detection.attributes)
        .context("serialize runtime resource attributes")?;
    std::fs::write(path, contents)
        .with_context(|| format!("write runtime resource attributes to {}", path.display()))?;
    Ok(detection)
}

fn build_metadata_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .connect_timeout(Duration::from_secs(1))
        .no_proxy()
        .build()
        .context("build metadata client")
}

async fn detect_cloud_metadata(client: &reqwest::Client) -> Result<Option<CloudMetadata>> {
    if let Some(aws) = detect_aws_metadata(client).await? {
        return Ok(Some(aws));
    }
    if let Some(azure) = detect_azure_metadata(client).await? {
        return Ok(Some(azure));
    }
    if let Some(gcp) = detect_gcp_metadata(client).await? {
        return Ok(Some(gcp));
    }
    Ok(None)
}

async fn detect_aws_metadata(client: &reqwest::Client) -> Result<Option<CloudMetadata>> {
    let token_response = client
        .put(format!("{AWS_IMDS_BASE}/latest/api/token"))
        .header("X-aws-ec2-metadata-token-ttl-seconds", "60")
        .send()
        .await;

    let Ok(token_response) = token_response else {
        return Ok(None);
    };
    if !token_response.status().is_success() {
        return Ok(None);
    }

    let token = token_response
        .text()
        .await
        .context("read AWS IMDSv2 token")?;
    if token.is_empty() {
        return Ok(None);
    }

    let document_response = client
        .get(format!(
            "{AWS_IMDS_BASE}/latest/dynamic/instance-identity/document"
        ))
        .header("X-aws-ec2-metadata-token", token)
        .send()
        .await;

    let Ok(document_response) = document_response else {
        return Ok(None);
    };
    if !document_response.status().is_success() {
        return Ok(None);
    }

    let document: AwsInstanceIdentityDocument = document_response
        .json()
        .await
        .context("parse AWS instance identity document")?;

    Ok(Some(CloudMetadata {
        provider: "aws",
        platform: "aws_ec2",
        instance_id: document.instance_id,
        region: Some(document.region),
        local_ip_address: detect_local_ip_for_target("169.254.169.254:80").or(document.private_ip),
    }))
}

async fn detect_azure_metadata(client: &reqwest::Client) -> Result<Option<CloudMetadata>> {
    let response = client
        .get(format!(
            "{AZURE_IMDS_BASE}/metadata/instance/compute?api-version=2021-02-01&format=json"
        ))
        .header("Metadata", "true")
        .send()
        .await;

    let Ok(response) = response else {
        return Ok(None);
    };
    if !response.status().is_success() {
        return Ok(None);
    }

    let metadata: AzureInstanceMetadata = response
        .json()
        .await
        .context("parse Azure instance metadata")?;

    Ok(Some(CloudMetadata {
        provider: "azure",
        platform: "azure_vm",
        instance_id: metadata.compute.vm_id,
        region: metadata.compute.location,
        local_ip_address: detect_local_ip_for_target("169.254.169.254:80"),
    }))
}

async fn detect_gcp_metadata(client: &reqwest::Client) -> Result<Option<CloudMetadata>> {
    let instance_id_response = client
        .get(format!("{GCP_IMDS_BASE}/computeMetadata/v1/instance/id"))
        .header("Metadata-Flavor", "Google")
        .send()
        .await;

    let Ok(instance_id_response) = instance_id_response else {
        return Ok(None);
    };
    if !instance_id_response.status().is_success() {
        return Ok(None);
    }

    let instance_id = instance_id_response
        .text()
        .await
        .context("read GCP instance id")?;
    if instance_id.is_empty() {
        return Ok(None);
    }

    let zone_response = client
        .get(format!("{GCP_IMDS_BASE}/computeMetadata/v1/instance/zone"))
        .header("Metadata-Flavor", "Google")
        .send()
        .await;

    let zone = match zone_response {
        Ok(response) if response.status().is_success() => {
            Some(response.text().await.context("read GCP instance zone")?)
        }
        _ => None,
    };

    Ok(Some(CloudMetadata {
        provider: "gcp",
        platform: "gcp_compute_engine",
        instance_id,
        region: zone.as_deref().and_then(parse_gcp_region_from_zone_path),
        local_ip_address: detect_local_ip_for_target("metadata.google.internal:80")
            .or_else(|| detect_local_ip_for_target("169.254.169.254:80")),
    }))
}

fn read_machine_id() -> Result<String> {
    let machine_id = std::fs::read_to_string("/etc/machine-id").context("read /etc/machine-id")?;
    let trimmed = machine_id.trim();
    if trimmed.is_empty() {
        bail!("/etc/machine-id was empty");
    }
    Ok(trimmed.to_string())
}

fn detect_best_effort_local_ip_address() -> Option<String> {
    for target in ["169.254.169.254:80", "1.1.1.1:80", "8.8.8.8:80"] {
        if let Some(ip) = detect_local_ip_for_target(target) {
            return Some(ip);
        }
    }
    None
}

fn detect_local_ip_for_target(target: &str) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect(target).ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
}

fn parse_gcp_region_from_zone_path(zone_path: &str) -> Option<String> {
    let zone = zone_path.rsplit('/').next()?;
    let (region, _) = zone.rsplit_once('-')?;
    Some(region.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gcp_region_from_zone_path() {
        assert_eq!(
            parse_gcp_region_from_zone_path("projects/123456789/zones/us-central1-a"),
            Some("us-central1".to_string())
        );
        assert_eq!(
            parse_gcp_region_from_zone_path("us-east4-b"),
            Some("us-east4".to_string())
        );
        assert_eq!(parse_gcp_region_from_zone_path("bogus"), None);
    }

    #[test]
    fn runtime_resource_attributes_serialize_expected_fields() {
        let attrs = RuntimeResourceAttributes {
            service_name: "forgeproxy".to_string(),
            service_namespace: "forgeproxy".to_string(),
            service_version: "0.1.0".to_string(),
            service_instance_id: Some("i-1234567890".to_string()),
            service_machine_id: Some("abcdef".to_string()),
            service_ip_address: Some("10.0.0.12".to_string()),
            cloud_provider: Some("aws".to_string()),
            cloud_platform: Some("aws_ec2".to_string()),
            cloud_region: Some("us-east-1".to_string()),
        };

        let encoded = serde_json::to_string(&attrs).unwrap();
        assert!(encoded.contains("\"service_instance_id\":\"i-1234567890\""));
        assert!(encoded.contains("\"service_machine_id\":\"abcdef\""));
        assert!(encoded.contains("\"service_ip_address\":\"10.0.0.12\""));
        assert!(encoded.contains("\"cloud_provider\":\"aws\""));
    }
}
