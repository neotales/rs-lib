#![allow(clippy::missing_panics_doc)]

//! Daemon-free `ComposeBridge` projection used by the CLI's `bridge convert`
//! command. The bridge is a deployment-shaped diagnostic model, not a
//! Kubernetes manifest and not an Engine request.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{ComposeProject, ComposeProjectService};

/// Current `ComposeBridge` API version.
pub const COMPOSE_BRIDGE_API_VERSION: &str = "neotales.compose/v1";
/// Current `ComposeBridge` kind.
pub const COMPOSE_BRIDGE_KIND: &str = "ComposeBridge";

/// A normalized `ComposeBridge` document.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeBridgeDocument {
    /// Bridge schema version.
    pub api_version: String,
    /// Stable bridge kind.
    pub kind: String,
    /// Deployment-shaped services.
    pub services: Vec<ComposeBridgeService>,
    /// Referenced network names.
    pub networks: Vec<ComposeBridgeNetwork>,
    /// Referenced volume names.
    pub volumes: Vec<ComposeBridgeVolume>,
}

/// A service projection in a `ComposeBridge` document.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeBridgeService {
    /// Compose service name.
    pub name: String,
    /// Image reference.
    pub image: String,
    /// Replica count.
    pub replicas: u32,
    /// Explicit environment values with sensitive names redacted.
    pub environment: BTreeMap<String, String>,
    /// Published/target ports.
    pub ports: Vec<ComposeBridgePort>,
    /// Named volume sources.
    pub volumes: Vec<String>,
    /// Network names.
    pub networks: Vec<String>,
}

/// A bridge port projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeBridgePort {
    /// Container target port.
    pub target: u16,
    /// Optional host-published port.
    pub published: Option<u16>,
    /// Port protocol.
    pub protocol: String,
    /// Optional host address.
    pub host_ip: Option<String>,
}

/// A bridge network projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeBridgeNetwork {
    /// Network resource name.
    pub name: String,
}

/// A bridge volume projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposeBridgeVolume {
    /// Volume resource name.
    pub name: String,
}

impl ComposeBridgeDocument {
    /// Projects a normalized project into the bridge model.
    #[must_use]
    pub fn from_project(project: &ComposeProject) -> Self {
        let services = project
            .services
            .iter()
            .map(|(name, service)| service_from_project(name, service, project))
            .collect();
        let networks = project
            .networks
            .keys()
            .map(|key| ComposeBridgeNetwork {
                name: project.resource_name(key, true),
            })
            .collect();
        let volumes = project
            .volumes
            .keys()
            .map(|key| ComposeBridgeVolume {
                name: project.resource_name(key, false),
            })
            .collect();
        Self {
            api_version: COMPOSE_BRIDGE_API_VERSION.to_owned(),
            kind: COMPOSE_BRIDGE_KIND.to_owned(),
            services,
            networks,
            volumes,
        }
    }

    /// Projects a normalized project into the bridge model.
    ///
    /// This alias mirrors the conversion terminology the Docker CLI uses for the
    /// same concepts, so output from either side is comparable by eye.
    #[must_use]
    pub fn convert(project: &ComposeProject) -> Self {
        Self::from_project(project)
    }

    /// Serializes the bridge as indented JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("ComposeBridge must serialize")
    }

    /// Serializes the bridge as YAML.
    #[must_use]
    pub fn to_yaml(&self) -> String {
        serde_yaml::to_string(self).expect("ComposeBridge must serialize")
    }
}

fn service_from_project(
    name: &str,
    service: &ComposeProjectService,
    project: &ComposeProject,
) -> ComposeBridgeService {
    let mut volume_names = service
        .volumes
        .iter()
        .filter_map(|mount| mount.source.clone())
        .filter(|source| project.volumes.contains_key(source))
        .map(|source| project.resource_name(&source, false))
        .collect::<Vec<_>>();
    volume_names.sort();
    volume_names.dedup();
    let mut network_names = service
        .networks
        .iter()
        .map(|network| project.resource_name(&network.name, true))
        .collect::<Vec<_>>();
    network_names.sort();
    network_names.dedup();
    ComposeBridgeService {
        name: name.to_owned(),
        image: service.image.clone(),
        replicas: service.replicas,
        environment: service
            .environment
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    if sensitive_name(key) {
                        "<redacted>".to_owned()
                    } else {
                        value.clone()
                    },
                )
            })
            .collect(),
        ports: service
            .ports
            .iter()
            .map(|port| ComposeBridgePort {
                target: port.target,
                published: port.published,
                protocol: port.protocol.as_str().to_owned(),
                host_ip: port.host_ip.clone(),
            })
            .collect(),
        volumes: volume_names,
        networks: network_names,
    }
}

fn sensitive_name(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "api_key",
        "apikey",
        "auth",
    ]
    .iter()
    .any(|needle| value.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::ComposeBridgeDocument;
    use crate::{ComposeProject, ComposeProjectOptions, InterpolationValues};

    #[test]
    fn bridge_projection_is_stable_and_secret_safe() {
        let project = ComposeProject::parse_yaml(
            "name: demo\nservices:\n  web:\n    image: nginx:alpine\n    environment:\n      PASSWORD: secret\n    ports: ['8080:80']\n    volumes: ['data:/data']\n    networks: [front]\nvolumes:\n  data: {}\nnetworks:\n  front: {}\n",
            "compose.yaml",
            &InterpolationValues::new(),
            ComposeProjectOptions::default(),
        )
        .expect("project");
        let bridge = ComposeBridgeDocument::from_project(&project);
        let json = bridge.to_json();
        assert!(json.contains("neotales.compose/v1"));
        assert!(json.contains("ComposeBridge"));
        assert!(json.contains("nginx:alpine"));
        assert!(!json.contains("secret"));
        assert!(json.contains("demo_data"));
    }
}
