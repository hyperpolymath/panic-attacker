// SPDX-License-Identifier: PMPL-1.0-or-later

//! Attack profile loading for custom argument sets.

use crate::types::{AttackAxis, ProbeMode};
use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde_json;
use serde_yaml;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AttackProfile {
    #[serde(default)]
    pub common_args: Vec<String>,
    #[serde(default)]
    pub axes: HashMap<AttackAxis, Vec<String>>,
    #[serde(default)]
    pub probe_mode: Option<ProbeMode>,
}

impl AttackProfile {
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("reading attack profile {}", path.display()))?;
        // Extension-based dispatch is explicit to avoid ambiguous parsing behavior.
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("json") => serde_json::from_str(&content)
                .with_context(|| format!("parsing json attack profile {}", path.display())),
            Some("yaml") | Some("yml") => serde_yaml::from_str(&content)
                .with_context(|| format!("parsing yaml attack profile {}", path.display())),
            _ => Err(anyhow!(
                "unsupported attack profile extension for {}",
                path.display()
            )),
        }
    }
}
