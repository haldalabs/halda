//! Enable: an approved catalog of add-ons, each pinned to the exact version that
//! was checked. A safe default path, so security can say yes faster.

use crate::{Item, Kind, Report};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An item's standing against the catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CatalogStatus {
    /// Approved, and unchanged since.
    Approved,
    /// Approved once, but its code or settings have changed.
    Drifted,
    /// Not in the catalog.
    Unapproved,
}

/// One approved add-on.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// Item name.
    pub name: String,
    /// Pin recorded at approval.
    pub pin: String,
    /// Who approved it.
    #[serde(default)]
    pub approved_by: String,
}

/// A catalog file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    /// Approved add-ons.
    #[serde(default)]
    pub approved: Vec<Entry>,
}

impl Catalog {
    /// Parses a catalog.
    pub fn from_toml(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// Serializes a catalog.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// Marks each add-on in `report`. Agents themselves are not catalog items.
    pub fn apply(&self, report: &mut Report) {
        let by_name: HashMap<&str, &Entry> =
            self.approved.iter().map(|e| (e.name.as_str(), e)).collect();
        for item in report.items.iter_mut().filter(|i| i.kind != Kind::Agent) {
            item.catalog = Some(match by_name.get(item.name.as_str()) {
                Some(entry) if entry.pin == item.pin => CatalogStatus::Approved,
                Some(_) => CatalogStatus::Drifted,
                None => CatalogStatus::Unapproved,
            });
        }
    }

    /// Records approval of an item at its current pin, replacing any older entry.
    pub fn approve(&mut self, item: &Item, by: &str) {
        self.approved.retain(|e| e.name != item.name);
        self.approved.push(Entry {
            name: item.name.clone(),
            pin: item.pin.clone(),
            approved_by: by.to_string(),
        });
        self.approved.sort_by(|a, b| a.name.cmp(&b.name));
    }
}
