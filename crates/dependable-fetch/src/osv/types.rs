//! Serde types for the OSV `querybatch` API.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct BatchRequest {
    pub queries: Vec<Query>,
}

#[derive(Debug, Serialize)]
pub struct Query {
    pub version: String,
    pub package: Package,
}

#[derive(Debug, Serialize)]
pub struct Package {
    pub name: String,
    pub ecosystem: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct BatchResponse {
    #[serde(default)]
    pub results: Vec<QueryResult>,
}

#[derive(Debug, Default, Deserialize)]
pub struct QueryResult {
    #[serde(default)]
    pub vulns: Vec<VulnRef>,
}

#[derive(Debug, Deserialize)]
pub struct VulnRef {
    pub id: String,
}
