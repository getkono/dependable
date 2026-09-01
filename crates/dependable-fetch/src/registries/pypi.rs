//! The PyPI fetcher (the JSON API at `pypi.org/pypi/<name>/json`).
//!
//! Versions are returned as raw PEP 440 strings (so pre-release detection sees the
//! real markers); they are sorted newest-first by their semver interpretation. The
//! evaluation layer converts them to semver for comparison.

use std::collections::{BTreeMap, HashMap};

use ::semver::Version;
use dependable_core::semver::python::pep440_to_semver;
use futures::FutureExt;
use futures::future::BoxFuture;
use serde::Deserialize;

use super::{FetchedVersions, Owner, OwnerKind, PackageMetadata, RegistryFetcher};
use crate::error::FetchError;

const DEFAULT_REGISTRY: &str = "https://pypi.org/pypi";

/// Fetches package versions from a PyPI-compatible JSON API.
#[derive(Clone)]
pub struct PyPiFetcher {
    client: reqwest::Client,
    base_url: String,
}

#[derive(Deserialize)]
struct Response {
    #[serde(default)]
    releases: HashMap<String, Vec<FileEntry>>,
}

#[derive(Deserialize)]
struct FileEntry {
    #[serde(default)]
    yanked: bool,
}

impl PyPiFetcher {
    /// A fetcher against the public PyPI JSON API.
    #[must_use]
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            client,
            base_url: DEFAULT_REGISTRY.to_string(),
        }
    }

    /// A fetcher against an alternate PyPI-compatible JSON API.
    #[must_use]
    pub fn with_registry(client: reqwest::Client, registry_url: impl Into<String>) -> Self {
        Self {
            client,
            base_url: registry_url.into().trim_end_matches('/').to_string(),
        }
    }
}

/// The `info` block of a PyPI project response, narrowed to what we render.
#[derive(Deserialize)]
struct InfoResponse {
    #[serde(default)]
    info: Info,
    #[serde(default)]
    urls: Vec<UploadedFile>,
    /// Every release and its files. PyPI has long signalled that this block may
    /// go away, so it is read opportunistically and never depended on — when it
    /// is absent only the newest release can be dated, from `urls`.
    #[serde(default)]
    releases: HashMap<String, Vec<UploadedFile>>,
}

#[derive(Deserialize, Default)]
struct Info {
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    home_page: Option<String>,
    #[serde(default)]
    license: Option<String>,
    /// PEP 639's `License-Expression`: a real SPDX expression, when the project
    /// publishes one.
    #[serde(default)]
    license_expression: Option<String>,
    /// The trove classifiers, which carry the license as a controlled vocabulary
    /// where `license` is free text.
    #[serde(default)]
    classifiers: Vec<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    author_email: Option<String>,
    #[serde(default)]
    maintainer: Option<String>,
    #[serde(default)]
    maintainer_email: Option<String>,
    #[serde(default)]
    yanked: bool,
    #[serde(default)]
    project_urls: HashMap<String, String>,
}

#[derive(Deserialize)]
struct UploadedFile {
    #[serde(default)]
    upload_time_iso_8601: Option<String>,
}

/// Publish dates per version, from whichever of the two shapes PyPI served.
///
/// A release is dated by its earliest uploaded file: a version's files can be
/// uploaded minutes or years apart (a later wheel for a new Python), and the
/// first upload is what "published" means.
fn pypi_published(body: &InfoResponse) -> BTreeMap<String, String> {
    if !body.releases.is_empty() {
        return body
            .releases
            .iter()
            .filter_map(|(version, files)| {
                let earliest = files
                    .iter()
                    .filter_map(|f| f.upload_time_iso_8601.as_deref())
                    .min()?;
                Some((version.clone(), earliest.to_owned()))
            })
            .collect();
    }

    // Only the newest release is described, so that is all we can date.
    match (
        body.info.version.as_deref(),
        body.urls
            .iter()
            .filter_map(|f| f.upload_time_iso_8601.as_deref())
            .min(),
    ) {
        (Some(version), Some(uploaded)) => {
            BTreeMap::from([(version.to_owned(), uploaded.to_owned())])
        }
        _ => BTreeMap::new(),
    }
}

/// SPDX identifiers for the trove classifiers whose license is unambiguous.
///
/// Deliberately partial. `License :: OSI Approved :: BSD License` is **not**
/// here: it covers BSD-2-Clause and BSD-3-Clause alike, which differ in a real
/// obligation, and inventing one of them would be worse than reporting nothing —
/// an allowlist would then approve a license the package never declared.
/// `Apache Software License` is mapped, because Apache-1.x is extinct on PyPI
/// and treating it as unknown would make the table useless for Python.
const CLASSIFIER_SPDX: &[(&str, &str)] = &[
    ("License :: OSI Approved :: MIT License", "MIT"),
    (
        "License :: OSI Approved :: MIT No Attribution License (MIT-0)",
        "MIT-0",
    ),
    (
        "License :: OSI Approved :: Apache Software License",
        "Apache-2.0",
    ),
    ("License :: OSI Approved :: ISC License (ISCL)", "ISC"),
    (
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        "MPL-2.0",
    ),
    (
        "License :: OSI Approved :: Mozilla Public License 1.1 (MPL 1.1)",
        "MPL-1.1",
    ),
    (
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "GPL-2.0",
    ),
    (
        "License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)",
        "GPL-2.0+",
    ),
    (
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "GPL-3.0",
    ),
    (
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "GPL-3.0+",
    ),
    (
        "License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)",
        "LGPL-2.0",
    ),
    (
        "License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)",
        "LGPL-2.0+",
    ),
    (
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
        "LGPL-3.0",
    ),
    (
        "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
        "LGPL-3.0+",
    ),
    (
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "AGPL-3.0",
    ),
    (
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        "AGPL-3.0+",
    ),
    (
        "License :: OSI Approved :: The Unlicense (Unlicense)",
        "Unlicense",
    ),
    (
        "License :: OSI Approved :: Boost Software License 1.0 (BSL-1.0)",
        "BSL-1.0",
    ),
    (
        "License :: OSI Approved :: Python Software Foundation License",
        "PSF-2.0",
    ),
    (
        "License :: OSI Approved :: Eclipse Public License 2.0 (EPL-2.0)",
        "EPL-2.0",
    ),
    (
        "License :: OSI Approved :: Eclipse Public License 1.0 (EPL-1.0)",
        "EPL-1.0",
    ),
    ("License :: OSI Approved :: zlib/libpng License", "Zlib"),
    (
        "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
        "CC0-1.0",
    ),
];

/// The longest a free-text `info.license` may be before it is discarded.
///
/// PyPI's `license` field is prose, and a large minority of projects paste the
/// **entire license body** into it. Sixty-four characters comfortably fits every
/// real SPDX expression and excludes a pasted paragraph.
const MAX_FREE_TEXT_LICENSE: usize = 64;

/// The package's license, resolved from the most trustworthy field PyPI served.
///
/// In priority order:
/// 1. `license_expression` (PEP 639) — already SPDX; used verbatim.
/// 2. `classifiers` — a controlled vocabulary, mapped through
///    [`CLASSIFIER_SPDX`] and joined with `OR` when several apply.
/// 3. `license` — free text, and accepted **only** when it is short and
///    single-line. A longer value is dropped rather than reported: handing a
///    license body (or prose such as `"Apache 2.0"`, which is not an SPDX
///    identifier) to a license allowlist manufactures a false verdict, where
///    `None` is honestly "not published in a usable form".
fn pypi_license(info: &Info) -> Option<String> {
    if let Some(expression) = info
        .license_expression
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        return Some(expression.to_string());
    }

    let mut mapped: Vec<&str> = Vec::new();
    for classifier in &info.classifiers {
        let trimmed = classifier.trim();
        if let Some((_, spdx)) = CLASSIFIER_SPDX.iter().find(|(name, _)| *name == trimmed)
            && !mapped.contains(spdx)
        {
            mapped.push(spdx);
        }
    }
    if !mapped.is_empty() {
        return Some(mapped.join(" OR "));
    }

    info.license
        .as_deref()
        .map(str::trim)
        .filter(|l| !l.is_empty() && l.len() <= MAX_FREE_TEXT_LICENSE && !l.contains(['\n', '\r']))
        .map(str::to_string)
}

/// PyPI records an author and a maintainer as two independent name/email pairs,
/// either of which may be blank or absent.
///
/// The two are frequently the same person, and a package that names the same
/// party twice should not read as having two owners.
fn pypi_owners(info: &Info) -> Vec<Owner> {
    let pair = |name: &Option<String>, email: &Option<String>| Owner {
        name: name.clone().filter(|v| !v.trim().is_empty()),
        login: None,
        email: email.clone().filter(|v| !v.trim().is_empty()),
        url: None,
        kind: OwnerKind::User,
    };

    let mut owners = Vec::new();
    for owner in [
        pair(&info.author, &info.author_email),
        pair(&info.maintainer, &info.maintainer_email),
    ] {
        if !owner.is_anonymous() && !owners.contains(&owner) {
            owners.push(owner);
        }
    }
    owners
}

/// The `project_urls` key naming a source repository, by PyPI convention.
fn repository_url(urls: &HashMap<String, String>) -> Option<String> {
    ["Source", "Source Code", "Repository", "Code", "Homepage"]
        .iter()
        .find_map(|key| urls.get(*key).cloned())
}

impl RegistryFetcher for PyPiFetcher {
    fn fetch_versions<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<FetchedVersions, FetchError>> {
        async move {
            let url = format!("{}/{name}/json", self.base_url);
            let resp = self.client.get(&url).send().await?;
            let status = resp.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                return Err(FetchError::NotFound(name.to_string()));
            }
            if !status.is_success() {
                return Err(FetchError::Status {
                    code: status.as_u16(),
                    package: name.to_string(),
                });
            }
            let body: Response = resp.json().await.map_err(|e| FetchError::Decode {
                package: name.to_string(),
                detail: e.to_string(),
            })?;

            // Keep a release if it has at least one non-yanked file (or no files at
            // all — some sdist-only releases list none but are installable).
            let mut versions: Vec<String> = body
                .releases
                .into_iter()
                .filter(|(_, files)| files.is_empty() || files.iter().any(|f| !f.yanked))
                .map(|(v, _)| v)
                .collect();
            sort_desc(&mut versions);
            Ok(FetchedVersions::new(versions))
        }
        .boxed()
    }

    fn fetch_metadata<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Option<PackageMetadata>, FetchError>> {
        async move {
            let url = format!("{}/{name}/json", self.base_url);
            let resp = self.client.get(&url).send().await?;
            let status = resp.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                return Err(FetchError::NotFound(name.to_string()));
            }
            if !status.is_success() {
                return Err(FetchError::Status {
                    code: status.as_u16(),
                    package: name.to_string(),
                });
            }
            let body: InfoResponse = resp.json().await.map_err(|e| FetchError::Decode {
                package: name.to_string(),
                detail: e.to_string(),
            })?;

            // Computed before the struct literal moves the fields they read.
            let owners = pypi_owners(&body.info);
            let published = pypi_published(&body);
            let license = pypi_license(&body.info);

            Ok(Some(PackageMetadata {
                description: body.info.summary,
                repository: repository_url(&body.info.project_urls),
                homepage: body.info.home_page,
                documentation: body.info.project_urls.get("Documentation").cloned(),
                license,
                owners,
                downloads: None,
                latest_published: body
                    .urls
                    .into_iter()
                    .filter_map(|f| f.upload_time_iso_8601)
                    .min(),
                published,
                yanked: body.info.yanked,
                msrv: None,
            }))
        }
        .boxed()
    }
}

/// Sort raw PEP 440 versions newest-first by their semver interpretation.
///
/// The comparison is **total**: versions that compare equal are ordered by their
/// own strings, so a list built in a nondeterministic order (a `HashMap`'s
/// iteration, pages appended as their fetches complete) cannot come out of here in
/// a nondeterministic one.
fn sort_desc(versions: &mut [String]) {
    versions.sort_by(|a, b| {
        let va = pep440_to_semver(a).and_then(|s| Version::parse(&s).ok());
        let vb = pep440_to_semver(b).and_then(|s| Version::parse(&s).ok());
        match (va, vb) {
            (Some(va), Some(vb)) => vb.cmp(&va).then_with(|| b.cmp(a)),
            _ => b.cmp(a),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PyPI's `releases` object is read into a `HashMap`, whose iteration order is
    /// randomized per process — so the list handed to the sort has no order of its
    /// own, and `psycopg2-binary` really does publish both `2.7.6` and `2.7.6.1`.
    ///
    /// The sort compares translations, and two versions can translate alike, so a
    /// stable sort left every tie group in the order it arrived in. Breaking the tie
    /// on the version string makes the order **total**, so one input set has exactly
    /// one sorted form however it was assembled.
    #[test]
    fn sorting_is_total_so_the_arrival_order_cannot_survive_it() {
        let published = ["2.7.6.1", "2.7.6", "2.7.5"];
        let expected = {
            let mut first: Vec<String> = published.iter().map(|v| (*v).to_string()).collect();
            sort_desc(&mut first);
            first
        };
        // Every ordering of the same set, so nothing positional can survive.
        let mut order: Vec<usize> = (0..published.len()).collect();
        let mut seen = 0;
        loop {
            let mut shuffled: Vec<String> =
                order.iter().map(|i| published[*i].to_string()).collect();
            sort_desc(&mut shuffled);
            assert_eq!(shuffled, expected, "arrived as {order:?}");
            seen += 1;
            // Next permutation, in place.
            let Some(pivot) = (0..order.len() - 1)
                .rev()
                .find(|i| order[*i] < order[i + 1])
            else {
                break;
            };
            let swap = (pivot + 1..order.len())
                .rev()
                .find(|i| order[*i] > order[pivot])
                .expect("a successor above the pivot");
            order.swap(pivot, swap);
            order[pivot + 1..].reverse();
        }
        assert_eq!(seen, 6, "every ordering was tried");
    }
}
