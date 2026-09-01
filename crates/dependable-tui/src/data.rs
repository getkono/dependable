//! The async side: discovering projects, and fetching what a selected package
//! needs without ever blocking the render loop.

use std::path::Path;
use std::sync::Arc;

use dependable_fetch::core::check_version;
use dependable_fetch::{
    Checker, Ecosystem, ManifestKind, WorkspaceGraphOptions, build_project_graph,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::model::{PackageData, PackageFacts, PackageKey, Project};

/// A message from a background task to the event loop.
#[derive(Debug)]
pub enum Message {
    /// Project discovery finished.
    Projects(Vec<Project>),
    /// A package lookup finished (successfully or not).
    Package(PackageKey, PackageData),
    /// Something went wrong that the user should see in the status bar.
    Notice(String),
}

/// Discover every project under `root` and build each one's graph.
///
/// Entirely offline and synchronous — it reads manifests and lockfiles — so the
/// caller runs it on a blocking thread and the tree is ready almost immediately.
#[must_use]
pub fn discover_projects(root: &Path, depth: usize) -> (Vec<Project>, Vec<String>) {
    let mut projects = Vec::new();
    let mut notices = Vec::new();

    // One walk answers both. A manifest we cannot read yields no project, so
    // nothing later in this loop could ever mention it.
    //
    // The TUI reads no config file, so every ecosystem counts as enabled.
    let found = dependable_fetch::discover(root, depth, |_| true);
    for notice in &found.notices {
        notices.push(notice.to_string());
    }

    for manifest in found.manifests {
        let Some(kind) = ManifestKind::detect(&manifest) else {
            continue;
        };
        // A lockfile that is present but unusable is the state a user can act
        // on, and it used to be indistinguishable from having none.
        for notice in dependable_fetch::lockfile_notices(&manifest, kind) {
            notices.push(notice.to_string());
        }

        // A Cargo workspace is reached through any of its members, which would
        // otherwise produce one identical graph per member.
        match build_project_graph(&manifest, &WorkspaceGraphOptions::default()) {
            Ok(built) => projects.push(Project {
                label: label_for(root, &manifest),
                manifest,
                ecosystem: kind.ecosystem(),
                graph: built.graph,
                source: built.source,
            }),
            Err(error) => {
                notices.push(format!("skipped {}: {error}", manifest.display()));
            }
        }
    }

    dedupe_workspaces(&mut projects);
    (projects, notices)
}

/// Collapse projects that resolved to the same graph roots, which is what every
/// member of one Cargo workspace does.
fn dedupe_workspaces(projects: &mut Vec<Project>) {
    let mut seen: Vec<(Ecosystem, Vec<String>)> = Vec::new();
    projects.retain(|project| {
        let mut fingerprint: Vec<String> = project
            .graph
            .roots()
            .iter()
            .map(|&i| {
                let node = &project.graph.nodes()[i];
                format!("{} {}", node.name, node.version)
            })
            .collect();
        fingerprint.sort();
        if fingerprint.is_empty() {
            return true;
        }
        let entry = (project.ecosystem, fingerprint);
        if seen.contains(&entry) {
            return false;
        }
        seen.push(entry);
        true
    });
}

/// How a manifest is labelled in the tree: relative to the scanned root.
fn label_for(root: &Path, manifest: &Path) -> String {
    manifest
        .strip_prefix(root)
        .unwrap_or(manifest)
        .display()
        .to_string()
}

/// Fetch everything the detail pane shows for one package.
///
/// Runs as its own task; the result is delivered over `tx`, so a slow or failing
/// registry never stalls the UI.
pub fn spawn_lookup(checker: Arc<Checker>, key: PackageKey, tx: UnboundedSender<Message>) {
    tokio::spawn(async move {
        let (ecosystem, name, version) = key.clone();
        let data = match lookup(&checker, ecosystem, &name, &version).await {
            Ok(facts) => PackageData::Ready(Box::new(facts)),
            Err(error) => PackageData::Failed(error),
        };
        let _ = tx.send(Message::Package(key, data));
    });
}

/// Gather metadata, freshness, and advisories for one package.
async fn lookup(
    checker: &Checker,
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
) -> Result<PackageFacts, String> {
    let mut facts = PackageFacts::default();

    // Metadata is the headline; a failure here is the one worth reporting.
    match checker.fetch_metadata(ecosystem, name).await {
        Ok(metadata) => facts.metadata = metadata,
        Err(error) => return Err(error.to_string()),
    }

    // Freshness and advisories are enrichment: if either is unavailable, still
    // show what we have, with a note, rather than failing the whole pane.
    match checker.fetch_versions(ecosystem, name).await {
        Ok(versions) => {
            // No declared constraint governs a resolved transitive package, so
            // `*` asks the engine the only question that applies: is the version
            // actually in use behind what the registry now offers?
            let evaluation = check_version("*", &versions, Some(version));
            facts.latest = evaluation.latest_available.clone();
            facts.status = Some(evaluation.status);
        }
        Err(error) => facts
            .warnings
            .push(format!("versions unavailable: {error}")),
    }

    match checker.scan_package(ecosystem, name, version).await {
        Ok(ids) => facts.vulnerabilities = ids,
        Err(error) => facts
            .warnings
            .push(format!("vulnerability scan unavailable: {error}")),
    }

    Ok(facts)
}
