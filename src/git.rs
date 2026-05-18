use anyhow::{Context, Result};
use colored::*;
use std::path::{Path, PathBuf};

pub struct ResolvedTarget {
    pub path: PathBuf,
    pub name: String,
    pub is_temp: bool, // true if we cloned it, so we can clean up
}

pub async fn resolve(target: &str) -> Result<ResolvedTarget> {
    if is_github_url(target) {
        clone_repo(target).await
    } else {
        resolve_local(target)
    }
}

fn is_github_url(target: &str) -> bool {
    target.starts_with("https://github.com")
        || target.starts_with("http://github.com")
        || target.starts_with("github.com")
}

async fn clone_repo(url: &str) -> Result<ResolvedTarget> {
    println!("  {} {}", "→".cyan(), format!("Cloning {}", url).dimmed());

    // Extract repo name from URL
    let name = url
        .trim_end_matches('/')
        .split('/')
        .last()
        .unwrap_or("repo")
        .trim_end_matches(".git")
        .to_string();

    // Clone into a temp directory
    let temp_dir = std::env::temp_dir().join(format!("limbo_{}", name));

    // Remove if already exists
    if temp_dir.exists() {
        std::fs::remove_dir_all(&temp_dir)?;
    }

    // Clone using git2
    git2::Repository::clone(url, &temp_dir)
        .with_context(|| format!("Failed to clone {}", url))?;

    println!(
        "  {} {}",
        "✓".green(),
        format!("Cloned {} successfully", name).dimmed()
    );

    Ok(ResolvedTarget {
        path: temp_dir,
        name,
        is_temp: true,
    })
}

fn resolve_local(target: &str) -> Result<ResolvedTarget> {
    let path = PathBuf::from(target);

    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", target);
    }

    // If it's a single .move file, use its parent directory
    let (resolved_path, name) = if path.is_file() {
        let name = path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        // For single files, we still need the parent for sui move build
        (path.parent().unwrap_or(Path::new(".")).to_path_buf(), name)
    } else {
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        (path, name)
    };

    println!(
        "  {} {}",
        "✓".green(),
        format!("Resolved local path: {}", resolved_path.display()).dimmed()
    );

    Ok(ResolvedTarget {
        path: resolved_path,
        name,
        is_temp: false,
    })
}

/// Walk directory and collect all .move source files
pub fn collect_move_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_recursive(dir, &mut files);
    files
}

fn collect_recursive(dir: &Path, files: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // Skip hidden dirs and build artifacts
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if !name.starts_with('.') && name != "build" && name != "target" {
                    collect_recursive(&path, files);
                }
            } else if path.extension().map_or(false, |e| e == "move") {
                files.push(path);
            }
        }
    }
}
