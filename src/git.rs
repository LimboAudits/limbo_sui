use anyhow::{Context, Result};
use colored::*;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub struct ResolvedTarget {
    pub path: PathBuf,
    pub name: String,
    pub is_temp: bool,
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
    let name = url
        .trim_end_matches('/')
        .split('/')
        .last()
        .unwrap_or("repo")
        .trim_end_matches(".git")
        .to_string();

    println!("  {} Cloning {}...", "↓".cyan(), url.dimmed());

    let temp_dir = std::env::temp_dir().join(format!("limbo_{}", name));

    if temp_dir.exists() {
        std::fs::remove_dir_all(&temp_dir)?;
    }

    git2::Repository::clone(url, &temp_dir)
        .with_context(|| format!("Failed to clone {}", url))?;

    println!("  {} Cloned {}", "✓".green(), name.white().bold());

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

    let (resolved_path, name) = if path.is_file() {
        let name = path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        (path.parent().unwrap_or(Path::new(".")).to_path_buf(), name)
    } else {
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        (path, name)
    };

    Ok(ResolvedTarget {
        path: resolved_path,
        name,
        is_temp: false,
    })
}

pub fn collect_move_files(dir: &Path) -> Vec<PathBuf> {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let path = e.path();
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();

            // Skip build artifacts and dependencies
            !path.to_string_lossy().contains("/build/")
                && !path.to_string_lossy().contains("/target/")
                && !path.to_string_lossy().contains("dependencies")
                && path.extension().map_or(false, |ext| ext == "move")
                && !name.starts_with('.')
        })
        .map(|e| e.path().to_path_buf())
        .collect()
}

pub fn find_move_packages(dir: &Path) -> Vec<PathBuf> {
    let mut packages = Vec::new();

    // Check root first
    if dir.join("Move.toml").exists() {
        packages.push(dir.to_path_buf());
    }

    // Walk subdirectories
    WalkDir::new(dir)
        .min_depth(1)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().is_dir()
                && e.path().join("Move.toml").exists()
                && !e.path().to_string_lossy().contains("/build/")
                && !e.path().to_string_lossy().contains("/target/")
        })
        .for_each(|e| {
            if !packages.contains(&e.path().to_path_buf()) {
                packages.push(e.path().to_path_buf());
            }
        });

    packages
}
