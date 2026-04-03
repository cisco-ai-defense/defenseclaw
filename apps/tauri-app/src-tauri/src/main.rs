// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::Command;


/// Install the DefenseClaw launchagent (macOS only)
#[tauri::command]
fn launchagent_install() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("launchctl")
            .args(&["bootstrap", "gui/$UID", &format!("{}/Library/LaunchAgents/com.defenseclaw.sidecar.plist", std::env::var("HOME").unwrap())])
            .output()
            .map_err(|e| format!("Failed to execute launchctl: {}", e))?;

        if output.status.success() {
            Ok("LaunchAgent installed successfully".to_string())
        } else {
            Err(format!("LaunchAgent install failed: {}", String::from_utf8_lossy(&output.stderr)))
        }
    }

    #[cfg(not(target_os = "macos"))]
    Err("LaunchAgent is only supported on macOS".to_string())
}

/// Uninstall the DefenseClaw launchagent (macOS only)
#[tauri::command]
fn launchagent_uninstall() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("launchctl")
            .args(&["bootout", "gui/$UID/com.defenseclaw.sidecar"])
            .output()
            .map_err(|e| format!("Failed to execute launchctl: {}", e))?;

        if output.status.success() {
            Ok("LaunchAgent uninstalled successfully".to_string())
        } else {
            Err(format!("LaunchAgent uninstall failed: {}", String::from_utf8_lossy(&output.stderr)))
        }
    }

    #[cfg(not(target_os = "macos"))]
    Err("LaunchAgent is only supported on macOS".to_string())
}

/// Run a defenseclaw CLI command
#[tauri::command]
async fn run_cli(args: Vec<String>) -> Result<String, String> {
    let output = Command::new("defenseclaw")
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to execute defenseclaw CLI: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(format!("CLI command failed: {}", String::from_utf8_lossy(&output.stderr)))
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            launchagent_install,
            launchagent_uninstall,
            run_cli
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
