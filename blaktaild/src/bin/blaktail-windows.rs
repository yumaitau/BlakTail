//! Windows (and any desktop) tool for console sign-in, enrolment, and file send.
//! The macOS and iPhone apps use the same console callback. This binary is the
//! Windows tool until a windowed client exists. The tunnel is still `blaktaild`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "blaktail-windows",
    about = "BlakTail tool for Windows desktops"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the console sign-in URL. The browser returns blaktail://auth/callback#token=…
    SignIn { console: String },
    /// Show the signed-in person. Pass the token from the callback fragment.
    Whoami { console: String, token: String },
    /// Ask the coordinator for an enrolment code. Approve it in the console.
    Enrol { coord: String, name: String },
    /// PUT one file to a writable overlay share.
    Send { url: String, file: PathBuf },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(cli.command).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run(command: Command) -> Result<(), String> {
    match command {
        Command::SignIn { console } => {
            println!("{}", sign_in_url(&console)?);
            Ok(())
        }
        Command::Whoami { console, token } => {
            let body = http_json(
                "GET",
                &format!("{}/api/desktop/me", trim(&console)),
                None,
                Some(&token),
            )
            .await?;
            println!("{body}");
            Ok(())
        }
        Command::Enrol { coord, name } => {
            let public_key = base64_key();
            let body = format!(
                "{{\"name\":{},\"wg_public_key\":{}}}",
                json_string(&name),
                json_string(&public_key)
            );
            let response = http_json(
                "POST",
                &format!("{}/v1/device-authorizations", trim(&coord)),
                Some(body),
                None,
            )
            .await?;
            println!("{response}");
            Ok(())
        }
        Command::Send { url, file } => {
            let bytes = std::fs::read(&file).map_err(|error| error.to_string())?;
            let status = put_share(&url, &bytes)?;
            println!("sent {} ({status})", file.display());
            Ok(())
        }
    }
}

fn sign_in_url(console: &str) -> Result<String, String> {
    let base = trim(console);
    if !(base.starts_with("https://")
        || base.starts_with("http://127.0.0.1")
        || base.starts_with("http://localhost"))
    {
        return Err("console URL must be HTTPS".into());
    }
    Ok(format!(
        "{base}/desktop/auth?redirect_uri={}",
        urlencoding_query("blaktail://auth/callback")
    ))
}

fn trim(value: &str) -> String {
    value.trim_end_matches('/').to_owned()
}

fn json_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn urlencoding_query(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn base64_key() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    base64::engine::general_purpose::STANDARD.encode(raw)
}

async fn http_json(
    method: &str,
    url: &str,
    body: Option<String>,
    bearer: Option<&str>,
) -> Result<String, String> {
    let response = reqwest::Client::builder()
        .build()
        .map_err(|error| error.to_string())?
        .request(
            method.parse().map_err(|_| format!("bad method {method}"))?,
            url,
        )
        .header("content-type", "application/json");
    let response = if let Some(token) = bearer {
        response.header("authorization", format!("Bearer {token}"))
    } else {
        response
    };
    let response = if let Some(body) = body {
        response.body(body)
    } else {
        response
    };
    let response = response.send().await.map_err(|error| error.to_string())?;
    let status = response.status();
    let text = response.text().await.map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!("console returned {status}: {text}"));
    }
    Ok(text)
}

fn put_share(url: &str, bytes: &[u8]) -> Result<u16, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or("share send stays on overlay HTTP")?;
    let (host, path) = rest.split_once('/').ok_or("share URL needs a file path")?;
    let mut stream = TcpStream::connect(host).map_err(|error| error.to_string())?;
    let request = format!(
        "PUT /{path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        bytes.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;
    stream.write_all(bytes).map_err(|error| error.to_string())?;
    let mut response = [0u8; 64];
    let read = stream
        .read(&mut response)
        .map_err(|error| error.to_string())?;
    let text = String::from_utf8_lossy(&response[..read]);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    if status != 201 && status != 204 {
        return Err(format!("share send failed ({status})"));
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_in_url_uses_the_shared_app_callback() {
        let url = sign_in_url("https://console.example/").unwrap();
        assert_eq!(
            url,
            "https://console.example/desktop/auth?redirect_uri=blaktail%3A%2F%2Fauth%2Fcallback"
        );
    }
}
