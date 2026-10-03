//! Apache Guacamole protocol to a guacd sidecar, for RDP.
//!
//! The gateway performs the guacd handshake itself, so the browser never
//! names a host, port, protocol or connection parameter: the target comes
//! from the redeemed ticket, the user name is the ticket's OS user, and only
//! the password is typed per session (kept in memory for the handshake,
//! never stored or logged). After the handshake the gateway relays whole
//! instructions and drops any browser instruction outside a small allowlist,
//! so file transfer and tunnel-level opcodes cannot be used.

use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_INSTRUCTION_BYTES: usize = 8 * 1024 * 1024;
const CLIENT_OPCODES: &[&str] = &[
    "ack",
    "blob",
    "clipboard",
    "disconnect",
    "end",
    "key",
    "mouse",
    "nop",
    "size",
    "sync",
    "touch",
];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GuacError {
    #[error("could not reach guacd: {0}")]
    Connect(String),
    #[error("guacd handshake failed: {0}")]
    Handshake(String),
    #[error("malformed Guacamole instruction")]
    Malformed,
}

/// Encodes one instruction. Lengths count Unicode code points.
pub fn encode(elements: &[&str]) -> String {
    let mut out = String::new();
    for (index, element) in elements.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&element.chars().count().to_string());
        out.push('.');
        out.push_str(element);
    }
    out.push(';');
    out
}

/// Parses one complete instruction from the start of `text`. Returns the
/// elements and the byte length consumed, or `None` when incomplete.
pub fn parse_one(text: &str) -> Result<Option<(Vec<String>, usize)>, GuacError> {
    let mut elements = Vec::new();
    let mut position = 0;
    loop {
        let rest = &text[position..];
        let Some(dot) = rest.find('.') else {
            if rest.len() > 10 || !rest.chars().all(|ch| ch.is_ascii_digit()) {
                return Err(GuacError::Malformed);
            }
            return Ok(None);
        };
        let length: usize = rest[..dot].parse().map_err(|_| GuacError::Malformed)?;
        if length > MAX_INSTRUCTION_BYTES {
            return Err(GuacError::Malformed);
        }
        let value_start = position + dot + 1;
        let mut chars = text[value_start..].char_indices();
        let mut end = value_start;
        for _ in 0..length {
            match chars.next() {
                Some((offset, ch)) => end = value_start + offset + ch.len_utf8(),
                None => return Ok(None),
            }
        }
        if length == 0 {
            end = value_start;
        }
        elements.push(text[value_start..end].to_owned());
        match text[end..].chars().next() {
            Some(',') => position = end + 1,
            Some(';') => return Ok(Some((elements, end + 1))),
            Some(_) => return Err(GuacError::Malformed),
            None => return Ok(None),
        }
    }
}

/// Buffers a byte stream into whole instructions.
#[derive(Default)]
pub struct Reader {
    pending: Vec<u8>,
    text: String,
}

impl Reader {
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), GuacError> {
        self.pending.extend_from_slice(bytes);
        let valid = match std::str::from_utf8(&self.pending) {
            Ok(text) => text.len(),
            Err(error) if error.error_len().is_none() => error.valid_up_to(),
            Err(_) => return Err(GuacError::Malformed),
        };
        self.text
            .push_str(std::str::from_utf8(&self.pending[..valid]).expect("validated UTF-8"));
        self.pending.drain(..valid);
        if self.text.len() > MAX_INSTRUCTION_BYTES {
            return Err(GuacError::Malformed);
        }
        Ok(())
    }

    /// Removes and returns every complete instruction as raw text.
    pub fn drain_complete(&mut self) -> Result<String, GuacError> {
        let mut consumed = 0;
        while let Some((_, used)) = parse_one(&self.text[consumed..])? {
            consumed += used;
        }
        Ok(self.text.drain(..consumed).collect())
    }

    pub fn next_instruction(&mut self) -> Result<Option<Vec<String>>, GuacError> {
        match parse_one(&self.text)? {
            Some((elements, used)) => {
                self.text.drain(..used);
                Ok(Some(elements))
            }
            None => Ok(None),
        }
    }
}

/// Keeps only well-formed browser instructions with allowlisted opcodes.
pub fn filter_client(text: &str) -> Result<String, GuacError> {
    let mut out = String::new();
    let mut position = 0;
    while position < text.len() {
        let Some((elements, used)) = parse_one(&text[position..])? else {
            return Err(GuacError::Malformed);
        };
        if elements
            .first()
            .is_some_and(|opcode| CLIENT_OPCODES.contains(&opcode.as_str()))
        {
            out.push_str(&text[position..position + used]);
        }
        position += used;
    }
    Ok(out)
}

pub struct RdpParams<'a> {
    pub hostname: &'a str,
    pub port: u16,
    pub username: &'a str,
    pub password: &'a str,
    pub width: u32,
    pub height: u32,
    pub dpi: u32,
}

fn connect_value(name: &str, params: &RdpParams<'_>) -> String {
    let (domain, user) = match params.username.split_once('\\') {
        Some((domain, user)) => (domain, user),
        None => ("", params.username),
    };
    match name {
        version if version.starts_with("VERSION_") => version.to_owned(),
        "hostname" => params.hostname.to_owned(),
        "port" => params.port.to_string(),
        "username" => user.to_owned(),
        "domain" => domain.to_owned(),
        "password" => params.password.to_owned(),
        // The overlay address is WireGuard-authenticated to the target's
        // node key; the RDP certificate itself is not pinned.
        "security" => "any".into(),
        "ignore-cert" => "true".into(),
        "disable-upload" | "disable-download" => "true".into(),
        "enable-drive" | "enable-printing" | "enable-sftp" | "create-drive-path" => "false".into(),
        "resize-method" => "display-update".into(),
        _ => String::new(),
    }
}

async fn read_instruction(
    stream: &mut TcpStream,
    reader: &mut Reader,
) -> Result<Vec<String>, GuacError> {
    let mut buffer = [0u8; 8192];
    loop {
        if let Some(instruction) = reader.next_instruction()? {
            return Ok(instruction);
        }
        let read = stream
            .read(&mut buffer)
            .await
            .map_err(|error| GuacError::Handshake(error.to_string()))?;
        if read == 0 {
            return Err(GuacError::Handshake("guacd closed the connection".into()));
        }
        reader.push(&buffer[..read])?;
    }
}

/// Connects to guacd and completes an RDP handshake. Returns the stream and
/// any instructions guacd sent after `ready`.
pub async fn handshake(
    guacd: &str,
    params: &RdpParams<'_>,
) -> Result<(TcpStream, Reader), GuacError> {
    let mut stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(guacd))
        .await
        .map_err(|_| GuacError::Connect("timed out".into()))?
        .map_err(|error| GuacError::Connect(error.to_string()))?;
    let mut reader = Reader::default();
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let write = |text: String| text.into_bytes();
        stream
            .write_all(&write(encode(&["select", "rdp"])))
            .await
            .map_err(|error| GuacError::Handshake(error.to_string()))?;
        let args = read_instruction(&mut stream, &mut reader).await?;
        if args.first().map(String::as_str) != Some("args") {
            return Err(GuacError::Handshake("guacd did not offer arguments".into()));
        }
        let width = params.width.clamp(640, 3840).to_string();
        let height = params.height.clamp(480, 2160).to_string();
        let dpi = params.dpi.clamp(72, 240).to_string();
        let mut opening = encode(&["size", &width, &height, &dpi]);
        opening.push_str(&encode(&["audio"]));
        opening.push_str(&encode(&["video"]));
        opening.push_str(&encode(&["image", "image/png", "image/jpeg", "image/webp"]));
        opening.push_str(&encode(&["timezone", "Australia/Sydney"]));
        let values = args[1..]
            .iter()
            .map(|name| connect_value(name, params))
            .collect::<Vec<_>>();
        let mut connect = vec!["connect"];
        connect.extend(values.iter().map(String::as_str));
        opening.push_str(&encode(&connect));
        stream
            .write_all(opening.as_bytes())
            .await
            .map_err(|error| GuacError::Handshake(error.to_string()))?;
        let ready = read_instruction(&mut stream, &mut reader).await?;
        match ready.first().map(String::as_str) {
            Some("ready") => Ok(()),
            Some("error") => Err(GuacError::Handshake(
                ready.get(1).cloned().unwrap_or_default(),
            )),
            _ => Err(GuacError::Handshake("guacd did not become ready".into())),
        }
    })
    .await
    .map_err(|_| GuacError::Handshake("timed out".into()))??;
    Ok((stream, reader))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn encodes_and_parses_unicode_lengths() {
        let text = encode(&["clipboard", "Ngurra ✓", ""]);
        assert_eq!(text, "9.clipboard,8.Ngurra ✓,0.;");
        let (elements, used) = parse_one(&text).unwrap().unwrap();
        assert_eq!(elements, vec!["clipboard", "Ngurra ✓", ""]);
        assert_eq!(used, text.len());
        assert_eq!(parse_one("4.size,4.10").unwrap(), None);
        assert!(parse_one("x.size;").is_err());
        assert!(parse_one("4.sizeX;").is_err());
    }

    #[test]
    fn reader_splits_partial_utf8_and_instructions() {
        let mut reader = Reader::default();
        let text = format!("{}{}", encode(&["sync", "1"]), encode(&["name", "✓✓"]));
        let bytes = text.as_bytes();
        let split = bytes.len() - 3;
        reader.push(&bytes[..split]).unwrap();
        assert_eq!(reader.drain_complete().unwrap(), encode(&["sync", "1"]));
        reader.push(&bytes[split..]).unwrap();
        assert_eq!(reader.drain_complete().unwrap(), encode(&["name", "✓✓"]));
    }

    #[test]
    fn browser_cannot_send_file_or_tunnel_opcodes() {
        let input = format!(
            "{}{}{}{}",
            encode(&["key", "65", "1"]),
            encode(&["file", "1", "text/plain", "evil.sh"]),
            encode(&["", "ping", "1"]),
            encode(&["mouse", "1", "2", "0"])
        );
        assert_eq!(
            filter_client(&input).unwrap(),
            format!(
                "{}{}",
                encode(&["key", "65", "1"]),
                encode(&["mouse", "1", "2", "0"])
            )
        );
        assert!(filter_client("3.key,2.65").is_err());
    }

    #[tokio::test]
    async fn handshake_sends_ticket_values_not_browser_values() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let fake = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut reader = Reader::default();
            let select = read_instruction(&mut socket, &mut reader).await.unwrap();
            assert_eq!(select, vec!["select", "rdp"]);
            socket
                .write_all(
                    encode(&[
                        "args",
                        "VERSION_1_5_0",
                        "hostname",
                        "port",
                        "domain",
                        "username",
                        "password",
                        "ignore-cert",
                        "enable-drive",
                        "disable-upload",
                    ])
                    .as_bytes(),
                )
                .await
                .unwrap();
            let mut seen = Vec::new();
            loop {
                let instruction = read_instruction(&mut socket, &mut reader).await.unwrap();
                let done = instruction[0] == "connect";
                seen.push(instruction);
                if done {
                    break;
                }
            }
            socket
                .write_all(
                    format!("{}{}", encode(&["ready", "$id"]), encode(&["sync", "1"])).as_bytes(),
                )
                .await
                .unwrap();
            seen
        });
        let (_, mut reader) = handshake(
            &address,
            &RdpParams {
                hostname: "100.64.0.7",
                port: 3389,
                username: "OFFICE\\deploy",
                password: "pa,ss;5.word",
                width: 1280,
                height: 720,
                dpi: 96,
            },
        )
        .await
        .unwrap();
        let seen = fake.await.unwrap();
        let connect = seen.last().unwrap();
        assert_eq!(
            connect,
            &vec![
                "connect",
                "VERSION_1_5_0",
                "100.64.0.7",
                "3389",
                "OFFICE",
                "deploy",
                "pa,ss;5.word",
                "true",
                "false",
                "true"
            ]
        );
        assert_eq!(seen[0][0], "size");
        // Instructions after `ready` are kept for the browser.
        assert_eq!(reader.drain_complete().unwrap(), encode(&["sync", "1"]));
    }
}
