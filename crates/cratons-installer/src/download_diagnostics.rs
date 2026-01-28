//! Download diagnostics for debugging package download failures.
//!
//! This module provides comprehensive HTTP response analysis to diagnose
//! download failures with actionable error messages.

use cratons_core::{CratonsError, Result};

/// Minimum size for a valid archive (gzip header alone is 10 bytes).
const MIN_ARCHIVE_SIZE: usize = 100;

/// Diagnostics captured from an HTTP download response.
#[derive(Debug)]
pub struct DownloadDiagnostics {
    /// The URL that was requested
    pub request_url: String,
    /// HTTP status code
    pub response_status: u16,
    /// Content-Type header value
    pub content_type: String,
    /// Content-Length header value (if present)
    pub content_length: Option<u64>,
    /// Actual bytes received
    pub actual_bytes: u64,
}

impl DownloadDiagnostics {
    /// Create diagnostics from an HTTP response.
    pub fn new(request_url: String, response: &reqwest::Response) -> Self {
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string();

        Self {
            request_url,
            response_status: response.status().as_u16(),
            content_type,
            content_length: response.content_length(),
            actual_bytes: 0,
        }
    }

    /// Validate downloaded content for common failure patterns.
    ///
    /// Detects:
    /// - Empty JSON responses (`{}`)
    /// - HTML error pages
    /// - JSON error responses
    /// - Truncated downloads
    /// - Suspiciously small archives
    pub fn validate_content(&self, bytes: &[u8]) -> Result<()> {
        let len = bytes.len();

        // Check for empty JSON object (common registry error response)
        if len == 2 && bytes == b"{}" {
            return Err(self.error(
                "Received empty JSON '{}' instead of package archive",
                "The registry returned an empty response. This may indicate:\n  \
                 - Package version doesn't exist\n  \
                 - Authentication required\n  \
                 - Registry rate limiting",
            ));
        }

        // Check for JSON error response
        if len < 1000 && self.looks_like_json(bytes) {
            let json_preview = self.safe_utf8_preview(bytes, 200);
            return Err(self.error(
                &format!("Received JSON error instead of package archive: {}", json_preview),
                "The registry returned a JSON response instead of a binary archive",
            ));
        }

        // Check for HTML error page
        if self.looks_like_html(bytes) {
            let html_preview = self.safe_utf8_preview(bytes, 100);
            return Err(self.error(
                &format!("Received HTML error page instead of package archive: {}", html_preview),
                "The registry returned an HTML page. Check:\n  \
                 - URL is correct\n  \
                 - Package exists\n  \
                 - No proxy/firewall interference",
            ));
        }

        // Check Content-Length mismatch (truncated download)
        if let Some(expected) = self.content_length {
            if (len as u64) != expected {
                return Err(self.error(
                    &format!(
                        "Download truncated: expected {} bytes, received {} bytes",
                        expected, len
                    ),
                    "The download was interrupted. Check network stability and retry",
                ));
            }
        }

        // Check for suspiciously small archive
        if self.is_archive_content_type() && len < MIN_ARCHIVE_SIZE {
            return Err(self.error(
                &format!(
                    "Archive too small: {} bytes (minimum {} expected)",
                    len, MIN_ARCHIVE_SIZE
                ),
                "The downloaded file is too small to be a valid archive",
            ));
        }

        // Validate archive magic bytes for known types
        if self.is_archive_content_type() && len >= 2 {
            self.validate_archive_magic(bytes)?;
        }

        Ok(())
    }

    /// Check if content looks like JSON.
    fn looks_like_json(&self, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }
        // Trim leading whitespace
        let trimmed = bytes.iter().skip_while(|&&b| b == b' ' || b == b'\n' || b == b'\r' || b == b'\t');
        matches!(trimmed.clone().next(), Some(b'{') | Some(b'['))
    }

    /// Check if content looks like HTML.
    fn looks_like_html(&self, bytes: &[u8]) -> bool {
        if bytes.len() < 15 {
            return false;
        }
        let lower: Vec<u8> = bytes.iter().take(100).map(|b| b.to_ascii_lowercase()).collect();
        lower.starts_with(b"<!doctype html")
            || lower.starts_with(b"<html")
            || lower.windows(6).any(|w| w == b"<head>")
    }

    /// Check if Content-Type indicates an archive.
    fn is_archive_content_type(&self) -> bool {
        let ct = self.content_type.to_lowercase();
        ct.contains("gzip")
            || ct.contains("tar")
            || ct.contains("zip")
            || ct.contains("octet-stream")
            || ct.contains("x-compressed")
    }

    /// Validate archive magic bytes.
    fn validate_archive_magic(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() < 2 {
            return Ok(());
        }

        // Gzip magic: 1f 8b
        let is_gzip = bytes[0] == 0x1f && bytes[1] == 0x8b;
        // Zip magic: 50 4b (PK)
        let is_zip = bytes[0] == 0x50 && bytes[1] == 0x4b;
        // Tar magic at offset 257: "ustar"
        let is_tar = bytes.len() > 262 && &bytes[257..262] == b"ustar";

        if !is_gzip && !is_zip && !is_tar {
            // Not a recognized archive format
            let hex_preview: String = bytes.iter().take(16).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
            return Err(self.error(
                &format!("Invalid archive format. First bytes: {}", hex_preview),
                "The downloaded file doesn't have valid archive headers. \
                 Expected gzip (1f 8b), zip (50 4b), or tar format",
            ));
        }

        Ok(())
    }

    /// Create a safe UTF-8 preview of bytes.
    fn safe_utf8_preview(&self, bytes: &[u8], max_len: usize) -> String {
        let preview_bytes = &bytes[..bytes.len().min(max_len)];
        String::from_utf8_lossy(preview_bytes)
            .chars()
            .filter(|c| !c.is_control() || *c == ' ')
            .collect::<String>()
            .trim()
            .to_string()
    }

    /// Create an error with context.
    fn error(&self, message: &str, hint: &str) -> CratonsError {
        CratonsError::Network(format!(
            "{}\n\nURL: {}\nStatus: {}\nContent-Type: {}\nContent-Length: {}\nReceived: {} bytes\n\nHint: {}",
            message,
            self.request_url,
            self.response_status,
            self.content_type,
            self.content_length.map_or("not specified".to_string(), |l| l.to_string()),
            self.actual_bytes,
            hint
        ))
    }
}
