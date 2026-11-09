//! Which vault entries belong to a web page. The browser bridge offers (and
//! fills) an entry only on pages its Website field matches, so a look-alike
//! domain never gets a password.
//!
//! Rules:
//! * An entry without a URL never matches. A URL without a scheme counts as `https://`.
//! * Same host, or the page is on a subdomain of the entry's host
//!   (`example.com` matches `login.example.com`). A leading `www.` on the entry
//!   is ignored, so `www.example.com` also matches `example.com`.
//! * IP addresses and single-label names (`localhost`, `router`) match exactly only.
//! * An entry saved for `https` is never filled into an `http` page.
//! * A port written in the entry must be the page's port.

use url::{Host, Url};

/// A page origin, as the browser extension reports it.
#[derive(Clone, Debug, PartialEq)]
pub struct Page {
    https: bool,
    host: Host<String>,
    port: Option<u16>,
}

impl Page {
    /// Parse `https://host[:port]`. Only http(s) pages qualify.
    pub fn parse(origin: &str) -> Option<Page> {
        let u = Url::parse(origin.trim()).ok()?;
        let https = match u.scheme() {
            "https" => true,
            "http" => false,
            _ => return None,
        };
        let host = normalize(u.host()?.to_owned());
        Some(Page { https, host, port: u.port_or_known_default() })
    }

    /// Host for display ("github.com").
    pub fn host(&self) -> String {
        self.host.to_string()
    }

    /// The same page over https (to explain a refused http fill).
    pub fn as_https(&self) -> Page {
        let port = if !self.https && self.port == Some(80) { Some(443) } else { self.port };
        Page { https: true, host: self.host.clone(), port }
    }
}

/// Lowercase (the url crate already does) and drop a trailing dot.
fn normalize(h: Host<String>) -> Host<String> {
    match h {
        Host::Domain(d) => Host::Domain(d.trim_end_matches('.').to_ascii_lowercase()),
        other => other,
    }
}

/// Does the entry URL `entry_url` belong to `page`?
pub fn matches(entry_url: &str, page: &Page) -> bool {
    let s = entry_url.trim();
    if s.is_empty() {
        return false;
    }
    let with_scheme;
    let s = if s.contains("://") { s } else { with_scheme = format!("https://{s}"); &with_scheme };
    let Ok(u) = Url::parse(s) else { return false };
    let entry_https = match u.scheme() {
        "https" => true,
        "http" => false,
        _ => return false,
    };
    if entry_https && !page.https {
        return false;
    }
    if let Some(p) = u.port() {
        if page.port != Some(p) {
            return false;
        }
    }
    let Some(host) = u.host() else { return false };
    match (normalize(host.to_owned()), &page.host) {
        (Host::Domain(e), Host::Domain(p)) => {
            let e = e.strip_prefix("www.").filter(|r| r.contains('.')).unwrap_or(&e);
            if e.is_empty() {
                return false;
            }
            p == e || (e.contains('.') && p.len() > e.len() && p.ends_with(e) && p.as_bytes()[p.len() - e.len() - 1] == b'.')
        }
        (e, p) => &e == p,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(entry: &str, origin: &str) -> bool {
        matches(entry, &Page::parse(origin).expect("valid origin"))
    }

    #[test]
    fn same_and_subdomains() {
        assert!(m("https://github.com/login", "https://github.com"));
        assert!(m("github.com", "https://github.com"));
        assert!(m("https://github.com", "https://gist.github.com"));
        assert!(m("https://GitHub.com.", "https://github.com"));
        assert!(m("https://www.example.com", "https://example.com"));
        assert!(m("https://www.example.com", "https://login.example.com"));
        assert!(m("https://example.com", "https://www.example.com"));
        // A subdomain entry doesn't cover its parent or siblings.
        assert!(!m("https://login.example.com", "https://example.com"));
        assert!(!m("https://login.example.com", "https://mail.example.com"));
    }

    #[test]
    fn look_alikes_never_match() {
        assert!(!m("https://github.com", "https://evilgithub.com"));
        assert!(!m("https://github.com", "https://github.com.evil.io"));
        assert!(!m("https://github.com", "https://githubXcom"));
        assert!(!m("https://www.com", "https://evil.com"), "www. is not stripped down to a bare TLD");
    }

    #[test]
    fn scheme_and_port() {
        assert!(!m("https://bank.example", "http://bank.example"), "no https → http downgrade");
        assert!(m("http://bank.example", "https://bank.example"));
        assert!(m("http://192.168.1.1", "http://192.168.1.1"));
        assert!(!m("ftp://files.example", "https://files.example"));
        assert!(m("https://nas.example:5001", "https://nas.example:5001"));
        assert!(!m("https://nas.example:5001", "https://nas.example"));
        assert!(m("https://nas.example", "https://nas.example:5001"), "no port in the entry: any port");
        let http = Page::parse("http://bank.example").unwrap();
        assert!(matches("https://bank.example", &http.as_https()));
    }

    #[test]
    fn ips_and_single_labels() {
        assert!(m("http://192.168.1.1/admin", "http://192.168.1.1"));
        assert!(!m("http://192.168.1.1", "http://192.168.1.10"));
        assert!(!m("http://1.1", "http://2.1.1"), "IPs are never suffix-matched");
        assert!(m("http://[::1]:8080", "http://[::1]:8080"));
        assert!(m("http://localhost:3000", "http://localhost:3000"));
        assert!(!m("http://localhost", "http://evil.localhost"), "single labels match exactly");
        assert!(m("router", "https://router"));
    }

    #[test]
    fn empty_and_invalid() {
        assert!(!m("", "https://example.com"));
        assert!(!m("   ", "https://example.com"));
        assert!(!m("not a url at all", "https://example.com"));
        assert!(Page::parse("moz-extension://abc").is_none());
        assert!(Page::parse("file:///etc/passwd").is_none());
        assert!(Page::parse("about:blank").is_none());
        assert_eq!(Page::parse("https://Example.COM").unwrap().host(), "example.com");
    }
}
