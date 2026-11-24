//! Cloudflare DNS-01: only create and remove the TXT record owned by this order.
//! Use the dashboard's existing verified HTTPS client; no shell commands or extra dependencies.
use bytes::Bytes;
use anyhow::{Context, Result, bail, ensure};
use http::{Method, header};
use instant_acme::{BodyWrapper, HttpClient};
use serde_json::{Value, json};
use std::time::Duration;

const API: &str = "https://api.cloudflare.com/client/v4";
const RESOLVER: &str = "https://cloudflare-dns.com/dns-query";
const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(300);

pub(super) fn validate_token(token: &str) -> Result<()> {
    ensure!(!token.is_empty() && !token.chars().any(char::is_whitespace),
        "enter a Cloudflare API token without whitespace");
    header::HeaderValue::from_str(token).context("invalid Cloudflare API token format")?;
    Ok(())
}

async fn request(client: &dyn HttpClient, method: Method, url: &str, token: Option<&str>, body: Option<Value>) -> Result<(http::StatusCode, Value)> {
    let mut req = http::Request::builder().method(method).uri(url)
        .header(header::ACCEPT, if token.is_some() { "application/json" } else { "application/dns-json" });
    if let Some(token) = token {
        let mut value = header::HeaderValue::from_str(&format!("Bearer {token}"))
            .context("invalid Cloudflare API token format")?;
        value.set_sensitive(true);
        req = req.header(header::AUTHORIZATION, value);
    }
    let bytes = if let Some(body) = body {
        req = req.header(header::CONTENT_TYPE, "application/json");
        serde_json::to_vec(&body)?
    } else { Vec::new() };
    let req = req.body(BodyWrapper::<Bytes>::from(bytes))?;
    let mut response = client.request(req).await?;
    let status = response.parts.status;
    let bytes = tokio::time::timeout(Duration::from_secs(30), response.body.into_bytes())
        .await.context("DNS service response timed out")?
        .map_err(|_| anyhow::anyhow!("could not read DNS service response"))?;
    let body = serde_json::from_slice(&bytes)
        .with_context(|| format!("DNS service returned an invalid response (HTTP {status})"))?;
    Ok((status, body))
}

fn result(status: http::StatusCode, body: Value, operation: &str) -> Result<Value> {
    if status.is_success() && body["success"].as_bool() == Some(true) {
        return Ok(body["result"].clone());
    }
    // API errors may echo supplied data. Expose status and stable error codes, never credentials.
    let codes: Vec<_> = body["errors"].as_array().into_iter().flatten()
        .filter_map(|error| error["code"].as_i64()).collect();
    bail!("Cloudflare {operation} failed (HTTP {status}, codes {codes:?}); check the API token's Zone Read and DNS Edit access and the challenge record");
}

async fn api(client: &dyn HttpClient, method: Method, path: &str, token: &str, body: Option<Value>, operation: &str) -> Result<Value> {
    let (status, response) = request(client, method, &format!("{API}{path}"), Some(token), body)
        .await.with_context(|| format!("Cloudflare {operation}"))?;
    result(status, response, operation)
}

fn id(value: &Value) -> Result<&str> {
    let id = value["id"].as_str().context("Cloudflare did not return an object ID")?;
    ensure!(id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()), "invalid Cloudflare object ID");
    Ok(id)
}

// Try the most specific zone first, including independently delegated subdomains.
fn zone_candidates(domain: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(domain), |name| name.split_once('.').map(|(_, suffix)| suffix))
        .take_while(|name| name.contains('.'))
}

async fn zone(client: &dyn HttpClient, domain: &str, token: &str) -> Result<String> {
    for name in zone_candidates(domain) {
        let zones = api(client, Method::GET, &format!("/zones?name={name}&status=active"), token, None, "zone lookup").await?;
        let matches: Vec<_> = zones.as_array().context("Cloudflare returned an invalid zone list")?.iter()
            .filter(|z| z["name"].as_str() == Some(name) && z["status"].as_str() == Some("active")).collect();
        match matches.as_slice() {
            [] => {}
            [z] => return Ok(id(z)?.to_owned()),
            _ => bail!("more than one active Cloudflare zone matches {name}"),
        }
    }
    bail!("no active Cloudflare DNS zone found for {domain}; check Zone Read access")
}

pub(super) struct Challenge {
    zone: String,
    record: String,
    name: String,
    value: String,
}

impl Challenge {
    pub(super) async fn create(client: &dyn HttpClient, domain: &str, value: String, token: &str) -> Result<Self> {
        let zone = zone(client, domain, token).await?;
        let name = format!("_acme-challenge.{domain}");
        let body = json!({"type":"TXT","name":name,"content":format!("\"{value}\""),"ttl":60});
        let response = api(client, Method::POST, &format!("/zones/{zone}/dns_records"), token, Some(body), "TXT creation").await
            .with_context(|| format!("could not create {name}; if the request was interrupted, inspect that name before retrying"))?;
        let record = id(&response)?.to_owned();
        Ok(Self { zone, record, name, value })
    }

    /// A cached ACME authorization says nothing about the new renewal token.
    /// Use the same challenge name and DNS lifecycle with a fresh, unrelated value.
    pub(super) async fn probe(client: &dyn HttpClient, domain: &str, token: &str) -> Result<Self> {
        let mut nonce = [0u8; 16];
        crate::dashboard::random_bytes(&mut nonce)?;
        Self::create(client, domain, format!("eztunnel-verify-{}", hex::encode(nonce)), token)
            .await.context("verify Cloudflare renewal credentials")
    }

    pub(super) async fn wait(&self, client: &dyn HttpClient) -> Result<()> {
        let start = tokio::time::Instant::now();
        let mut observation = "no DNS response yet".to_string();
        loop {
            let remaining = PROPAGATION_TIMEOUT.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                bail!("DNS-01 TXT record {} was not visible through public DNS within five minutes ({observation}); check delegation and propagation", self.name);
            }
            let url = format!("{RESOLVER}?name={}&type=TXT", self.name);
            let lookup = tokio::time::timeout(remaining, request(client, Method::GET, &url, None, None)).await;
            observation = match lookup {
                Ok(Ok((status, response))) if status.is_success() && visible(&response, &self.name, &self.value) => return Ok(()),
                Ok(Ok((status, response))) => format!("HTTP {status}, DNS status {}", response["Status"]),
                Ok(Err(error)) => format!("{error:#}"),
                Err(_) => "public DNS request timed out".to_string(),
            };
            tokio::time::sleep(Duration::from_secs(5).min(PROPAGATION_TIMEOUT.saturating_sub(start.elapsed()))).await;
        }
    }

    pub(super) async fn remove(self, client: &dyn HttpClient, token: &str) -> Result<()> {
        let path = format!("/zones/{}/dns_records/{}", self.zone, self.record);
        api(client, Method::DELETE, &path, token, None, "TXT cleanup").await
            .with_context(|| format!("remove only the temporary TXT record {} (record ID {})", self.name, self.record))?;
        Ok(())
    }
}

fn visible(response: &Value, name: &str, value: &str) -> bool {
    response["Status"].as_u64() == Some(0) && response["Answer"].as_array().into_iter().flatten().any(|answer| {
        answer["type"].as_u64() == Some(16)
            && answer["name"].as_str().is_some_and(|owner| owner.trim_end_matches('.').eq_ignore_ascii_case(name))
            && answer["data"].as_str().is_some_and(|data| data.trim_matches('"') == value)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zones_try_subdomains_before_parent() {
        assert_eq!(zone_candidates("panel.example.co.uk").collect::<Vec<_>>(), ["panel.example.co.uk", "example.co.uk", "co.uk"]);
    }
    #[test]
    fn txt_visibility_requires_exact_owner_and_value() {
        let name = "_acme-challenge.panel.example.com";
        let mut answer = json!({"Status":0,"Answer":[{"type":16,"name":format!("{name}."),"data":"\"another-order\""}]});
        assert!(!visible(&answer,name,"our-order"));
        answer["Answer"][0]["data"] = json!("\"our-order\"");
        assert!(visible(&answer,name,"our-order"));
        assert!(!visible(&answer,"_acme-challenge.other.example.com","our-order"));
        answer["Status"] = json!(3);
        assert!(!visible(&answer,name,"our-order"));
    }
    #[test]
    fn cloudflare_errors_do_not_echo_secrets() {
        let error = result(http::StatusCode::FORBIDDEN, json!({"success":false,"errors":[{"code":10000,"message":"secret-token"}]}), "zone lookup").unwrap_err().to_string();
        assert!(error.contains("10000") && !error.contains("secret-token"));
        assert!(validate_token(" ").is_err());
        assert!(validate_token("test-token").is_ok());
    }
}
