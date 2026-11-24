//! Deterministic ACME + Cloudflare provider interactions. The real instant-acme
//! order/authorization machinery runs against in-memory HTTP responses.
use super::*;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Full};
use serde_json::{Value, json};

const DOMAIN: &str = "panel.example.test";
const ZONE_ID: &str = "11111111111111111111111111111111";
const RECORD_ID: &str = "22222222222222222222222222222222";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Access {
    Revoked,
    NoZone,
    ReadOnly,
    Full,
    DeleteDenied,
}

#[derive(Default)]
struct Observed {
    dns_calls: Vec<String>,
    created: Option<String>,
    deleted: bool,
    ready: bool,
}

#[derive(Clone)]
struct Provider {
    access: Access,
    cached: bool,
    token: String,
    observed: Arc<Mutex<Observed>>,
}

impl Provider {
    fn new(access: Access, cached: bool, token: &str) -> Self {
        Self { access, cached, token: token.into(), observed: Arc::default() }
    }

    async fn order(&self) -> Order {
        let key = rcgen::KeyPair::generate().unwrap();
        let account = Account::builder_with_http(Box::new(self.clone()))
            .from_parts(
                "https://acme.invalid/account".into(),
                PrivatePkcs8KeyDer::from(key.serialize_der()),
                "https://acme.invalid/directory".into(),
            )
            .await.unwrap();
        account.new_order(&NewOrder::new(&[Identifier::Dns(DOMAIN.into())])).await.unwrap()
    }
}

impl HttpClient for Provider {
    fn request(&self, request: http::Request<BodyWrapper<Bytes>>)
        -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>>
    {
        let provider = self.clone();
        Box::pin(async move {
            let method = request.method().clone();
            let uri = request.uri().clone();
            let authorization = request.headers().get(http::header::AUTHORIZATION)
                .map(|v| v.to_str().unwrap().to_owned());
            let bytes = request.into_body().collect().await.unwrap().to_bytes();
            let mut state = provider.observed.lock().unwrap();
            let mut response_status = StatusCode::OK;
            let challenge = json!({
                "type":"dns-01", "status":"pending", "url":"https://acme.invalid/challenge",
                "token":"actual-acme-challenge"
            });
            let body = match (uri.host().unwrap(), uri.path(), &method) {
                ("acme.invalid", "/directory", &Method::GET) => json!({
                    "newNonce":"https://acme.invalid/nonce",
                    "newAccount":"https://acme.invalid/account",
                    "newOrder":"https://acme.invalid/new-order"
                }),
                ("acme.invalid", "/nonce", &Method::HEAD) => Value::Null,
                ("acme.invalid", "/new-order" | "/order", &Method::POST) => json!({
                    "status":if provider.cached || state.ready {"ready"} else {"pending"},
                    "authorizations":["https://acme.invalid/authorization"],
                    "finalize":"https://acme.invalid/finalize"
                }),
                ("acme.invalid", "/authorization", &Method::POST) => json!({
                    "identifier":{"type":"dns","value":DOMAIN},
                    "status":if provider.cached {"valid"} else {"pending"},
                    // A cached authorization may have come from HTTP-01 and
                    // offer no DNS challenge to set ready.
                    "challenges":if provider.cached {json!([])} else {json!([challenge])}
                }),
                ("acme.invalid", "/challenge", &Method::POST) => {
                    assert!(!provider.cached);
                    assert!(state.created.is_some() && !state.deleted);
                    state.ready = true;
                    let mut answer = challenge;
                    answer["status"] = json!("valid");
                    answer
                }
                ("api.cloudflare.com", "/client/v4/zones", &Method::GET) => {
                    assert_eq!(authorization.as_deref(), Some(format!("Bearer {}",provider.token).as_str()));
                    state.dns_calls.push("zone".into());
                    if provider.access == Access::Revoked {
                        response_status = StatusCode::UNAUTHORIZED;
                        json!({"success":false,"errors":[{"code":9109,"message":"revoked"}]})
                    } else {
                        let parent = uri.query().unwrap() == "name=example.test&status=active";
                        json!({"success":true,"result":if parent && provider.access != Access::NoZone {
                            json!([{"name":"example.test","status":"active","id":ZONE_ID}])
                        } else { json!([]) }})
                    }
                }
                ("api.cloudflare.com", path, &Method::POST)
                    if path == format!("/client/v4/zones/{ZONE_ID}/dns_records") =>
                {
                    assert_eq!(authorization.as_deref(), Some(format!("Bearer {}",provider.token).as_str()));
                    state.dns_calls.push("create".into());
                    if provider.access == Access::ReadOnly {
                        response_status = StatusCode::FORBIDDEN;
                        json!({"success":false,"errors":[{"code":10000,"message":"no DNS Edit"}]})
                    } else {
                        assert!(state.created.is_none(), "only one TXT record per order");
                        let form: Value = serde_json::from_slice(&bytes).unwrap();
                        assert_eq!(form["type"], "TXT");
                        assert_eq!(form["name"], format!("_acme-challenge.{DOMAIN}"));
                        let value = form["content"].as_str().unwrap().trim_matches('"').to_owned();
                        if provider.cached {
                            assert!(value.starts_with("eztunnel-verify-"));
                        } else {
                            assert!(!value.starts_with("eztunnel-verify-"));
                            assert_eq!(value.len(), 43);
                        }
                        state.created = Some(value);
                        json!({"success":true,"result":{"id":RECORD_ID}})
                    }
                }
                ("cloudflare-dns.com", "/dns-query", &Method::GET) => {
                    assert!(authorization.is_none(), "never forward provider tokens to DNS");
                    assert_eq!(uri.query().unwrap(), format!("name=_acme-challenge.{DOMAIN}&type=TXT"));
                    state.dns_calls.push("resolve".into());
                    assert!(!state.deleted);
                    let value = state.created.as_ref().unwrap();
                    json!({"Status":0,"Answer":[
                        {"type":16,"name":format!("_acme-challenge.{DOMAIN}."),"data":"\"unrelated\""},
                        {"type":16,"name":format!("_acme-challenge.{DOMAIN}."),"data":format!("\"{value}\"")}
                    ]})
                }
                ("api.cloudflare.com", path, &Method::DELETE)
                    if path == format!("/client/v4/zones/{ZONE_ID}/dns_records/{RECORD_ID}") =>
                {
                    assert_eq!(authorization.as_deref(), Some(format!("Bearer {}",provider.token).as_str()));
                    state.dns_calls.push("delete".into());
                    assert!(state.created.is_some() && !state.deleted);
                    if provider.access == Access::DeleteDenied {
                        response_status = StatusCode::FORBIDDEN;
                        json!({"success":false,"errors":[{"code":10000}]})
                    } else {
                        state.deleted = true;
                        json!({"success":true,"result":{"id":RECORD_ID}})
                    }
                }
                _ => panic!("unexpected mock request {method} {uri}"),
            };
            let response = http::Response::builder()
                .status(response_status)
                .header("Replay-Nonce","test-nonce")
                .header("Location","https://acme.invalid/order")
                .body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap()))).unwrap();
            Ok(BytesResponse::from(response))
        })
    }
}

fn settings(token: Option<&str>) -> AcmeSettings {
    AcmeSettings { address: DOMAIN.into(), staging: false, cloudflare_token: token.map(str::to_owned) }
}

fn fixture(dir: &Path, token: Option<&str>) -> (AcmeSettings, Issued) {
    let wanted = settings(token);
    let rcgen::CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(vec![DOMAIN.into()]).unwrap();
    let issued = Issued {
        chain: vec![CertificateDer::from(cert.der().as_ref().to_vec())],
        key: PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
    };
    super::super::save_settings(dir, &super::super::Settings {
        version: 1, port: 7177, password_hash: "unchanged".into(), created: 1,
        acme: Some(wanted.clone()),
        acme_certificate: Some(SavedCertificate::from_issued(&wanted, &issued).unwrap()),
    }).unwrap();
    (wanted, issued)
}

#[tokio::test]
async fn cached_authorization_rejects_revoked_unscoped_and_read_only_tokens_without_changing_settings() {
    for old_token in [None, Some("working-token")] {
        for (access, expected_calls, error_fragment) in [
            (Access::Revoked, vec!["zone"], "401"),
            (Access::NoZone, vec!["zone","zone"], "no active Cloudflare DNS zone"),
            (Access::ReadOnly, vec!["zone","zone","create"], "403"),
            (Access::DeleteDenied, vec!["zone","zone","create","resolve","delete"], "probe cleanup failed"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (previous, previous_issued) = fixture(dir.path(), old_token);
            let before = std::fs::read(dir.path().join("settings.json")).unwrap();
            let requested = settings(Some("replacement-token"));
            let provider = Provider::new(access, true, "replacement-token");
            let mut order = provider.order().await;
            let error = validate_order(&mut order, &requested, 0, IssuePurpose::Configure, &provider)
                .await.unwrap_err();
            let detail = format!("{error:#}");
            assert!(detail.contains(error_fragment), "{access:?}: {detail}");
            assert!(!detail.contains("replacement-token"));
            let observed = provider.observed.lock().unwrap();
            assert_eq!(observed.dns_calls, expected_calls);
            assert!(!observed.ready, "cached authorization is never re-triggered");
            assert_eq!(std::fs::read(dir.path().join("settings.json")).unwrap(), before);
            assert_eq!(super::super::load_settings(dir.path()).unwrap().acme, Some(previous.clone()));
            let loaded = load_for(dir.path(), &previous).unwrap();
            assert_eq!(loaded.chain, previous_issued.chain);
        }
    }
}

#[tokio::test]
async fn cached_authorization_validates_rotated_token_and_http_to_dns_transition() {
    for old_token in [None, Some("working-token")] {
        let dir = tempfile::tempdir().unwrap();
        let (previous, previous_issued) = fixture(dir.path(), old_token);
        let requested = settings(Some("rotated-token"));
        let provider = Provider::new(Access::Full, true, "rotated-token");
        let mut order = provider.order().await;
        validate_order(&mut order, &requested, 0, IssuePurpose::Configure, &provider).await.unwrap();
        {
            let observed = provider.observed.lock().unwrap();
            assert_eq!(observed.dns_calls, ["zone","zone","create","resolve","delete"]);
            assert!(observed.deleted);
            assert!(!observed.ready);
        }
        // Real configuration activation is separate from the network order.
        // Use the same atomic test persistence helper and an already-issued
        // certificate for the same domain to demonstrate the new selection.
        assert_eq!(super::super::load_settings(dir.path()).unwrap().acme, Some(previous));
        super::super::change_certificate_settings(dir.path(), Some((requested.clone(), &previous_issued))).unwrap();
        assert_eq!(super::super::load_settings(dir.path()).unwrap().acme, Some(requested.clone()));
        assert!(load_for(dir.path(), &requested).is_some());
    }
}

#[tokio::test]
async fn pending_dns_authorization_uses_real_challenge_without_an_extra_probe() {
    for purpose in [IssuePurpose::Configure, IssuePurpose::Renew] {
        let provider = Provider::new(Access::Full, false, "working-token");
        let mut order = provider.order().await;
        validate_order(&mut order, &settings(Some("working-token")), 0, purpose, &provider).await.unwrap();
        let observed = provider.observed.lock().unwrap();
        assert_eq!(observed.dns_calls, ["zone","zone","create","resolve","delete"]);
        assert!(observed.ready && observed.deleted);
    }
}

#[tokio::test]
async fn cached_scheduled_renewal_does_not_probe_or_replace_its_token() {
    let provider = Provider::new(Access::Full, true, "working-token");
    let mut order = provider.order().await;
    validate_order(&mut order, &settings(Some("working-token")), 0, IssuePurpose::Renew, &provider).await.unwrap();
    let observed = provider.observed.lock().unwrap();
    assert!(observed.dns_calls.is_empty());
    assert!(!observed.ready);
}
