//! Version-one Ed25519 challenge-response. No private client keys reach this module.
use anyhow::{bail, ensure, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use url::{Host, Url};
use y_sweet_core::auth::{b64_decode, b64_encode};

pub const CHALLENGE_TTL: u64 = 60;
pub const SESSION_TTL: u64 = 900;
const MAX_CHALLENGES: usize = 4096;
const MAX_SESSIONS: usize = 4096;

pub fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn decode<const N: usize>(s: &str) -> Result<[u8; N]> {
    ensure!(s.len() == (N * 8).div_ceil(6), "invalid encoding");
    let bytes = b64_decode(s)?;
    ensure!(b64_encode(&bytes) == s, "noncanonical encoding");
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid length"))
}

pub fn principal_id(key: &[u8; 32]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"freelay-principal-v1\0");
    hash.update(key);
    b64_encode(&hash.finalize())
}

pub fn canonical_url(input: &str) -> Result<String> {
    let mut url = Url::parse(input)?;
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "URL credentials forbidden"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "URL query/fragment forbidden"
    );
    let loopback = match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "HTTPS required"
    );
    let path = format!("{}/", url.path().trim_end_matches('/'));
    url.set_path(&path);
    Ok(url.to_string())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Challenge {
    pub version: u8,
    pub id: String,
    pub nonce: String,
    pub audience: String,
    pub public_key: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl Challenge {
    pub fn transcript(&self) -> Result<Vec<u8>> {
        ensure!(self.version == 1, "unsupported version");
        let mut bytes = b"freelay-auth-v1\0".to_vec();
        for field in [&self.audience, "session"] {
            bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
        bytes.extend_from_slice(&decode::<16>(&self.id)?);
        bytes.extend_from_slice(&decode::<32>(&self.nonce)?);
        bytes.extend_from_slice(&decode::<32>(&self.public_key)?);
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        Ok(bytes)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Proof {
    pub id: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone)]
pub struct Session {
    pub principal: String,
    pub public_key: String,
    pub expires_at: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    pub token: String,
    pub principal: String,
    pub expires_at: u64,
}

// Held under one short-lived mutex by the HTTP adapter; consume and replacement
// are atomic. Capacity never evicts a live session or an unexpired challenge.
pub struct Identity {
    audience: String,
    challenges: HashMap<String, Challenge>,
    sessions: HashMap<[u8; 32], Session>,
    window: u64,
    requests: u32,
}

impl Identity {
    pub fn new(audience: &str) -> Result<Self> {
        Ok(Self {
            audience: canonical_url(audience)?,
            challenges: HashMap::new(),
            sessions: HashMap::new(),
            window: 0,
            requests: 0,
        })
    }

    pub fn challenge(&mut self, public_key: &str, now: u64) -> Result<Challenge> {
        let key = VerifyingKey::from_bytes(&decode(public_key)?)?;
        ensure!(!key.is_weak(), "invalid public key");
        self.challenges.retain(|_, c| c.expires_at > now);
        if now / 60 != self.window {
            self.window = now / 60;
            self.requests = 0;
        }
        ensure!(
            self.requests < 120 && self.challenges.len() < MAX_CHALLENGES,
            "authentication rate limit"
        );
        self.requests += 1;
        let c = Challenge {
            version: 1,
            id: b64_encode(&random::<16>()),
            nonce: b64_encode(&random::<32>()),
            audience: self.audience.clone(),
            public_key: public_key.to_owned(),
            issued_at: now,
            expires_at: now + CHALLENGE_TTL,
        };
        self.challenges.insert(c.id.clone(), c.clone());
        Ok(c)
    }

    pub fn authenticate(
        &mut self,
        proof: Proof,
        previous: Option<&str>,
        now: u64,
    ) -> Result<SessionResponse> {
        let c = self
            .challenges
            .remove(&proof.id)
            .ok_or_else(|| anyhow::anyhow!("invalid challenge"))?;
        ensure!(
            c.issued_at <= now && now < c.expires_at && c.public_key == proof.public_key,
            "invalid challenge"
        );
        let public_key = decode::<32>(&proof.public_key)?;
        let key = VerifyingKey::from_bytes(&public_key)?;
        key.verify_strict(
            &c.transcript()?,
            &Signature::from_bytes(&decode(&proof.signature)?),
        )?;
        self.sessions.retain(|_, s| s.expires_at > now);
        let principal = principal_id(&public_key);
        if let Some(old) = previous {
            let digest = Self::session_hash(old)?;
            if let Some(s) = self.sessions.get(&digest) {
                ensure!(s.principal == principal, "session identity mismatch");
                self.sessions.remove(&digest);
            }
        }
        ensure!(self.sessions.len() < MAX_SESSIONS, "session capacity");
        let token = b64_encode(&random::<32>());
        let expires_at = now + SESSION_TTL;
        self.sessions.insert(
            Self::session_hash(&token)?,
            Session {
                principal: principal.clone(),
                public_key: proof.public_key,
                expires_at,
            },
        );
        Ok(SessionResponse {
            token,
            principal,
            expires_at,
        })
    }

    fn session_hash(token: &str) -> Result<[u8; 32]> {
        Ok(Sha256::digest(decode::<32>(token)?).into())
    }

    pub fn session(&self, token: &str, now: u64) -> Result<Session> {
        match self.sessions.get(&Self::session_hash(token)?) {
            Some(s) if s.expires_at > now => Ok(s.clone()),
            _ => bail!("invalid session"),
        }
    }

    pub fn logout(&mut self, token: &str) -> Result<()> {
        self.sessions.remove(&Self::session_hash(token)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn frozen_auth_v1_vector() -> Result<()> {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/auth-v1.json"))?;
        let c: Challenge = serde_json::from_value(vector["challenge"].clone())?;
        let key = SigningKey::from_bytes(&decode::<32>(vector["seed"].as_str().unwrap())?);
        assert_eq!(hex::encode(c.transcript()?), vector["transcript"]);
        assert_eq!(b64_encode(&key.verifying_key().to_bytes()), c.public_key);
        assert_eq!(
            principal_id(&key.verifying_key().to_bytes()),
            vector["principal"]
        );
        assert_eq!(
            b64_encode(&key.sign(&c.transcript()?).to_bytes()),
            vector["signature"]
        );
        key.verifying_key().verify_strict(
            &c.transcript()?,
            &Signature::from_bytes(&decode(vector["signature"].as_str().unwrap())?),
        )?;
        Ok(())
    }

    fn proof(c: &Challenge, key: &SigningKey) -> Proof {
        Proof {
            id: c.id.clone(),
            public_key: c.public_key.clone(),
            signature: b64_encode(&key.sign(&c.transcript().unwrap()).to_bytes()),
        }
    }

    #[test]
    fn single_use_expiry_refresh_and_restart() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let public = b64_encode(&key.verifying_key().to_bytes());
        let mut auth = Identity::new("https://example.test").unwrap();
        let c = auth.challenge(&public, 100).unwrap();
        let session = auth.authenticate(proof(&c, &key), None, 101).unwrap();
        assert!(auth.authenticate(proof(&c, &key), None, 101).is_err());
        assert!(auth.session(&session.token, 1001).is_err());
        let c = auth.challenge(&public, 102).unwrap();
        let next = auth
            .authenticate(proof(&c, &key), Some(&session.token), 103)
            .unwrap();
        assert!(auth.session(&session.token, 103).is_err());
        assert!(auth.session(&next.token, 103).is_ok());
        assert!(Identity::new("https://example.test")
            .unwrap()
            .session(&next.token, 103)
            .is_err());
        let c = auth.challenge(&public, 200).unwrap();
        assert!(auth.authenticate(proof(&c, &key), None, 260).is_err());
    }

    #[test]
    fn substitution_consumes_and_cross_server_signatures_fail() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut auth = Identity::new("https://example.test").unwrap();
        let c = auth
            .challenge(&b64_encode(&key.verifying_key().to_bytes()), 100)
            .unwrap();
        let mut altered = c.clone();
        altered.audience = "https://evil.test/".into();
        assert!(auth.authenticate(proof(&altered, &key), None, 101).is_err());
        assert!(auth.authenticate(proof(&c, &key), None, 101).is_err());
    }

    #[test]
    fn canonical_encodings_and_urls() {
        assert!(decode::<32>(&format!("{}=", b64_encode(&[0; 32]))).is_err());
        assert!(canonical_url("http://localhost/").is_err());
        assert!(canonical_url("https://user@example.test/").is_err());
        assert!(canonical_url("https://example.test/?secret=x").is_err());
        assert_eq!(
            canonical_url("HTTPS://EXAMPLE.test:443/base").unwrap(),
            "https://example.test/base/"
        );
        assert!(canonical_url("http://127.0.0.1:8080").is_ok());
    }
}
