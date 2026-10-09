//! Process-local capability key, using the existing CWT wire format/verifier.
use super::{
    identity::{canonical_url, random},
    metadata::canonical_uuid,
};
use anyhow::{ensure, Result};
use y_sweet_core::{
    auth::{b64_encode, Authenticator},
    config::{AuthKeyConfig, TokenType},
    cwt::{CwtAuthenticator, CwtClaims},
};

pub struct TokenIssuer {
    signer: CwtAuthenticator,
    verifier: Authenticator,
    audience: String,
    ttl: u64,
}

impl TokenIssuer {
    pub fn new(audience: &str, ttl: u64) -> Result<Self> {
        ensure!(
            (60..=3600).contains(&ttl),
            "data token TTL must be 60..3600 seconds"
        );
        let audience = canonical_url(audience)?;
        let key = random::<32>();
        let kid = b64_encode(&random::<16>());
        let signer = CwtAuthenticator::new_symmetric(&key, Some(kid.clone()))?;
        let mut verifier = Authenticator::from_multi_key_config(&[AuthKeyConfig {
            key_id: Some(kid),
            private_key: Some(b64_encode(&key)),
            public_key: None,
            allowed_token_types: vec![TokenType::Document, TokenType::File],
        }])?;
        verifier.set_expected_audience(Some(audience.clone()));
        Ok(Self {
            signer,
            verifier,
            audience,
            ttl,
        })
    }

    pub fn verifier(&self) -> Authenticator {
        self.verifier.clone()
    }

    pub fn file(
        &self,
        relay: &str,
        folder: &str,
        guid: &str,
        hash: &str,
        content_type: &str,
        length: u64,
        principal: &str,
        write: bool,
        now: u64,
    ) -> Result<serde_json::Value> {
        canonical_uuid(relay)?;
        canonical_uuid(folder)?;
        canonical_uuid(guid)?;
        ensure!(
            y_sweet_core::api_types::validate_file_hash(hash),
            "invalid file hash"
        );
        ensure!(
            content_type.len() <= 200 && !content_type.contains(['\r', '\n']),
            "invalid content type"
        );
        let id = format!("{relay}-{guid}");
        let scope = format!(
            "file:{hash}:{id}:{}:{length}:{}",
            if write { "rw" } else { "r" },
            b64_encode(content_type.as_bytes())
        );
        let expires = now + self.ttl;
        let mac0 = self.signer.create_cwt_mac0_with_alg(
            CwtClaims {
                issuer: Some("relay-server".into()),
                subject: Some(principal.to_owned()),
                audience: Some(self.audience.clone()),
                expiration: Some(expires),
                issued_at: Some(now),
                scope,
                channel: Some(format!("{relay}-{folder}")),
            },
            coset::iana::Algorithm::HMAC_256_256,
        )?;
        let cose: ciborium::Value = ciborium::from_reader(&mac0[..])?;
        let mut encoded = Vec::new();
        ciborium::into_writer(&ciborium::Value::Tag(61, Box::new(cose)), &mut encoded)?;
        Ok(
            serde_json::json!({"url":format!("{}f/{id}",self.audience),"baseUrl":format!("{}f/{id}",self.audience),"docId":id,"folder":folder,"token":b64_encode(&encoded),"authorization":if write {"full"} else {"read-only"},"expiryTime":expires*1000,"fileHash":hash,"contentType":content_type,"contentLength":length}),
        )
    }

    /// Call only with a transactionally authorized, immutable folder binding.
    pub fn document(
        &self,
        relay: &str,
        folder: &str,
        guid: &str,
        principal: &str,
        write: bool,
        now: u64,
    ) -> Result<serde_json::Value> {
        canonical_uuid(relay)?;
        canonical_uuid(folder)?;
        canonical_uuid(guid)?;
        let id = format!("{relay}-{guid}");
        let scope = format!("doc:{id}:{}", if write { "rw" } else { "r" });
        let expires = now + self.ttl;
        let mac0 = self.signer.create_cwt_mac0_with_alg(
            CwtClaims {
                // Compatibility identifier accepted by the upstream verifier.
                issuer: Some("relay-server".into()),
                subject: Some(principal.to_owned()),
                audience: Some(self.audience.clone()),
                expiration: Some(expires),
                issued_at: Some(now),
                scope,
                channel: if folder == guid {
                    None
                } else {
                    Some(format!("{relay}-{folder}"))
                },
            },
            coset::iana::Algorithm::HMAC_256_256,
        )?;
        let cose: ciborium::Value = ciborium::from_reader(&mac0[..])?;
        let mut encoded = Vec::new();
        ciborium::into_writer(&ciborium::Value::Tag(61, Box::new(cose)), &mut encoded)?;
        let token = b64_encode(&encoded);
        let base = format!("{}d/{id}", self.audience);
        let mut ws = url::Url::parse(&format!("{base}/ws"))?;
        let scheme = if ws.scheme() == "https" { "wss" } else { "ws" };
        ws.set_scheme(scheme)
            .map_err(|_| anyhow::anyhow!("invalid websocket URL"))?;
        Ok(
            serde_json::json!({"url":ws.as_str(),"baseUrl":base,"docId":id,"folder":folder,"token":token,"authorization":if write {"full"} else {"read-only"},"expiryTime":expires*1000}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::CborSerializable;
    const RELAY: &str = "11111111-1111-4111-8111-111111111111";
    const FOLDER: &str = "22222222-2222-4222-8222-222222222222";
    const DOC: &str = "33333333-3333-4333-8333-333333333333";

    #[test]
    fn file_metadata_survives_cwt_verification() -> Result<()> {
        let issuer = TokenIssuer::new("https://example.test", 900)?;
        let response = issuer.file(
            RELAY,
            FOLDER,
            DOC,
            &"a".repeat(64),
            "application/octet-stream",
            123,
            "alice",
            true,
            100,
        )?;
        let token = response["token"].as_str().unwrap();
        let permission = issuer.verifier.verify_token_auto(token, 101000)?;
        let y_sweet_core::auth::Permission::File(file) = permission else {
            panic!("expected file permission")
        };
        assert_eq!(file.doc_id, format!("{RELAY}-{DOC}"));
        assert_eq!(file.content_length, Some(123));
        assert_eq!(
            file.content_type.as_deref(),
            Some("application/octet-stream")
        );
        assert!(issuer
            .file(
                RELAY,
                FOLDER,
                DOC,
                "invalid",
                "text/plain",
                123,
                "alice",
                true,
                100
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn full_tag_matches_upstream_verifier_and_expires() -> Result<()> {
        let issuer = TokenIssuer::new("https://example.test", 900)?;
        let response = issuer.document(RELAY, FOLDER, DOC, "alice", true, 100)?;
        let token = response["token"].as_str().unwrap();
        let id = format!("{RELAY}-{DOC}");
        issuer.verifier.verify_doc_token(token, &id, 101000)?;
        assert!(issuer
            .verifier
            .verify_doc_token(token, &id, 1001000)
            .is_err());
        assert!(issuer
            .verifier
            .verify_doc_token(token, &format!("{RELAY}-{FOLDER}"), 101000)
            .is_err());
        assert!(issuer.verifier.verify_server_token(token, 101000).is_err());
        let (_, channel) = issuer.verifier.verify_token_with_channel(token, 101000)?;
        assert_eq!(channel, Some(format!("{RELAY}-{FOLDER}")));
        let bytes = y_sweet_core::auth::b64_decode(token)?;
        let tagged: ciborium::Value = ciborium::from_reader(&bytes[..])?;
        let ciborium::Value::Tag(61, cose) = tagged else {
            panic!("expected CWT")
        };
        let ciborium::Value::Tag(17, mac) = *cose else {
            panic!("expected COSE_Mac0")
        };
        let mut encoded = Vec::new();
        ciborium::into_writer(&mac, &mut encoded)?;
        assert_eq!(coset::CoseMac0::from_slice(&encoded).unwrap().tag.len(), 32);
        let restarted = TokenIssuer::new("https://example.test", 900)?;
        assert!(restarted
            .verifier
            .verify_doc_token(token, &id, 101000)
            .is_err());
        Ok(())
    }
}
