//! Deezer audio source integration: catalog matching, stream resolution, and BF_CBC_STRIPE decryption.

use std::sync::Arc;
use std::time::Duration;

use blowfish::Blowfish;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
#[cfg(test)]
use cbc::cipher::BlockModeEncrypt;
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::model::Track;

pub const CHUNK_SIZE: usize = 2048;
pub const CHUNK_STRIDE: u64 = 3;
const SECRET: &[u8; 16] = b"g4el58wc0zvf9na1";
const IV: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

const GATEWAY_URL: &str = "https://www.deezer.com/ajax/gw-light.php";
const MEDIA_URL: &str = "https://media.deezer.com/v1/get_url";
const PUBLIC_API_URL: &str = "https://api.deezer.com";
pub const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
const TIMEOUT: Duration = Duration::from_secs(8);

type BfCbcDec = cbc::Decryptor<Blowfish>;
#[cfg(test)]
type BfCbcEnc = cbc::Encryptor<Blowfish>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeezerTier {
    HiFi,
    Premium,
    Free,
}

impl DeezerTier {
    pub fn label(&self) -> &'static str {
        match self {
            Self::HiFi => "HiFi (FLAC)",
            Self::Premium => "Premium (320 kbps)",
            Self::Free => "Free (128 kbps)",
        }
    }

    pub fn can_stream_lossless(&self) -> bool {
        matches!(self, Self::HiFi)
    }

    pub fn can_stream_hq(&self) -> bool {
        matches!(self, Self::HiFi | Self::Premium)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeezerSession {
    pub arl: String,
    pub sid: String,
    pub api_token: String,
    pub license_token: String,
    pub user_id: u64,
    pub user_name: String,
    pub tier: DeezerTier,
}

/// Derive the 16-byte Blowfish key for a Deezer track ID.
pub fn derive_key(track_id: &str) -> [u8; 16] {
    let clean_id = track_id.trim();
    let mut hasher = Md5::new();
    hasher.update(clean_id.as_bytes());
    let md5_bytes = hasher.finalize();
    let md5_hex = format!("{:032x}", md5_bytes);
    let hex_bytes = md5_hex.as_bytes();

    let mut key = [0u8; 16];
    for i in 0..16 {
        key[i] = hex_bytes[i] ^ hex_bytes[i + 16] ^ SECRET[i];
    }
    key
}

/// Decrypt one 2048-byte chunk in place.
pub fn decrypt_chunk(key: &[u8; 16], buffer: &mut [u8]) {
    if buffer.len() < CHUNK_SIZE {
        return;
    }
    let mut dec = BfCbcDec::new_from_slices(key, &IV).expect("valid blowfish key/iv");
    let inout = cbc::cipher::inout::InOutBuf::from(&mut buffer[..CHUNK_SIZE]);
    let (chunks, _) = inout.into_chunks();
    dec.decrypt_blocks_inout(chunks);
}

/// Encrypt one 2048-byte chunk in place (used for test fixtures).
#[cfg(test)]
pub fn encrypt_chunk(key: &[u8; 16], buffer: &mut [u8]) {
    if buffer.len() < CHUNK_SIZE {
        return;
    }
    let mut enc = BfCbcEnc::new_from_slices(key, &IV).expect("valid blowfish key/iv");
    let inout = cbc::cipher::inout::InOutBuf::from(&mut buffer[..CHUNK_SIZE]);
    let (chunks, _) = inout.into_chunks();
    enc.encrypt_blocks_inout(chunks);
}

/// Decrypt an entire stream or slice in place according to Deezer's BF_CBC_STRIPE rules.
/// `start_offset` is the global byte offset of this slice (aligned to 2048-byte chunks for ranges).
pub fn decrypt_stream_slice(key: &[u8; 16], data: &mut [u8], start_offset: u64) {
    let mut chunk_idx = start_offset / CHUNK_SIZE as u64;
    let mut offset = 0;
    while offset + CHUNK_SIZE <= data.len() {
        if chunk_idx % CHUNK_STRIDE == 0 {
            decrypt_chunk(key, &mut data[offset..offset + CHUNK_SIZE]);
        }
        chunk_idx += 1;
        offset += CHUNK_SIZE;
    }
}

pub fn parse_user_data_session(raw: &Value, arl: &str, cookie_sid: Option<&str>) -> anyhow::Result<DeezerSession> {
    if let Some(err) = raw.get("error").and_then(Value::as_object).filter(|o| !o.is_empty()) {
        let msg = err.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join(", ");
        anyhow::bail!("Deezer gateway error: {msg}");
    }
    let results = raw.get("results").and_then(Value::as_object).ok_or_else(|| anyhow::anyhow!("Missing results"))?;
    let user = results.get("USER").and_then(Value::as_object);
    let user_id = user.and_then(|u| u.get("USER_ID")).or_else(|| results.get("USER_ID"))
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(0);
    if user_id == 0 {
        anyhow::bail!("ARL token is invalid or expired (USER_ID is 0)");
    }

    let user_name = user.and_then(|u| u.get("BLOG_NAME").or_else(|| u.get("FIRSTNAME")))
        .and_then(Value::as_str)
        .unwrap_or("Deezer User")
        .to_owned();

    let options = user.and_then(|u| u.get("OPTIONS")).or_else(|| results.get("OPTIONS")).and_then(Value::as_object);
    let can_lossless = options.map_or(false, |o| {
        o.get("web_lossless").is_some_and(|v| v == true || v == "true" || v == 1)
            || o.get("mobile_lossless").is_some_and(|v| v == true || v == "true" || v == 1)
    });
    let can_hq = can_lossless || options.map_or(false, |o| {
        o.get("web_hq").is_some_and(|v| v == true || v == "true" || v == 1)
            || o.get("mobile_hq").is_some_and(|v| v == true || v == "true" || v == 1)
    });

    let tier = if can_lossless {
        DeezerTier::HiFi
    } else if can_hq {
        DeezerTier::Premium
    } else {
        DeezerTier::Free
    };

    let sid = results.get("SESSION_ID").or_else(|| results.get("SESSION"))
        .and_then(Value::as_str)
        .or(cookie_sid)
        .unwrap_or_default()
        .to_owned();

    let api_token = results.get("checkForm").or_else(|| results.get("CHECKFORM"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();

    let license_token = options.and_then(|o| o.get("license_token")).or_else(|| results.get("PLAYER_TOKEN"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();

    Ok(DeezerSession {
        arl: arl.trim().to_owned(),
        sid,
        api_token,
        license_token,
        user_id,
        user_name,
        tier,
    })
}

/// Validate a Deezer ARL token with the gateway.
pub async fn validate_arl(http: &reqwest::Client, arl: &str) -> anyhow::Result<DeezerSession> {
    let clean_arl = arl.trim();
    anyhow::ensure!(!clean_arl.is_empty(), "ARL token cannot be empty");

    let url = format!("{GATEWAY_URL}?method=deezer.getUserData&input=3&api_version=1.0&api_token=null");
    let resp = http.post(&url)
        .header("User-Agent", USER_AGENT)
        .header("Cookie", format!("arl={clean_arl}"))
        .header("Content-Type", "application/json")
        .body("{}")
        .timeout(TIMEOUT)
        .send()
        .await?
        .error_for_status()?;

    let cookie_sid = resp.headers().get_all(reqwest::header::SET_COOKIE).iter().find_map(|h| {
        h.to_str().ok().and_then(extract_sid_from_cookie)
    });
    let raw: Value = resp.json().await?;
    let mut session = parse_user_data_session(&raw, clean_arl, cookie_sid.as_deref())?;

    // If sid or license_token is missing, try deezer.page.getUserData
    if session.license_token.is_empty() || session.api_token.is_empty() {
        let page_url = format!("{GATEWAY_URL}?method=deezer.page.getUserData&input=3&api_version=1.0&api_token={}", if session.api_token.is_empty() { "null" } else { &session.api_token });
        let cookie = if session.sid.is_empty() { format!("arl={clean_arl}") } else { format!("arl={clean_arl}; sid={}", session.sid) };
        if let Ok(page_resp) = http.post(&page_url)
            .header("User-Agent", USER_AGENT)
            .header("Cookie", cookie)
            .header("Content-Type", "application/json")
            .body("{}")
            .timeout(TIMEOUT)
            .send()
            .await
        {
            let page_cookie_sid = page_resp.headers().get_all(reqwest::header::SET_COOKIE).iter().find_map(|h| {
                h.to_str().ok().and_then(extract_sid_from_cookie)
            });
            if let Ok(page_raw) = page_resp.json::<Value>().await {
                if let Ok(page_sess) = parse_user_data_session(&page_raw, clean_arl, page_cookie_sid.as_deref()) {
                    if session.license_token.is_empty() && !page_sess.license_token.is_empty() {
                        session.license_token = page_sess.license_token;
                    }
                    if session.api_token.is_empty() && !page_sess.api_token.is_empty() {
                        session.api_token = page_sess.api_token;
                    }
                    if session.sid.is_empty() && !page_sess.sid.is_empty() {
                        session.sid = page_sess.sid;
                    }
                }
            }
        }
    }

    Ok(session)
}

#[derive(Clone, Debug)]
pub struct DeezerStream {
    pub id: String,
    pub url: String,
    pub size: u64,
    pub duration_ms: u64,
    pub format: crate::stream::Format,
    pub info: crate::hires::Info,
    pub encrypted: bool,
}

pub struct DeezerClient {
    session: tokio::sync::RwLock<DeezerSession>,
}

impl DeezerClient {
    pub fn new(session: DeezerSession) -> Arc<Self> {
        Arc::new(Self { session: tokio::sync::RwLock::new(session) })
    }

    pub async fn session(&self) -> DeezerSession {
        self.session.read().await.clone()
    }

    /// Search Deezer and match the track to find its Deezer stream.
    pub async fn find(&self, http: &reqwest::Client, track: &Track) -> anyhow::Result<Option<DeezerStream>> {
        let session = self.session().await;
        let artist = track.artists.first().map(|a| a.name.as_str()).unwrap_or("");
        let query = if artist.is_empty() {
            track.title.clone()
        } else {
            format!("{} {}", track.title, artist)
        };

        // 1. Search Deezer catalog
        let search_url = format!("{PUBLIC_API_URL}/search/track?q={}&limit=10", urlencoding(&query));
        let search_resp = http.get(&search_url)
            .header("User-Agent", USER_AGENT)
            .timeout(TIMEOUT)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;

        let tracks = search_resp.get("data").and_then(Value::as_array).cloned().unwrap_or_default();
        if tracks.is_empty() {
            return Ok(None);
        }

        // Rank candidates
        let mut best: Option<(u64, String, u32, bool)> = None;
        let norm_title = normalize(&track.title);
        let track_dur = track.duration.unwrap_or(0);

        for item in &tracks {
            let id = match item.get("id") {
                Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
                Some(Value::String(s)) => s.parse().unwrap_or(0),
                _ => 0,
            };
            if id == 0 {
                continue;
            }
            let title = item.get("title").and_then(Value::as_str).unwrap_or("");
            let dur = item.get("duration").and_then(Value::as_u64).unwrap_or(0) as u32;
            let explicit = item.get("explicit_lyrics").and_then(Value::as_bool).unwrap_or(false);

            let cand_norm = normalize(title);
            let title_match = cand_norm == norm_title
                || cand_norm.starts_with(&norm_title)
                || norm_title.starts_with(&cand_norm);

            let dur_diff = if track_dur > 0 && dur > 0 {
                track_dur.abs_diff(dur)
            } else {
                0
            };

            if title_match && dur_diff <= 12 {
                // Good match found
                best = Some((id, title.to_owned(), dur, explicit));
                break;
            } else if best.is_none() && title_match {
                best = Some((id, title.to_owned(), dur, explicit));
            }
        }

        let Some((track_id, _title, duration_sec, _)) = best else {
            return Ok(None);
        };

        // 2. Resolve stream URL via song.getData + media.get_url
        let sng_id_str = track_id.to_string();
        let gw_url = format!("{GATEWAY_URL}?method=song.getData&input=3&api_version=1.0&api_token={}", session.api_token);
        let gw_resp: Value = http.post(&gw_url)
            .header("User-Agent", USER_AGENT)
            .header("Cookie", format!("arl={}; sid={}", session.arl, session.sid))
            .header("Content-Type", "application/json")
            .json(&json!({ "SNG_ID": sng_id_str }))
            .timeout(TIMEOUT)
            .send()
            .await?
            .json()
            .await?;

        let song_results = gw_resp.get("results").and_then(Value::as_object);
        let track_token = song_results
            .and_then(|r| r.get("TRACK_TOKEN").or_else(|| r.get("DATA").and_then(|d| d.get("TRACK_TOKEN"))))
            .and_then(Value::as_str);

        let Some(track_token) = track_token else {
            return Ok(None);
        };

        let requested_formats = if session.tier.can_stream_lossless() {
            vec!["FLAC", "MP3_320", "MP3_128"]
        } else if session.tier.can_stream_hq() {
            vec!["MP3_320", "MP3_128"]
        } else {
            vec!["MP3_128"]
        };

        let media_payload = json!({
            "license_token": session.license_token,
            "media": [{
                "type": "FULL",
                "formats": requested_formats.iter().map(|fmt| json!({ "cipher": "BF_CBC_STRIPE", "format": fmt })).collect::<Vec<_>>()
            }],
            "track_tokens": [track_token]
        });

        let media_resp: Value = http.post(MEDIA_URL)
            .header("User-Agent", USER_AGENT)
            .header("Content-Type", "application/json")
            .json(&media_payload)
            .timeout(TIMEOUT)
            .send()
            .await?
            .json()
            .await?;

        let media_arr = media_resp.get("data").and_then(Value::as_array)
            .and_then(|d| d.first())
            .and_then(|d| d.get("media"))
            .and_then(Value::as_array);

        let Some(media_list) = media_arr else {
            return Ok(None);
        };

        let mut candidate_stream = None;
        for target_fmt in requested_formats {
            for m in media_list {
                let fmt = m.get("format").and_then(Value::as_str).unwrap_or("");
                if fmt.eq_ignore_ascii_case(target_fmt) {
                    let cipher_type = m.get("cipher").and_then(|c| c.get("type")).and_then(Value::as_str);
                    let encrypted = cipher_type.is_none_or(|t| t.eq_ignore_ascii_case("BF_CBC_STRIPE"));
                    let stream_url = m.get("sources").and_then(Value::as_array)
                        .and_then(|s| s.first())
                        .and_then(|s| s.get("url"))
                        .and_then(Value::as_str);
                    if let Some(u) = stream_url {
                        candidate_stream = Some((fmt.to_owned(), u.to_owned(), encrypted));
                        break;
                    }
                }
            }
            if candidate_stream.is_some() {
                break;
            }
        }

        let Some((fmt, url, encrypted)) = candidate_stream else {
            return Ok(None);
        };

        let is_flac = fmt.eq_ignore_ascii_case("FLAC");
        let format = if is_flac {
            crate::stream::Format::File { hint: "flac", mime: Some("audio/flac".to_owned()) }
        } else {
            crate::stream::Format::File { hint: "mp3", mime: Some("audio/mpeg".to_owned()) }
        };

        let info = crate::hires::Info {
            source: "Deezer".to_owned(),
            host: "deezer.com".to_owned(),
            codec: if is_flac { "FLAC".to_owned() } else { "MP3".to_owned() },
            quality: if is_flac { "LOSSLESS".to_owned() } else { "HIGH".to_owned() },
            bitrate_kbps: if is_flac { None } else if fmt.contains("320") { Some(320) } else { Some(128) },
            sample_rate: Some(44_100),
            bit_depth: if is_flac { Some(16) } else { None },
            channels: Some(2),
            atmos: false,
            size: crate::hires::UNKNOWN_SIZE,
            duration_ms: (duration_sec as u64) * 1000,
        };

        // Probe size
        let size = match http.head(&url).header("User-Agent", USER_AGENT).send().await {
            Ok(r) if r.status().is_success() => r.content_length().unwrap_or(crate::hires::UNKNOWN_SIZE),
            _ => crate::hires::UNKNOWN_SIZE,
        };

        Ok(Some(DeezerStream {
            id: sng_id_str,
            url,
            size,
            duration_ms: (duration_sec as u64) * 1000,
            format,
            info,
            encrypted,
        }))
    }
}

fn extract_sid_from_cookie(s: &str) -> Option<String> {
    for part in s.split(';') {
        let mut kv = part.trim().splitn(2, '=');
        if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
            if k.eq_ignore_ascii_case("sid") && !v.is_empty() && v != "deleted" {
                return Some(v.to_owned());
            }
        }
    }
    None
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn normalize(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace())
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key() {
        let key = derive_key("3135556");
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let track_id = "3135556";
        let key = derive_key(track_id);

        let total_size = 7 * CHUNK_SIZE + 519;
        let mut original = vec![0u8; total_size];
        for (i, b) in original.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }

        let mut wire = original.clone();
        for chunk_idx in 0..7usize {
            if (chunk_idx as u64) % CHUNK_STRIDE == 0 {
                encrypt_chunk(&key, &mut wire[chunk_idx * CHUNK_SIZE..]);
            }
        }

        // Chunk 0 must differ, chunk 1 must be identical, chunk 3 must differ, trailing must be identical
        assert_ne!(&original[0..2048], &wire[0..2048]);
        assert_eq!(&original[2048..4096], &wire[2048..4096]);
        assert_ne!(&original[3 * 2048..4 * 2048], &wire[3 * 2048..4 * 2048]);
        assert_eq!(&original[7 * 2048..total_size], &wire[7 * 2048..total_size]);

        // Decrypt stream slice
        decrypt_stream_slice(&key, &mut wire, 0);
        assert_eq!(original, wire);
    }

    #[test]
    fn test_parse_user_data_session() {
        let raw = json!({
            "error": [],
            "results": {
                "SESSION_ID": "sid_hifi_123",
                "checkForm": "token_abc_999",
                "USER": {
                    "USER_ID": 424242,
                    "BLOG_NAME": "AudiophileUser",
                    "OPTIONS": {
                        "license_token": "lic_xyz_777",
                        "web_lossless": true,
                        "mobile_lossless": true,
                        "web_hq": true
                    }
                }
            }
        });

        let session = parse_user_data_session(&raw, "arl_secret_token", None).unwrap();
        assert_eq!(session.arl, "arl_secret_token");
        assert_eq!(session.sid, "sid_hifi_123");
        assert_eq!(session.api_token, "token_abc_999");
        assert_eq!(session.license_token, "lic_xyz_777");
        assert_eq!(session.user_id, 424242);
        assert_eq!(session.user_name, "AudiophileUser");
        assert_eq!(session.tier, DeezerTier::HiFi);
        assert!(session.tier.can_stream_lossless());
        assert!(session.tier.can_stream_hq());
    }

    #[test]
    fn test_parse_premium_and_free_tiers() {
        let premium_json = json!({
            "error": [],
            "results": {
                "SESSION": "sid_prem",
                "CHECKFORM": "tok_prem",
                "USER": {
                    "USER_ID": 1001,
                    "FIRSTNAME": "PremUser",
                    "OPTIONS": {
                        "license_token": "lic_prem",
                        "web_lossless": false,
                        "mobile_lossless": false,
                        "web_hq": true
                    }
                }
            }
        });
        let prem_res = parse_user_data_session(&premium_json, "arl_prem", None).unwrap();
        assert_eq!(prem_res.tier, DeezerTier::Premium);

        let free_json = json!({
            "error": [],
            "results": {
                "USER": {
                    "USER_ID": 1002,
                    "OPTIONS": {
                        "license_token": "lic_free",
                        "web_lossless": false,
                        "web_hq": false
                    }
                }
            }
        });
        let free_res = parse_user_data_session(&free_json, "arl_free", Some("sid_cookie")).unwrap();
        assert_eq!(free_res.tier, DeezerTier::Free);
        assert_eq!(free_res.sid, "sid_cookie");
    }
}
