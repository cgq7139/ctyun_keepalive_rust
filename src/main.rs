use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
use chrono::Local;
use futures_util::SinkExt;
use futures_util::StreamExt;
use hex::ToHex;
use md5::{Md5, Digest};
use num_bigint::BigUint;
use num_traits::Zero;
use rand::Rng;
use reqwest::{Client, multipart};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;
use sysinfo::Networks;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use urlencoding::encode;



fn get_system_fingerprint() -> String {
    let networks = Networks::new_with_refreshed_list();
    let mac_address = networks
        .iter()
        .next()
        .map(|(_, net)| net.mac_address().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    
    let fingerprint = mac_address;
    
    let mut hasher = Sha256::new();
    hasher.update(fingerprint.as_bytes());
    hasher.finalize().to_vec().encode_hex::<String>()
}

fn generate_salt() -> String {
    let mut rng = rand::thread_rng();
    let mut salt = [0u8; 16];
    rng.fill(&mut salt);
    salt.encode_hex::<String>()
}

fn derive_key(system_fingerprint: &str, salt: &str) -> Result<[u8; 32]> {
    let key_material = format!("{}|{}", system_fingerprint, salt);
    let mut hasher = Sha256::new();
    hasher.update(key_material.as_bytes());
    let hash = hasher.finalize();
    
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    Ok(key)
}

fn encrypt_data(plaintext: &str, key: &[u8; 32]) -> Result<String> {
    let cipher = ChaCha20Poly1305::new(key.into());
    
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;
    
    let mut result = Vec::new();
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    
    Ok(STANDARD.encode(&result))
}

fn decrypt_data(ciphertext_b64: &str, key: &[u8; 32]) -> Result<String> {
    match STANDARD.decode(ciphertext_b64) {
        Ok(data) => {
            if data.len() < 12 {
                return Err(anyhow!("Invalid ciphertext: too short"));
            }
            
            let nonce_bytes = &data[0..12];
            let ciphertext = &data[12..];
            
            let cipher = ChaCha20Poly1305::new(key.into());
            let nonce = Nonce::from_slice(nonce_bytes);
            
            match cipher.decrypt(nonce, ciphertext) {
                Ok(plaintext) => {
                    match String::from_utf8(plaintext) {
                        Ok(s) => Ok(s),
                        Err(e) => Err(anyhow!("UTF-8 decode failed: {}", e))
                    }
                }
                Err(e) => Err(anyhow!("Decryption failed: {}", e))
            }
        }
        Err(e) => Err(anyhow!("Base64 decode failed: {}", e))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Account {
    #[serde(rename = "user_account")]
    user_account: String,
    #[serde(rename = "password")]
    password: String,
    #[serde(rename = "device_code")]
    device_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccountsFile {
    salt: String,
    accounts: Vec<Account>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginInfo {
    user_account: String,
    bonded_device: bool,
    secret_key: String,
    user_id: i32,
    tenant_id: i32,
    user_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DesktopInfo {
    desktop_id: i32,
    host: String,
    port: String,
    clink_lvs_out_host: String,
    ca_cert: String,
    client_cert: String,
    client_key: String,
    token: String,
    tenant_member_account: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Desktop {
    desktop_id: String,
    desktop_name: String,
    desktop_code: String,
    use_status_text: String,
    desktop_info: Option<DesktopInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResultBase<T> {
    code: i32,
    #[serde(default)]
    msg: String,
    data: Option<T>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeData {
    challenge_id: String,
    challenge_code: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientInfo {
    desktop_list: Vec<Desktop>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectInfo {
    desktop_info: DesktopInfo,
}

#[derive(Debug, Clone)]
struct SendInfo {
    type_val: i32,
    data: Vec<u8>,
}

impl SendInfo {
    fn to_buffer(&self, is_build_msg: bool) -> Vec<u8> {
        let msg_length = if is_build_msg { 8 } else { 0 };
        let data_length = self.data.len();
        let size = msg_length + data_length;
        let mut buffer = vec![0u8; 2 + 4 + msg_length + data_length];

        buffer[0..2].copy_from_slice(&(self.type_val as u16).to_le_bytes());
        buffer[2..6].copy_from_slice(&(size as u32).to_le_bytes());

        if is_build_msg {
            buffer[6..10].copy_from_slice(&(data_length as u32).to_le_bytes());
            buffer[10..14].copy_from_slice(&8u32.to_le_bytes());
        }

        if data_length > 0 {
            buffer[6 + msg_length..].copy_from_slice(&self.data);
        }

        buffer
    }

    fn from_buffer(buffer: &[u8]) -> Vec<Self> {
        let mut results = Vec::new();
        if buffer.is_empty() {
            return results;
        }

        let mut offset = 0;
        while offset + 6 <= buffer.len() {
            let type_val = u16::from_le_bytes([buffer[offset], buffer[offset + 1]]) as i32;
            let data_length = i32::from_le_bytes([
                buffer[offset + 2],
                buffer[offset + 3],
                buffer[offset + 4],
                buffer[offset + 5],
            ]);

            if data_length < 0 || offset + 6 + data_length as usize > buffer.len() {
                let remaining = buffer.len() - offset;
                if remaining > 0 {
                    let data = buffer[offset..].to_vec();
                    results.push(SendInfo { type_val, data });
                }
                break;
            }

            let data = if data_length > 0 {
                buffer[offset + 6..offset + 6 + data_length as usize].to_vec()
            } else {
                Vec::new()
            };

            results.push(SendInfo { type_val, data });
            offset += 6 + data_length as usize;

            if offset + 6 > buffer.len() && offset < buffer.len() {
                let all_zero = buffer[offset..].iter().all(|&b| b == 0);
                if all_zero {
                    break;
                }
            }
        }

        results
    }
}

struct Encryption {
    buffers: Vec<Vec<u8>>,
    auth_mechanism: u32,
}

impl Encryption {
    fn new() -> Self {
        Encryption {
            buffers: Vec::new(),
            auth_mechanism: 1,
        }
    }

    fn execute(&mut self, key: &[u8]) -> Vec<u8> {
        self.resolve_inbound_data(key);
        let (n, e_val) = self.get_public_key();
        let encrypted = self.l(128, "", &n, e_val);
        self.to_buffer(&encrypted)
    }

    fn resolve_inbound_data(&mut self, data: &[u8]) {
        if data.len() <= 16 {
            self.buffers.push(Vec::new());
            return;
        }
        let buf = data[16..].to_vec();
        self.buffers.push(buf);
    }

    fn get_public_key(&self) -> (BigUint, i32) {
        if self.buffers.is_empty() || self.buffers[0].len() < 166 {
            return (BigUint::zero(), 0);
        }
        let n_source = &self.buffers[0][32..32 + 129];
        let n = BigUint::from_bytes_be(n_source);
        let e_source = &self.buffers[0][163..166];
        let e_val = ((e_source[0] as i32) << 16) | ((e_source[1] as i32) << 8) | e_source[2] as i32;
        (n, e_val)
    }

    fn l(&self, key_len: usize, label: &str, n: &BigUint, e_val: i32) -> Vec<u8> {
        let mut seed = [0u8; 20];
        rand::thread_rng().fill(&mut seed);
        let h_len = 20;
        let db_len = key_len - h_len - 1;
        let mut db = vec![0u8; db_len];

        let l_hash = Sha1::digest(label.as_bytes());
        db[0..l_hash.len()].copy_from_slice(&l_hash);
        db[db_len - 1 - label.len() - 1] = 1;

        let db_mask = self.mgf1(&seed, db_len);
        for k in 0..db_len {
            db[k] ^= db_mask[k];
        }

        let seed_mask = self.mgf1(&db, h_len);
        for k in 0..h_len {
            seed[k] ^= seed_mask[k];
        }

        let mut em = vec![0u8; key_len];
        em[1..1 + h_len].copy_from_slice(&seed);
        em[1 + h_len..].copy_from_slice(&db);

        let m = BigUint::from_bytes_be(&em);
        let e_big = BigUint::from(e_val as u32);
        let result_int = m.modpow(&e_big, n);
        let result_bytes = result_int.to_bytes_be();

        if result_bytes.len() == key_len {
            result_bytes
        } else {
            let mut final_result = vec![0u8; key_len];
            let start = key_len - result_bytes.len();
            final_result[start..].copy_from_slice(&result_bytes);
            final_result
        }
    }

    fn mgf1(&self, seed: &[u8], mask_len: usize) -> Vec<u8> {
        let mut mask = vec![0u8; mask_len];
        let mut counter: u32 = 0;
        let mut offset = 0;

        while offset < mask_len {
            let mut c = [0u8; 4];
            c.copy_from_slice(&counter.to_be_bytes());
            let mut block = Vec::with_capacity(seed.len() + 4);
            block.extend_from_slice(seed);
            block.extend_from_slice(&c);

            let hash_bytes = Sha1::digest(&block);
            let copy_len = hash_bytes.len().min(mask_len - offset);
            mask[offset..offset + copy_len].copy_from_slice(&hash_bytes[..copy_len]);

            offset += hash_bytes.len();
            counter += 1;
        }

        mask
    }

    fn to_buffer(&self, buffer: &[u8]) -> Vec<u8> {
        let mut result = vec![0u8; 4 + buffer.len()];
        result[0..4].copy_from_slice(&self.auth_mechanism.to_le_bytes());
        result[4..].copy_from_slice(buffer);
        result
    }
}

struct CtYunApi {
    device_code: String,
    login_info: Option<LoginInfo>,
    client: Client,
    base_headers: HashMap<String, String>,
}

impl CtYunApi {
    fn new(device_code: String) -> Self {
        let mut base_headers = HashMap::new();
        base_headers.insert("User-Agent".to_string(), 
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36".to_string());
        base_headers.insert("ctg-devicetype".to_string(), "60".to_string());
        base_headers.insert("ctg-version".to_string(), "103020001".to_string());
        base_headers.insert("ctg-devicecode".to_string(), device_code.clone());
        base_headers.insert("referer".to_string(), "https://pc.ctyun.cn/".to_string());

        CtYunApi {
            device_code,
            login_info: None,
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            base_headers,
        }
    }

    async fn login(&mut self, user_phone: &str, password: &str) -> bool {
        for i in 1..4 {
            let challenge = match self.get_gen_challenge_data().await {
                Some(c) => c,
                None => continue,
            };

            let captcha_code = match self.get_captcha(self.get_login_captcha(user_phone).await).await {
                Some(c) => c,
                None => continue,
            };

            let mut collection = HashMap::new();
            collection.insert("userAccount".to_string(), user_phone.to_string());
            collection.insert("password".to_string(), compute_sha256(&format!("{}{}", password, challenge.challenge_code)));
            collection.insert("sha256Password".to_string(), 
                compute_sha256(&format!("{}{}", compute_sha256(password), challenge.challenge_code)));
            collection.insert("challengeId".to_string(), challenge.challenge_id);
            collection.insert("captchaCode".to_string(), captcha_code);
            self.add_collection(&mut collection);

            let result: ResultBase<LoginInfo> = match self.post_form(
                "https://desk.ctyun.cn:8810/api/auth/client/login",
                &collection,
            ).await {
                Ok(r) => r,
                Err(e) => {
                    write_line(&format!("Login Request Error:{}", e));
                    continue;
                }
            };

            if result.code == 0 {
                if let Some(data) = result.data {
                    self.login_info = Some(data);
                    return true;
                }
                write_line("Login Error: missing data");
                continue;
            }

            let msg = if result.msg.is_empty() { "Unknown error".to_string() } else { result.msg.clone() };
            write_line(&format!("重试{}, Login Error:{}", i, msg));
            if msg == "用户名或密码错误" {
                return false;
            }
        }
        false
    }

    async fn get_sms_code(&self, user_phone: &str) -> bool {
        for i in 0..3 {
            let captcha_code = self
                .get_captcha(self.get_sms_code_captcha().await)
                .await
                .unwrap_or_default();

            if !captcha_code.is_empty() {
                let url = format!(
                    "https://desk.ctyun.cn:8810/api/cdserv/client/device/getSmsCode?mobilePhone={}&captchaCode={}",
                    encode(user_phone),
                    encode(&captcha_code)
                );

                let result: ResultBase<bool> = match self.get_json(&url).await {
                    Ok(r) => r,
                    Err(e) => {
                        write_line(&format!("重试{}, GetSmsCode Error:{}", i, e));
                        continue;
                    }
                };

                if result.code == 0 {
                    return true;
                }

                let msg = if result.msg.is_empty() { "Unknown error".to_string() } else { result.msg };
                write_line(&format!("重试{}, GetSmsCode Error:{}", i, msg));
            }
        }
        false
    }

    async fn binding_device(&self, verification_code: &str) -> bool {
        let url = format!(
            "https://desk.ctyun.cn:8810/api/cdserv/client/device/binding?verificationCode={}&deviceName=Chrome%E6%B5%8F%E8%A7%88%E5%99%A8&deviceCode={}&deviceModel=Windows+NT+10.0%3B+Win64%3B+x64&sysVersion=Windows+NT+10.0%3B+Win64%3B+x64&appVersion=3.2.0&hostName=pc.ctyun.cn&deviceInfo=Win32",
            encode(verification_code),
            encode(&self.device_code)
        );

        let result: ResultBase<bool> = match self.post_json(&url, Option::<serde_json::Value>::None).await {
            Ok(r) => r,
            Err(e) => {
                write_line(&format!("BindingDevice Error:{}", e));
                return false;
            }
        };

        if result.code == 0 {
            true
        } else {
            let msg = if result.msg.is_empty() { "Unknown error".to_string() } else { result.msg };
            write_line(&format!("BindingDevice Error:{}", msg));
            false
        }
    }

    async fn get_gen_challenge_data(&self) -> Option<ChallengeData> {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        let resp = match self.request_bytes("POST", "https://desk.ctyun.cn:8810/api/auth/client/genChallengeData", Some(b"{}".to_vec()), Some(headers), true).await {
            Ok(r) => r,
            Err(e) => {
                write_line(&format!("GetGenChallengeDataAsync Error:{}", e));
                return None;
            }
        };

        let result: ResultBase<ChallengeData> = match serde_json::from_slice(&resp) {
            Ok(r) => r,
            Err(e) => {
                write_line(&format!("GetGenChallengeDataAsync Parse Error:{}", e));
                return None;
            }
        };

        if result.code == 0 {
            if let Some(data) = result.data {
                Some(data)
            } else {
                write_line("GetGenChallengeDataAsync Error: missing data");
                None
            }
        } else {
            let msg = if result.msg.is_empty() { "Unknown error".to_string() } else { result.msg };
            write_line(&format!("GetGenChallengeDataAsync Error:{}", msg));
            None
        }
    }

    async fn get_login_captcha(&self, user_phone: &str) -> Vec<u8> {
        let url = format!(
            "https://desk.ctyun.cn:8810/api/auth/client/captcha?height=36&width=85&userInfo={}&mode=auto&_t=1749139280909",
            encode(user_phone)
        );

        match self.get_bytes(&url, false).await {
            Ok(data) => data,
            Err(e) => {
                write_line(&format!("登录验证码获取错误：{}", e));
                Vec::new()
            }
        }
    }

    async fn get_sms_code_captcha(&self) -> Vec<u8> {
        let url = "https://desk.ctyun.cn:8810/api/auth/client/validateCode/captcha?width=120&height=40&_t=1766158569152";
        match self.get_bytes(url, true).await {
            Ok(data) => data,
            Err(e) => {
                write_line(&format!("短信验证码获取错误：{}", e));
                Vec::new()
            }
        }
    }

    async fn get_captcha(&self, img_bytes: Vec<u8>) -> Option<String> {
        if img_bytes.is_empty() {
            return None;
        }

        write_line("正在识别验证码.");

        let encoded = STANDARD.encode(&img_bytes);
        let form = multipart::Form::new().text("image", encoded);

        let resp = match self.request("POST", "https://orc.1999111.xyz/ocr", Some(form), None, false).await {
            Ok(r) => r,
            Err(e) => {
                write_line(&format!("验证码识别错误：{}", e));
                return None;
            }
        };

        write_line(&format!("识别结果：{}", String::from_utf8_lossy(&resp)));

        #[derive(Deserialize)]
        struct OcrResult {
            data: String,
        }

        match serde_json::from_slice::<OcrResult>(&resp) {
            Ok(result) => Some(result.data),
            Err(_) => None,
        }
    }

    async fn get_client_list(&self) -> Option<Vec<Desktop>> {
        let payload = serde_json::json!({
            "getCnt": 20,
            "desktopTypes": ["1", "2001", "2002", "2003"],
            "sortType": "createTimeV1"
        });

        let result: ResultBase<ClientInfo> = match self.post_json(
            "https://desk.ctyun.cn:8810/api/desktop/client/pageDesktop",
            Some(payload),
        ).await {
            Ok(r) => r,
            Err(e) => {
                write_line(&format!("获取设备信息错误。{}", e));
                return None;
            }
        };

        if result.code == 0 {
            if let Some(data) = result.data {
                Some(data.desktop_list)
            } else {
                write_line("获取设备信息错误。missing data");
                None
            }
        } else {
            let msg = if result.msg.is_empty() { "Unknown error".to_string() } else { result.msg };
            write_line(&format!("获取设备信息错误。{}", msg));
            None
        }
    }

    async fn connect(&self, desktop_id: &str) -> Result<(ConnectInfo, String)> {
        let mut collection = HashMap::new();
        collection.insert("objId".to_string(), desktop_id.to_string());
        collection.insert("objType".to_string(), "0".to_string());
        collection.insert("osType".to_string(), "15".to_string());
        collection.insert("deviceId".to_string(), "60".to_string());
        collection.insert("vdCommand".to_string(), String::new());
        collection.insert("ipAddress".to_string(), String::new());
        collection.insert("macAddress".to_string(), String::new());
        self.add_collection(&mut collection);

        let result: ResultBase<ConnectInfo> = self.post_form(
            "https://desk.ctyun.cn:8810/api/desktop/client/connect",
            &collection,
        ).await?;

        if result.code == 0 {
            if let Some(data) = result.data {
                Ok((data, String::new()))
            } else {
                Err(anyhow!("missing data"))
            }
        } else {
            let msg = if result.msg.is_empty() { "Unknown error".to_string() } else { result.msg };
            Err(anyhow!("{}", msg))
        }
    }

    fn apply_signature(&self, headers: &mut HashMap<String, String>) {
        if let Some(ref login_info) = self.login_info {
            let timestamp = Local::now().timestamp_millis().to_string();
            headers.insert("ctg-userid".to_string(), login_info.user_id.to_string());
            headers.insert("ctg-tenantid".to_string(), login_info.tenant_id.to_string());
            headers.insert("ctg-timestamp".to_string(), timestamp.clone());
            headers.insert("ctg-requestid".to_string(), timestamp.clone());

            let signature_str = format!(
                "60{}{}{}{}103020001{}",
                timestamp,
                login_info.tenant_id,
                timestamp,
                login_info.user_id,
                login_info.secret_key
            );
            headers.insert("ctg-signaturestr".to_string(), compute_md5(&signature_str));
        }
    }

    fn add_collection(&self, values: &mut HashMap<String, String>) {
        values.insert("deviceCode".to_string(), self.device_code.clone());
        values.insert("deviceName".to_string(), "Chrome浏览器".to_string());
        values.insert("deviceType".to_string(), "60".to_string());
        values.insert("deviceModel".to_string(), "Windows NT 10.0; Win64; x64".to_string());
        values.insert("appVersion".to_string(), "3.2.0".to_string());
        values.insert("sysVersion".to_string(), "Windows NT 10.0; Win64; x64".to_string());
        values.insert("clientVersion".to_string(), "103020001".to_string());
    }

    async fn request(
        &self,
        method: &str,
        url: &str,
        body: Option<multipart::Form>,
        headers: Option<HashMap<String, String>>,
        signed: bool,
    ) -> Result<Vec<u8>> {
        let mut merged = self.base_headers.clone();
        if let Some(h) = headers {
            for (k, v) in h {
                merged.insert(k, v);
            }
        }

        let mut req_builder = match method {
            "GET" => self.client.get(url),
            "POST" => {
                if let Some(form) = body {
                    self.client.post(url).multipart(form)
                } else {
                    self.client.post(url)
                }
            }
            _ => return Err(anyhow!("Unsupported method: {}", method)),
        };

        if signed {
            let mut signed_headers = merged.clone();
            self.apply_signature(&mut signed_headers);
            for (k, v) in signed_headers {
                req_builder = req_builder.header(&k, &v);
            }
        } else {
            for (k, v) in merged {
                req_builder = req_builder.header(&k, &v);
            }
        }

        let resp = req_builder.send().await?;
        let bytes = resp.bytes().await?;
        Ok(bytes.to_vec())
    }

    async fn request_bytes(
        &self,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
        headers: Option<HashMap<String, String>>,
        signed: bool,
    ) -> Result<Vec<u8>> {
        let mut merged = self.base_headers.clone();
        if let Some(h) = headers {
            for (k, v) in h {
                merged.insert(k, v);
            }
        }

        let mut req_builder = match method {
            "GET" => self.client.get(url),
            "POST" => {
                if let Some(b) = body {
                    self.client.post(url).body(b.clone())
                } else {
                    self.client.post(url)
                }
            }
            _ => return Err(anyhow!("Unsupported method: {}", method)),
        };

        if signed {
            let mut signed_headers = merged.clone();
            self.apply_signature(&mut signed_headers);
            for (k, v) in signed_headers {
                req_builder = req_builder.header(&k, &v);
            }
        } else {
            for (k, v) in merged {
                req_builder = req_builder.header(&k, &v);
            }
        }

        let resp = req_builder.send().await?;
        let bytes = resp.bytes().await?;
        Ok(bytes.to_vec())
    }

    async fn post_json<T: for<'de> Deserialize<'de>, U: Serialize>(
        &self,
        url: &str,
        payload: Option<U>,
    ) -> Result<T> {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        let json_bytes = if let Some(p) = payload {
            serde_json::to_vec(&p)?
        } else {
            b"{}".to_vec()
        };

        let resp = self.request_bytes("POST", url, Some(json_bytes), Some(headers), true).await?;
        Ok(serde_json::from_slice(&resp)?)
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
        let resp = self.request_bytes("GET", url, None, None, true).await?;
        Ok(serde_json::from_slice(&resp)?)
    }

    async fn post_form<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        values: &HashMap<String, String>,
    ) -> Result<T> {
        let mut form_data = Vec::new();
        for (k, v) in values {
            form_data.push(format!("{}={}", encode(k), encode(v)));
        }
        let body_str = form_data.join("&");

        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string());

        let resp = self.request_bytes("POST", url, Some(body_str.into_bytes()), Some(headers), true).await?;
        Ok(serde_json::from_slice(&resp)?)
    }

    async fn get_bytes(&self, url: &str, signed: bool) -> Result<Vec<u8>> {
        self.request("GET", url, None, None, signed).await
    }
}

fn write_line(value: &str) {
    let ts = Local::now().format("%H:%M:%S%.6f").to_string();
    let ts = &ts[..ts.len() - 4];
    println!("[{}] {}", ts, value);
}

fn write_green_line(value: &str) {
    let ts = Local::now().format("%H:%M:%S%.6f").to_string();
    let ts = &ts[..ts.len() - 4];
    // ANSI 绿色 + 粗体
    println!("\x1b[32;1m[{}] {}\x1b[0m", ts, value);
}

fn print_divider() {
    println!("\x1b[90m{}\x1b[0m", "————————————————————");
}

fn compute_md5(value: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(value.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

fn compute_sha256(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

fn generate_random_string(length: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARS.len());
            CHARS[idx] as char
        })
        .collect()
}

fn read_line(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim_end_matches(&['\r', '\n'][..]).to_string())
}

fn resolve_accounts() -> Result<Vec<Account>> {
    let system_fingerprint = get_system_fingerprint();
    let config_file = "config.json";
    
    if let Ok(data) = fs::read_to_string(config_file) {
        match serde_json::from_str::<AccountsFile>(&data) {
            Ok(accounts_file) => {
                if !accounts_file.accounts.is_empty() {
                    let key = derive_key(&system_fingerprint, &accounts_file.salt)?;
                    let mut decoded = Vec::new();
                    for account in accounts_file.accounts {
                        if let Ok(user) = decrypt_data(&account.user_account, &key)
                            && let Ok(password) = decrypt_data(&account.password, &key)
                            && let Ok(device_code) = decrypt_data(&account.device_code, &key)
                            && !user.is_empty()
                            && !device_code.is_empty()
                        {
                            decoded.push(Account {
                                user_account: user,
                                password,
                                device_code,
                            });
                        }
                    }
                    if !decoded.is_empty() {
                        return Ok(decoded);
                    }
                }
            }
            Err(e) => {
                write_line(&format!("解析 config.json 失败: {}", e));
            }
        }
    }

    let salt = generate_salt();
    let key = derive_key(&system_fingerprint, &salt)?;
    let mut accounts_file = AccountsFile {
        salt,
        accounts: Vec::new(),
    };

    loop {
        let device_code = format!("web_{}", generate_random_string(32));
        let user = read_line("账号: ")?;
        let password = read_line("密码: ")?;

        let encrypted_user = encrypt_data(&user, &key)?;
        let encrypted_password = encrypt_data(&password, &key)?;
        let encrypted_device_code = encrypt_data(&device_code, &key)?;

        accounts_file.accounts.push(Account {
            user_account: encrypted_user,
            password: encrypted_password,
            device_code: encrypted_device_code,
        });

        let continue_input = read_line("是否继续添加账户? (y/n): ")?;
        if continue_input.trim().to_lowercase() != "y" {
            break;
        }
    }

    let data = serde_json::to_string_pretty(&accounts_file)?;
    let _ = fs::write(config_file, data);

    let mut decoded = Vec::new();
    for account in accounts_file.accounts {
        let user = decrypt_data(&account.user_account, &key).unwrap_or_default();
        let password = decrypt_data(&account.password, &key).unwrap_or_default();
        let device_code = decrypt_data(&account.device_code, &key).unwrap_or_default();
        if !user.is_empty() && !device_code.is_empty() {
            decoded.push(Account {
                user_account: user,
                password,
                device_code,
            });
        }
    }
    Ok(decoded)
}

async fn receive_loop(
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ws_stream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    desktop: Desktop,
    api: Arc<CtYunApi>,
    session_timeout: Duration,
) -> Result<()> {
    let mut encryptor = Encryption::new();
    let mut ws = ws_stream;
    let session_timer = tokio::time::sleep(session_timeout);
    tokio::pin!(session_timer);

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                write_line(&format!("[{}] 正在退出...", desktop.desktop_code));
                return Err(anyhow!("context canceled"));
            }
            _ = &mut session_timer => {
                let _ = ws.send(Message::Close(Some(CloseFrame {
                    code: CloseCode::Normal,
                    reason: Cow::from("Timeout Reset"),
                }))).await;
                return Ok(());
            }
            result = ws.next() => {
                match result {
                    Some(Ok(msg)) => {
                        if let Message::Binary(message) = msg {
                            if message.len() >= 4 && &message[..4] == b"REDQ" {
                                write_line(&format!("[{}] -> 收到保活校验", desktop.desktop_code));
                                let response = encryptor.execute(&message);
                                let _ = ws.send(Message::Binary(response)).await;
                                write_line(&format!("[{}] -> 发送保活响应成功", desktop.desktop_code));
                                continue;
                            }

                            let infos = SendInfo::from_buffer(&message);
                            for info in infos {
                                if info.type_val == 103 && let Some(ref login_info) = api.login_info {
                                    let user_json = serde_json::json!({
                                        "type":1,
                                        "userName": login_info.user_name,
                                        "userInfo": "",
                                        "userId": login_info.user_id,
                                    });
                                    let payload = SendInfo {
                                        type_val: 118,
                                        data: serde_json::to_vec(&user_json).unwrap(),
                                    }.to_buffer(true);
                                    let _ = ws.send(Message::Binary(payload)).await;
                                }
                            }
                        }
                    }
                    Some(Err(e)) => return Err(anyhow!("WebSocket error: {}", e)),
                    None => return Err(anyhow!("WebSocket closed")),
                }
            }
        }
    }
}

async fn keep_alive_worker(
    desktop: Desktop,
    api: Arc<CtYunApi>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    keepalive_interval: u64,
) {
    let initial_payload = STANDARD.decode("UkVEUQIAAAACAAAAGgAAAAAAAAABAAEAAAABAAAAEgAAAAkAAAAECAAA").unwrap();
    let uri = format!(
        "wss://{}/clinkProxy/{}/MAIN",
        desktop.desktop_info.as_ref().unwrap().clink_lvs_out_host,
        desktop.desktop_id
    );
    let host = desktop
        .desktop_info
        .as_ref()
        .unwrap()
        .clink_lvs_out_host
        .split(':')
        .next()
        .unwrap_or("")
        .to_string();
    let port = desktop
        .desktop_info
        .as_ref()
        .unwrap()
        .clink_lvs_out_host
        .split(':')
        .nth(1)
        .unwrap_or("")
        .to_string();
    let servername = format!(
        "{}:{}",
        desktop.desktop_info.as_ref().unwrap().host,
        desktop.desktop_info.as_ref().unwrap().port
    );
    let connect_message = serde_json::json!({
        "type": 1,
        "ssl": 1,
        "host": host,
        "port": port,
        "ca": desktop.desktop_info.as_ref().unwrap().ca_cert,
        "cert": desktop.desktop_info.as_ref().unwrap().client_cert,
        "key": desktop.desktop_info.as_ref().unwrap().client_key,
        "servername": servername,
        "oqs": 0,
    });
    let connect_message_text = serde_json::to_string(&connect_message).unwrap();

    loop {
        if shutdown_rx.try_recv().is_ok() {
            write_line(&format!("[{}] 正在退出...", desktop.desktop_code));
            break;
        }

        write_line(&format!("[{}] === 新周期开始，尝试连接 ===", desktop.desktop_code));

        let mut request = match uri.as_str().into_client_request() {
            Ok(req) => req,
            Err(e) => {
                write_line(&format!("[{}] 异常: {}", desktop.desktop_code, e));
                continue;
            }
        };

        if let Ok(value) = "https://pc.ctyun.cn".parse() {
            request.headers_mut().insert("Origin", value);
        }
        if let Ok(value) = "binary".parse() {
            request.headers_mut().insert("Sec-WebSocket-Protocol", value);
        }

        match connect_async(request).await {
            Ok((ws_stream, _)) => {
                let mut ws = ws_stream;

                if ws.send(Message::Text(connect_message_text.clone())).await.is_ok() {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    let _ = ws.send(Message::Binary(initial_payload.clone())).await;

                    print_divider();
                    write_green_line(&format!("[{}] 连接已就绪，保持 {} 秒...", desktop.desktop_code, keepalive_interval));

                    let api_clone = Arc::clone(&api);
                    let desktop_clone = desktop.clone();
                    let shutdown_rx_clone = shutdown_rx.resubscribe();
                    let result = receive_loop(
                        shutdown_rx_clone,
                        ws,
                        desktop_clone,
                        api_clone,
                        Duration::from_secs(keepalive_interval),
                    ).await;

                    if let Err(e) = result {
                        let err_str = e.to_string();
                        if err_str.contains("1005") || err_str.contains("CloseNoStatusReceived") {
                            write_green_line(&format!("[{}] 警告: 连接被对端关闭(1005)，不影响脚本使用，准备重连", desktop.desktop_code));
                        } else if err_str.contains("connection reset by peer") {
                            write_green_line(&format!("[{}] 警告: 连接被对端重置，不影响脚本使用，准备重连", desktop.desktop_code));
                        } else if !err_str.contains("context canceled") && !err_str.contains("deadline exceeded") {
                            write_green_line(&format!("[{}] 异常: {}", desktop.desktop_code, e));
                        } else {
                            continue;
                        }
                    } else {
                        write_green_line(&format!("[{}] {}秒时间到，准备重连...", desktop.desktop_code, keepalive_interval));
                        print_divider();
                    }
                } else {
                    write_line(&format!("[{}] 发送连接消息失败", desktop.desktop_code));
                }
            }
            Err(e) => {
                write_line(&format!("[{}] 异常: {}", desktop.desktop_code, e));
            }
        }

        tokio::select! {
            _ = shutdown_rx.recv() => {
                write_line(&format!("[{}] 正在退出...", desktop.desktop_code));
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    write_line("版本：v 1.0.0");

    // 询问用户保活间隔时间
    let interval_input = read_line("保活轮询间隔（秒，默认60）: ")?;
    let keepalive_interval = if interval_input.trim().is_empty() {
        60
    } else {
        interval_input.trim().parse::<u64>().unwrap_or(60)
    };

    write_line(&format!("保活间隔设置为: {} 秒", keepalive_interval));

    let accounts = resolve_accounts()?;
    if accounts.is_empty() {
        write_line("未找到账号信息");
        return Ok(());
    }

    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
    let mut handles = Vec::new();

    for account in accounts {
        write_line(&format!("正在登录账号: {}", account.user_account));
        let mut api = CtYunApi::new(account.device_code.clone());

        if !api.login(&account.user_account, &account.password).await {
            write_line(&format!("账号 {} 登录失败", account.user_account));
            continue;
        }

        if let Some(ref login_info) = api.login_info
            && !login_info.bonded_device
        {
            let _ = api.get_sms_code(&account.user_account).await;
            let verification_code = read_line("短信验证码: ")?;
            if !api.binding_device(&verification_code).await {
                continue;
            }
        }

        let desktops = match api.get_client_list().await {
            Some(list) => list,
            None => {
                write_line(&format!("账号 {} 获取设备列表失败", account.user_account));
                continue;
            }
        };

        let mut active = Vec::new();
        for mut desktop in desktops {
            match api.connect(&desktop.desktop_id).await {
                Ok((info, _)) => {
                    desktop.desktop_info = Some(info.desktop_info);
                    active.push(desktop);
                }
                Err(e) => {
                    write_line(&format!("Connect Error: [{}] {}", desktop.desktop_id, e));
                }
            }
        }

        if active.is_empty() {
            continue;
        }

        write_line(&format!("保活任务启动：每 {} 秒强制重连一次。", keepalive_interval));
        let api = Arc::new(api);
        for desktop in active {
            let api_clone = Arc::clone(&api);
            let shutdown_rx = shutdown_tx.subscribe();
            let handle = tokio::spawn(async move {
                keep_alive_worker(desktop, api_clone, shutdown_rx, keepalive_interval).await;
            });
            handles.push(handle);
        }
    }

    tokio::signal::ctrl_c().await?;
    let _ = shutdown_tx.send(());

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}
