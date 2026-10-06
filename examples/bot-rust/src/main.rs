//! Minimal Extrovert bot (planned.md F5.6).
//!
//! Setup (as an instance admin):
//!   POST /api/v1/bots {"username":"echo_bot"} -> data.token (shown once)
//!
//! Run:
//!   EXTROVERT_BOT_TOKEN=exb_... cargo run            # SSE mode (recommended)
//!   EXTROVERT_BOT_TOKEN=exb_... MODE=poll cargo run  # mentions polling
//!   EXTROVERT_WEBHOOK_SECRET=whsec_...               # to verify webhook HMAC
//!
//! Everything goes through the plain Bearer REST API — no SDK required.

use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::error::Error;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

struct Bot {
    base: String,
    client: reqwest::Client,
    token: String,
    secret: String,
}

impl Bot {
    async fn api(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Result<Value> {
        let mut req = self
            .client
            .request(method, format!("{}/api/v1{}", self.base, path))
            .bearer_auth(&self.token);
        if let Some(b) = body {
            req = req.json(&b);
        }
        Ok(req.send().await?.error_for_status()?.json().await?)
    }

    /// Verify X-Webhook-Signature: hex(HMAC-SHA256(secret, raw_body)).
    #[allow(dead_code)]
    fn verify(&self, signature: &str, body: &[u8]) -> bool {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.secret.as_bytes()).expect("hmac");
        mac.update(body);
        hex::encode(mac.finalize().into_bytes()) == signature
    }

    async fn handle(&self, event: &Value) -> Result<()> {
        let etype = event["type"].as_str().unwrap_or("");
        let actor_id = match event["actor_id"].as_i64() {
            Some(id) => id,
            None => return Ok(()),
        };
        let actor = self.api(reqwest::Method::GET, &format!("/accounts/{actor_id}"), None).await?;
        let username = actor["data"]["username"].as_str().unwrap_or("friend");
        match etype {
            "mention" => {
                let post_id = event["post_id"].as_i64().unwrap_or(0);
                let post = self
                    .api(reqwest::Method::GET, &format!("/statuses/{post_id}"), None)
                    .await?;
                let text = format!(
                    "@{} thanks for the mention! You said: {:.80}",
                    username, post["data"]["body"].as_str().unwrap_or("")
                );
                self.api(
                    reqwest::Method::POST,
                    "/statuses",
                    Some(json!({ "type": "text", "body": text })),
                )
                .await?;
                println!("replied to mention from @{username}");
            }
            "follow" => {
                self.api(
                    reqwest::Method::POST,
                    "/follow",
                    Some(json!({ "uri": username })),
                )
                .await?;
                println!("followed back @{username}");
            }
            _ => {}
        }
        Ok(())
    }

    /// Recommended: one long-lived SSE connection to /notifications/stream.
    async fn run_sse(&self) -> Result<()> {
        let resp = self
            .client
            .get(format!("{}/api/v1/notifications/stream", self.base))
            .bearer_auth(&self.token)
            .send()
            .await?
            .error_for_status()?;
        let mut stream = resp.bytes_stream();
        let mut buf = String::new();
        while let Some(chunk) = stream.next().await {
            buf.push_str(&String::from_utf8_lossy(&chunk?));
            while let Some(pos) = buf.find("\n\n") {
                let frame: String = buf.drain(..pos + 2).collect();
                if let Some(data) = frame.lines().find(|l| l.starts_with("data: ")) {
                    if let Ok(event) = serde_json::from_str::<Value>(&data[6..]) {
                        if let Err(err) = self.handle(&event).await {
                            eprintln!("handle error: {err}");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Fallback: poll the mentions timeline.
    async fn run_poll(&self) -> Result<()> {
        let mut seen: Vec<String> = Vec::new();
        loop {
            let feed = self.api(reqwest::Method::GET, "/timelines/mentions", None).await?;
            if let Some(posts) = feed["data"].as_array() {
                for post in posts {
                    let pid = post["id"].as_str().unwrap_or("").to_string();
                    if seen.contains(&pid) {
                        continue;
                    }
                    seen.push(pid.clone());
                    let event = json!({
                        "type": "mention",
                        "actor_id": post["account"]["id"],
                        "post_id": post["id"],
                    });
                    if let Err(err) = self.handle(&event).await {
                        eprintln!("handle error: {err}");
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let bot = Bot {
        base: std::env::var("EXTROVERT_URL").unwrap_or_else(|_| "https://extrovert.redforged.eu".into()),
        client: reqwest::Client::new(),
        token: std::env::var("EXTROVERT_BOT_TOKEN")?,
        secret: std::env::var("EXTROVERT_WEBHOOK_SECRET").unwrap_or_default(),
    };
    let me = bot.api(reqwest::Method::GET, "/bot/me", None).await?;
    println!("running as @{} (bot={})", me["data"]["username"].as_str().unwrap_or("?"), me["data"]["is_bot"]);
    if std::env::var("MODE").as_deref() == Ok("poll") {
        bot.run_poll().await
    } else {
        bot.run_sse().await
    }
}
