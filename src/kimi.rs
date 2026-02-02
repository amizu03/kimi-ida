use reqwest::{blocking::Client, redirect::Policy};
use serde::{Serialize, Deserialize};
use serde_json::{Value, json};
use core::sync::atomic::AtomicUsize;
use std::{collections::HashMap, sync::atomic::Ordering, time::Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Variable {
    pub original_name: String,
    pub new_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Comment {
    pub ea: u64,
    pub comment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PseudocodeLocation {
    pub ea: u64,
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnalysisResult {
    pub function_name: String,
    pub comment: String,
    pub variables: Vec<Variable>,
    pub comments: Vec<Comment>,
}

pub struct Kimi {
    api_key: String,
    base_url: &'static str,
    client: Client,
    num_active_models: AtomicUsize,
    pub models: Vec<String>,
}

static mut KIMI: Option<Kimi> = None;

impl Kimi {
    pub fn init(api_key: String) {
        unsafe {
            core::mem::forget(KIMI.take());
            KIMI = Some(Self::new(api_key).expect("Failed to initialize KIMI client"));
        }
    }

    pub fn get() -> &'static mut Kimi {
        unsafe {
            KIMI.as_mut().unwrap_unchecked()
        }
    }

    fn new(api_key: String) -> Option<Self> {
        if !api_key.starts_with("sk-kimi-") {
            println!("Warning: Moonshot API keys usually start with 'sk-' or 'sk-kimi-'");
        }
        
        let client = Client::builder()
            .timeout(Duration::from_secs(60_000))
            .redirect(Policy::none())
            .referer(false)
            .tcp_nodelay(true)
            .tcp_keepalive(None)
            .build().ok()?;
            
        Some(Self {
            api_key,
            base_url: "https://api.kimi.com/coding/v1",
            client,
            num_active_models: 0.into(),
            models: Vec::new(),
        })
    }
    
    pub fn chat(
        &self,
        messages: Value,
        model: &str,
        temperature: f32,
        max_tokens: Option<i32>,
        thinking: bool,
    ) -> Option<Value> {
        // Rate limiting
        self.num_active_models.fetch_add(1, Ordering::Relaxed);
        
        let endpoint = format!("{}/chat/completions", self.base_url);
        
        let thinking_mode = if thinking { "enabled" } else { "disabled" };

        let mut payload = json!({
            "model": model,
            "messages": messages,
            "stream": false,
            "temperature": temperature,
            "thinking": { "type": thinking_mode },
        });
        
        if let Some(tokens) = max_tokens {
            payload["max_tokens"] = json!(tokens);
        }
        
        let response = self.client
            .post(&endpoint)
            .bearer_auth(&self.api_key)
            .header("User-Agent", "KimiCLI/1.3")
            .json(&payload)
            .send()
            .ok()?;
            
        if response.status() == 403 {
            println!("403 Error: Check if model '{model}' is available to your API key");
            return None;
        }
        
        response.error_for_status_ref().ok()?;
        
        let result = response.json::<Value>().ok()?;
        
        self.num_active_models.fetch_sub(1, Ordering::Relaxed);
        
        Some(result)
    }
    
    pub fn list_models(&self) -> Option<Vec<String>> {
        let endpoint = format!("{}/models", self.base_url);
        let response = self.client
            .get(&endpoint)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .send().ok()?;
            
        let data: Value = response.json().ok()?;
        let models: Vec<String> = data["data"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|m| m["id"].as_str().map(|s| s.to_string()))
            .collect();
            
        Some(models)
    }
    
    pub fn wait_for_slot(&self, max_concurrent: usize) {
        while self.num_active_models.load(Ordering::Relaxed) >= max_concurrent {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}