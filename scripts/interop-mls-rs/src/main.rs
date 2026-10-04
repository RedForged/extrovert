use std::io::{self, BufRead, Write};
use mls_rs::{
    group::ReceivedMessage,
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, MlsMessage,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Command {
    Init {
        identity: String,
    },
    JoinGroup {
        welcome_hex: String,
    },
    DecryptMessage {
        ciphertext_hex: String,
    },
    EncryptMessage {
        plaintext: String,
    },
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Response {
    Ok {
        #[serde(skip_serializing_if = "Option::is_none")]
        key_package_hex: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        epoch: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        plaintext: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        ciphertext_hex: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sender_index: Option<u32>,
    },
    Error {
        message: String,
    },
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    let cp = RustCryptoProvider::default();
    let cs_provider = match cp.cipher_suite_provider(CipherSuite::CURVE25519_AES128) {
        Some(p) => p,
        None => {
            eprintln!("Failed to get CipherSuite::CURVE25519_AES128 provider");
            return;
        }
    };

    let (secret_key, public_key) = match cs_provider.signature_key_generate() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Signature keygen failed: {e:?}");
            return;
        }
    };

    let basic = BasicCredential::new(b"bob_mls_rs".to_vec());
    let signing_identity = SigningIdentity::new(basic.into_credential(), public_key);

    let client = Client::builder()
        .crypto_provider(cp)
        .identity_provider(BasicIdentityProvider::new())
        .signing_identity(signing_identity, secret_key, CipherSuite::CURVE25519_AES128)
        .build();

    let mut active_group = None;

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let cmd: Command = match serde_json::from_str(trimmed) {
            Ok(c) => c,
            Err(e) => {
                let resp = Response::Error {
                    message: format!("Invalid JSON command: {e}"),
                };
                let _ = serde_json::to_writer(&mut stdout, &resp);
                let _ = stdout.write_all(b"\n");
                let _ = stdout.flush();
                continue;
            }
        };

        let response = match cmd {
            Command::Init { identity: _ } => {
                match client.generate_key_package_message(Default::default(), Default::default(), None) {
                    Ok(kp_msg) => match kp_msg.to_bytes() {
                        Ok(bytes) => Response::Ok {
                            key_package_hex: Some(hex::encode(bytes)),
                            epoch: None,
                            plaintext: None,
                            ciphertext_hex: None,
                            sender_index: None,
                        },
                        Err(e) => Response::Error {
                            message: format!("Failed to serialize KeyPackage: {e:?}"),
                        },
                    },
                    Err(e) => Response::Error {
                        message: format!("Failed to generate KeyPackage: {e:?}"),
                    },
                }
            }
            Command::JoinGroup { welcome_hex } => {
                let welcome_bytes = match hex::decode(&welcome_hex) {
                    Ok(b) => b,
                    Err(e) => {
                        let resp = Response::Error {
                            message: format!("Invalid welcome hex: {e}"),
                        };
                        let _ = serde_json::to_writer(&mut stdout, &resp);
                        let _ = stdout.write_all(b"\n");
                        let _ = stdout.flush();
                        continue;
                    }
                };

                match MlsMessage::from_bytes(&welcome_bytes) {
                    Ok(welcome_msg) => {
                        match client.join_group(None, &welcome_msg, None) {
                            Ok((group, _new_member_info)) => {
                                let epoch = group.current_epoch();
                                active_group = Some(group);
                                Response::Ok {
                                    key_package_hex: None,
                                    epoch: Some(epoch),
                                    plaintext: None,
                                    ciphertext_hex: None,
                                    sender_index: None,
                                }
                            }
                            Err(e) => Response::Error {
                                message: format!("join_group failed: {e:?}"),
                            },
                        }
                    }
                    Err(e) => Response::Error {
                        message: format!("Failed to parse Welcome MlsMessage: {e:?}"),
                    },
                }
            }
            Command::DecryptMessage { ciphertext_hex } => {
                if let Some(ref mut group) = active_group {
                    let ct_bytes = match hex::decode(&ciphertext_hex) {
                        Ok(b) => b,
                        Err(e) => {
                            let resp = Response::Error {
                                message: format!("Invalid ciphertext hex: {e}"),
                            };
                            let _ = serde_json::to_writer(&mut stdout, &resp);
                            let _ = stdout.write_all(b"\n");
                            let _ = stdout.flush();
                            continue;
                        }
                    };

                    match MlsMessage::from_bytes(&ct_bytes) {
                        Ok(mls_msg) => match group.process_incoming_message(mls_msg) {
                            Ok(received) => match received {
                                ReceivedMessage::ApplicationMessage(desc) => {
                                    match String::from_utf8(desc.data().to_vec()) {
                                        Ok(pt) => Response::Ok {
                                            key_package_hex: None,
                                            epoch: None,
                                            plaintext: Some(pt),
                                            ciphertext_hex: None,
                                            sender_index: Some(desc.sender_index),
                                        },
                                        Err(e) => Response::Error {
                                            message: format!("Plaintext is not valid UTF-8: {e:?}"),
                                        },
                                    }
                                }
                                other => Response::Error {
                                    message: format!("Expected ApplicationMessage, got: {other:?}"),
                                },
                            },
                            Err(e) => Response::Error {
                                message: format!("process_incoming_message failed: {e:?}"),
                            },
                        },
                        Err(e) => Response::Error {
                            message: format!("Failed to parse ciphertext MlsMessage: {e:?}"),
                        },
                    }
                } else {
                    Response::Error {
                        message: "No active MLS group joined".to_string(),
                    }
                }
            }
            Command::EncryptMessage { plaintext } => {
                if let Some(ref mut group) = active_group {
                    match group.encrypt_application_message(plaintext.as_bytes(), vec![]) {
                        Ok(msg) => match msg.to_bytes() {
                            Ok(bytes) => Response::Ok {
                                key_package_hex: None,
                                epoch: None,
                                plaintext: None,
                                ciphertext_hex: Some(hex::encode(bytes)),
                                sender_index: None,
                            },
                            Err(e) => Response::Error {
                                message: format!("Failed to serialize encrypted message: {e:?}"),
                            },
                        },
                        Err(e) => Response::Error {
                            message: format!("encrypt_application_message failed: {e:?}"),
                        },
                    }
                } else {
                    Response::Error {
                        message: "No active MLS group joined".to_string(),
                    }
                }
            }
        };

        let _ = serde_json::to_writer(&mut stdout, &response);
        let _ = stdout.write_all(b"\n");
        let _ = stdout.flush();
    }
}
