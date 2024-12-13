use aes::Aes256;
use block_padding::{Padding, Pkcs7};
use cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use console::style;
use dotenv::dotenv;
use generic_array::typenum::U16;
use hex::{decode, encode};
use local_ip_address::list_afinet_netifas;
use local_ip_address::local_ip;
use nix::unistd;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::File;

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    hostname: String,
    path: String,
    password: String,
    kind: String,
    tools: Vec<String>,
}

impl Config {
    fn new(
        hostname: String,
        path: String,
        password: String,
        kind: String,
        tools: Vec<String>,
    ) -> Self {
        Self {
            hostname,
            path,
            password,
            kind,
            tools,
        }
    }
}

fn encrypt_password(password: &str, key: &[u8]) -> String {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut block: GenericArray<u8, U16> = GenericArray::clone_from_slice(&[0u8; 16]);
    let pos = password.len();
    block[..pos].copy_from_slice(password.as_bytes());
    Pkcs7::pad(&mut block, pos);
    let mut encrypted_block = block;
    cipher.encrypt_block(&mut encrypted_block);

    encode(encrypted_block)
}
fn decrypt_password(encrypted_password: &str, key: &[u8]) -> String {
    let cipher = Aes256::new(GenericArray::from_slice(key));
    let encrypted_bytes = decode(encrypted_password).expect("Decoding failed");

    let mut block: GenericArray<u8, U16> = GenericArray::clone_from_slice(&encrypted_bytes);
    cipher.decrypt_block(&mut block);

    let decrypted_bytes = Pkcs7::unpad(&block).unwrap();
    String::from_utf8(decrypted_bytes.to_vec()).expect("Invalid UTF-8")
}

fn main() -> std::io::Result<()> {
    dotenv().ok();
    let hostname = unistd::gethostname().expect("Failed getting hostname");
    let hostname = hostname.into_string().expect("Hostname wasn't valid UTF-8");
    let install_location = "/opt/CHM";
    let my_local_ip = local_ip();
    cliclack::clear_screen()?;
    cliclack::intro(style(" CHM Initialize ").on_cyan().black())?;
    let hostname: String = cliclack::input("What's your hostname?")
        .placeholder(&hostname)
        .default_input(&hostname)
        .interact()?;
    let path: String = cliclack::input("Where should we install project?")
        .placeholder(install_location)
        .validate(|input: &String| {
            if input.is_empty() {
                Err("Please enter a path.")
            } else {
                Ok(())
            }
        })
        .default_input(install_location)
        .interact()?;
    let password = cliclack::password("Provide a password")
        .mask('▪')
        .interact()?;
    let network_interfaces = list_afinet_netifas();
    let mut kind_select = cliclack::select("Choose Active IP".to_string());
    if let Ok(interfaces) = network_interfaces {
        for (_, ip) in interfaces.iter() {
            kind_select = kind_select.item(ip.to_string(), ip.to_string(), "");
        }
    } else {
        println!("Error getting network interfaces: {:?}", network_interfaces);
    }
    if let Ok(my_local_ip) = my_local_ip {
        kind_select = kind_select.initial_value(my_local_ip.to_string());
    }
    let kind: String = kind_select.interact()?;

    let tools = cliclack::multiselect("Select additional tools")
        .initial_values(vec!["prettier".to_string(), "eslint".to_string()])
        .item("prettier".to_string(), "Prettier", "recommended")
        .item("eslint".to_string(), "ESLint", "recommended")
        .item("stylelint".to_string(), "Stylelint", "")
        .item("gh-action".to_string(), "GitHub Action", "")
        .interact()?;

    // 密钥（必须是 32 字节）
    let key = env::var("KEY").expect("No KEY Found!"); // 请确保你的密钥长度是32字节
    let key_bytes = key.as_bytes();
    if key_bytes.len() < 32 {
        panic!("Key must be 32 bytes long");
    }
    let key: &[u8; 32] = key_bytes[..32]
        .try_into()
        .expect("Key must be 32 bytes long");

    let encrypted_password = encrypt_password(&password, key);
    let decrypted_password = decrypt_password(&encrypted_password, key);

    println!("Encrypted password: {}", encrypted_password);
    println!("Decrypted password: {}", decrypted_password);

    let config = Config::new(hostname, path, encrypted_password, kind, tools);

    // For debugging: Print the config
    println!("{:#?}", config);
    // 将配置转换为 JSON 并保存到 config.json
    let file = File::create("config.json")?;
    serde_json::to_writer_pretty(&file, &config)?;

    println!("Configuration saved to config.json");
    Ok(())
}
