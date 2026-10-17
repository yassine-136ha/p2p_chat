//! نظام مراسلة P2P لامركزي: libp2p (Gossipsub + mDNS) + تشفير طرف-لطرف حقيقي.
//!
//! التشفير: صندوق مختوم (sealed box): مفتاح X25519 مؤقت لكل رسالة + XChaCha20-Poly1305.
//! لا يظهر المستلم في الحزمة؛ كل عقدة تحاول الفك والفاشل يُتجاهل بصمت.
//! هوية المرسل: توقيع Gossipsub الصارم (message.source).

use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use dialoguer::Password;
use ed25519_dalek::{SigningKey, VerifyingKey};
use futures::StreamExt;
use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode},
    identity, mdns, noise,
    swarm::{behaviour::toggle::Toggle, NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, SwarmBuilder,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::HashMap,
    error::Error,
    fs,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublic, StaticSecret};
use zeroize::Zeroize;

static AR: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
fn ar() -> bool {
    *AR.get_or_init(|| std::env::var("CHAT_LANG").map(|v| v.eq_ignore_ascii_case("ar")).unwrap_or(false))
}
/// اختيار النص حسب اللغة (الافتراضي: إنجليزي لأن Termux لا يدعم وصل الحروف العربية)
macro_rules! t {
    ($ar:expr, $en:expr) => {
        if ar() { $ar } else { $en }
    };
}
macro_rules! say {
    ($ar:literal, $en:literal $(, $a:expr)* $(,)?) => {
        if ar() { println!($ar $(, $a)*) } else { println!($en $(, $a)*) }
    };
}

// ───────────── إدخال نصي بسيط (قوائم مرقّمة، بدون أسهم) ─────────────
fn ask(prompt: &str) -> String {
    use std::io::{self, Write};
    print!("{prompt}: ");
    io::stdout().flush().ok();
    let mut l = String::new();
    if io::stdin().read_line(&mut l).unwrap_or(0) == 0 {
        std::process::exit(0); // نهاية الإدخال
    }
    l.trim().to_string()
}

fn ask_default(prompt: &str, def: &str) -> String {
    let a = ask(&format!("{prompt} [{def}]"));
    if a.is_empty() { def.to_string() } else { a }
}

fn confirm(prompt: &str) -> bool {
    matches!(ask(&format!("{prompt} (y/n)")).to_lowercase().as_str(), "y" | "yes" | "ن" | "نعم")
}

/// قائمة مرقّمة: يكتب المستخدم رقم الخيار ثم Enter. يعيد الفهرس (يبدأ من 0).
fn menu(title: &str, items: &[&str]) -> usize {
    loop {
        println!("\n{title}");
        for (i, it) in items.iter().enumerate() {
            println!("  {}. {}", i + 1, it);
        }
        if let Ok(n) = ask(t!("اختر رقماً", "Choose a number")).parse::<usize>() {
            if (1..=items.len()).contains(&n) {
                return n - 1;
            }
        }
        say!("[!] خيار غير صالح", "[!] Invalid choice");
    }
}

// ───────────── وضع Tor ─────────────
// الاستماع: عقدتك تستمع على 127.0.0.1 فقط، و Tor ينشر خدمة .onion تشير إليها (HiddenService).
// الاتصال: لكل عقدة بعيدة نفتح مُمرِّراً محلياً يمرّ عبر وكيل SOCKS5 الخاص بـ Tor إلى عنوان .onion.
// بروتوكول libp2p (Noise + PeerId) يعمل فوق النفق دون تغيير.
fn socks_addr() -> String {
    std::env::var("TOR_SOCKS").unwrap_or_else(|_| "127.0.0.1:9050".into())
}

fn onion_hostname() -> Option<String> {
    let dir = std::env::var("TOR_HS_DIR").unwrap_or_else(|_| {
        format!("{}/var/lib/tor/chat_service", std::env::var("PREFIX").unwrap_or_else(|_| "/usr".into()))
    });
    let h = fs::read_to_string(format!("{dir}/hostname")).ok()?;
    Some(h.trim().to_string())
}

async fn start_forward(host: String, port: u16) -> std::io::Result<u16> {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let lp = l.local_addr()?.port();
    let proxy = socks_addr();
    tokio::spawn(async move {
        while let Ok(Ok((mut inbound, _))) = tokio::time::timeout(Duration::from_secs(300), l.accept()).await {
            let (host, proxy) = (host.clone(), proxy.clone());
            tokio::spawn(async move {
                match tokio_socks::tcp::Socks5Stream::connect(proxy.as_str(), (host.as_str(), port)).await {
                    Ok(mut s) => {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut s).await;
                    }
                    Err(e) => say!("[tor] فشل الاتصال عبر Tor: {}", "[tor] Connection via Tor failed: {}", e),
                }
            });
        }
    });
    Ok(lp)
}

const KEY_FILE: &str = "node_identity.key";
const TOPIC: &str = "decentralized-chat-topic-v1";

// ───────────── الحزم ─────────────
#[derive(Serialize, Deserialize, Debug, Clone)]
enum Packet {
    /// إعلان عن العقدة (يُتحقق من أن المفتاح يطابق مصدر الرسالة الموقّع)
    NodeInfo {
        public_key_hex: String,
        /// عنوان onion للعقدة بالشكل host.onion:port (وضع Tor فقط) لتمكين الاكتشاف التلقائي
        #[serde(default)]
        onion: Option<String>,
    },
    /// رسالة مشفرة؛ لا تحتوي أي معرّف للمستلم
    Sealed { eph_pub: [u8; 32], nonce: [u8; 24], ct: Vec<u8> },
}

enum Cmd {
    Advertise,
    Send { target_hex: String, text: String },
    Dial(Multiaddr),
    DialOnion { host: String, port: u16, peer: Option<PeerId> },
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: Toggle<mdns::tokio::Behaviour>,
}

// ───────────── التشفير ─────────────
fn x_secret_from_seed(seed: &[u8; 32]) -> StaticSecret {
    let h = Sha512::digest(seed);
    let mut b = [0u8; 32];
    b.copy_from_slice(&h[..32]);
    let s = StaticSecret::from(b); // يتم التثبيت (clamp) عند الاستخدام
    b.zeroize();
    s
}

fn derive_key(shared: &[u8; 32], eph: &[u8; 32], rcpt: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"p2p-chat-v1");
    h.update(shared);
    h.update(eph);
    h.update(rcpt);
    h.finalize().into()
}

fn seal(recipient_ed_hex: &str, text: &str) -> Result<Packet, Box<dyn Error>> {
    let raw: [u8; 32] = hex::decode(recipient_ed_hex.trim())?
        .try_into()
        .map_err(|_| t!("طول المفتاح العام غير صحيح (يجب 32 بايت = 64 خانة hex)","Invalid public key length (need 32 bytes = 64 hex chars)"))?;
    let vk = VerifyingKey::from_bytes(&raw).map_err(|_| t!("مفتاح عام غير صالح","Invalid public key"))?;
    let rcpt = XPublic::from(vk.to_montgomery().to_bytes());

    let eph = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = XPublic::from(&eph);
    let shared = eph.diffie_hellman(&rcpt);
    let mut key = derive_key(shared.as_bytes(), eph_pub.as_bytes(), rcpt.as_bytes());

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new((&key).into())
        .encrypt(XNonce::from_slice(&nonce), text.as_bytes())
        .map_err(|_| t!("فشل التشفير","Encryption failed"))?;
    key.zeroize();
    Ok(Packet::Sealed { eph_pub: *eph_pub.as_bytes(), nonce, ct })
}

fn open(eph_pub: &[u8; 32], nonce: &[u8; 24], ct: &[u8], me: &StaticSecret) -> Option<String> {
    let my_pub = XPublic::from(me);
    let shared = me.diffie_hellman(&XPublic::from(*eph_pub));
    let mut key = derive_key(shared.as_bytes(), eph_pub, my_pub.as_bytes());
    let pt = XChaCha20Poly1305::new((&key).into())
        .decrypt(XNonce::from_slice(nonce), ct)
        .ok();
    key.zeroize();
    String::from_utf8(pt?).ok()
}

// ───────────── تخزين المفتاح (مشفّر بكلمة مرور) ─────────────
// الصيغة: salt(16) | nonce(24) | ciphertext(seed 32 + tag 16)
fn pass_key(pass: &str, salt: &[u8]) -> Result<[u8; 32], Box<dyn Error>> {
    let mut out = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(pass.as_bytes(), salt, &mut out)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

fn save_seed(seed: &[u8; 32], pass: &str) -> Result<(), Box<dyn Error>> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let mut k = pass_key(pass, &salt)?;
    let ct = XChaCha20Poly1305::new((&k).into())
        .encrypt(XNonce::from_slice(&nonce), seed.as_slice())
        .map_err(|_| t!("فشل تشفير المفتاح","Key encryption failed"))?;
    k.zeroize();
    let mut blob = Vec::new();
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);

    #[cfg(unix)]
    {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let mut f = fs::OpenOptions::new()
            .write(true).create(true).truncate(true).mode(0o600)
            .open(KEY_FILE)?;
        f.write_all(hex::encode(blob).as_bytes())?;
    }
    #[cfg(not(unix))]
    fs::write(KEY_FILE, hex::encode(blob))?;
    Ok(())
}

fn load_seed(pass: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let blob = hex::decode(fs::read_to_string(KEY_FILE)?.trim())?;
    if blob.len() < 16 + 24 + 48 {
        return Err(t!("ملف المفتاح تالف","Key file is corrupted").into());
    }
    let (salt, rest) = blob.split_at(16);
    let (nonce, ct) = rest.split_at(24);
    let mut k = pass_key(pass, salt)?;
    let pt = XChaCha20Poly1305::new((&k).into())
        .decrypt(XNonce::from_slice(nonce), ct)
        .map_err(|_| t!("كلمة المرور خاطئة أو الملف تالف","Wrong password or corrupted file"))?;
    k.zeroize();
    pt.try_into().map_err(|_| t!("طول المفتاح غير صحيح","Invalid key length").into())
}

// ───────────── البرنامج ─────────────
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    say!("== نظام مراسلة P2P لامركزي مشفّر (libp2p + E2E) ==", "== Decentralized encrypted P2P chat (libp2p + E2E) ==");

    // 1) الهوية
    let choice = menu(
        t!("إدارة الهوية", "Identity"),
        &[t!("إنشاء هوية جديدة", "Create new identity"), t!("تحميل الهوية القديمة من الملف", "Load existing identity from file")],
    );

    let mut seed: [u8; 32] = if choice == 0 {
        if Path::new(KEY_FILE).exists()
            && !confirm(t!("يوجد ملف هوية سابق وسيُستبدل نهائياً. متابعة؟", "An identity file exists and will be permanently replaced. Continue?"))
        {
            return Ok(());
        }
        let pass = Password::new()
            .with_prompt(t!("كلمة مرور لحماية المفتاح", "Password to protect your key"))
            .with_confirmation(t!("أعد كتابتها", "Repeat password"), t!("غير متطابقة", "Does not match"))
            .interact()?;
        let sk = SigningKey::generate(&mut OsRng);
        save_seed(&sk.to_bytes(), &pass)?;
        say!("[✓] حُفظ المفتاح مشفّراً في {}", "[✓] Key saved (encrypted) to {}", KEY_FILE);
        sk.to_bytes()
    } else {
        if !Path::new(KEY_FILE).exists() {
            say!("[!] لا يوجد ملف مفتاح. أنشئ هوية أولاً.", "[!] No key file found. Create an identity first.");
            return Ok(());
        }
        let pass = Password::new().with_prompt(t!("كلمة المرور", "Password")).interact()?;
        match load_seed(&pass) {
            Ok(s) => s,
            Err(e) => {
                println!("[!] {e}");
                return Ok(());
            }
        }
    };

    let sk = SigningKey::from_bytes(&seed);
    let my_pub_hex = hex::encode(sk.verifying_key().as_bytes());
    let my_xsecret = Arc::new(x_secret_from_seed(&seed));
    let mut kp_bytes = seed;
    let keypair = identity::Keypair::ed25519_from_bytes(&mut kp_bytes)?;
    seed.zeroize();
    kp_bytes.zeroize();
    let local_peer_id = PeerId::from(keypair.public());

    println!("--------------------------------------------------");
    say!("🔑 مفتاحك العام (شاركه): {}", "🔑 Your public key (share it): {}", my_pub_hex);
    println!("🌐 PeerId: {local_peer_id}");
    println!("--------------------------------------------------");

    // 2) الشبكة
    let use_tor = std::env::var("CHAT_TOR").is_ok()
        || confirm(t!("استخدام Tor؟ (يتطلب تشغيل tor على الجهاز)", "Use Tor? (requires the tor daemon running)"));
    let topic = IdentTopic::new(TOPIC);
    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key| {
            let cfg = gossipsub::ConfigBuilder::default()
                .validation_mode(ValidationMode::Strict)
                .heartbeat_interval(Duration::from_secs(1))
                .build()
                .map_err(|e| e.to_string())?;
            let gossipsub = gossipsub::Behaviour::new(MessageAuthenticity::Signed(key.clone()), cfg)
                .map_err(|e| e.to_string())?;
            // في وضع Tor نُعطّل mDNS لأنه يكشف وجودك على الشبكة المحلية
            let mdns: Toggle<mdns::tokio::Behaviour> = if use_tor {
                Toggle::from(None)
            } else {
                Toggle::from(Some(mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?))
            };
            Ok(Behaviour { gossipsub, mdns })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    let port: String = ask_default(t!("منفذ الاستماع", "Listen port"), "8001");
    let bind_ip = if use_tor { "127.0.0.1" } else { "0.0.0.0" };
    swarm.listen_on(format!("/ip4/{bind_ip}/tcp/{port}").parse()?)?;
    if use_tor {
        say!("[tor] الاستماع على 127.0.0.1 فقط. أضف إلى torrc:\n      HiddenServiceDir <مجلد>/chat_service/\n      HiddenServicePort {} 127.0.0.1:{}",
             "[tor] Listening on 127.0.0.1 only. Add to torrc:\n      HiddenServiceDir <dir>/chat_service/\n      HiddenServicePort {} 127.0.0.1:{}", port, port);
        match onion_hostname() {
            Some(h) => say!("[tor] عنوانك للمشاركة: {}:{} {}", "[tor] Your address to share: {}:{} {}", h, port, local_peer_id),
            None => say!("[tor] لم أجد ملف hostname بعد (شغّل tor أولاً)", "[tor] hostname file not found yet (start tor first)"),
        }
    }

    let peers: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Cmd>();

    // 3) حلقة الشبكة (تملك الـ swarm)
    {
        let peers = peers.clone();
        let my_pub_hex = my_pub_hex.clone();
        let xsecret = my_xsecret.clone();
        let task_port = port.clone();
        tokio::spawn(async move {
            let publish = |swarm: &mut libp2p::Swarm<Behaviour>, p: &Packet| -> Result<(), String> {
                let data = serde_json::to_vec(p).map_err(|e| e.to_string())?;
                swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), data)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            };
            let make_info = || Packet::NodeInfo {
                public_key_hex: my_pub_hex.clone(),
                onion: if use_tor { onion_hostname().map(|h| format!("{h}:{task_port}")) } else { None },
            };
            let mut tried: HashMap<PeerId, std::time::Instant> = HashMap::new();
            let mut tick = tokio::time::interval(Duration::from_secs(20));
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        let _ = publish(&mut swarm, &make_info());
                    }
                    cmd = rx.recv() => match cmd {
                        None => break,
                        Some(Cmd::Advertise) => {
                            match publish(&mut swarm, &make_info()) {
                                Ok(()) => say!("[✓] تم البث", "[✓] Advertised"),
                                Err(e) => say!("[!] تعذر البث: {} (لا يوجد أقران بعد؟)", "[!] Advertise failed: {} (no peers yet?)", e),
                            }
                        }
                        Some(Cmd::Send { target_hex, text }) => {
                            match seal(&target_hex, &text) {
                                Err(e) => println!("[!] {e}"),
                                Ok(p) => match publish(&mut swarm, &p) {
                                    Ok(()) => say!("[✓] أُرسلت مشفّرة (لا نسخة محلية)", "[✓] Sent encrypted (no local copy)"),
                                    Err(e) => say!("[!] تعذر الإرسال: {} (لا يوجد أقران متصلون؟)", "[!] Send failed: {} (no connected peers?)", e),
                                },
                            }
                        }
                        Some(Cmd::DialOnion { host, port, peer }) => {
                            match start_forward(host, port).await {
                                Ok(lp) => {
                                    let mut a = format!("/ip4/127.0.0.1/tcp/{lp}");
                                    if let Some(pid) = peer { a.push_str(&format!("/p2p/{pid}")); }
                                    match a.parse::<Multiaddr>() {
                                        Ok(a) => if let Err(e) = swarm.dial(a) {
                                            say!("[!] فشل الاتصال: {}", "[!] Dial failed: {}", e);
                                        } else {
                                            say!("[tor] جارٍ الاتصال عبر Tor (قد يستغرق دقيقة)...", "[tor] Connecting via Tor (may take up to a minute)...");
                                        },
                                        Err(e) => say!("[!] عنوان غير صالح: {}", "[!] Invalid address: {}", e),
                                    }
                                }
                                Err(e) => say!("[!] تعذر فتح الممرِّر المحلي: {}", "[!] Could not open local forwarder: {}", e),
                            }
                        }
                        Some(Cmd::Dial(a)) => {
                            if let Err(e) = swarm.dial(a) { say!("[!] فشل الاتصال: {}", "[!] Dial failed: {}", e); }
                        }
                    },
                    ev = swarm.select_next_some() => match ev {
                        SwarmEvent::NewListenAddr { address, .. } => say!("[*] أستمع على {}", "[*] Listening on {}", address),
                        SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                            for (pid, addr) in list {
                                say!("[mDNS] عقدة محلية: {}", "[mDNS] Local peer: {}", pid);
                                swarm.behaviour_mut().gossipsub.add_explicit_peer(&pid);
                                let _ = addr;
                            }
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                            for (pid, _) in list {
                                swarm.behaviour_mut().gossipsub.remove_explicit_peer(&pid);
                            }
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { .. })) => {
                            let _ = publish(&mut swarm, &make_info());
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                            let Ok(packet) = serde_json::from_slice::<Packet>(&message.data) else { continue };
                            match packet {
                                Packet::NodeInfo { public_key_hex, onion } => {
                                    // تحقق: المفتاح المعلن يجب أن يشتق نفس PeerId الموقّع للرسالة
                                    let Some(src) = message.source else { continue };
                                    let Ok(raw) = hex::decode(&public_key_hex) else { continue };
                                    let Ok(epk) = identity::ed25519::PublicKey::try_from_bytes(&raw) else { continue };
                                    if PeerId::from(identity::PublicKey::from(epk)) != src { continue }
                                    let is_new = {
                                        let mut map = peers.lock().unwrap();
                                        map.insert(src.to_string(), public_key_hex.clone()).is_none()
                                    };
                                    if is_new {
                                        say!("\n[+] عقدة جديدة: {}\n    المفتاح: {}", "\n[+] New peer: {}\n    Key: {}", src, public_key_hex);
                                    }
                                    // اكتشاف تلقائي عبر Tor: نتصل بالعقدة المعلنة (ويتحقق Noise من أنها تملك PeerId المعلن)
                                    let retry_ok = tried.get(&src).map_or(true, |t| t.elapsed() > Duration::from_secs(120));
                                    if use_tor && src != local_peer_id && tried.len() < 50 && retry_ok && !swarm.is_connected(&src) {
                                        if let Some((h, pt)) = onion
                                            .as_deref()
                                            .and_then(|o| o.rsplit_once(':'))
                                            .and_then(|(h, p)| Some((h.to_string(), p.parse::<u16>().ok()?)))
                                        {
                                            if h.len() == 62 && h.ends_with(".onion") {
                                                tried.insert(src, std::time::Instant::now());
                                                if let Ok(lp) = start_forward(h, pt).await {
                                                    if let Ok(a) = format!("/ip4/127.0.0.1/tcp/{lp}/p2p/{src}").parse::<Multiaddr>() {
                                                        if swarm.dial(a).is_ok() {
                                                            say!("[tor] اتصال تلقائي بعقدة مكتشفة: {}", "[tor] Auto-connecting to discovered peer: {}", src);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                Packet::Sealed { eph_pub, nonce, ct } => {
                                    // فشل الفك = ليست لنا → تجاهل صامت
                                    if let Some(text) = open(&eph_pub, &nonce, &ct, &xsecret) {
                                        let from = message.source.map(|p| p.to_string()).unwrap_or_default();
                                        say!("\n──────── رسالة مشفّرة وصلتك ────────", "\n──────── Encrypted message received ────────");
                                        say!("من: {}\n{}", "From: {}\n{}", from, text);
                                        println!("──────────────────────────────────");
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        });
    }

    // 4) القائمة (dialoguer متزامن → spawn_blocking)
    loop {
        let sel = tokio::task::spawn_blocking(|| {
            menu(
                t!("--- القائمة ---", "--- Menu ---"),
                &[
                    t!("عرض مفتاحي ومعرّفي", "Show my key and PeerId"),
                    t!("العقد المكتشفة", "Discovered peers"),
                    t!("بث معلومات عقدتي", "Advertise my node"),
                    t!("إرسال رسالة مشفّرة", "Send encrypted message"),
                    t!("الاتصال بعقدة يدوياً (multiaddr)", "Dial a peer manually (multiaddr)"),
                    t!("خروج", "Quit"),
                ],
            )
        })
        .await?;

        match sel {
            0 => {
                println!("🔑 {my_pub_hex}\n🌐 {local_peer_id}");
                if use_tor {
                    match onion_hostname() {
                        Some(h) => println!("🧅 {h}:{port} {local_peer_id}"),
                        None => say!("🧅 لا يوجد عنوان onion بعد", "🧅 No onion address yet"),
                    }
                }
            }
            1 => {
                let map = peers.lock().unwrap();
                if map.is_empty() {
                    say!("لا توجد عقد بعد.", "No peers yet.");
                }
                for (i, (pid, k)) in map.iter().enumerate() {
                    println!("{}. {pid}\n   {k}", i + 1);
                }
            }
            2 => { tx.send(Cmd::Advertise)?; }
            3 => {
                let (target_hex, text) = tokio::task::spawn_blocking(|| {
                    let t = ask(t!("المفتاح العام للمستلم (hex)", "Recipient public key (hex)"));
                    let m = ask(t!("الرسالة", "Message"));
                    (t, m)
                })
                .await?;
                tx.send(Cmd::Send { target_hex, text })?;
            }
            4 => {
                let prompt = if use_tor {
                    t!("عنوان العقدة: xxxx.onion:8001 [PeerId اختياري]", "Peer address: xxxx.onion:8001 [optional PeerId]")
                } else {
                    t!("مثال: /ip4/1.2.3.4/tcp/8001", "e.g. /ip4/1.2.3.4/tcp/8001")
                };
                let a: String = tokio::task::spawn_blocking(move || ask(prompt)).await?;
                if use_tor {
                    let mut it = a.split_whitespace();
                    let target = it.next().unwrap_or("");
                    let peer = it.next().and_then(|x| x.parse::<PeerId>().ok());
                    match target.rsplit_once(':').and_then(|(h, p)| Some((h, p.parse::<u16>().ok()?))) {
                        Some((h, pt)) if h.ends_with(".onion") => {
                            tx.send(Cmd::DialOnion { host: h.to_string(), port: pt, peer })?;
                        }
                        _ => say!("[!] في وضع Tor يُقبل عنوان .onion فقط بالشكل host.onion:port", "[!] In Tor mode only host.onion:port is accepted"),
                    }
                } else {
                    match a.parse() {
                        Ok(addr) => { tx.send(Cmd::Dial(addr))?; }
                        Err(e) => say!("[!] عنوان غير صالح: {}", "[!] Invalid address: {}", e),
                    }
                }
            }
            _ => break,
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    say!("إغلاق العقدة.", "Node closed.");
    Ok(())
}
