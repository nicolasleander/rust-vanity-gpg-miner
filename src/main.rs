#[global_allocator]
#[cfg(not(target_env = "msvc"))]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[cfg(target_env = "msvc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use dashmap::DashSet;
use indicatif::{ProgressBar, ProgressStyle};
use lazy_static::lazy_static;
use parking_lot::Mutex;
use rayon::prelude::*;
use rustc_hash::FxHashSet;
use sequoia_openpgp::{
    cert::{CertBuilder, CipherSuite},
    packet::prelude::*,
    serialize::Marshal,
    types::*,
    Cert, Result,
};
use std::iter;
use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

const BUFFER_SIZE: usize = 32768;
const PROGRESS_UPDATE_MS: u64 = 100;
const DEFAULT_TOTAL_KEYS: usize = 2_000_000;
const THREAD_STACK_SIZE: usize = 4 * 1024 * 1024;

struct Config {
    name: String,
    email: String,
    export_dir: PathBuf,
    total_keys: usize,
}

struct Stats {
    keys_checked: AtomicUsize,
    keys_found: AtomicUsize,
    start_time: Instant,
}

struct PatternCache {
    patterns: FxHashSet<String>,
}

impl PatternCache {
    fn new(patterns: Vec<String>) -> Self {
        Self {
            patterns: patterns.into_iter().collect(),
        }
    }

    #[inline(always)]
    fn contains<'a>(&self, key_id: &'a str) -> Option<&'a str> {
        if key_id.len() >= 40 {
            let target_section = &key_id[24..32];
            if self.patterns.contains(target_section) {
                return Some(target_section);
            }
        }
        None
    }
}

lazy_static! {
    static ref LOG_MUTEX: Mutex<()> = Mutex::new(());
    static ref PATTERN_CACHE: PatternCache = PatternCache::new(generate_patterns());
    static ref FOUND_KEYS: DashSet<String> = DashSet::new();
}

#[inline(always)]
fn generate_key(uid: &UserID) -> Result<(Cert, String)> {
    let (cert, _) = CertBuilder::new()
        .add_userid(uid.clone())
        .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
        .set_cipher_suite(CipherSuite::Cv25519)
        .add_subkey(
            KeyFlags::empty()
                .set_transport_encryption()
                .set_storage_encryption(),
            None,
            CipherSuite::Cv25519,
        )
        .generate()?;

    let key_id = cert.fingerprint().to_hex();
    Ok((cert, key_id))
}

fn generate_patterns() -> Vec<String> {
    let mut patterns = Vec::new();
    const HEX_WORDS: &[&str] = &[
        "DEAD", "BEEF", "CAFE", "BABE", "FACE", "FEED", "F00D", "FADE", "ACE0", "BAD0", "DAD0",
        "DEAF", "DEED", "B00T", "C0DE", "1337", "D00M", "B105", "CA11", "0000", "1111", "2222",
        "3333", "4444", "5555", "6666", "7777", "8888", "9999", "AAAA", "BBBB", "CCCC", "DDDD",
        "EEEE", "FFFF", "A0A0", "B1B1", "C2C2", "D3D3", "E4E4", "F5F5", "0F0F", "1E1E", "2D2D",
        "3C3C", "4B4B", "5A5A",
    ];

    for w1 in HEX_WORDS {
        for w2 in HEX_WORDS {
            patterns.push(format!("{}{}", w1, w2));
        }
    }

    patterns.extend(
        ["DEADBEEF", "CAFEBABE", "FEEDFACE"]
            .iter()
            .map(|&s| s.to_string()),
    );

    for digit in "0123456789ABCDEF".chars() {
        patterns.push(iter::repeat(digit).take(8).collect::<String>());
    }

    for d1 in "0123456789ABCDEF".chars() {
        for d2 in "0123456789ABCDEF".chars() {
            if d1 != d2 {
                let pair = format!("{}{}", d1, d2);
                patterns.push(pair.repeat(4));
            }
        }
    }

    patterns.push("0123456789ABCDEF".chars().cycle().take(8).collect());
    patterns.push("FEDCBA9876543210".chars().cycle().take(8).collect());

    patterns.sort_unstable();
    patterns.dedup();
    patterns
}

fn save_key(cert: &Cert, key_id: &str, pattern: &str, index: usize, config: &Config) -> Result<()> {
    let _lock = LOG_MUTEX.lock();

    let public_path = config.export_dir.join(format!("public_key_{}.asc", index));
    let mut writer = BufWriter::with_capacity(BUFFER_SIZE, File::create(public_path)?);
    cert.armored().serialize(&mut writer)?;
    writer.flush()?;

    let private_path = config.export_dir.join(format!("private_key_{}.asc", index));
    let mut writer = BufWriter::with_capacity(BUFFER_SIZE, File::create(private_path)?);
    cert.as_tsk().armored().serialize(&mut writer)?;
    writer.flush()?;

    let log_path = config.export_dir.join("found_keys.txt");
    let mut writer = BufWriter::with_capacity(
        BUFFER_SIZE,
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?,
    );
    writeln!(
        writer,
        "[{}] {} - Matched pattern: {}",
        index, key_id, pattern
    )?;
    writer.flush()?;

    Ok(())
}

fn mine_keys(config: Arc<Config>, stats: Arc<Stats>) -> Result<()> {
    let uid = UserID::from(format!("{} <{}>", config.name, config.email));
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(rayon::current_num_threads())
        .stack_size(THREAD_STACK_SIZE)
        .build()
        .unwrap();

    pool.install(|| {
        (0..config.total_keys)
            .par_bridge()
            .try_for_each(|_| -> Result<()> {
                let current = stats.keys_checked.load(Ordering::Relaxed);
                if current >= config.total_keys {
                    return Ok(());
                }

                if let Ok((cert, key_id)) = generate_key(&uid) {
                    if let Some(pattern) = PATTERN_CACHE.contains(&key_id) {
                        if FOUND_KEYS.insert(key_id.clone()) {
                            let found = stats.keys_found.fetch_add(1, Ordering::Relaxed);
                            println!("\nMATCH FOUND! Key: {} Pattern: {}", key_id, pattern);
                            if let Err(e) = save_key(&cert, &key_id, pattern, found, &config) {
                                eprintln!("Error saving key: {}", e);
                            }
                        }
                    }
                    stats.keys_checked.fetch_add(1, Ordering::Relaxed);
                }
                Ok(())
            })
    })?;

    Ok(())
}

fn display_progress(total: usize, stats: Arc<Stats>) {
    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );

    while stats.keys_checked.load(Ordering::Relaxed) < total {
        let current = stats.keys_checked.load(Ordering::Relaxed);
        let found = stats.keys_found.load(Ordering::Relaxed);
        pb.set_position(current as u64);

        let elapsed = stats.start_time.elapsed();
        let speed = if elapsed.as_secs() > 0 {
            current as u64 / elapsed.as_secs()
        } else {
            0
        };

        pb.set_message(format!("({}/s) | Found: {}", speed, found));
        std::thread::sleep(Duration::from_millis(PROGRESS_UPDATE_MS));
    }

    pb.finish_with_message("Done!");
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || args.len() > 4 {
        eprintln!(
            "Usage: {} \"Your Name\" \"your.email@example.com\" [total_keys]",
            args[0]
        );
        std::process::exit(1);
    }

    let total_keys = args
        .get(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_TOTAL_KEYS);

    let config = Arc::new(Config {
        name: args[1].clone(),
        email: args[2].clone(),
        export_dir: PathBuf::from("./gpg_export"),
        total_keys,
    });

    let stats = Arc::new(Stats {
        keys_checked: AtomicUsize::new(0),
        keys_found: AtomicUsize::new(0),
        start_time: Instant::now(),
    });

    fs::create_dir_all(&config.export_dir)?;

    let stats_clone = Arc::clone(&stats);
    let total = config.total_keys;
    std::thread::spawn(move || {
        display_progress(total, stats_clone);
    });

    mine_keys(config, stats)?;

    Ok(())
}
