use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

fn gen_key() -> [u8; 32] {
    let mut rng = SmallRng::from_entropy();
    let key: [u8; 32] = rng.gen(); // expect: CA023 medium
    key
}

fn fill_nonce() -> [u8; 12] {
    let mut rng = SmallRng::from_entropy();
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce); // expect: CA023 high
    nonce
}

fn salt() -> Vec<u8> {
    let mut rng = rand_pcg::Pcg64::from_entropy();
    let salt: Vec<u8> = (0..16).map(|_| rng.gen()).collect(); // expect: CA023 high
    salt
}

fn session() -> String {
    let mut rng = SmallRng::from_entropy();
    let session_token: String = (0..32).map(|_| rng.sample(rand::distributions::Alphanumeric) as char).collect(); // expect: CA023 high
    session_token
}

fn fastrand_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for b in key.iter_mut() {
        *b = fastrand::u8(..);
    }
    key
}

fn fastrand_secret() -> u64 {
    let secret = fastrand::u64(..); // expect: CA023 high
    secret
}

struct Config {
    api_key: String,
    iv: [u8; 16],
}

fn build(rng: &mut SmallRng) -> Config {
    let mut rng = SmallRng::from_entropy();
    Config {
        api_key: rng.sample_iter(rand::distributions::Alphanumeric).take(32).map(char::from).collect(), // expect: CA023 high
        iv: rng.gen(), // expect: CA023 high
    }
}

fn assign() {
    let mut rng = oorandom::Rand64::new(1);
    let mut password = 0u64;
    password = rng.rand_u64(); // expect: CA023 high
}
