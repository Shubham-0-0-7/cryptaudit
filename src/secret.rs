//! The secret-bearing heuristic shared by most rules.
//!
//! Names are split into lowercase words (`HMACKey` -> `hmac`, `key`) and matched
//! word-by-word, so `keyboard` and `monkey` never match `key`.

use syn::{GenericArgument, PathArguments, Type};

/// How strongly a name suggests secret material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    /// `key`, `token`: secret in crypto code, but also common in map entries and lexers.
    Weak,
    /// `password`, `secret_key`, `api_key`: secret almost everywhere.
    Strong,
}

/// Words that are secret on their own.
const STRONG: &[&str] = &[
    "secret",
    "secrets",
    "private",
    "priv",
    "privkey",
    "seckey",
    "secretkey",
    "sk",
    "seed",
    "seeds",
    "password",
    "passwords",
    "passwd",
    "passphrase",
    "mnemonic",
    "apikey",
];

/// Words that are secret in crypto code but have common benign uses.
const WEAK: &[&str] = &[
    "key",
    "keys",
    "token",
    "tokens",
    "keypair",
    // Often a public identity (MLS, WebAuthn), so only a hint.
    "credential",
    "credentials",
];

/// Words that upgrade a weak word to strong: `api_key`, `signing_key`, `access_token`.
const QUALIFIERS: &[&str] = &[
    "api",
    "master",
    "signing",
    "sign",
    "session",
    "encryption",
    "enc",
    "decryption",
    "aes",
    "hmac",
    "mac",
    "root",
    "shared",
    "symmetric",
    "sym",
    "derived",
    "aead",
    "cipher",
    "auth",
    "access",
    "refresh",
    "bearer",
    "csrf",
    "jwt",
    "oauth",
    "kek",
    "dek",
    "wrapping",
    "ephemeral",
    "chacha",
];

/// Words that mark a name as metadata about a secret, or as public material.
const EXCLUDED: &[&str] = &[
    "public",
    "pub",
    "pubkey",
    "pk",
    "nonce",
    "nonces",
    "iv",
    "ivs",
    "salt",
    "id",
    "ids",
    "kid",
    "len",
    "length",
    "size",
    "count",
    "index",
    "idx",
    "bits",
    "name",
    "names",
    "path",
    "file",
    "tmp",
    // Handles and slots address a secret; they are not the secret.
    "handle",
    "handles",
    "slot",
    // XOR obfuscation keys are not secrets.
    "xor",
    "obfuscation",
    "obfuscated",
    "temp",
    "dir",
    "directory",
    "folder",
    "type",
    "kind",
    "version",
    "format",
    "fingerprint",
    "hash",
    "algorithm",
    "alg",
    "url",
    "uri",
    "header",
    "expiry",
    "expires",
    "ttl",
    "prefix",
    "label",
    "error",
    "err",
    // Public parts of a protocol: certificates, OCSP staples, KEM ciphertexts.
    "ocsp",
    "cert",
    "certs",
    "certificate",
    "ciphertext",
    "encapsulated",
    "signature",
    "scheme",
    "pwd",
];

/// Splits an identifier into lowercase words on `_`, camelCase, acronym and
/// letter/digit boundaries.
pub fn words(name: &str) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut out = Vec::new();
    let mut cur = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_alphanumeric() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if !cur.is_empty() {
            let prev = chars[i - 1];
            let next = chars.get(i + 1).copied();
            let boundary = (prev.is_lowercase() && c.is_uppercase())
                || (prev.is_alphabetic() != c.is_alphabetic())
                || (prev.is_uppercase()
                    && c.is_uppercase()
                    && next.is_some_and(char::is_lowercase));
            if boundary {
                out.push(std::mem::take(&mut cur));
            }
        }
        cur.extend(c.to_lowercase());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// True if the name describes public material or metadata (`public_key`, `key_id`).
pub fn is_excluded(name: &str) -> bool {
    words(name).iter().any(|w| EXCLUDED.contains(&w.as_str()))
}

/// True if a field name says the value is already encrypted: `encrypted_private_key`,
/// `wrapped_signing_key`. Such a field is ciphertext, not key material.
pub fn is_ciphertext_name(name: &str) -> bool {
    words(name)
        .iter()
        .any(|w| matches!(w.as_str(), "encrypted" | "wrapped"))
}

/// True if the source calls a constant-time comparison under any common name
/// (`ct_eq`, `equal_ct`, `ct_equal`, `constant_time_eq`, `ConstantTimeEq`).
pub fn has_constant_time_call(source: &str) -> bool {
    [
        "ct_eq",
        "equal_ct",
        "ct_equal",
        "constant_time",
        "ConstantTimeEq",
    ]
    .iter()
    .any(|n| source.contains(n))
}

/// True if an integer field name says it is a size or a count: `sk_bytes`,
/// `n_secret`. Such a value describes a secret without being one.
pub fn is_size_name(name: &str) -> bool {
    words(name).iter().any(|w| {
        matches!(
            w.as_str(),
            "n" | "num" | "bytes" | "byte" | "max" | "min" | "limit"
        )
    })
}

/// True if a type name says it holds public material: `PublicKey`, `VerifyingKey`.
/// Its fields are not secret, whatever they are called.
pub fn is_public_name(name: &str) -> bool {
    words(name).iter().any(|w| {
        matches!(
            w.as_str(),
            "public"
                | "pub"
                | "pubkey"
                | "pk"
                | "verifying"
                | "verification"
                | "vk"
                | "encap"
                | "encapsulation"
                | "encapsulated"
        )
    })
}

/// True if the only secret-sounding word is `token`: a lexer token, a ciphertext
/// blob called `raw_token`, a bearer token that is public. Weaker than `key`.
pub fn is_token_only(name: &str) -> bool {
    let ws = words(name);
    ws.iter().any(|w| w == "token" || w == "tokens")
        && !ws.iter().any(|w| {
            STRONG.contains(&w.as_str()) || matches!(w.as_str(), "key" | "keys" | "keypair")
        })
}

/// Classifies a field, variable or type name.
pub fn classify_name(name: &str) -> Option<Strength> {
    let words = words(name);
    let has = |list: &[&str]| words.iter().any(|w| list.contains(&w.as_str()));
    if has(EXCLUDED) {
        None
    } else if has(STRONG) {
        Some(Strength::Strong)
    } else if has(WEAK) {
        Some(if has(QUALIFIERS) {
            Strength::Strong
        } else {
            Strength::Weak
        })
    } else {
        None
    }
}

/// What a value of a type looks like when formatted or copied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeClass {
    /// `secrecy` wrappers: their `Debug` already redacts.
    Redacting,
    /// Byte arrays, `Vec<u8>`, `GenericArray`, `aead::Key<..>`: formatting prints key bytes.
    Bytes,
    /// `String`, `str`.
    Str,
    /// Integers, e.g. an RNG seed.
    Int,
    /// `&'static str`, `&'static [u8]`: fixed at compile time, so a label or a
    /// domain-separation constant, not a runtime secret.
    Static,
    /// Anything else. Whether it leaks depends on that type's own `Debug`.
    Opaque(String),
}

const REDACTING: &[&str] = &[
    "Secret",
    "SecretBox",
    "SecretString",
    "SecretVec",
    "SecretSlice",
];
const WRAPPERS: &[&str] = &[
    "Option",
    "Box",
    "Arc",
    "Rc",
    "Cow",
    "RefCell",
    "Cell",
    "Mutex",
    "RwLock",
    "Zeroizing",
    "Pin",
];
const BYTE_TYPES: &[&str] = &["GenericArray", "Array", "Bytes", "BytesMut"];
const INTS: &[&str] = &[
    "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize",
];

pub fn classify_type(ty: &Type) -> TypeClass {
    match ty {
        Type::Array(a) => match classify_type(&a.elem) {
            TypeClass::Int => TypeClass::Bytes,
            other => other,
        },
        Type::Slice(s) => match classify_type(&s.elem) {
            TypeClass::Int => TypeClass::Bytes,
            other => other,
        },
        Type::Reference(r) => {
            if r.lifetime.as_ref().is_some_and(|l| l.ident == "static") {
                TypeClass::Static
            } else {
                classify_type(&r.elem)
            }
        }
        Type::Group(g) => classify_type(&g.elem),
        Type::Paren(p) => classify_type(&p.elem),
        Type::Path(p) => {
            let Some(seg) = p.path.segments.last() else {
                return TypeClass::Opaque(String::new());
            };
            let ident = seg.ident.to_string();
            let first_arg = first_type_arg(&seg.arguments);
            let name = ident.as_str();
            if REDACTING.contains(&name) {
                TypeClass::Redacting
            } else if WRAPPERS.contains(&name) {
                first_arg.map_or(TypeClass::Opaque(ident.clone()), classify_type)
            } else if name == "Vec" {
                match first_arg.map(classify_type) {
                    Some(TypeClass::Int) => TypeClass::Bytes,
                    Some(other) => other,
                    None => TypeClass::Opaque(ident.clone()),
                }
            } else if BYTE_TYPES.contains(&name) {
                TypeClass::Bytes
            } else if name == "Key" && first_arg.is_some() {
                // `aead::Key<Aes256Gcm>` is a `GenericArray` alias. A bare `Key` is a user type.
                TypeClass::Bytes
            } else if matches!(name, "String" | "str" | "OsString") {
                TypeClass::Str
            } else if INTS.contains(&name) {
                TypeClass::Int
            } else {
                TypeClass::Opaque(ident.clone())
            }
        }
        _ => TypeClass::Opaque(String::new()),
    }
}

fn first_type_arg(args: &PathArguments) -> Option<&Type> {
    let PathArguments::AngleBracketed(args) = args else {
        return None;
    };
    args.args.iter().find_map(|a| match a {
        GenericArgument::Type(t) => Some(t),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_words() {
        assert_eq!(words("HMACKey"), ["hmac", "key"]);
        assert_eq!(words("secretKey"), ["secret", "key"]);
        assert_eq!(words("API_KEY"), ["api", "key"]);
        assert_eq!(words("x25519_secret"), ["x", "25519", "secret"]);
        assert_eq!(words("Aes256GcmKey"), ["aes", "256", "gcm", "key"]);
        assert_eq!(words("__priv"), ["priv"]);
    }

    #[test]
    fn classifies_names() {
        use Strength::{Strong, Weak};
        #[rustfmt::skip]
        let cases: &[(&str, Option<Strength>)] = &[
            // Strong on their own.
            ("password", Some(Strong)), ("user_password", Some(Strong)), ("passwd", Some(Strong)),
            ("pwd", None), ("passphrase", Some(Strong)), ("secret", Some(Strong)),
            ("client_secret", Some(Strong)), ("SecretKey", Some(Strong)), ("secret_key", Some(Strong)),
            ("private_key", Some(Strong)), ("PrivateKey", Some(Strong)), ("privkey", Some(Strong)),
            ("sk", Some(Strong)), ("seed", Some(Strong)), ("rng_seed", Some(Strong)),
            ("mnemonic", Some(Strong)), ("credentials", Some(Weak)), ("StaticSecret", Some(Strong)),
            // Weak words, upgraded by a qualifier.
            ("api_key", Some(Strong)), ("apiKey", Some(Strong)), ("signing_key", Some(Strong)),
            ("SigningKey", Some(Strong)), ("session_key", Some(Strong)), ("hmac_key", Some(Strong)),
            ("HMACKey", Some(Strong)), ("access_token", Some(Strong)), ("refresh_token", Some(Strong)),
            ("master_key", Some(Strong)), ("aes_key", Some(Strong)),
            // Weak words alone.
            ("key", Some(Weak)), ("keys", Some(Weak)), ("token", Some(Weak)), ("Key", Some(Weak)),
            ("keypair", Some(Weak)), ("Token", Some(Weak)),
            // Excluded: public material and metadata.
            ("public_key", None), ("PublicKey", None), ("pubkey", None), ("pk", None),
            ("key_id", None), ("kid", None), ("key_len", None), ("nonce", None), ("iv", None),
            ("salt", None), ("password_hash", None), ("token_kind", None), ("TokenType", None),
            ("secret_len", None), ("key_path", None), ("KeyError", None), ("key_size", None),
            ("seed_len", None),
            // Not secret at all; `key` must match as a whole word.
            ("keyboard", None), ("monkey", None), ("hotkey", None), ("tokenizer", None),
            ("value", None), ("username", None), ("data", None), ("inner", None),
        ];
        for (name, want) in cases {
            assert_eq!(classify_name(name), *want, "{name}");
        }
    }

    #[test]
    fn public_and_token_names() {
        for n in [
            "PublicKey",
            "PasetoAsymmetricPublicKey",
            "VerifyingKey",
            "pubkey",
            "Pk",
        ] {
            assert!(is_public_name(n), "{n}");
        }
        for n in ["SecretKey", "SigningKey", "Publisher", "Session", "key"] {
            assert!(!is_public_name(n), "{n}");
        }
        for n in ["raw_token", "token", "access_token", "Token", "tokens"] {
            assert!(is_token_only(n), "{n}");
        }
        // A token that is also a key is not "token only".
        for n in ["token_key", "secret_token", "api_key", "key", "password"] {
            assert!(!is_token_only(n), "{n}");
        }
    }

    #[test]
    fn classifies_types() {
        let class = |s: &str| classify_type(&syn::parse_str::<Type>(s).unwrap());
        assert_eq!(class("[u8; 32]"), TypeClass::Bytes);
        assert_eq!(class("&[u8]"), TypeClass::Bytes);
        assert_eq!(class("Vec<u8>"), TypeClass::Bytes);
        assert_eq!(class("Box<[u8]>"), TypeClass::Bytes);
        assert_eq!(class("Option<Zeroizing<Vec<u8>>>"), TypeClass::Bytes);
        assert_eq!(class("GenericArray<u8, U32>"), TypeClass::Bytes);
        assert_eq!(class("aead::Key<Aes256Gcm>"), TypeClass::Bytes);
        assert_eq!(class("[u32; 8]"), TypeClass::Bytes);
        assert_eq!(class("String"), TypeClass::Str);
        assert_eq!(class("&'static str"), TypeClass::Static);
        assert_eq!(class("&'static [u8]"), TypeClass::Static);
        assert_eq!(class("&'a str"), TypeClass::Str);
        assert_eq!(class("Option<&'static str>"), TypeClass::Static);
        assert_eq!(class("u64"), TypeClass::Int);
        assert_eq!(class("SecretBox<[u8; 32]>"), TypeClass::Redacting);
        assert_eq!(class("secrecy::SecretString"), TypeClass::Redacting);
        assert_eq!(class("Arc<SecretString>"), TypeClass::Redacting);
        assert_eq!(class("Key"), TypeClass::Opaque("Key".into()));
        assert_eq!(class("SigningKey"), TypeClass::Opaque("SigningKey".into()));
    }
}
