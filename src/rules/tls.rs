//! CA064, CA065, CA066: certificate, hostname and token verification switched off.
//!
//! These are the cheapest rules to get right: the unsafe switch has a fixed name
//! (`danger_accept_invalid_certs`) and almost no benign use outside tests.

use proc_macro2::{Span, TokenStream, TokenTree};
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprAssign, ExprCall, ExprMethodCall, ExprPath, ExprStruct, ImplItemFn, Lit};

use super::{Rule, RuleMeta};
use crate::finding::{Confidence, Finding, Severity};
use crate::secret::words;
use crate::source::ParsedFile;

pub static CERT_META: RuleMeta = RuleMeta {
    id: "CA064",
    name: "tls-certificate-validation-disabled",
    severity: Severity::Critical,
    explain: "\
CA064: TLS certificate validation switched off

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

When a program connects over TLS it checks the server's certificate: is it
signed by an authority I trust, has it expired, is it really the server I
meant to reach? That check is the whole point of TLS. With it off, the
connection is still encrypted, but the program will happily encrypt it to
whoever answers. Anyone on the network path (a shared Wi-Fi, a hostile
router, a compromised DNS server) can pose as the server, read everything
sent, and change the replies. It is called a man-in-the-middle attack.

The usual story is that someone hit a certificate error against a test server
or a self-signed certificate, found this switch, and left it in.

Detected:
  reqwest, native-tls, attohttpc  `danger_accept_invalid_certs(true)`
  lettre                          `dangerous_accept_invalid_certs(true)`
  ureq                            `disable_verification(true)`
  isahc                           `SslOption::DANGER_ACCEPT_INVALID_CERTS`
  curl                            `ssl_verify_peer(false)`
  openssl                         `set_verify(SslVerifyMode::NONE)`, and a
                                  `set_verify_callback` closure that returns true
  redis                           `TcpTls { insecure: true }`
  rustls                          a `ServerCertVerifier` whose
                                  `verify_server_cert` accepts without looking,
                                  or a custom verifier named like `NoVerifier`,
                                  `InsecureVerifier`, `SkipServerVerification`

Fix: trust the certificate authority that signed the server's certificate
(`add_root_certificate`), or pin the certificate, and keep validation on.

Confidence:
  high    the switch is a literal `true` (or `false` where the flag is inverted)
  medium  the same, but only inside an `if` or `match`: an explicit opt-in such
          as an `--insecure` command-line flag. Still dangerous, but chosen.
  low     the switch is a variable, so it may be off or on

Known false positives: a developer tool whose purpose is to talk to servers
with self-signed certificates, where the flag is a setting the user turns on.
",
};

pub static HOST_META: RuleMeta = RuleMeta {
    id: "CA065",
    name: "tls-hostname-verification-disabled",
    severity: Severity::Critical,
    explain: "\
CA065: TLS hostname verification switched off

    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_hostnames(true)
        .build()?;

A certificate says \"I am bank.example\", signed by an authority. Checking the
signature is not enough: the program must also check that the name in the
certificate is the name it was trying to reach. If it skips that, then any
valid certificate for any site works. An attacker can get a perfectly
legitimate certificate for their own domain, and the program accepts it as
the bank.

Not reported: OpenSSL's `set_verify_hostname(false)` in a file that also calls
`add_host`, `set_host` or `set1_host`: the name is then checked by hand.

Detected: `danger_accept_invalid_hostnames(true)` (reqwest, native-tls),
`dangerous_accept_invalid_hostnames(true)` (lettre),
`SslOption::DANGER_ACCEPT_INVALID_HOSTS` (isahc), `ssl_verify_host(false)`
(curl) and `verify_hostname(false)` / `set_verify_hostname(false)` (openssl).

Fix: remove the switch. If the server is reached by IP address or an internal
name that does not match its certificate, give it a certificate that does.

Confidence is graded as for CA064.
",
};

pub static JWT_META: RuleMeta = RuleMeta {
    id: "CA066",
    name: "jwt-verification-disabled",
    severity: Severity::Critical,
    explain: "\
CA066: JSON Web Token signature check disabled, or algorithm taken from the token

    let data = jsonwebtoken::dangerous_insecure_decode::<Claims>(&token)?;

A JSON Web Token (JWT) is a login ticket: \"user 42 is an admin\", plus a
signature that proves the server issued it. If the program decodes the ticket
without checking the signature, anyone can write their own ticket saying
whatever they like, and the program believes it.

A related mistake is letting the token choose how it is verified:

    let header = jsonwebtoken::decode_header(&token)?;
    let validation = Validation::new(header.alg);   // the attacker picks `alg`

The `alg` field of a token is written by whoever made the token. Old libraries
accepted `alg: none` (no signature at all), or let an attacker switch from an
asymmetric algorithm to HMAC and use the public key as the HMAC secret.
Decide the algorithm in your own code and never read it from the token.

Detected: `dangerous_insecure_decode`, `dangerous_insecure_decode_with_validation`,
`insecure_disable_signature_validation()`, `validation.validate_signature = false`
and `Validation::new(<something>.alg)`.

Confidence:
  high    signature checking is switched off
  medium  the algorithm comes from the token header
",
};

pub struct CertValidation;
pub struct HostnameValidation;
pub struct JwtValidation;

impl Rule for CertValidation {
    fn meta(&self) -> &'static RuleMeta {
        &CERT_META
    }
    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        scan(file, CERT_META.id)
    }
}

impl Rule for HostnameValidation {
    fn meta(&self) -> &'static RuleMeta {
        &HOST_META
    }
    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        scan(file, HOST_META.id)
    }
}

impl Rule for JwtValidation {
    fn meta(&self) -> &'static RuleMeta {
        &JWT_META
    }
    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        scan(file, JWT_META.id)
    }
}

fn scan(file: &ParsedFile, rule: &'static str) -> Vec<Finding> {
    let mut v = Visitor {
        file,
        rule,
        conditional: 0,
        out: Vec::new(),
        verifier_impls: Vec::new(),
        verifier_in_use: false,
    };
    v.visit_file(&file.ast);
    // One finding per problem: where an accept-all verifier is switched on in
    // this file, the impl that defines it adds nothing.
    if !v.verifier_in_use {
        v.out.append(&mut v.verifier_impls);
    }
    v.out
}

/// Which switch a method call or path turns.
struct Switch {
    meta: &'static RuleMeta,
    /// The flag is `true` when validation is off (`danger_accept_invalid_certs(true)`),
    /// or `false` when it is on (`ssl_verify_peer(false)` is the unsafe one).
    unsafe_value: bool,
}

fn method_switch(name: &str) -> Option<Switch> {
    let (meta, unsafe_value) = match name {
        "danger_accept_invalid_certs" | "dangerous_accept_invalid_certs" => (&CERT_META, true),
        "disable_verification" => (&CERT_META, true),
        "ssl_verify_peer" => (&CERT_META, false),
        "danger_accept_invalid_hostnames" | "dangerous_accept_invalid_hostnames" => {
            (&HOST_META, true)
        }
        "ssl_verify_host" | "verify_hostname" | "set_verify_hostname" => (&HOST_META, false),
        _ => return None,
    };
    Some(Switch { meta, unsafe_value })
}

fn bool_lit(expr: &Expr) -> Option<bool> {
    match expr {
        Expr::Lit(l) => match &l.lit {
            Lit::Bool(b) => Some(b.value),
            _ => None,
        },
        Expr::Paren(p) => bool_lit(&p.expr),
        Expr::Group(g) => bool_lit(&g.expr),
        _ => None,
    }
}

fn idents_in(tokens: TokenStream, out: &mut Vec<String>) {
    for tt in tokens {
        match tt {
            TokenTree::Ident(i) => out.push(i.to_string()),
            TokenTree::Group(g) => idents_in(g.stream(), out),
            _ => {}
        }
    }
}

/// A verifier type named for what it does not do: `NoCertificateVerification`,
/// `InsecureVerifier`, `SkipServerVerification`, `AcceptAnyCert`.
fn insecure_verifier_name(name: &str) -> bool {
    let ws = words(name);
    let has = |list: &[&str]| ws.iter().any(|w| list.contains(&w.as_str()));
    let check = &[
        "verification",
        "verifier",
        "verify",
        "validation",
        "validator",
        "cert",
        "certificate",
        "certs",
    ];
    has(&["insecure", "dangerous", "dummy", "unverified", "noop"])
        || (has(&["no", "skip", "disabled", "disable"]) && has(check))
        || (has(&["accept"]) && has(&["all", "any"]))
}

/// `Ok(ServerCertVerified::assertion())` and nothing else: a verifier that
/// accepts every certificate.
fn accepts_everything(f: &ImplItemFn) -> bool {
    let [syn::Stmt::Expr(expr, _)] = f.block.stmts.as_slice() else {
        return false;
    };
    let expr = match expr {
        Expr::Return(r) => match &r.expr {
            Some(e) => &**e,
            None => return false,
        },
        e => e,
    };
    let Expr::Call(call) = expr else {
        return false;
    };
    let Expr::Path(func) = &*call.func else {
        return false;
    };
    if func.path.segments.last().is_none_or(|s| s.ident != "Ok") {
        return false;
    }
    let Some(Expr::Call(inner)) = call.args.first() else {
        return false;
    };
    let Expr::Path(inner_func) = &*inner.func else {
        return false;
    };
    let segs: Vec<String> = inner_func
        .path
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect();
    segs.len() >= 2
        && segs[segs.len() - 2] == "ServerCertVerified"
        && matches!(segs[segs.len() - 1].as_str(), "assertion" | "new")
}

struct Visitor<'a> {
    file: &'a ParsedFile,
    rule: &'static str,
    /// Depth of enclosing `if` / `match` branches: an opt-in flag, not a constant.
    conditional: usize,
    out: Vec<Finding>,
    /// Accept-all `verify_server_cert` impls, kept only if nothing here uses one.
    verifier_impls: Vec<Finding>,
    verifier_in_use: bool,
}

impl Visitor<'_> {
    fn report(
        &mut self,
        meta: &'static RuleMeta,
        confidence: Confidence,
        span: Span,
        message: String,
        help: &str,
    ) {
        if meta.id == self.rule {
            self.out
                .push(self.file.finding(meta, confidence, span, message, help));
        }
    }

    /// High for a constant switch, medium when it sits inside an `if` or `match`.
    fn flag_level(&self) -> Confidence {
        if self.conditional > 0 {
            Confidence::Medium
        } else {
            Confidence::High
        }
    }

    /// Confidence for a flag argument, or `None` if it is the safe value.
    fn flag_confidence(&self, arg: &Expr, unsafe_value: bool) -> Option<Confidence> {
        match bool_lit(arg) {
            Some(v) if v == unsafe_value => Some(if self.conditional > 0 {
                Confidence::Medium
            } else {
                Confidence::High
            }),
            Some(_) => None,
            None => Some(Confidence::Low),
        }
    }

    fn switch_finding(&mut self, switch: &Switch, name: &str, arg: &Expr, span: Span) {
        let Some(confidence) = self.flag_confidence(arg, switch.unsafe_value) else {
            return;
        };
        // OpenSSL: `set_verify_hostname(false)` followed by `add_host(name)` is the
        // documented way to check the name by hand, and is as strict.
        if matches!(name, "set_verify_hostname" | "verify_hostname")
            && ["add_host", "set_host", "set1_host"]
                .iter()
                .any(|h| self.file.source.contains(h))
        {
            return;
        }
        let literal = if switch.unsafe_value { "true" } else { "false" };
        let (what, help) = if switch.meta.id == CERT_META.id {
            (
                "TLS certificate validation is switched off",
                "remove it and trust the server's certificate authority with `add_root_certificate`, or pin the certificate",
            )
        } else {
            (
                "TLS hostname verification is switched off",
                "remove it; make the server's certificate name match the name you connect to",
            )
        };
        let message = match confidence {
            Confidence::Low => format!(
                "`{name}(..)` with a value that is not a constant: {what} whenever that value says so"
            ),
            Confidence::Medium => format!(
                "`{name}({literal})` inside a condition: {what} when that condition holds, so any server is accepted"
            ),
            Confidence::High => format!(
                "`{name}({literal})`: {what}, so any server is accepted, including one run by an attacker in the middle"
            ),
        };
        self.report(switch.meta, confidence, span, message, help);
    }
}

impl<'ast> Visit<'ast> for Visitor<'_> {
    fn visit_expr_if(&mut self, e: &'ast syn::ExprIf) {
        self.visit_expr(&e.cond);
        self.conditional += 1;
        self.visit_block(&e.then_branch);
        if let Some((_, else_branch)) = &e.else_branch {
            self.visit_expr(else_branch);
        }
        self.conditional -= 1;
    }

    fn visit_expr_match(&mut self, e: &'ast syn::ExprMatch) {
        self.visit_expr(&e.expr);
        self.conditional += 1;
        for arm in &e.arms {
            self.visit_arm(arm);
        }
        self.conditional -= 1;
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let name = call.method.to_string();
        if let Some(switch) = method_switch(&name) {
            // `ssl_verify_host` and friends take one flag; `verify_hostname(false)`
            // is also a method name in unrelated code, so require the argument.
            if let Some(arg) = call.args.first() {
                self.switch_finding(&switch, &name, arg, call.method.span());
            }
        }
        match name.as_str() {
            "set_verify" => {
                if let Some(Expr::Path(p)) = call.args.first() {
                    let segs: Vec<String> = p
                        .path
                        .segments
                        .iter()
                        .map(|s| s.ident.to_string())
                        .collect();
                    if segs.last().is_some_and(|s| s == "NONE")
                        && segs.iter().any(|s| s == "SslVerifyMode")
                    {
                        self.report(
                            &CERT_META,
                            self.flag_level(),
                            call.method.span(),
                            "`set_verify(SslVerifyMode::NONE)`: the peer's certificate is not checked, so any server is accepted".into(),
                            "use `SslVerifyMode::PEER` and give the connector the right root certificates",
                        );
                    }
                }
            }
            "set_verify_callback" => {
                if let Some(Expr::Closure(c)) = call.args.iter().nth(1) {
                    if bool_lit(&c.body) == Some(true) {
                        self.report(
                            &CERT_META,
                            self.flag_level(),
                            call.method.span(),
                            "`set_verify_callback` with a closure that always returns true: every certificate is accepted".into(),
                            "return the verification result that OpenSSL passes in, instead of `true`",
                        );
                    }
                }
            }
            "with_custom_certificate_verifier" => {
                let mut idents = Vec::new();
                for arg in &call.args {
                    idents_in(arg.to_token_stream(), &mut idents);
                }
                if let Some(bad) = idents.iter().find(|i| insecure_verifier_name(i)) {
                    self.verifier_in_use = true;
                    self.report(
                        &CERT_META,
                        Confidence::High,
                        call.method.span(),
                        format!(
                            "custom certificate verifier `{bad}` is named like one that accepts any certificate"
                        ),
                        "use the default verifier, or a verifier that checks the chain and the name",
                    );
                }
            }
            "insecure_disable_signature_validation" => {
                self.report(
                    &JWT_META,
                    Confidence::High,
                    call.method.span(),
                    "`insecure_disable_signature_validation()`: tokens are accepted without checking their signature, so anyone can forge one".into(),
                    "remove it and verify tokens with the issuer's key",
                );
            }
            _ => {}
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(func) = &*call.func {
            let segs: Vec<String> = func
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            let last = segs.last().map(String::as_str).unwrap_or("");
            if matches!(
                last,
                "dangerous_insecure_decode" | "dangerous_insecure_decode_with_validation"
            ) {
                self.report(
                    &JWT_META,
                    Confidence::High,
                    func.path.segments.last().map_or(call.span(), |s| s.ident.span()),
                    format!(
                        "`{last}` decodes a token without checking its signature, so anyone can forge one"
                    ),
                    "use `decode` with a `DecodingKey` for the issuer's key",
                );
            }
            // `danger_accept_invalid_certs(true)` as a free function (attohttpc).
            if let Some(switch) = method_switch(last) {
                if segs.len() > 1 {
                    if let Some(arg) = call.args.first() {
                        let span = func
                            .path
                            .segments
                            .last()
                            .map_or(call.span(), |s| s.ident.span());
                        self.switch_finding(&switch, last, arg, span);
                    }
                }
            }
            // `Validation::new(header.alg)`: the token chooses its own algorithm.
            if segs.len() >= 2 && segs[segs.len() - 2] == "Validation" && last == "new" {
                if let Some(Expr::Field(f)) = call.args.first() {
                    if matches!(&f.member, syn::Member::Named(n) if n == "alg") {
                        self.report(
                            &JWT_META,
                            Confidence::Medium,
                            call.span(),
                            "`Validation::new(<token header>.alg)`: the algorithm is read from the token, which the sender writes".into(),
                            "name the algorithm in your own code, for example `Validation::new(Algorithm::RS256)`",
                        );
                    }
                }
            }
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast ExprPath) {
        let segs: Vec<String> = path
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect();
        let last = segs.last().map(String::as_str).unwrap_or("");
        let (meta, what) = match last {
            "DANGER_ACCEPT_INVALID_CERTS" => (&CERT_META, "certificate validation"),
            "DANGER_ACCEPT_INVALID_HOSTS" => (&HOST_META, "hostname verification"),
            _ => return,
        };
        self.report(
            meta,
            Confidence::High,
            path.span(),
            format!("`{last}` turns off TLS {what}, so any server is accepted"),
            "remove the option and keep validation on",
        );
    }

    fn visit_expr_struct(&mut self, e: &'ast ExprStruct) {
        // redis: `ConnectionAddr::TcpTls { insecure: true, .. }`
        if e.path.segments.last().is_some_and(|s| s.ident == "TcpTls") {
            for field in &e.fields {
                let named = matches!(&field.member, syn::Member::Named(n) if n == "insecure");
                if named {
                    if let Some(c) = self.flag_confidence(&field.expr, true) {
                        self.report(
                            &CERT_META,
                            c,
                            field.span(),
                            "`TcpTls { insecure: .. }`: the server's certificate is not checked"
                                .into(),
                            "set `insecure: false` and trust the server's certificate authority",
                        );
                    }
                }
            }
        }
        visit::visit_expr_struct(self, e);
    }

    fn visit_expr_assign(&mut self, e: &'ast ExprAssign) {
        // `validation.validate_signature = false`
        if let Expr::Field(f) = &*e.left {
            if matches!(&f.member, syn::Member::Named(n) if n == "validate_signature")
                && bool_lit(&e.right) == Some(false)
            {
                self.report(
                    &JWT_META,
                    Confidence::High,
                    e.span(),
                    "`validate_signature = false`: tokens are accepted without checking their signature, so anyone can forge one".into(),
                    "remove it and verify tokens with the issuer's key",
                );
            }
        }
        visit::visit_expr_assign(self, e);
    }

    fn visit_impl_item_fn(&mut self, f: &'ast ImplItemFn) {
        if f.sig.ident == "verify_server_cert" && accepts_everything(f) {
            let before = self.out.len();
            self.report(
                &CERT_META,
                Confidence::High,
                f.sig.ident.span(),
                "`verify_server_cert` returns success without looking at the certificate, so every server is accepted".into(),
                "check the certificate chain and server name, or delegate to rustls' `WebPkiServerVerifier`",
            );
            self.verifier_impls.extend(self.out.drain(before..));
        }
        visit::visit_impl_item_fn(self, f);
    }
}
