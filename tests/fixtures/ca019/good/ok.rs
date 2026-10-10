fn propagated(mut mac: Hmac<Sha256>, tag: &[u8]) -> Result<(), Error> {
    mac.verify_slice(tag)?;
    Ok(())
}

fn checked(mut mac: Hmac<Sha256>, tag: &[u8]) -> bool {
    mac.verify_slice(tag).is_ok()
}

fn matched(mut mac: Hmac<Sha256>, tag: &[u8]) {
    match mac.verify_slice(tag) {
        Ok(()) => accept(),
        Err(_) => reject(),
    }
}

// Only proceeds on success.
fn if_let(mut mac: Hmac<Sha256>, tag: &[u8]) {
    if let Ok(()) = mac.verify_slice(tag) {
        accept();
    }
}

fn used(cipher: &Aes256Gcm, nonce: &Nonce, ct: &[u8]) -> Result<Vec<u8>, Error> {
    let pt = cipher.decrypt(nonce, ct)?;
    Ok(pt)
}

// Discarding something that is not a crypto result.
fn unrelated(v: &mut Vec<u8>) {
    let _ = v.pop();
    v.clear();
}

#[cfg(test)]
mod tests {
    fn t(mut mac: Hmac<Sha256>, tag: &[u8]) {
        let _ = mac.verify_slice(tag);
    }
}
