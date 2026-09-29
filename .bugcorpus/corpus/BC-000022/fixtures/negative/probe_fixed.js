// trace:exempt reason=bugcorpus-fixture-no-product-behavior
async function proofOfBytes(raw, token) {
    const secret = enc.encode(token);
    const data = new Uint8Array(
        PROOF_PREFIX.length + PROOF_WORD.length + raw.length + secret.length,
    );
    data.set(PROOF_PREFIX, 0);
    data.set(PROOF_WORD, PROOF_PREFIX.length);
    data.set(raw, PROOF_PREFIX.length + PROOF_WORD.length);
    data.set(secret, PROOF_PREFIX.length + PROOF_WORD.length + raw.length);
    return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}


// trace:exempt reason=bugcorpus-fixture-no-product-behavior
async function makeOffer(token) {
    this.token = token;
    return {
        proof: await proofOfBytes(new Uint8Array([1, 2, 3]), token),
    };
}
