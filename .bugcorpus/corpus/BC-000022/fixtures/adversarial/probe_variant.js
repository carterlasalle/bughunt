// trace:exempt reason=bugcorpus-fixture-no-product-behavior -- options-bag auth material reaching a digest only through a member read; documents the v1 single-identifier aliasing ceiling
async function proofOfBytes(raw, options) {
    const data = new Uint8Array(PROOF_PREFIX.length + PROOF_WORD.length + raw.length);
    data.set(PROOF_PREFIX, 0);
    data.set(PROOF_WORD, PROOF_PREFIX.length);
    data.set(raw, PROOF_PREFIX.length + PROOF_WORD.length);
    return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}


// trace:exempt reason=bugcorpus-fixture-no-product-behavior
async function signChallenge(options) {
    const label = options.token;
    return new Uint8Array(await crypto.subtle.digest("SHA-256", raw(label)));
}
