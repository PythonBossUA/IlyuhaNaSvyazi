/* ============================================================
   Криптографія: ECDH P-256 + HKDF-SHA256 + AES-GCM-256
   Винесено з index.html, логіка не змінена
============================================================ */
"use strict";

window.IlyuhaCrypto = (() => {
    const enc = new TextEncoder();
    const dec = new TextDecoder();

    // ---------- Base64 ----------
    function bufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = "";
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    function base64ToBytes(b64) {
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    // ---------- ECDH ----------
    async function generateKeyPair() {
        return await crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            true,
            ["deriveBits"]
        );
    }

    async function exportPublicJwk(keyPair) {
        const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
        return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
    }

    async function importPublicJwk(jwk) {
        return await crypto.subtle.importKey(
            "jwk",
            jwk,
            { name: "ECDH", namedCurve: "P-256" },
            false,
            []
        );
    }

    async function deriveAesKey(privateKey, peerPublicKey, saltStr, infoStr) {
        const sharedBits = await crypto.subtle.deriveBits(
            { name: "ECDH", public: peerPublicKey },
            privateKey,
            256
        );

        const hkdfKey = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);

        return await crypto.subtle.deriveKey(
            { name: "HKDF", hash: "SHA-256", salt: enc.encode(saltStr), info: enc.encode(infoStr) },
            hkdfKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    }

    // ---------- AES-GCM (nonce 12B + ciphertext, AAD = client_id) ----------
    function makeNonce() {
        const nonce = new Uint8Array(12);
        crypto.getRandomValues(nonce);
        return nonce;
    }

    async function encryptText(key, text, clientId) {
        if (!key) throw new Error("AES ключ ще не виведено");

        const nonce = makeNonce();
        const aad = enc.encode(`client_id=${clientId}|v=1`);

        const ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: nonce, additionalData: aad },
            key,
            enc.encode(text)
        );

        const result = new Uint8Array(nonce.length + ciphertext.byteLength);
        result.set(nonce, 0);
        result.set(new Uint8Array(ciphertext), nonce.length);

        return bufferToBase64(result.buffer);
    }

    async function decryptText(key, base64Packet, clientId) {
        if (!key) throw new Error("AES ключ ще не виведено");

        const packet = base64ToBytes(base64Packet);
        const nonce = packet.slice(0, 12);
        const ciphertext = packet.slice(12);
        const aad = enc.encode(`client_id=${clientId}|v=1`);

        const plaintext = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: nonce, additionalData: aad },
            key,
            ciphertext
        );

        return dec.decode(plaintext);
    }

    return {
        generateKeyPair,
        exportPublicJwk,
        importPublicJwk,
        deriveAesKey,
        encryptText,
        decryptText,
    };
})();