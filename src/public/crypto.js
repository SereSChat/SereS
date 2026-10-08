"use strict";
// End-to-end encryption for SereS.
//
// Every account owns two P-256 key pairs that are generated in the browser:
//   - ECDH  (key agreement, used to wrap per-message keys for each member)
//   - ECDSA (signatures, proves who wrote a message)
// The private keys are encrypted with a key derived from the password
// (PBKDF2 -> HKDF) before they are uploaded, so the server only ever stores
// ciphertext. The server also only receives a separate HKDF output of the
// password ("auth hash"), never the password or the encryption key.
//
// Messages: a fresh AES-256-GCM key per message encrypts the content. That key
// is wrapped for every chat member (including the sender) with a pairwise key
// derived from ECDH(sender, member). The whole envelope is signed with ECDSA.
const SeresCrypto = (() => {
    const subtle = window.crypto.subtle;
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    const ECDH = { name: "ECDH", namedCurve: "P-256" };
    const ECDSA = { name: "ECDSA", namedCurve: "P-256" };
    const DEFAULT_ITERATIONS = 600000;
    const DB_NAME = "seres-keys";
    const STORE = "identity";
    function toB64(data) {
        const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
        let binary = "";
        for (let i = 0; i < bytes.length; i++)
            binary += String.fromCharCode(bytes[i]);
        return btoa(binary);
    }
    function fromB64(value) {
        const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++)
            bytes[i] = binary.charCodeAt(i);
        return bytes;
    }
    function randomBytes(length) {
        return window.crypto.getRandomValues(new Uint8Array(length));
    }
    function newSalt() {
        return toB64(randomBytes(16));
    }
    // ---------------------------------------------------------------- account
    async function deriveAccountKeys(password, saltB64, iterations) {
        const passwordKey = await subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
        const master = await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: fromB64(saltB64), iterations }, passwordKey, 256);
        const hkdf = await subtle.importKey("raw", master, "HKDF", false, [
            "deriveBits",
            "deriveKey",
        ]);
        const authBits = await subtle.deriveBits({
            name: "HKDF",
            hash: "SHA-256",
            salt: new Uint8Array(0),
            info: encoder.encode("seres-auth-v1"),
        }, hkdf, 256);
        const wrapKey = await subtle.deriveKey({
            name: "HKDF",
            hash: "SHA-256",
            salt: new Uint8Array(0),
            info: encoder.encode("seres-keywrap-v1"),
        }, hkdf, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
        return { authHash: toB64(authBits), wrapKey };
    }
    async function encryptPrivateKeys(ecdhPkcs8, signPkcs8, wrapKey) {
        const iv = randomBytes(12);
        const plain = encoder.encode(JSON.stringify({ ecdh: toB64(ecdhPkcs8), sign: toB64(signPkcs8) }));
        const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: encoder.encode("seres-identity-v1") }, wrapKey, plain);
        return JSON.stringify({ v: 1, iv: toB64(iv), ct: toB64(ct) });
    }
    async function decryptPrivateKeys(encPrivate, wrapKey) {
        const blob = JSON.parse(encPrivate);
        const plain = await subtle.decrypt({
            name: "AES-GCM",
            iv: fromB64(blob.iv),
            additionalData: encoder.encode("seres-identity-v1"),
        }, wrapKey, fromB64(blob.ct));
        const keys = JSON.parse(decoder.decode(plain));
        return { ecdh: fromB64(keys.ecdh), sign: fromB64(keys.sign) };
    }
    /** Creates a new identity and returns what the server stores for it. */
    async function createKeyBundle(wrapKey) {
        const ecdh = await subtle.generateKey(ECDH, true, ["deriveBits"]);
        const sign = await subtle.generateKey(ECDSA, true, ["sign", "verify"]);
        const [ecdhPub, signPub, ecdhPriv, signPriv] = await Promise.all([
            subtle.exportKey("spki", ecdh.publicKey),
            subtle.exportKey("spki", sign.publicKey),
            subtle.exportKey("pkcs8", ecdh.privateKey),
            subtle.exportKey("pkcs8", sign.privateKey),
        ]);
        return {
            pub_ecdh: toB64(ecdhPub),
            pub_sign: toB64(signPub),
            enc_private: await encryptPrivateKeys(ecdhPriv, signPriv, wrapKey),
        };
    }
    /** Decrypts the private keys and imports them as non-extractable keys. */
    async function unlockIdentity(userId, encPrivate, wrapKey, pubEcdh, pubSign) {
        const raw = await decryptPrivateKeys(encPrivate, wrapKey);
        const ecdhPriv = await subtle.importKey("pkcs8", raw.ecdh, ECDH, false, [
            "deriveBits",
        ]);
        const signPriv = await subtle.importKey("pkcs8", raw.sign, ECDSA, false, [
            "sign",
        ]);
        raw.ecdh.fill(0);
        raw.sign.fill(0);
        return { userId, ecdhPriv, signPriv, pubEcdh, pubSign };
    }
    async function rewrapPrivateKeys(encPrivate, oldWrapKey, newWrapKey) {
        const raw = await decryptPrivateKeys(encPrivate, oldWrapKey);
        try {
            return await encryptPrivateKeys(raw.ecdh, raw.sign, newWrapKey);
        }
        finally {
            raw.ecdh.fill(0);
            raw.sign.fill(0);
        }
    }
    // --------------------------------------------------------------- storage
    // Unlocked keys are kept in IndexedDB as non-extractable CryptoKeys, so even
    // script running in the page can use but never export them.
    function openDb() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(DB_NAME, 1);
            request.onupgradeneeded = () => {
                request.result.createObjectStore(STORE, { keyPath: "userId" });
            };
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }
    async function withStore(mode, action) {
        const dbh = await openDb();
        try {
            return await new Promise((resolve, reject) => {
                const tx = dbh.transaction(STORE, mode);
                const request = action(tx.objectStore(STORE));
                tx.oncomplete = () => resolve(request.result);
                tx.onerror = () => reject(tx.error);
                tx.onabort = () => reject(tx.error);
            });
        }
        finally {
            dbh.close();
        }
    }
    async function saveIdentity(identity) {
        await withStore("readwrite", (store) => store.put(identity));
    }
    async function loadIdentity(userId) {
        try {
            const result = await withStore("readonly", (store) => store.get(userId));
            return result || null;
        }
        catch {
            return null;
        }
    }
    async function clearIdentities() {
        try {
            await withStore("readwrite", (store) => store.clear());
        }
        catch {
            /* nothing stored */
        }
    }
    // ------------------------------------------------------------ public keys
    const ecdhPublicCache = new Map();
    const signPublicCache = new Map();
    const pairKeyCache = new Map();
    function importEcdhPublic(b64) {
        let key = ecdhPublicCache.get(b64);
        if (!key) {
            key = subtle.importKey("spki", fromB64(b64), ECDH, false, []);
            ecdhPublicCache.set(b64, key);
        }
        return key;
    }
    function importSignPublic(b64) {
        let key = signPublicCache.get(b64);
        if (!key) {
            key = subtle.importKey("spki", fromB64(b64), ECDSA, false, ["verify"]);
            signPublicCache.set(b64, key);
        }
        return key;
    }
    function pairKey(identity, otherPubEcdh) {
        const cacheKey = identity.userId + "|" + otherPubEcdh;
        let key = pairKeyCache.get(cacheKey);
        if (!key) {
            key = (async () => {
                const pub = await importEcdhPublic(otherPubEcdh);
                const shared = await subtle.deriveBits({ name: "ECDH", public: pub }, identity.ecdhPriv, 256);
                const hkdf = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
                return subtle.deriveKey({
                    name: "HKDF",
                    hash: "SHA-256",
                    salt: new Uint8Array(0),
                    info: encoder.encode("seres-pair-v1"),
                }, hkdf, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
            })();
            pairKeyCache.set(cacheKey, key);
            key.catch(() => pairKeyCache.delete(cacheKey));
        }
        return key;
    }
    /** Hex fingerprint of a user's identity keys. */
    async function fingerprint(pubEcdh, pubSign) {
        const digest = await subtle.digest("SHA-256", encoder.encode("seres-fp-v1|" + pubEcdh + "|" + pubSign));
        return Array.from(new Uint8Array(digest))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
    }
    /** 60 digit security code two people can compare, like WhatsApp/Signal. */
    async function safetyNumber(fpA, fpB) {
        const [first, second] = [fpA, fpB].sort();
        const digest = new Uint8Array(await subtle.digest("SHA-512", encoder.encode("seres-safety-v1|" + first + "|" + second)));
        const groups = [];
        for (let i = 0; i < 12; i++) {
            const value = ((digest[i * 4] << 24) |
                (digest[i * 4 + 1] << 16) |
                (digest[i * 4 + 2] << 8) |
                digest[i * 4 + 3]) >>>
                0;
            groups.push(String(value % 100000).padStart(5, "0"));
        }
        return groups.join(" ");
    }
    // --------------------------------------------------------------- messages
    function signingInput(chatId, messageId, senderId, iv, ct, keys) {
        const wrapped = Object.keys(keys)
            .sort()
            .map((id) => id + ":" + keys[id].iv + ":" + keys[id].k)
            .join(",");
        return encoder.encode(["seres-sig-v1", chatId, messageId, senderId, iv, ct, wrapped].join("\n"));
    }
    function contentAad(chatId, messageId, senderId) {
        return encoder.encode(["seres-msg-v1", chatId, messageId, senderId].join("|"));
    }
    function keyAad(messageId, recipientId) {
        return encoder.encode(["seres-key-v1", messageId, recipientId].join("|"));
    }
    async function encryptMessage(identity, chatId, messageId, content, members) {
        const messageKey = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
            "encrypt",
        ]);
        const rawKey = new Uint8Array(await subtle.exportKey("raw", messageKey));
        const iv = randomBytes(12);
        const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: contentAad(chatId, messageId, identity.userId) }, messageKey, encoder.encode(JSON.stringify(content)));
        const keys = {};
        for (const member of members) {
            const wrapIv = randomBytes(12);
            const wrapped = await subtle.encrypt({ name: "AES-GCM", iv: wrapIv, additionalData: keyAad(messageId, member.id) }, await pairKey(identity, member.pub_ecdh), rawKey);
            keys[member.id] = { iv: toB64(wrapIv), k: toB64(wrapped) };
        }
        rawKey.fill(0);
        const ivB64 = toB64(iv);
        const ctB64 = toB64(ct);
        const sig = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, identity.signPriv, signingInput(chatId, messageId, identity.userId, ivB64, ctB64, keys));
        return { v: 1, iv: ivB64, ct: ctB64, sig: toB64(sig), keys };
    }
    async function decryptMessage(identity, chatId, messageId, sender, envelope) {
        const verified = await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, await importSignPublic(sender.pub_sign), fromB64(envelope.sig), signingInput(chatId, messageId, sender.id, envelope.iv, envelope.ct, envelope.keys));
        if (!verified)
            throw new Error("Invalid signature");
        const mine = envelope.keys[identity.userId];
        if (!mine)
            throw new Error("Message was not encrypted for this account");
        const rawKey = await subtle.decrypt({ name: "AES-GCM", iv: fromB64(mine.iv), additionalData: keyAad(messageId, identity.userId) }, await pairKey(identity, sender.pub_ecdh), fromB64(mine.k));
        const messageKey = await subtle.importKey("raw", rawKey, "AES-GCM", false, ["decrypt"]);
        const plain = await subtle.decrypt({
            name: "AES-GCM",
            iv: fromB64(envelope.iv),
            additionalData: contentAad(chatId, messageId, sender.id),
        }, messageKey, fromB64(envelope.ct));
        return JSON.parse(decoder.decode(plain));
    }
    return {
        DEFAULT_ITERATIONS,
        newSalt,
        deriveAccountKeys,
        createKeyBundle,
        unlockIdentity,
        rewrapPrivateKeys,
        saveIdentity,
        loadIdentity,
        clearIdentities,
        fingerprint,
        safetyNumber,
        encryptMessage,
        decryptMessage,
    };
})();
window.SeresCrypto = SeresCrypto;
