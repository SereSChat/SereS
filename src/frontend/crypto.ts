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
//
// After a password reset by e-mail an account has new keys and can't unwrap
// its old message keys any more. Another member who still can unwraps them
// and wraps each one again for the new keys ("shared key"); the content and
// the sender's signature stay the same, the server never sees a message key.

interface SeresIdentity {
  userId: string;
  ecdhPriv: CryptoKey;
  signPriv: CryptoKey;
  pubEcdh: string;
  pubSign: string;
}

/** The account keys sealed for a new device by the main device. */
interface SeresSealedIdentity {
  epub: string;
  iv: string;
  ct: string;
}

interface SeresPublicKeys {
  id: string;
  pub_ecdh: string;
  pub_sign: string;
}

interface SeresEnvelope {
  v: 1;
  iv: string;
  ct: string;
  sig: string;
  keys: Record<string, { iv: string; k: string }>;
}

/** A message key another member wrapped again for this account. */
interface SeresSharedKey {
  iv: string;
  k: string;
  // ECDH public key of the member who shared it.
  from_pub: string;
}

interface SeresKeyBundle {
  pub_ecdh: string;
  pub_sign: string;
  enc_private: string;
}

const SeresCrypto = (() => {
  const subtle = window.crypto.subtle;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const ECDH = { name: "ECDH", namedCurve: "P-256" };
  const ECDSA = { name: "ECDSA", namedCurve: "P-256" };
  const DEFAULT_ITERATIONS = 600000;
  const MIN_ITERATIONS = 100_000;
  const MAX_ITERATIONS = 5_000_000;
  const MIN_SALT_BYTES = 16;
  const E2EE_USED_KEY = "seres-e2ee-used";
  const DB_NAME = "seres-keys";
  const STORE = "identity";

  function toB64(data: ArrayBuffer | Uint8Array): string {
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  function toB64url(data: ArrayBuffer | Uint8Array): string {
    return toB64(data).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function fromB64(value: string): Uint8Array<ArrayBuffer> {
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function randomBytes(length: number): Uint8Array<ArrayBuffer> {
    return window.crypto.getRandomValues(new Uint8Array(length));
  }

  function newSalt(): string {
    return toB64(randomBytes(16));
  }

  // ---------------------------------------------------------------- account

  async function deriveAccountKeys(
    password: string,
    saltB64: string,
    iterations: number,
  ): Promise<{ authHash: string; wrapKey: CryptoKey }> {
    if (!Number.isInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
      throw new Error("Invalid KDF iterations");
    }
    if (typeof saltB64 !== "string" || !saltB64) {
      throw new Error("Invalid KDF salt");
    }
    const salt = fromB64(saltB64);
    if (salt.length < MIN_SALT_BYTES) {
      throw new Error("Invalid KDF salt");
    }
    const passwordKey = await subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"],
    );
    const master = await subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations },
      passwordKey,
      256,
    );
    const hkdf = await subtle.importKey("raw", master, "HKDF", false, [
      "deriveBits",
      "deriveKey",
    ]);
    const authBits = await subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0),
        info: encoder.encode("seres-auth-v1"),
      },
      hkdf,
      256,
    );
    const wrapKey = await subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0),
        info: encoder.encode("seres-keywrap-v1"),
      },
      hkdf,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    return { authHash: toB64(authBits), wrapKey };
  }

  interface IdentityBindContext {
    userId?: string;
    pubEcdh?: string;
    pubSign?: string;
  }

  async function deriveSpkiFromPkcs8(
    pkcs8: Uint8Array | ArrayBuffer,
    algorithm: EcKeyImportParams,
    privUsages: KeyUsage[],
    pubUsages: KeyUsage[],
  ): Promise<string> {
    const tmp = await subtle.importKey("pkcs8", pkcs8, algorithm, true, privUsages);
    const jwk = await subtle.exportKey("jwk", tmp);
    try {
      const pub = await subtle.importKey(
        "jwk",
        { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, ext: true },
        algorithm,
        true,
        pubUsages,
      );
      return toB64(await subtle.exportKey("spki", pub));
    } finally {
      jwk.d = "";
    }
  }

  async function derivePublicSpki(
    ecdhPkcs8: Uint8Array | ArrayBuffer,
    signPkcs8: Uint8Array | ArrayBuffer,
  ): Promise<{ pubEcdh: string; pubSign: string }> {
    const [pubEcdh, pubSign] = await Promise.all([
      deriveSpkiFromPkcs8(ecdhPkcs8, ECDH, ["deriveBits"], []),
      deriveSpkiFromPkcs8(signPkcs8, ECDSA, ["sign"], ["verify"]),
    ]);
    return { pubEcdh, pubSign };
  }

  function identityAad(userId: string | undefined, pubEcdh: string, pubSign: string, unbound: boolean) {
    return encoder.encode(
      ["seres-identity-v2", unbound ? "unbound" : userId || "", pubEcdh, pubSign].join("|"),
    );
  }

  async function encryptPrivateKeys(
    ecdhPkcs8: Uint8Array | ArrayBuffer,
    signPkcs8: Uint8Array | ArrayBuffer,
    wrapKey: CryptoKey,
    context?: IdentityBindContext,
  ): Promise<string> {
    const derived = await derivePublicSpki(ecdhPkcs8, signPkcs8);
    if (context?.pubEcdh && context.pubEcdh !== derived.pubEcdh) {
      throw new Error("ECDH private key does not match public key");
    }
    if (context?.pubSign && context.pubSign !== derived.pubSign) {
      throw new Error("Signing private key does not match public key");
    }
    const unbound = !context?.userId;
    const iv = randomBytes(12);
    const plain = encoder.encode(
      JSON.stringify({ ecdh: toB64(ecdhPkcs8), sign: toB64(signPkcs8) }),
    );
    try {
      const ct = await subtle.encrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: identityAad(context?.userId, derived.pubEcdh, derived.pubSign, unbound),
        },
        wrapKey,
        plain,
      );
      return JSON.stringify(
        unbound
          ? { v: 2, unbound: true, iv: toB64(iv), ct: toB64(ct) }
          : { v: 2, iv: toB64(iv), ct: toB64(ct) },
      );
    } finally {
      plain.fill(0);
    }
  }

  async function decryptPrivateKeys(
    encPrivate: string,
    wrapKey: CryptoKey,
    context?: IdentityBindContext,
  ): Promise<{ ecdh: Uint8Array<ArrayBuffer>; sign: Uint8Array<ArrayBuffer> }> {
    const blob = JSON.parse(encPrivate);
    let additionalData: Uint8Array<ArrayBuffer>;
    if (blob?.v === 2) {
      if (!context?.pubEcdh || !context?.pubSign) {
        throw new Error("Missing public keys for identity decryption");
      }
      const unbound = blob.unbound === true;
      if (!unbound && !context.userId) {
        throw new Error("Missing userId for identity decryption");
      }
      additionalData = identityAad(context.userId, context.pubEcdh, context.pubSign, unbound);
    } else if (blob?.v === 1 || blob?.v === undefined) {
      additionalData = encoder.encode("seres-identity-v1");
    } else {
      throw new Error("Unsupported identity version");
    }
    const plain = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: fromB64(blob.iv),
        additionalData,
      },
      wrapKey,
      fromB64(blob.ct),
    );
    const plainBytes = new Uint8Array(plain);
    try {
      const keys = JSON.parse(decoder.decode(plainBytes));
      return { ecdh: fromB64(keys.ecdh), sign: fromB64(keys.sign) };
    } finally {
      plainBytes.fill(0);
    }
  }

  /** Creates a new identity and returns what the server stores for it. */
  async function createKeyBundle(wrapKey: CryptoKey, userId?: string): Promise<SeresKeyBundle> {
    const ecdh = await subtle.generateKey(ECDH, true, ["deriveBits"]);
    const sign = await subtle.generateKey(ECDSA, true, ["sign", "verify"]);
    const [ecdhPub, signPub, ecdhPriv, signPriv] = await Promise.all([
      subtle.exportKey("spki", ecdh.publicKey),
      subtle.exportKey("spki", sign.publicKey),
      subtle.exportKey("pkcs8", ecdh.privateKey),
      subtle.exportKey("pkcs8", sign.privateKey),
    ]);
    const pub_ecdh = toB64(ecdhPub);
    const pub_sign = toB64(signPub);
    return {
      pub_ecdh,
      pub_sign,
      enc_private: await encryptPrivateKeys(ecdhPriv, signPriv, wrapKey, {
        userId,
        pubEcdh: pub_ecdh,
        pubSign: pub_sign,
      }),
    };
  }

  /** Decrypts the private keys and imports them as non-extractable keys. */
  async function unlockIdentity(
    userId: string,
    encPrivate: string,
    wrapKey: CryptoKey,
    pubEcdh: string,
    pubSign: string,
  ): Promise<SeresIdentity> {
    const raw = await decryptPrivateKeys(encPrivate, wrapKey, { userId, pubEcdh, pubSign });
    return identityFromRaw(userId, raw, pubEcdh, pubSign);
  }

  /** Imports the private keys as non-extractable keys without persisting raw key material. */
  async function identityFromRaw(
    userId: string,
    raw: { ecdh: Uint8Array<ArrayBuffer>; sign: Uint8Array<ArrayBuffer> },
    pubEcdh: string,
    pubSign: string,
  ): Promise<SeresIdentity> {
    try {
      const derived = await derivePublicSpki(raw.ecdh, raw.sign);
      if (derived.pubEcdh !== pubEcdh || derived.pubSign !== pubSign) {
        throw new Error("Decrypted private keys do not match public keys");
      }
      const ecdhPriv = await subtle.importKey("pkcs8", raw.ecdh, ECDH, false, ["deriveBits"]);
      const signPriv = await subtle.importKey("pkcs8", raw.sign, ECDSA, false, ["sign"]);
      return { userId, ecdhPriv, signPriv, pubEcdh: derived.pubEcdh, pubSign: derived.pubSign };
    } finally {
      raw.ecdh.fill(0);
      raw.sign.fill(0);
    }
  }

  // ---------------------------------------------------------- linking
  // The new device makes a key pair and shows the public key in the QR code.
  // The main device derives a shared key from it (ECDH + HKDF) and encrypts
  // the account's private keys with it. Both devices show the same short
  // check code, made from that public key, so a swapped key is noticed.

  const LINK_INFO = encoder.encode("seres-link-v1");
  const linkPubByPriv = new WeakMap<CryptoKey, string>();

  async function linkKey(privateKey: CryptoKey, publicB64: string) {
    const shared = await subtle.deriveBits({ name: "ECDH", public: await importEcdhPublic(publicB64) }, privateKey, 256);
    const hkdf = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    return subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: LINK_INFO },
      hkdf,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }

  async function newLinkKeyPair(): Promise<{ privateKey: CryptoKey; pub: string }> {
    const pair = await subtle.generateKey(ECDH, false, ["deriveBits"]);
    const pub = toB64(await subtle.exportKey("spki", pair.publicKey));
    linkPubByPriv.set(pair.privateKey, pub);
    return { privateKey: pair.privateKey, pub };
  }

  /** Full SHA-256 base64url digest of the new device's linking public key. */
  async function linkPubHash(pubB64: string): Promise<string> {
    const digest = new Uint8Array(await subtle.digest("SHA-256", encoder.encode(pubB64)));
    return toB64url(digest);
  }

  /** Six digits both devices show, made from the new device's public key. */
  async function linkCheckCode(publicB64: string): Promise<string> {
    const digest = new Uint8Array(await subtle.digest("SHA-256", encoder.encode("seres-link-check-v1|" + publicB64)));
    const value = ((digest[0] << 16) | (digest[1] << 8) | digest[2]) % 1000000;
    const digits = String(value).padStart(6, "0");
    return digits.slice(0, 3) + " " + digits.slice(3);
  }

  function linkAad(userId: string, devicePub: string, epub: string) {
    return encoder.encode(["seres-link-v2", userId, devicePub, epub].join("|"));
  }

  function linkSigningInput(
    userId: string,
    devicePub: string,
    epub: string,
    ecdhB64: string,
    signB64: string,
  ) {
    return encoder.encode(["seres-link-seal-v2", userId, devicePub, epub, ecdhB64, signB64].join("\n"));
  }

  /** Main device: decrypts encPrivate with wrapKey, signs, and seals the account keys for the new device. */
  async function sealPrivateKeys(
    encPrivate: string,
    wrapKey: CryptoKey,
    devicePub: string,
    identity: SeresIdentity,
  ): Promise<SeresSealedIdentity> {
    if (!identity?.userId || !identity?.signPriv) {
      throw new Error("Missing identity for sealing keys");
    }
    const raw = await decryptPrivateKeys(encPrivate, wrapKey, {
      userId: identity.userId,
      pubEcdh: identity.pubEcdh,
      pubSign: identity.pubSign,
    });
    try {
      const ephemeral = await subtle.generateKey(ECDH, false, ["deriveBits"]);
      const epub = toB64(await subtle.exportKey("spki", ephemeral.publicKey));
      const key = await linkKey(ephemeral.privateKey, devicePub);
      const iv = randomBytes(12);
      const ecdhB64 = toB64(raw.ecdh);
      const signB64 = toB64(raw.sign);
      const sigBytes = await subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        identity.signPriv,
        linkSigningInput(identity.userId, devicePub, epub, ecdhB64, signB64),
      );
      const plain = encoder.encode(
        JSON.stringify({ v: 2, ecdh: ecdhB64, sign: signB64, sig: toB64(sigBytes) }),
      );
      try {
        const ct = await subtle.encrypt(
          { name: "AES-GCM", iv, additionalData: linkAad(identity.userId, devicePub, epub) },
          key,
          plain,
        );
        return { epub, iv: toB64(iv), ct: toB64(ct) };
      } finally {
        plain.fill(0);
      }
    } finally {
      raw.ecdh.fill(0);
      raw.sign.fill(0);
    }
  }

  /** New device: verifies AAD and signature, then opens what the main device sealed for it. */
  async function openSealedIdentity(
    userId: string,
    privateKey: CryptoKey,
    sealed: SeresSealedIdentity,
    pubEcdh: string,
    pubSign: string,
    devicePubOrOpts?: string | { devicePub?: string; signerPubSign?: string },
  ): Promise<SeresIdentity> {
    const devicePub =
      (typeof devicePubOrOpts === "string" ? devicePubOrOpts : devicePubOrOpts?.devicePub) ??
      linkPubByPriv.get(privateKey);
    if (!devicePub) throw new Error("Missing device public key");
    const signerPub =
      (typeof devicePubOrOpts === "object" && devicePubOrOpts?.signerPubSign) || pubSign;
    const key = await linkKey(privateKey, sealed.epub);
    const plain = new Uint8Array(
      await subtle.decrypt(
        {
          name: "AES-GCM",
          iv: fromB64(sealed.iv),
          additionalData: linkAad(userId, devicePub, sealed.epub),
        },
        key,
        fromB64(sealed.ct),
      ),
    );
    let keys: { v?: number; ecdh: string; sign: string; sig?: string };
    try {
      keys = JSON.parse(decoder.decode(plain));
    } finally {
      plain.fill(0);
    }
    if (keys.v !== 2 || typeof keys.sig !== "string" || !keys.sig) {
      throw new Error("Missing sealed identity signature");
    }
    const verified = await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      await importSignPublic(signerPub),
      fromB64(keys.sig),
      linkSigningInput(userId, devicePub, sealed.epub, keys.ecdh, keys.sign),
    );
    if (!verified) throw new Error("Invalid sealed identity signature");
    return identityFromRaw(
      userId,
      { ecdh: fromB64(keys.ecdh), sign: fromB64(keys.sign) },
      pubEcdh,
      pubSign,
    );
  }

  async function rewrapPrivateKeys(
    encPrivate: string,
    oldWrapKey: CryptoKey,
    newWrapKey: CryptoKey,
    context?: IdentityBindContext,
  ): Promise<string> {
    const raw = await decryptPrivateKeys(encPrivate, oldWrapKey, context);
    try {
      return await encryptPrivateKeys(raw.ecdh, raw.sign, newWrapKey, context);
    } finally {
      raw.ecdh.fill(0);
      raw.sign.fill(0);
    }
  }

  // --------------------------------------------------------------- storage
  // Unlocked keys are kept in IndexedDB as non-extractable CryptoKeys, so even
  // script running in the page can use but never export them.

  function openDb(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, 1);
      request.onupgradeneeded = () => {
        request.result.createObjectStore(STORE, { keyPath: "userId" });
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async function withStore<T>(
    mode: IDBTransactionMode,
    action: (store: IDBObjectStore) => IDBRequest<T>,
  ): Promise<T> {
    const dbh = await openDb();
    try {
      return await new Promise<T>((resolve, reject) => {
        const tx = dbh.transaction(STORE, mode);
        const request = action(tx.objectStore(STORE));
        tx.oncomplete = () => resolve(request.result);
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
      });
    } finally {
      dbh.close();
    }
  }

  function stripTransfer(identity: SeresIdentity): SeresIdentity {
    return {
      userId: identity.userId,
      ecdhPriv: identity.ecdhPriv,
      signPriv: identity.signPriv,
      pubEcdh: identity.pubEcdh,
      pubSign: identity.pubSign,
    };
  }

  function markE2eeUsed(): void {
    try {
      localStorage.setItem(E2EE_USED_KEY, "1");
    } catch {
      /* storage unavailable */
    }
  }

  async function hasUsedE2ee(): Promise<boolean> {
    try {
      if (localStorage.getItem(E2EE_USED_KEY) === "1") return true;
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (
          key &&
          (key.startsWith("seres-pins:") ||
            key.startsWith("seres-pin-keys:") ||
            key.startsWith("seres-pin-history:"))
        ) {
          return true;
        }
      }
    } catch {
      /* storage unavailable */
    }
    return false;
  }

  async function saveIdentity(identity: SeresIdentity): Promise<void> {
    await withStore("readwrite", (store) => store.put(stripTransfer(identity)));
    markE2eeUsed();
  }

  async function loadIdentity(userId: string): Promise<SeresIdentity | null> {
    try {
      const result = await withStore("readonly", (store) => store.get(userId));
      if (!result) return null;
      const clean = stripTransfer(result as SeresIdentity);
      if ("transfer" in (result as any)) {
        await saveIdentity(clean).catch(() => {});
      }
      return clean;
    } catch {
      return null;
    }
  }

  async function clearIdentities(): Promise<void> {
    try {
      await withStore("readwrite", (store) => store.clear());
    } catch {
      /* nothing stored */
    }
  }

  // ------------------------------------------------------------ public keys

  const ecdhPublicCache = new Map<string, Promise<CryptoKey>>();
  const signPublicCache = new Map<string, Promise<CryptoKey>>();
  const pairKeyCache = new Map<string, Promise<CryptoKey>>();

  function importEcdhPublic(b64: string): Promise<CryptoKey> {
    let key = ecdhPublicCache.get(b64);
    if (!key) {
      key = subtle.importKey("spki", fromB64(b64), ECDH, false, []);
      ecdhPublicCache.set(b64, key);
    }
    return key;
  }

  function importSignPublic(b64: string): Promise<CryptoKey> {
    let key = signPublicCache.get(b64);
    if (!key) {
      key = subtle.importKey("spki", fromB64(b64), ECDSA, false, ["verify"]);
      signPublicCache.set(b64, key);
    }
    return key;
  }

  function pairKey(identity: SeresIdentity, otherPubEcdh: string): Promise<CryptoKey> {
    const cacheKey = identity.userId + "|" + otherPubEcdh;
    let key = pairKeyCache.get(cacheKey);
    if (!key) {
      key = (async () => {
        const pub = await importEcdhPublic(otherPubEcdh);
        const shared = await subtle.deriveBits(
          { name: "ECDH", public: pub },
          identity.ecdhPriv,
          256,
        );
        const hkdf = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
        return subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-256",
            salt: new Uint8Array(0),
            info: encoder.encode("seres-pair-v1"),
          },
          hkdf,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"],
        );
      })();
      pairKeyCache.set(cacheKey, key);
      key.catch(() => pairKeyCache.delete(cacheKey));
    }
    return key;
  }

  /** Hex fingerprint of a user's identity keys. */
  async function fingerprint(pubEcdh: string, pubSign: string): Promise<string> {
    const digest = await subtle.digest(
      "SHA-256",
      encoder.encode("seres-fp-v1|" + pubEcdh + "|" + pubSign),
    );
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  /** 60 digit security code two people can compare, like WhatsApp/Signal. */
  async function safetyNumber(fpA: string, fpB: string): Promise<string> {
    const [first, second] = [fpA, fpB].sort();
    const digest = new Uint8Array(
      await subtle.digest("SHA-512", encoder.encode("seres-safety-v1|" + first + "|" + second)),
    );
    const groups: string[] = [];
    for (let i = 0; i < 12; i++) {
      const value =
        ((digest[i * 4] << 24) |
          (digest[i * 4 + 1] << 16) |
          (digest[i * 4 + 2] << 8) |
          digest[i * 4 + 3]) >>>
        0;
      groups.push(String(value % 100000).padStart(5, "0"));
    }
    return groups.join(" ");
  }

  // --------------------------------------------------------------- messages

  function signingInput(
    chatId: string,
    messageId: string,
    senderId: string,
    iv: string,
    ct: string,
    keys: Record<string, { iv: string; k: string }>,
  ): Uint8Array<ArrayBuffer> {
    const wrapped = Object.keys(keys)
      .sort()
      .map((id) => id + ":" + keys[id].iv + ":" + keys[id].k)
      .join(",");
    return encoder.encode(
      ["seres-sig-v1", chatId, messageId, senderId, iv, ct, wrapped].join("\n"),
    );
  }

  function contentAad(chatId: string, messageId: string, senderId: string) {
    return encoder.encode(["seres-msg-v1", chatId, messageId, senderId].join("|"));
  }

  function keyAad(messageId: string, recipientId: string) {
    return encoder.encode(["seres-key-v1", messageId, recipientId].join("|"));
  }

  function shareAad(messageId: string, recipientId: string) {
    return encoder.encode(["seres-share-v1", messageId, recipientId].join("|"));
  }

  async function encryptMessage(
    identity: SeresIdentity,
    chatId: string,
    messageId: string,
    content: object,
    members: SeresPublicKeys[],
  ): Promise<SeresEnvelope> {
    const messageKey = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
      "encrypt",
    ]);
    const rawKey = new Uint8Array(await subtle.exportKey("raw", messageKey));
    const iv = randomBytes(12);
    const ct = await subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: contentAad(chatId, messageId, identity.userId) },
      messageKey,
      encoder.encode(JSON.stringify(content)),
    );
    const keys: Record<string, { iv: string; k: string }> = {};
    for (const member of members) {
      const wrapIv = randomBytes(12);
      const wrapped = await subtle.encrypt(
        { name: "AES-GCM", iv: wrapIv, additionalData: keyAad(messageId, member.id) },
        await pairKey(identity, member.pub_ecdh),
        rawKey,
      );
      keys[member.id] = { iv: toB64(wrapIv), k: toB64(wrapped) };
    }
    rawKey.fill(0);
    const ivB64 = toB64(iv);
    const ctB64 = toB64(ct);
    const sig = await subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      identity.signPriv,
      signingInput(chatId, messageId, identity.userId, ivB64, ctB64, keys),
    );
    return { v: 1, iv: ivB64, ct: ctB64, sig: toB64(sig), keys };
  }

  async function verifyEnvelope(chatId: string, messageId: string, sender: SeresPublicKeys, envelope: SeresEnvelope) {
    const verified = await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      await importSignPublic(sender.pub_sign),
      fromB64(envelope.sig),
      signingInput(chatId, messageId, sender.id, envelope.iv, envelope.ct, envelope.keys),
    );
    if (!verified) throw new Error("Invalid signature");
  }

  /** The raw message key: from a shared key (trying multiple if present), or from the envelope. */
  async function messageKeyBytes(
    identity: SeresIdentity,
    messageId: string,
    sender: SeresPublicKeys,
    envelope: SeresEnvelope,
    share?: SeresSharedKey | SeresSharedKey[] | null,
  ): Promise<ArrayBuffer> {
    const shares = Array.isArray(share) ? share : share ? [share] : [];
    for (const entry of shares) {
      if (!entry || !entry.from_pub || !entry.iv || !entry.k) continue;
      try {
        return await subtle.decrypt(
          { name: "AES-GCM", iv: fromB64(entry.iv), additionalData: shareAad(messageId, identity.userId) },
          await pairKey(identity, entry.from_pub),
          fromB64(entry.k),
        );
      } catch {
        // Ignore invalid/poisoned share and try the next share or envelope key.
      }
    }
    if (envelope.keys && Object.prototype.hasOwnProperty.call(envelope.keys, identity.userId)) {
      const mine = envelope.keys[identity.userId];
      if (mine) {
        return subtle.decrypt(
          { name: "AES-GCM", iv: fromB64(mine.iv), additionalData: keyAad(messageId, identity.userId) },
          await pairKey(identity, sender.pub_ecdh),
          fromB64(mine.k),
        );
      }
    }
    throw new Error("Message was not encrypted for this account");
  }

  async function decryptMessage(
    identity: SeresIdentity,
    chatId: string,
    messageId: string,
    sender: SeresPublicKeys,
    envelope: SeresEnvelope,
    share?: SeresSharedKey | SeresSharedKey[] | null,
  ): Promise<any> {
    await verifyEnvelope(chatId, messageId, sender, envelope);
    const rawKey = await messageKeyBytes(identity, messageId, sender, envelope, share);
    const messageKey = await subtle.importKey("raw", rawKey, "AES-GCM", false, ["decrypt"]);
    const plain = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: fromB64(envelope.iv),
        additionalData: contentAad(chatId, messageId, sender.id),
      },
      messageKey,
      fromB64(envelope.ct),
    );
    return JSON.parse(decoder.decode(plain));
  }

  /** Wraps the key of a message this account can read for someone who reset their keys. */
  async function shareMessageKey(
    identity: SeresIdentity,
    chatId: string,
    messageId: string,
    sender: SeresPublicKeys,
    envelope: SeresEnvelope,
    recipient: { id: string; pub_ecdh: string },
    ownShare?: SeresSharedKey | SeresSharedKey[] | null,
  ): Promise<{ iv: string; k: string }> {
    if (!envelope.keys || !Object.prototype.hasOwnProperty.call(envelope.keys, recipient.id)) {
      throw new Error("Recipient is not in message envelope");
    }
    // Never pass on a message whose signature doesn't hold.
    await verifyEnvelope(chatId, messageId, sender, envelope);
    const rawKey = new Uint8Array(await messageKeyBytes(identity, messageId, sender, envelope, ownShare));
    const iv = randomBytes(12);
    const wrapped = await subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: shareAad(messageId, recipient.id) },
      await pairKey(identity, recipient.pub_ecdh),
      rawKey,
    );
    rawKey.fill(0);
    return { iv: toB64(iv), k: toB64(wrapped) };
  }

  // ------------------------------------------------------------------ calls
  // The audio of a call is encrypted by WebRTC (DTLS-SRTP). Its connection
  // offer contains the fingerprint of that encryption; signing it with the
  // account key means the server can't swap in its own and listen in.

  function callSigningInput(callId: string, fromId: string, toId: string, kind: string, sdp: string) {
    return encoder.encode(["seres-call-v1", callId, fromId, toId, kind, sdp].join("\n"));
  }

  async function signCall(identity: SeresIdentity, callId: string, toId: string, kind: string, sdp: string) {
    const sig = await subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      identity.signPriv,
      callSigningInput(callId, identity.userId, toId, kind, sdp),
    );
    return toB64(sig);
  }

  async function verifyCall(
    fromPubSign: string,
    callId: string,
    fromId: string,
    toId: string,
    kind: string,
    sdp: string,
    sig: string,
  ): Promise<boolean> {
    try {
      return await subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        await importSignPublic(fromPubSign),
        fromB64(sig),
        callSigningInput(callId, fromId, toId, kind, sdp),
      );
    } catch {
      return false;
    }
  }

  // ----------------------------------------------------------- backup codes
  // Each code looks like "K7QF-2M9X-HP4C-ZT8B". The first group is a public
  // "slot" so the server can find the code; all 16 characters (80 bits) go
  // through the same key derivation as a password. The private keys are
  // encrypted once per code, so any unused code can unlock the account.

  const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O, 1/I
  const RECOVERY_ITERATIONS = 100000;
  const RECOVERY_CODE_COUNT = 10;

  function randomCode(): string {
    // 256 is a multiple of 32, so taking the byte modulo 32 is unbiased.
    const chars = Array.from(randomBytes(16), (b) => CODE_ALPHABET[b % 32]).join("");
    return chars.match(/.{4}/g)!.join("-");
  }

  /** Accepts codes with or without dashes, spaces or lower case. */
  function normalizeCode(input: string): { slot: string; code: string } | null {
    const plain = input.toUpperCase().replace(/[\s-]/g, "");
    if (plain.length !== 16 || [...plain].some((c) => !CODE_ALPHABET.includes(c))) return null;
    return { slot: plain.slice(0, 4), code: plain.match(/.{4}/g)!.join("-") };
  }

  /** Derives the server check value and the key-wrapping key of a code. */
  function deriveCodeKeys(code: string, saltB64: string) {
    return deriveAccountKeys(code, saltB64, RECOVERY_ITERATIONS);
  }

  /**
   * Makes 10 new codes for the private keys in encPrivate (unlocked with wrapKey).
   * Returns the codes to show once and what the server stores for them.
   */
  async function createRecoveryCodes(encPrivate: string, wrapKey: CryptoKey, context?: IdentityBindContext) {
    const raw = await decryptPrivateKeys(encPrivate, wrapKey, context);
    try {
      const codes: string[] = [];
      const slots = new Set<string>();
      while (codes.length < RECOVERY_CODE_COUNT) {
        const code = randomCode();
        if (slots.has(code.slice(0, 4))) continue;
        slots.add(code.slice(0, 4));
        codes.push(code);
      }
      const stored = await Promise.all(
        codes.map(async (code) => {
          const salt = newSalt();
          const keys = await deriveCodeKeys(code, salt);
          return {
            slot: code.slice(0, 4),
            kdf_salt: salt,
            auth_hash: keys.authHash,
            enc_private: await encryptPrivateKeys(raw.ecdh, raw.sign, keys.wrapKey, {
              pubEcdh: context?.pubEcdh,
              pubSign: context?.pubSign,
            }),
          };
        }),
      );
      return { codes, stored };
    } finally {
      raw.ecdh.fill(0);
      raw.sign.fill(0);
    }
  }

  // ------------------------------------------------------------ attachments
  // Each file gets its own random AES-256-GCM key. The key and IV are put into
  // the (encrypted and signed) message, the server only stores the ciphertext.

  const FILE_AAD = encoder.encode("seres-file-v1");

  async function encryptFile(data: ArrayBuffer): Promise<{ data: ArrayBuffer; key: string; iv: string }> {
    const key = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
    const iv = randomBytes(12);
    const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: FILE_AAD }, key, data);
    const raw = await subtle.exportKey("raw", key);
    return { data: ct, key: toB64(raw), iv: toB64(iv) };
  }

  async function decryptFile(data: ArrayBuffer, keyB64: string, ivB64: string): Promise<ArrayBuffer> {
    const key = await subtle.importKey("raw", fromB64(keyB64), "AES-GCM", false, ["decrypt"]);
    return subtle.decrypt({ name: "AES-GCM", iv: fromB64(ivB64), additionalData: FILE_AAD }, key, data);
  }

  return {
    DEFAULT_ITERATIONS,
    normalizeCode,
    deriveCodeKeys,
    createRecoveryCodes,
    encryptFile,
    decryptFile,
    newSalt,
    deriveAccountKeys,
    encryptPrivateKeys,
    decryptPrivateKeys,
    identityFromRaw,
    createKeyBundle,
    unlockIdentity,
    newLinkKeyPair,
    linkPubHash,
    linkCheckCode,
    sealPrivateKeys,
    openSealedIdentity,
    rewrapPrivateKeys,
    saveIdentity,
    loadIdentity,
    clearIdentities,
    markE2eeUsed,
    hasUsedE2ee,
    fingerprint,
    safetyNumber,
    encryptMessage,
    decryptMessage,
    shareMessageKey,
    signCall,
    verifyCall,
  };
})();

(window as any).SeresCrypto = SeresCrypto;
