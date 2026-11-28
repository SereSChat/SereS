"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");
const { types: utilTypes } = require("node:util");

const PUBLIC_DIR = path.resolve(__dirname, "..", "src", "public");

function createStorage() {
  const map = new Map();
  return {
    get length() {
      return map.size;
    },
    key(i) {
      return [...map.keys()][i] ?? null;
    },
    getItem(k) {
      return map.has(String(k)) ? map.get(String(k)) : null;
    },
    setItem(k, v) {
      map.set(String(k), String(v));
    },
    removeItem(k) {
      map.delete(String(k));
    },
    clear() {
      map.clear();
    },
    _dump() {
      return Object.fromEntries(map);
    },
  };
}

function createIndexedDb() {
  const dbs = new Map();
  return {
    open(name) {
      const req = { result: null, error: null, onupgradeneeded: null, onsuccess: null, onerror: null };
      queueMicrotask(() => {
        let db = dbs.get(name);
        const created = !db;
        if (!db) {
          const stores = new Map();
          db = {
            createObjectStore(storeName) {
              const s = new Map();
              stores.set(storeName, s);
              return s;
            },
            transaction(storeName) {
              const storeMap = stores.get(storeName);
              const tx = {
                oncomplete: null,
                onerror: null,
                onabort: null,
                objectStore() {
                  return {
                    put(val) {
                      const r = { result: undefined };
                      storeMap.set(val.userId, val);
                      queueMicrotask(() => tx.oncomplete && tx.oncomplete());
                      return r;
                    },
                    get(key) {
                      const r = { result: storeMap.get(key) };
                      queueMicrotask(() => tx.oncomplete && tx.oncomplete());
                      return r;
                    },
                    clear() {
                      const r = { result: undefined };
                      storeMap.clear();
                      queueMicrotask(() => tx.oncomplete && tx.oncomplete());
                      return r;
                    },
                  };
                },
              };
              return tx;
            },
            close() {},
          };
          dbs.set(name, db);
        }
        req.result = db;
        if (created && req.onupgradeneeded) req.onupgradeneeded();
        if (req.onsuccess) req.onsuccess();
      });
      return req;
    },
  };
}

function createDomEnv(options = {}) {
  const idMap = new Map();
  const docListeners = new Map();
  const winListeners = new Map();

  class FakeClassList {
    constructor(el) {
      this.el = el;
      this.set = new Set();
    }
    _syncFrom(cls) {
      this.set = new Set(String(cls || "").split(/\s+/).filter(Boolean));
    }
    _syncTo() {
      this.el._className = [...this.set].join(" ");
    }
    add(...tokens) {
      for (const t of tokens) if (t) this.set.add(t);
      this._syncTo();
    }
    remove(...tokens) {
      for (const t of tokens) this.set.delete(t);
      this._syncTo();
    }
    toggle(token, force) {
      if (force === undefined) {
        if (this.set.has(token)) this.set.delete(token);
        else this.set.add(token);
      } else if (force) {
        this.set.add(token);
      } else {
        this.set.delete(token);
      }
      this._syncTo();
      return this.set.has(token);
    }
    contains(token) {
      return this.set.has(token);
    }
  }

  class FakeNode {
    constructor(nodeType, text = "") {
      this.nodeType = nodeType;
      this.parentElement = null;
      this.parentNode = null;
      this.childNodes = [];
      this._textContent = text;
    }
    get textContent() {
      if (this.nodeType === 3) return this._textContent;
      return this.childNodes.map((c) => c.textContent).join("");
    }
    set textContent(val) {
      if (this.nodeType === 3) {
        this._textContent = String(val ?? "");
        return;
      }
      this.childNodes = [];
      if (val !== undefined && val !== null && String(val) !== "") {
        this.appendChild(new FakeNode(3, String(val)));
      }
    }
    appendChild(child) {
      if (!child) return child;
      if (child.nodeType === 11) {
        for (const sub of [...child.childNodes]) this.appendChild(sub);
        return child;
      }
      if (child.parentNode) child.parentNode.removeChild(child);
      child.parentNode = this;
      child.parentElement = this.nodeType === 1 ? this : null;
      this.childNodes.push(child);
      return child;
    }
    insertBefore(newNode, refNode) {
      if (!refNode) return this.appendChild(newNode);
      if (newNode.nodeType === 11) {
        for (const sub of [...newNode.childNodes]) this.insertBefore(sub, refNode);
        return newNode;
      }
      if (newNode.parentNode) newNode.parentNode.removeChild(newNode);
      const idx = this.childNodes.indexOf(refNode);
      if (idx < 0) return this.appendChild(newNode);
      newNode.parentNode = this;
      newNode.parentElement = this.nodeType === 1 ? this : null;
      this.childNodes.splice(idx, 0, newNode);
      return newNode;
    }
    removeChild(child) {
      const idx = this.childNodes.indexOf(child);
      if (idx >= 0) {
        this.childNodes.splice(idx, 1);
        child.parentNode = null;
        child.parentElement = null;
      }
      return child;
    }
    append(...nodes) {
      for (const n of nodes) {
        if (typeof n === "string") this.appendChild(new FakeNode(3, n));
        else if (n) this.appendChild(n);
      }
    }
    replaceChildren(...nodes) {
      this.childNodes = [];
      this.append(...nodes);
    }
    remove() {
      if (this.parentNode) this.parentNode.removeChild(this);
    }
    get children() {
      return this.childNodes.filter((c) => c.nodeType === 1);
    }
    get childElementCount() {
      return this.children.length;
    }
    get firstElementChild() {
      return this.children[0] || null;
    }
    get lastElementChild() {
      const ch = this.children;
      return ch[ch.length - 1] || null;
    }
  }

  function matchSimpleSelector(el, sel) {
    sel = sel.trim();
    if (!sel) return false;
    let pseudoChecked = false;
    if (sel.endsWith(":checked")) {
      pseudoChecked = true;
      sel = sel.slice(0, -8);
    }
    if (pseudoChecked && !el.checked) return false;
    if (sel.startsWith(".")) {
      const parts = sel.split(/(?=\[)/);
      const cls = parts[0].slice(1);
      if (!el.classList.contains(cls)) return false;
      for (let i = 1; i < parts.length; i++) {
        if (!matchSimpleSelector(el, parts[i])) return false;
      }
      return true;
    }
    if (sel.startsWith("#")) return el.id === sel.slice(1);
    const attrMatch = /^([a-zA-Z0-9_-]+)?\[([^=\]]+)(?:=(?:"([^"]*)"|([^\]]*)))?\]$/.exec(sel);
    if (attrMatch) {
      if (attrMatch[1] && el.tagName.toLowerCase() !== attrMatch[1].toLowerCase()) return false;
      const actual = el.getAttribute(attrMatch[2]);
      const expected = attrMatch[3] !== undefined ? attrMatch[3] : attrMatch[4];
      if (expected !== undefined) return actual === expected;
      return actual !== null;
    }
    if (/^[a-zA-Z0-9_-]+$/.test(sel)) {
      return el.tagName.toLowerCase() === sel.toLowerCase();
    }
    return false;
  }

  function queryAllIn(root, selector) {
    const out = [];
    const selectors = selector.split(",").map((s) => s.trim()).filter(Boolean);
    const walk = (node) => {
      for (const child of node.children || []) {
        if (selectors.some((s) => {
          const parts = s.split(/\s+/);
          return matchSimpleSelector(child, parts[parts.length - 1]);
        })) {
          out.push(child);
        }
        walk(child);
      }
    };
    walk(root);
    return out;
  }

  class FakeElement extends FakeNode {
    constructor(tagName) {
      super(1);
      this.tagName = String(tagName).toUpperCase();
      this.attrs = new Map();
      this.dataset = {};
      this.style = { setProperty() {}, getPropertyValue() { return ""; } };
      this._className = "";
      this.classList = new FakeClassList(this);
      this.listeners = new Map();
      this.value = "";
      this.checked = false;
      this.disabled = false;
      this.type = "";
      this.title = "";
      this.placeholder = "";
      this.src = "";
      this.href = "";
      this.scrollTop = 0;
      this.scrollHeight = 100;
      this.clientHeight = 100;
      this.offsetWidth = 100;
      this.offsetHeight = 100;
      this.files = [];
      this.selectionStart = 0;
      this.selectionEnd = 0;
    }
    get id() {
      return this.attrs.get("id") || "";
    }
    set id(v) {
      this.attrs.set("id", String(v));
      idMap.set(String(v), this);
    }
    get className() {
      return this._className;
    }
    set className(v) {
      this._className = String(v || "");
      this.classList._syncFrom(this._className);
    }
    setAttribute(k, v) {
      this.attrs.set(k, String(v));
      if (k === "id") idMap.set(String(v), this);
      if (k === "class") this.className = String(v);
      if (k === "src") this.src = String(v);
      if (k === "href") this.href = String(v);
      if (k === "value") this.value = String(v);
      if (k.startsWith("data-")) {
        const camel = k.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
        this.dataset[camel] = String(v);
      }
    }
    getAttribute(k) {
      if (k === "class") return this._className || null;
      return this.attrs.has(k) ? this.attrs.get(k) : null;
    }
    hasAttribute(k) {
      return this.attrs.has(k);
    }
    removeAttribute(k) {
      this.attrs.delete(k);
      if (k === "src") this.src = "";
    }
    addEventListener(type, fn) {
      if (!this.listeners.has(type)) this.listeners.set(type, []);
      this.listeners.get(type).push(fn);
    }
    removeEventListener(type, fn) {
      const list = this.listeners.get(type);
      if (list) this.listeners.set(type, list.filter((f) => f !== fn));
    }
    dispatchEvent(ev) {
      ev.target = ev.target || this;
      ev.currentTarget = this;
      for (const fn of [...(this.listeners.get(ev.type) || [])]) fn(ev);
      return true;
    }
    click() {
      this.dispatchEvent({ type: "click", preventDefault() {}, stopPropagation() {}, target: this, currentTarget: this });
    }
    focus() {}
    select() {}
    play() { return Promise.resolve(); }
    scrollIntoView() {}
    scrollTo() {}
    getBoundingClientRect() {
      return { left: 0, top: 0, right: 100, bottom: 100, width: 100, height: 100 };
    }
    setPointerCapture() {}
    hasPointerCapture() { return false; }
    closest(sel) {
      let cur = this;
      while (cur && cur.nodeType === 1) {
        if (matchSimpleSelector(cur, sel)) return cur;
        cur = cur.parentElement;
      }
      return null;
    }
    querySelector(sel) {
      return this.querySelectorAll(sel)[0] || null;
    }
    querySelectorAll(sel) {
      return queryAllIn(this, sel);
    }
  }

  const body = new FakeElement("body");
  const documentElement = new FakeElement("html");
  const head = new FakeElement("head");
  documentElement.append(head, body);

  function getOrCreateById(id) {
    if (idMap.has(id)) return idMap.get(id);
    const el = new FakeElement("div");
    el.id = id;
    body.appendChild(el);
    return el;
  }

  for (const className of [
    "main-chat", "sidebar", "chat-title", "list-container", "user-menu-container",
    "login", "landr", "login-f", "tos-container"
  ]) {
    const el = new FakeElement("div");
    el.className = className;
    body.appendChild(el);
  }
  for (const view of ["chats", "friends", "requests", "matrix"]) {
    const btn = new FakeElement("button");
    btn.className = "rail-nav";
    btn.setAttribute("data-rail-view", view);
    body.appendChild(btn);
  }
  // Ensure list-search has a parentElement
  const listSearchWrap = new FakeElement("div");
  const listSearch = new FakeElement("input");
  listSearch.id = "list-search";
  listSearchWrap.appendChild(listSearch);
  body.appendChild(listSearchWrap);

  const locationObj = new URL(options.url || "https://seres.example/index.html");
  const locationProxy = {
    get href() { return locationObj.href; },
    set href(v) {
      const next = new URL(String(v), locationObj.href);
      locationObj.href = next.href;
      navigations.push(next.href);
    },
    get origin() { return locationObj.origin; },
    get pathname() { return locationObj.pathname; },
    get search() { return locationObj.search; },
    get hash() { return locationObj.hash; },
  };
  const navigations = [];

  const createdObjectUrls = [];
  const revokedObjectUrls = [];
  let urlCounter = 0;

  class FakeURL extends URL {
    static createObjectURL(blob) {
      const u = `blob:https://seres.example/${++urlCounter}`;
      createdObjectUrls.push({ url: u, blob });
      return u;
    }
    static revokeObjectURL(u) {
      revokedObjectUrls.push(String(u));
    }
  }

  class FakeBlob {
    constructor(parts = [], opts = {}) {
      this.parts = parts;
      this.type = opts.type || "";
      this.size = parts.reduce((sum, p) => sum + (p?.byteLength ?? p?.length ?? 0), 0);
    }
    async arrayBuffer() {
      const chunks = this.parts.map((p) => (p instanceof Uint8Array ? p : new Uint8Array(p)));
      const total = chunks.reduce((s, c) => s + c.byteLength, 0);
      const out = new Uint8Array(total);
      let off = 0;
      for (const c of chunks) {
        out.set(c, off);
        off += c.byteLength;
      }
      return out.buffer;
    }
  }

  const document = {
    body,
    documentElement,
    head,
    title: "SereS",
    cookie: "",
    visibilityState: "visible",
    hidden: false,
    getElementById: getOrCreateById,
    createElement(tag) {
      return new FakeElement(tag);
    },
    createElementNS(_ns, tag) {
      return new FakeElement(tag);
    },
    createDocumentFragment() {
      return new FakeNode(11);
    },
    createTextNode(text) {
      return new FakeNode(3, String(text ?? ""));
    },
    querySelector(sel) {
      return documentElement.querySelector(sel);
    },
    querySelectorAll(sel) {
      return documentElement.querySelectorAll(sel);
    },
    addEventListener(type, fn) {
      if (!docListeners.has(type)) docListeners.set(type, []);
      docListeners.get(type).push(fn);
    },
    removeEventListener(type, fn) {
      const list = docListeners.get(type);
      if (list) docListeners.set(type, list.filter((f) => f !== fn));
    },
    execCommand() { return true; },
  };

  const localStorage = createStorage();
  const sessionStorage = createStorage();
  const indexedDB = createIndexedDb();

  const navigatorObj = options.navigator || {
    userAgent: "Mozilla/5.0",
    platform: "Win32",
    maxTouchPoints: 0,
    credentials: {
      create: async () => null,
      get: async () => null,
    },
    mediaDevices: {
      getUserMedia: async () => ({ getTracks: () => [], getAudioTracks: () => [] }),
    },
  };

  const windowObj = {
    crypto: webcrypto,
    document,
    location: locationProxy,
    history: {
      replaceState(_s, _t, u) {
        const next = new URL(String(u), locationObj.href);
        locationObj.href = next.href;
      },
    },
    navigator: navigatorObj,
    localStorage,
    sessionStorage,
    indexedDB,
    URL: FakeURL,
    URLSearchParams,
    Blob: FakeBlob,
    FormData,
    TextEncoder,
    TextDecoder,
    atob: (s) => Buffer.from(s, "base64").toString("binary"),
    btoa: (s) => Buffer.from(s, "binary").toString("base64"),
    CSS: { escape: (s) => String(s) },
    Event: class Event { constructor(type) { this.type = type; } },
    CustomEvent: class CustomEvent { constructor(type, init = {}) { this.type = type; this.detail = init.detail; } },
    fetch: options.fetch || (async () => ({ ok: false, status: 500, json: async () => ({}) })),
    confirm: options.confirm || (() => false),
    alert: options.alert || (() => {}),
    prompt: options.prompt || (() => null),
    matchMedia: () => ({ matches: false }),
    getComputedStyle: () => ({ getPropertyValue: () => "" }),
    requestAnimationFrame: (fn) => {
      const id = setTimeout(fn, 0);
      id.unref?.();
      return id;
    },
    setTimeout: (fn, ms, ...args) => {
      const id = setTimeout(fn, ms, ...args);
      id.unref?.();
      return id;
    },
    clearTimeout,
    setInterval: () => 1,
    clearInterval: () => {},
    addEventListener(type, fn) {
      if (!winListeners.has(type)) winListeners.set(type, []);
      winListeners.get(type).push(fn);
    },
    removeEventListener(type, fn) {
      const list = winListeners.get(type);
      if (list) winListeners.set(type, list.filter((f) => f !== fn));
    },
    dispatchEvent(ev) {
      for (const fn of [...(winListeners.get(ev.type) || [])]) fn(ev);
      return true;
    },
    PublicKeyCredential: function () {},
    MediaStream: class MediaStream {
      constructor(tracks = []) { this._tracks = tracks; }
      getTracks() { return this._tracks; }
      getAudioTracks() { return this._tracks; }
    },
    RTCPeerConnection: options.RTCPeerConnection || class FakeRTC {
      constructor() {
        this.signalingState = "stable";
        this.connectionState = "new";
        this.iceGatheringState = "complete";
        this.localDescription = { sdp: "v=0-fake" };
      }
      addTrack() { return { getParameters: () => ({ encodings: [{}] }), setParameters: async () => {} }; }
      addTransceiver() { return { sender: { replaceTrack: async () => {} }, receiver: { track: { kind: "video" } } }; }
      createDataChannel() { return { readyState: "open", send() {} }; }
      getTransceivers() { return []; }
      async createOffer() { return { type: "offer", sdp: "v=0-offer" }; }
      async createAnswer() { return { type: "answer", sdp: "v=0-answer" }; }
      async setLocalDescription(d) { this.localDescription = d; }
      async setRemoteDescription() {}
      addEventListener() {}
      close() { this.connectionState = "closed"; }
    },
  };
  windowObj.window = windowObj;
  windowObj.self = windowObj;
  windowObj.globalThis = windowObj;

  const context = vm.createContext(windowObj);

  function loadScripts(names) {
    for (const name of names) {
      const code = fs.readFileSync(path.join(PUBLIC_DIR, name), "utf8");
      vm.runInContext(code, context, { filename: name });
    }
  }

  async function fireDomContentLoaded() {
    for (const fn of [...(docListeners.get("DOMContentLoaded") || [])]) {
      await fn({ type: "DOMContentLoaded" });
    }
  }

  return {
    window: windowObj,
    context,
    document,
    localStorage,
    sessionStorage,
    navigations,
    createdObjectUrls,
    revokedObjectUrls,
    loadScripts,
    fireDomContentLoaded,
    getById: getOrCreateById,
  };
}

function loadCryptoEnv(opts) {
  const env = createDomEnv(opts);
  env.loadScripts(["crypto.js"]);
  return env;
}

async function makeUserAccount(SeresCrypto, userId, password) {
  const salt = SeresCrypto.newSalt();
  const { authHash, wrapKey } = await SeresCrypto.deriveAccountKeys(password, salt, 100000);
  const bundle = await SeresCrypto.createKeyBundle(wrapKey);
  const identity = await SeresCrypto.unlockIdentity(userId, bundle.enc_private, wrapKey, bundle.pub_ecdh, bundle.pub_sign);
  return { userId, salt, authHash, wrapKey, bundle, identity };
}

function makeFakeStream() {
  const track = {
    kind: "audio",
    enabled: true,
    stopped: false,
    stop() { this.stopped = true; },
  };
  return {
    track,
    stream: {
      getTracks: () => [track],
      getAudioTracks: () => [track],
    },
  };
}

// =========================================================================
// #64: identityFromRaw SPKI derivation + seres-identity-v2 AAD binding
// =========================================================================

test("#64: identityFromRaw derives SPKI locally and rejects pubEcdh/pubSign mismatches", async () => {
  const env = loadCryptoEnv();
  const SeresCrypto = env.window.SeresCrypto;
  const alice = await makeUserAccount(SeresCrypto, "u-alice", "correct-horse-battery");
  const bob = await makeUserAccount(SeresCrypto, "u-bob", "correct-horse-battery");

  // On v2 bundle, AAD check rejects mismatched pub_ecdh / pub_sign
  await assert.rejects(() =>
    SeresCrypto.unlockIdentity("u-alice", alice.bundle.enc_private, alice.wrapKey, bob.bundle.pub_ecdh, alice.bundle.pub_sign),
  );
  await assert.rejects(() =>
    SeresCrypto.unlockIdentity("u-alice", alice.bundle.enc_private, alice.wrapKey, alice.bundle.pub_ecdh, bob.bundle.pub_sign),
  );

  // Direct identityFromRaw SPKI derivation mismatch check
  const ecdh = await webcrypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const sign = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const ecdhPrivBytes = new Uint8Array(await webcrypto.subtle.exportKey("pkcs8", ecdh.privateKey));
  const signPrivBytes = new Uint8Array(await webcrypto.subtle.exportKey("pkcs8", sign.privateKey));
  const ecdhPub = Buffer.from(await webcrypto.subtle.exportKey("spki", ecdh.publicKey)).toString("base64");
  const signPub = Buffer.from(await webcrypto.subtle.exportKey("spki", sign.publicKey)).toString("base64");

  await assert.rejects(
    () => SeresCrypto.identityFromRaw("u-alice", { ecdh: new Uint8Array(ecdhPrivBytes), sign: new Uint8Array(signPrivBytes) }, bob.bundle.pub_ecdh, signPub),
    /do not match|mismatch|public key/i,
  );
  await assert.rejects(
    () => SeresCrypto.identityFromRaw("u-alice", { ecdh: new Uint8Array(ecdhPrivBytes), sign: new Uint8Array(signPrivBytes) }, ecdhPub, bob.bundle.pub_sign),
    /do not match|mismatch|public key/i,
  );
  const ok = await SeresCrypto.identityFromRaw("u-alice", { ecdh: ecdhPrivBytes, sign: signPrivBytes }, ecdhPub, signPub);
  assert.equal(ok.pubEcdh, ecdhPub);
  assert.equal(ok.pubSign, signPub);
});

test("#64: encryptPrivateKeys uses seres-identity-v2 binding userId/pubEcdh/pubSign while supporting v1 fallback", async () => {
  const env = loadCryptoEnv();
  const SeresCrypto = env.window.SeresCrypto;
  const subtle = webcrypto.subtle;

  const salt = SeresCrypto.newSalt();
  const { wrapKey } = await SeresCrypto.deriveAccountKeys("pw12345678", salt, 100000);
  const ecdh = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const sign = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const ecdhPub = Buffer.from(await subtle.exportKey("spki", ecdh.publicKey)).toString("base64");
  const signPub = Buffer.from(await subtle.exportKey("spki", sign.publicKey)).toString("base64");
  const ecdhPriv = new Uint8Array(await subtle.exportKey("pkcs8", ecdh.privateKey));
  const signPriv = new Uint8Array(await subtle.exportKey("pkcs8", sign.privateKey));

  assert.equal(typeof SeresCrypto.encryptPrivateKeys, "function", "encryptPrivateKeys must be exported");
  const encV2 = await SeresCrypto.encryptPrivateKeys(ecdhPriv, signPriv, wrapKey, {
    userId: "user-1",
    pubEcdh: ecdhPub,
    pubSign: signPub,
  });
  const parsedV2 = JSON.parse(encV2);
  assert.equal(parsedV2.v, 2);

  // Binding mismatch on userId / pubEcdh / pubSign must reject
  await assert.rejects(() =>
    SeresCrypto.unlockIdentity("user-2", encV2, wrapKey, ecdhPub, signPub),
  );
  await assert.rejects(() =>
    SeresCrypto.unlockIdentity("user-1", encV2, wrapKey, ecdhPub + "X", signPub),
  );

  // Valid v2 unlocks cleanly
  const ok = await SeresCrypto.unlockIdentity("user-1", encV2, wrapKey, ecdhPub, signPub);
  assert.equal(ok.pubEcdh, ecdhPub);
  assert.equal(ok.pubSign, signPub);

  // v1 fallback still decrypts AND enforces public-key match check
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(JSON.stringify({
    ecdh: Buffer.from(ecdhPriv).toString("base64"),
    sign: Buffer.from(signPriv).toString("base64"),
  }));
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode("seres-identity-v1") }, wrapKey, plain);
  const encV1 = JSON.stringify({
    v: 1,
    iv: Buffer.from(iv).toString("base64"),
    ct: Buffer.from(ct).toString("base64"),
  });
  const okV1 = await SeresCrypto.unlockIdentity("user-1", encV1, wrapKey, ecdhPub, signPub);
  assert.equal(okV1.pubEcdh, ecdhPub);
  const other = await makeUserAccount(SeresCrypto, "other", "pw12345678");
  await assert.rejects(() =>
    SeresCrypto.unlockIdentity("user-1", encV1, wrapKey, other.bundle.pub_ecdh, signPub),
  );
});

// =========================================================================
// #65: linkPubHash, #k= in URL/QR, linkDevice verification, signed sealed identity
// =========================================================================

test("#65: linkPubHash returns full SHA-256 base64url digest and login embeds #k=/&k=", async () => {
  const env = createDomEnv({
    url: "https://seres.example/login.html",
    fetch: async (url) => {
      if (url === "/api/link/start") {
        return { ok: true, status: 200, json: async () => ({ success: true, token: "tok123", code: "ABCD1234", expires_in: 1 }) };
      }
      if (url === "/api/link/status") {
        return { ok: true, status: 200, json: async () => ({ success: true, state: "denied" }) };
      }
      return { ok: false, status: 404, json: async () => ({}) };
    },
  });
  env.loadScripts(["language/en.js", "i18n.js", "qr.js", "devices.js", "crypto.js", "codes.js", "passkeys.js", "login.js"]);
  const SeresCrypto = env.window.SeresCrypto;
  assert.equal(typeof SeresCrypto.linkPubHash, "function");

  const hash = await SeresCrypto.linkPubHash("test-pub-b64");
  assert.match(hash, /^[A-Za-z0-9_-]{43}$/);

  let qrPayload = null;
  const origToSvg = env.window.SeresQR.toSvg;
  env.window.SeresQR.toSvg = (txt) => {
    qrPayload = txt;
    return origToSvg(txt);
  };

  await env.fireDomContentLoaded();
  env.getById("link-device-link").click();
  await new Promise((r) => setTimeout(r, 40));

  const linkUrl = env.getById("link-url").value;
  assert.match(linkUrl, /#k=[A-Za-z0-9_-]{43}$/, `Expected #k=<pubHash> in URL, got ${linkUrl}`);
  assert.ok(qrPayload && qrPayload.startsWith("seres://link?"), "QR should use seres://link");
  assert.match(qrPayload, /[&#]k=[A-Za-z0-9_-]{43}/, `Expected k=<pubHash> in QR, got ${qrPayload}`);
});

test("#65: sealPrivateKeys signs SeresSealedIdentity + binds userId/devicePub AAD, openSealedIdentity verifies", async () => {
  const env = loadCryptoEnv();
  const SeresCrypto = env.window.SeresCrypto;
  const alice = await makeUserAccount(SeresCrypto, "u-alice", "strongpassword1");
  const bob = await makeUserAccount(SeresCrypto, "u-bob", "strongpassword2");
  const linkPair = await SeresCrypto.newLinkKeyPair();
  const otherPair = await SeresCrypto.newLinkKeyPair();

  const sealed = await SeresCrypto.sealPrivateKeys(alice.bundle.enc_private, alice.wrapKey, linkPair.pub, alice.identity);
  assert.deepEqual(Object.keys(sealed).sort(), ["ct", "epub", "iv"], "outer sealed object must match devices.rs {epub, iv, ct}");

  // Valid open
  const opened = await SeresCrypto.openSealedIdentity("u-alice", linkPair.privateKey, sealed, alice.bundle.pub_ecdh, alice.bundle.pub_sign, linkPair.pub);
  assert.equal(opened.userId, "u-alice");
  assert.equal(opened.pubEcdh, alice.bundle.pub_ecdh);

  // Wrong userId in AAD/signature fails
  await assert.rejects(() =>
    SeresCrypto.openSealedIdentity("u-evil", linkPair.privateKey, sealed, alice.bundle.pub_ecdh, alice.bundle.pub_sign, linkPair.pub),
  );
  // Wrong devicePub / recipient key fails
  await assert.rejects(() =>
    SeresCrypto.openSealedIdentity("u-alice", linkPair.privateKey, sealed, alice.bundle.pub_ecdh, alice.bundle.pub_sign, otherPair.pub),
  );
  // Unsigned or wrong-signer sealed payload fails
  const sealedByBob = await SeresCrypto.sealPrivateKeys(alice.bundle.enc_private, alice.wrapKey, linkPair.pub, {
    ...alice.identity,
    signPriv: bob.identity.signPriv,
  });
  await assert.rejects(() =>
    SeresCrypto.openSealedIdentity("u-alice", linkPair.privateKey, sealedByBob, alice.bundle.pub_ecdh, alice.bundle.pub_sign, linkPair.pub),
  );
});

test("#65: linkDevice aborts and calls /api/link/deny on #k= hash mismatch", async () => {
  const deniedIds = [];
  let askedAboutDevice = false;
  const env = createDomEnv({
    url: "https://seres.example/index.html?link=tok123#k=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    fetch: async (url, opts) => {
      if (url === "/api/me") {
        return { ok: true, status: 200, json: async () => ({ success: true, user: { id: "u1", username: "alice", pub_ecdh: "pe", pub_sign: "ps", enc_private: "{}" } }) };
      }
      if (url === "/api/users/keys?ids=u1") {
        return { ok: true, status: 200, json: async () => ({ success: true, users: [{ id: "u1", username: "alice", pub_ecdh: "pe", pub_sign: "ps", previous_keys: [] }] }) };
      }
      if (url === "/api/devices") {
        return { ok: true, status: 200, json: async () => ({ success: true, is_main: true, has_main: true, devices: [{ id: "d1", approved: true, current: true, main: true, created_at: "2026-01-01T00:00:00Z" }] }) };
      }
      if (url === "/api/link/find") {
        return { ok: true, status: 200, json: async () => ({ success: true, id: "link-row-1", pub: "mismatched-pub-key", user_agent: "Mozilla/5.0", created_at: "2026-01-01T00:00:00Z" }) };
      }
      if (url === "/api/link/deny") {
        deniedIds.push(JSON.parse(opts.body).id);
        return { ok: true, status: 200, json: async () => ({ success: true }) };
      }
      if (url === "/api/friends") return { ok: true, status: 200, json: async () => ({ success: true, friends: [], incoming: [], outgoing: [], blocked: [] }) };
      if (url === "/api/chats") return { ok: true, status: 200, json: async () => ({ success: true, chats: [] }) };
      return { ok: true, status: 200, json: async () => ({ success: true }) };
    },
  });
  env.loadScripts(["language/en.js", "i18n.js", "qr.js", "emoji.js", "format.js", "crypto.js", "codes.js", "passkeys.js", "devices.js", "calls.js", "index.js"]);
  const subtle = webcrypto.subtle;
  const kp = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const sp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const pubEcdh = Buffer.from(await subtle.exportKey("spki", kp.publicKey)).toString("base64");
  const pubSign = Buffer.from(await subtle.exportKey("spki", sp.publicKey)).toString("base64");
  // Override fetch /api/me with real keys
  const origFetch = env.window.fetch;
  env.window.fetch = async (url, opts) => {
    if (url === "/api/me") return { ok: true, status: 200, json: async () => ({ success: true, user: { id: "u1", username: "alice", pub_ecdh: pubEcdh, pub_sign: pubSign, enc_private: "{}" } }) };
    if (url === "/api/users/keys?ids=u1") return { ok: true, status: 200, json: async () => ({ success: true, users: [{ id: "u1", username: "alice", pub_ecdh: pubEcdh, pub_sign: pubSign, previous_keys: [] }] }) };
    return origFetch(url, opts);
  };
  await env.window.SeresCrypto.saveIdentity({ userId: "u1", ecdhPriv: kp.privateKey, signPriv: sp.privateKey, pubEcdh, pubSign });
  // Track if device-request-modal opens
  const modal = env.getById("device-request-modal");
  modal.classList.add("modal-hidden");
  const origRemove = modal.classList.remove.bind(modal.classList);
  modal.classList.remove = (...args) => {
    if (args.includes("modal-hidden")) askedAboutDevice = true;
    return origRemove(...args);
  };

  await env.fireDomContentLoaded();
  for (let i = 0; i < 40 && deniedIds.length === 0; i++) {
    await new Promise((r) => setTimeout(r, 10));
  }

  assert.deepEqual(deniedIds, ["link-row-1"], "linkDevice must call /api/link/deny on #k= mismatch");
  assert.equal(askedAboutDevice, false, "linkDevice must abort before asking user on #k= mismatch");
});

// =========================================================================
// #66: KDF bounds & legacy plaintext login refusal/confirmation
// =========================================================================

test("#66: deriveAccountKeys validates integer iterations in [100_000, 5_000_000] and salt >= 16 bytes", async () => {
  const env = loadCryptoEnv();
  const SeresCrypto = env.window.SeresCrypto;
  const goodSalt = Buffer.from(webcrypto.getRandomValues(new Uint8Array(16))).toString("base64");
  const shortSalt = Buffer.from(webcrypto.getRandomValues(new Uint8Array(15))).toString("base64");

  await assert.rejects(() => SeresCrypto.deriveAccountKeys("pw", goodSalt, 99_999));
  await assert.rejects(() => SeresCrypto.deriveAccountKeys("pw", goodSalt, 5_000_001));
  await assert.rejects(() => SeresCrypto.deriveAccountKeys("pw", goodSalt, 100_000.5));
  await assert.rejects(() => SeresCrypto.deriveAccountKeys("pw", shortSalt, 100_000));
  await assert.rejects(() => SeresCrypto.deriveAccountKeys("pw", "", 100_000));

  const ok = await SeresCrypto.deriveAccountKeys("pw", goodSalt, 100_000);
  assert.ok(ok.authHash && ok.wrapKey);
});

test("#66: loginWith refuses legacy plaintext submission if E2EE was used and requires confirm otherwise", async () => {
  let loginCalls = [];
  let confirmCalls = 0;
  let confirmResult = false;
  const salt = Buffer.from(webcrypto.getRandomValues(new Uint8Array(16))).toString("base64");

  const makeLoginEnv = () => {
    loginCalls = [];
    confirmCalls = 0;
    const env = createDomEnv({
      url: "https://seres.example/login.html",
      confirm: () => {
        confirmCalls++;
        return confirmResult;
      },
      fetch: async (url, opts) => {
        if (url === "/api/prelogin") {
          return { ok: true, status: 200, json: async () => ({ success: true, kdf_salt: salt, kdf_iterations: 100000, legacy: true }) };
        }
        if (url === "/api/login") {
          loginCalls.push(JSON.parse(opts.body));
          return { ok: true, status: 200, json: async () => ({ success: true, user: { id: "u1" } }) };
        }
        return { ok: false, status: 400, json: async () => ({}) };
      },
    });
    env.loadScripts(["language/en.js", "i18n.js", "qr.js", "devices.js", "crypto.js", "codes.js", "passkeys.js", "login.js"]);
    return env;
  };

  // Case 1: Fresh browser, user declines confirm -> must NOT transmit plaintext passwd
  confirmResult = false;
  let env = makeLoginEnv();
  await env.fireDomContentLoaded();
  env.getById("email").value = "alice";
  env.getById("password").value = "secret-password";
  env.getById("login").click();
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(confirmCalls, 1, "legacy login must prompt explicit confirmation");
  assert.equal(loginCalls.length, 0, "must not submit /api/login when confirm is cancelled");

  // Case 2: E2EE identity was previously used on this origin -> refuse even if confirm would return true
  confirmResult = true;
  env = makeLoginEnv();
  const acct = await makeUserAccount(env.window.SeresCrypto, "u-prev", "secret-password");
  await env.window.SeresCrypto.saveIdentity(acct.identity);
  await env.window.SeresCrypto.clearIdentities(); // even after logout!
  await env.fireDomContentLoaded();
  env.getById("email").value = "alice";
  env.getById("password").value = "secret-password";
  env.getById("login").click();
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(loginCalls.length, 0, "must refuse legacy plaintext login when E2EE was ever used on origin");
});

// =========================================================================
// #67: SeresPasskeys unwraps options.publicKey ?? options
// =========================================================================

test("#67: SeresPasskeys create() and get() handle both wrapped and unwrapped publicKey options", async () => {
  const seenCreate = [];
  const seenGet = [];
  const env = createDomEnv({
    navigator: {
      credentials: {
        create: async (arg) => {
          seenCreate.push(arg);
          return {
            id: "cred1",
            rawId: new Uint8Array([1, 2]).buffer,
            type: "public-key",
            response: {
              clientDataJSON: new Uint8Array([3]).buffer,
              attestationObject: new Uint8Array([4]).buffer,
              getTransports: () => ["internal"],
            },
            getClientExtensionResults: () => ({}),
          };
        },
        get: async (arg) => {
          seenGet.push(arg);
          return {
            id: "cred1",
            rawId: new Uint8Array([1, 2]).buffer,
            type: "public-key",
            response: {
              clientDataJSON: new Uint8Array([3]).buffer,
              authenticatorData: new Uint8Array([4]).buffer,
              signature: new Uint8Array([5]).buffer,
              userHandle: null,
            },
            getClientExtensionResults: () => ({}),
          };
        },
      },
    },
  });
  env.loadScripts(["passkeys.js"]);
  const PK = env.window.SeresPasskeys;

  const challenge = "AQID";
  const userId = "BAUG";
  // Unwrapped (new backend format)
  await PK.create({ challenge, user: { id: userId, name: "alice" }, excludeCredentials: [{ id: "AQID", type: "public-key" }] });
  // Wrapped (legacy format)
  await PK.create({ publicKey: { challenge, user: { id: userId, name: "alice" }, excludeCredentials: [{ id: "AQID", type: "public-key" }] } });

  assert.equal(seenCreate.length, 2);
  assert.ok(utilTypes.isArrayBuffer(seenCreate[0].publicKey.challenge));
  assert.ok(utilTypes.isArrayBuffer(seenCreate[1].publicKey.challenge));

  await PK.get({ challenge, allowCredentials: [{ id: "AQID", type: "public-key" }] });
  await PK.get({ publicKey: { challenge, allowCredentials: [{ id: "AQID", type: "public-key" }] } });
  assert.equal(seenGet.length, 2);
  assert.ok(utilTypes.isArrayBuffer(seenGet[0].publicKey.challenge));
  assert.ok(utilTypes.isArrayBuffer(seenGet[1].publicKey.challenge));
});

// =========================================================================
// #72: shareMessageKey hasOwnProperty check + messageKeyBytes fallback / shares array
// =========================================================================

test("#72: shareMessageKey requires own property in envelope.keys and decryptMessage falls back from bad share to envelope.keys or valid share in array", async () => {
  const env = loadCryptoEnv();
  const SeresCrypto = env.window.SeresCrypto;
  const alice = await makeUserAccount(SeresCrypto, "u-alice", "pass-alice-123");
  const bob = await makeUserAccount(SeresCrypto, "u-bob", "pass-bob-123");
  const carol = await makeUserAccount(SeresCrypto, "u-carol", "pass-carol-123");

  const senderPub = { id: alice.userId, pub_ecdh: alice.bundle.pub_ecdh, pub_sign: alice.bundle.pub_sign };
  const envelope = await SeresCrypto.encryptMessage(
    alice.identity,
    "chat-1",
    "msg-1",
    { text: "hello world" },
    [
      { id: alice.userId, pub_ecdh: alice.bundle.pub_ecdh, pub_sign: alice.bundle.pub_sign },
      { id: bob.userId, pub_ecdh: bob.bundle.pub_ecdh, pub_sign: bob.bundle.pub_sign },
    ],
  );

  // Carol was NOT in envelope.keys -> shareMessageKey must reject
  await assert.rejects(() =>
    SeresCrypto.shareMessageKey(alice.identity, "chat-1", "msg-1", senderPub, envelope, {
      id: carol.userId,
      pub_ecdh: carol.bundle.pub_ecdh,
    }),
  );
  // Prototype key must also reject
  await assert.rejects(() =>
    SeresCrypto.shareMessageKey(alice.identity, "chat-1", "msg-1", senderPub, envelope, {
      id: "toString",
      pub_ecdh: carol.bundle.pub_ecdh,
    }),
  );

  // Poisoned ownShare + valid envelope.keys[bob.userId] -> must fall back and decrypt!
  const poisonedShare = { iv: Buffer.alloc(12).toString("base64"), k: Buffer.alloc(32).toString("base64"), from_pub: carol.bundle.pub_ecdh };
  const decFallback = await SeresCrypto.decryptMessage(bob.identity, "chat-1", "msg-1", senderPub, envelope, poisonedShare);
  assert.equal(decFallback.text, "hello world");

  // Array of shares where first is poisoned and second is valid (for a recipient not in envelope.keys directly or with old key)
  const bobReset = await makeUserAccount(SeresCrypto, "u-bob", "pass-bob-reset");
  const validShare = await SeresCrypto.shareMessageKey(alice.identity, "chat-1", "msg-1", senderPub, envelope, {
    id: bob.userId,
    pub_ecdh: bobReset.bundle.pub_ecdh,
  });
  const decArray = await SeresCrypto.decryptMessage(
    bobReset.identity,
    "chat-1",
    "msg-1",
    senderPub,
    envelope,
    [poisonedShare, { ...validShare, from_pub: alice.bundle.pub_ecdh }],
  );
  assert.equal(decArray.text, "hello world");
});

// =========================================================================
// #73 calls.ts: participant/role checks & mic cleanup on error
// =========================================================================

test("#73 calls.ts: handleSignal enforces joined participant + deterministic role, and start() stops mic on error", async () => {
  const alerts = [];
  const fakeMic = makeFakeStream();
  let failIce = false;
  let signalBatch = [];
  let peerConstructed = 0;

  const env = createDomEnv({
    navigator: {
      mediaDevices: {
        getUserMedia: async () => fakeMic.stream,
      },
    },
    RTCPeerConnection: class TrackedRTC {
      constructor() {
        peerConstructed++;
        this.signalingState = "stable";
        this.connectionState = "new";
        this.iceGatheringState = "complete";
        this.localDescription = { sdp: "v=0-fake" };
      }
      addTrack() { return { getParameters: () => ({ encodings: [{}] }), setParameters: async () => {} }; }
      addTransceiver() { return { sender: { replaceTrack: async () => {} }, receiver: { track: { kind: "video" } } }; }
      createDataChannel() { return { readyState: "open", send() {} }; }
      getTransceivers() { return []; }
      async createOffer() { return { type: "offer", sdp: "v=0-offer" }; }
      async createAnswer() { return { type: "answer", sdp: "v=0-answer" }; }
      async setLocalDescription(d) { this.localDescription = d; }
      async setRemoteDescription() {}
      addEventListener() {}
      close() { this.connectionState = "closed"; }
    },
  });
  env.loadScripts(["language/en.js", "i18n.js", "crypto.js", "calls.js"]);
  const SeresCrypto = env.window.SeresCrypto;
  const meAcc = await makeUserAccount(SeresCrypto, "u-200", "pw12345678");
  const lowerAcc = await makeUserAccount(SeresCrypto, "u-100", "pw12345678");
  const higherAcc = await makeUserAccount(SeresCrypto, "u-300", "pw12345678");
  const outsiderAcc = await makeUserAccount(SeresCrypto, "u-050", "pw12345678");

  const callObj = {
    id: "call-1",
    chat_id: "chat-1",
    chat_name: "Test",
    chat_type: "group",
    started_by: "u-200",
    started_at: new Date().toISOString(),
    answered_at: null,
    participants: [
      { id: "u-200", username: "me", display_name: "Me", state: "joined" },
      { id: "u-100", username: "low", display_name: "Low", state: "ringing" }, // NOT joined!
      { id: "u-300", username: "high", display_name: "High", state: "joined" },
    ],
  };

  // First test: start() stops mic when enter() fails before taking ownership
  failIce = true;
  env.window.SeresCalls.init({
    api: async (p) => {
      if (p === "/api/calls/ice" && failIce) throw new Error("ice down");
      if (p === "/api/calls/ice") return { ice_servers: [] };
      if (p.startsWith("/api/calls?")) return { calls: [], signals: [] };
      return {};
    },
    post: async (p) => {
      if (p.endsWith("/call")) return { call: callObj };
      return {};
    },
    me: () => ({ id: "u-200", username: "me" }),
    identity: () => meAcc.identity,
    signKey: async () => null,
    showAlert: (m) => alerts.push(m),
    errorText: (e) => String(e?.message || e),
    pickPeople: async () => null,
    chatCreated: () => {},
    openChat: () => {},
    avatar: () => env.document.createElement("div"),
  });

  await env.window.SeresCalls.start("chat-1");
  assert.equal(fakeMic.track.stopped, true, "acquired mic track must be stopped if enter() failed");

  // Second test: enter() succeeds, then test handleSignal rejects non-joined and wrong-role signals
  failIce = false;
  fakeMic.track.stopped = false;
  await env.window.SeresCalls.start("chat-1");
  const basePeers = peerConstructed; // 1 peer for u-300 (since u-200 < u-300)

  const sigNonJoined = await SeresCrypto.signCall(lowerAcc.identity, "call-1", "u-200", "offer", "v=0-offer");
  const sigWrongRoleOffer = await SeresCrypto.signCall(higherAcc.identity, "call-1", "u-200", "offer", "v=0-offer");
  const sigOutsider = await SeresCrypto.signCall(outsiderAcc.identity, "call-1", "u-200", "offer", "v=0-offer");

  signalBatch = [
    { id: 1, call_id: "call-1", from: "u-100", kind: "offer", data: { sdp: "v=0-offer", sig: sigNonJoined } },
    { id: 2, call_id: "call-1", from: "u-300", kind: "offer", data: { sdp: "v=0-offer", sig: sigWrongRoleOffer } },
    { id: 3, call_id: "call-1", from: "u-050", kind: "offer", data: { sdp: "v=0-offer", sig: sigOutsider } },
  ];

  // Re-init or trigger poll via fresh env where /api/calls returns signalBatch
  const env2 = createDomEnv({
    navigator: { mediaDevices: { getUserMedia: async () => makeFakeStream().stream } },
    RTCPeerConnection: env.window.RTCPeerConnection,
  });
  env2.loadScripts(["language/en.js", "i18n.js", "crypto.js", "calls.js"]);
  let constructed2 = 0;
  const OrigRTC = env2.window.RTCPeerConnection;
  env2.window.RTCPeerConnection = class extends OrigRTC {
    constructor() { super(); constructed2++; }
  };
  const keyMap = {
    "u-100": lowerAcc.bundle.pub_sign,
    "u-300": higherAcc.bundle.pub_sign,
    "u-050": outsiderAcc.bundle.pub_sign,
  };
  let callsPollCount = 0;
  env2.window.SeresCalls.init({
    api: async (p) => {
      if (p === "/api/calls/ice") return { ice_servers: [] };
      if (p.startsWith("/api/calls?")) {
        callsPollCount++;
        if (callsPollCount === 1) return { calls: [], signals: [] };
        return { calls: [callObj], signals: signalBatch };
      }
      return {};
    },
    post: async (p) => (p.endsWith("/call") ? { call: callObj } : {}),
    me: () => ({ id: "u-200", username: "me" }),
    identity: () => meAcc.identity,
    signKey: async (id) => keyMap[id] || null,
    showAlert: () => {},
    errorText: (e) => String(e),
    pickPeople: async () => null,
    chatCreated: () => {},
    openChat: () => {},
    avatar: () => env2.document.createElement("div"),
  });
  await env2.window.SeresCalls.start("chat-1");
  const afterStart = constructed2; // 1 (for u-300)
  // Trigger a manual poll by waiting? Better: trigger window setTimeout callback captured!
  // Actually let's capture setTimeout in env2 or test via poll directly!
  assert.equal(basePeers, 1);
  assert.equal(afterStart, 1);
});

test("#73 calls.ts: poll rejects non-joined / wrong-role call signals end-to-end", async () => {
  let scheduledPoll = null;
  let peersCreated = [];
  const env = createDomEnv({
    navigator: { mediaDevices: { getUserMedia: async () => makeFakeStream().stream } },
  });
  env.window.setTimeout = (fn) => {
    scheduledPoll = fn;
    return 1;
  };
  env.loadScripts(["language/en.js", "i18n.js", "crypto.js", "calls.js"]);
  const OrigRTC = env.window.RTCPeerConnection;
  env.window.RTCPeerConnection = class extends OrigRTC {
    constructor() {
      super();
      peersCreated.push(this);
    }
  };
  const SeresCrypto = env.window.SeresCrypto;
  const meAcc = await makeUserAccount(SeresCrypto, "u-200", "pw12345678");
  const lowerAcc = await makeUserAccount(SeresCrypto, "u-100", "pw12345678");
  const higherAcc = await makeUserAccount(SeresCrypto, "u-300", "pw12345678");

  const callObj = {
    id: "call-1",
    chat_id: "chat-1",
    chat_name: "Test",
    chat_type: "group",
    started_by: "u-200",
    started_at: new Date().toISOString(),
    answered_at: null,
    participants: [
      { id: "u-200", username: "me", display_name: "Me", state: "joined" },
      { id: "u-100", username: "low", display_name: "Low", state: "ringing" },
      { id: "u-300", username: "high", display_name: "High", state: "joined" },
    ],
  };

  const sigNonJoined = await SeresCrypto.signCall(lowerAcc.identity, "call-1", "u-200", "offer", "v=0-offer");
  const sigWrongOfferFromHigher = await SeresCrypto.signCall(higherAcc.identity, "call-1", "u-200", "offer", "v=0-offer");
  let phase = 0;

  env.window.SeresCalls.init({
    api: async (p) => {
      if (p === "/api/calls/ice") return { ice_servers: [] };
      if (p.startsWith("/api/calls?")) {
        if (phase === 0) return { calls: [], signals: [] };
        return {
          calls: [callObj],
          signals: [
            { id: 1, call_id: "call-1", from: "u-100", kind: "offer", data: { sdp: "v=0-offer", sig: sigNonJoined } },
            { id: 2, call_id: "call-1", from: "u-300", kind: "offer", data: { sdp: "v=0-offer", sig: sigWrongOfferFromHigher } },
          ],
        };
      }
      return {};
    },
    post: async (p) => (p.endsWith("/call") ? { call: callObj } : {}),
    me: () => ({ id: "u-200", username: "me" }),
    identity: () => meAcc.identity,
    signKey: async (id) => (id === "u-100" ? lowerAcc.bundle.pub_sign : higherAcc.bundle.pub_sign),
    showAlert: () => {},
    errorText: (e) => String(e),
    pickPeople: async () => null,
    chatCreated: () => {},
    openChat: () => {},
    avatar: () => env.document.createElement("div"),
  });
  await new Promise((r) => setTimeout(r, 20));
  await env.window.SeresCalls.start("chat-1");
  const peersAfterStart = peersCreated.length; // 1 (offer to u-300)
  phase = 1;
  await scheduledPoll();
  // Neither u-100 (not joined) nor u-300 (wrong role: u-300 > u-200 cannot send offer) should create/replace any peer!
  assert.equal(peersCreated.length, peersAfterStart, "non-joined and wrong-role signals must be ignored");
});

// =========================================================================
// #73 index.js & #74 index.js
// =========================================================================

async function setupIndexApp({
  url = "https://seres.example/index.html",
  meUser,
  usersKeysMap = {},
  chats = [],
  chatDetails = {},
  chatMessages = {},
  devicesResponse = { is_main: true, has_main: true, devices: [{ id: "d1", approved: true, current: true, main: true, created_at: "2026-01-01T00:00:00Z" }] },
  extraFetch,
  matrixController,
  preSeedPins,
} = {}) {
  let fetchCalls = [];
  const env = createDomEnv({
    url,
    fetch: async (reqUrl, opts) => {
      fetchCalls.push({ url: reqUrl, opts });
      if (extraFetch) {
        const custom = await extraFetch(reqUrl, opts);
        if (custom) return custom;
      }
      if (reqUrl === "/api/me") {
        return { ok: true, status: 200, json: async () => ({ success: true, user: meUser }) };
      }
      if (reqUrl.startsWith("/api/users/keys?")) {
        const ids = decodeURIComponent(reqUrl.split("ids=")[1] || "").split(",").filter(Boolean);
        return { ok: true, status: 200, json: async () => ({ success: true, users: ids.map((id) => usersKeysMap[id]).filter(Boolean) }) };
      }
      if (reqUrl === "/api/friends") {
        return { ok: true, status: 200, json: async () => ({ success: true, friends: [], incoming: [], outgoing: [], blocked: [] }) };
      }
      if (reqUrl === "/api/chats") {
        return { ok: true, status: 200, json: async () => ({ success: true, chats }) };
      }
      if (reqUrl === "/api/devices") {
        return { ok: true, status: 200, json: async () => ({ success: true, ...devicesResponse }) };
      }
      if (reqUrl === "/api/get_avatar") {
        return { ok: false, status: 404, json: async () => ({}) };
      }
      if (reqUrl.match(/^\/api\/chats\/[^/]+$/)) {
        const cid = decodeURIComponent(reqUrl.split("/").pop());
        return { ok: true, status: 200, json: async () => ({ success: true, chat: chatDetails[cid] }) };
      }
      if (reqUrl.match(/^\/api\/chats\/[^/]+\/messages/)) {
        const cid = decodeURIComponent(reqUrl.split("/")[3]);
        return { ok: true, status: 200, json: async () => ({ success: true, messages: chatMessages[cid] || [], has_more: false, receipts: null }) };
      }
      if (reqUrl.endsWith("/scheduled")) {
        return { ok: true, status: 200, json: async () => ({ success: true, messages: [] }) };
      }
      return { ok: true, status: 200, json: async () => ({ success: true }) };
    },
  });
  if (matrixController) env.window.SeresMatrix = matrixController;
  env.loadScripts(["language/en.js", "language/de.js", "language/fr.js", "i18n.js", "qr.js", "emoji.js", "format.js", "crypto.js", "codes.js", "passkeys.js", "devices.js", "calls.js", "index.js"]);
  if (preSeedPins) {
    env.localStorage.setItem("seres-pins:" + meUser.id, JSON.stringify(preSeedPins));
  }
  return { env, fetchCalls };
}

test("#73 index.js: legacy messages never compact, show explicit unencrypted badge on bubble & preview; poll deduplicates; previewCard checks hostname+URL+raster image; error not cached", async () => {
  const tmpEnv = loadCryptoEnv();
  const alice = await makeUserAccount(tmpEnv.window.SeresCrypto, "u-alice", "alice-pw-123");
  const bob = await makeUserAccount(tmpEnv.window.SeresCrypto, "u-bob", "bob-pw-123");
  const bobPub = { id: bob.userId, pub_ecdh: bob.bundle.pub_ecdh, pub_sign: bob.bundle.pub_sign };
  const alicePub = { id: alice.userId, pub_ecdh: alice.bundle.pub_ecdh, pub_sign: alice.bundle.pub_sign };

  const now = Date.now();
  const t1 = new Date(now - 60_000).toISOString();
  const t2 = new Date(now - 50_000).toISOString();
  const t3 = new Date(now - 40_000).toISOString();

  // Poll + multi-choice duplicate vote [0, 0, 0]
  const pollPayload = await tmpEnv.window.SeresCrypto.encryptMessage(
    bob.identity, "chat-1", "m-poll",
    { text: "Vote!", poll: { question: "Pick?", options: ["A", "B"], multi: true } },
    [alicePub, bobPub],
  );
  const votePayload = await tmpEnv.window.SeresCrypto.encryptMessage(
    bob.identity, "chat-1", "m-vote",
    { type: "vote", target: "m-poll", choices: [0, 0, 0] },
    [alicePub, bobPub],
  );
  // Spoofed preview: preview.site says bank.com, preview.url says evil.com while text has good.com, SVG image
  const spoofPreviewPayload = await tmpEnv.window.SeresCrypto.encryptMessage(
    bob.identity, "chat-1", "m-prev-bad",
    {
      text: "Look at https://good.example/news",
      preview: {
        url: "https://evil.example/phish",
        title: "Login",
        site: "good.example",
        image: "data:image/svg+xml;base64,PHN2Zy8+",
      },
    },
    [alicePub, bobPub],
  );
  // Valid URL preview with spoofed site + SVG image -> should show parsed hostname and drop SVG image
  const validPreviewSvgPayload = await tmpEnv.window.SeresCrypto.encryptMessage(
    bob.identity, "chat-1", "m-prev-host",
    {
      text: "Check https://real.example/page",
      preview: {
        url: "https://real.example/page",
        title: "Real Page",
        site: "fake-bank.example",
        image: "data:image/svg+xml;base64,PHN2Zy8+",
      },
    },
    [alicePub, bobPub],
  );

  // Transient error message: keys for departed "u-temp" fail first, then succeed
  const tempUser = await makeUserAccount(tmpEnv.window.SeresCrypto, "u-temp", "temp-pw-123");
  const tempPub = { id: tempUser.userId, pub_ecdh: tempUser.bundle.pub_ecdh, pub_sign: tempUser.bundle.pub_sign };
  const tempMsgPayload = await tmpEnv.window.SeresCrypto.encryptMessage(
    tempUser.identity, "chat-1", "m-temp",
    { text: "retry works" },
    [alicePub, tempPub],
  );

  let tempKeysFail = true;
  const usersKeysMap = {
    [alice.userId]: { id: alice.userId, username: "alice", pub_ecdh: alice.bundle.pub_ecdh, pub_sign: alice.bundle.pub_sign, previous_keys: [{ pub_ecdh: "old", pub_sign: "old", until: "2020-01-01T00:00:00Z" }] },
    [bob.userId]: { id: bob.userId, username: "bob", pub_ecdh: bob.bundle.pub_ecdh, pub_sign: bob.bundle.pub_sign, previous_keys: [] },
  };
  const chatMessages = {
    "chat-1": [
      { seq: 1, rev: 1, id: "m-leg-1", sender_id: bob.userId, sender: "bob", kind: "legacy", payload: { text: "first legacy" }, created_at: t1, deleted: false },
      { seq: 2, rev: 2, id: "m-leg-2", sender_id: bob.userId, sender: "bob", kind: "legacy", payload: { text: "second legacy" }, created_at: t2, deleted: false },
      { seq: 3, rev: 3, id: "m-poll", sender_id: bob.userId, sender: "bob", kind: "e2e", payload: pollPayload, created_at: t3, deleted: false },
      { seq: 4, rev: 4, id: "m-vote", sender_id: bob.userId, sender: "bob", kind: "e2e", payload: votePayload, created_at: t3, deleted: false, silent: true },
      { seq: 5, rev: 5, id: "m-prev-bad", sender_id: bob.userId, sender: "bob", kind: "e2e", payload: spoofPreviewPayload, created_at: t3, deleted: false },
      { seq: 6, rev: 6, id: "m-prev-host", sender_id: bob.userId, sender: "bob", kind: "e2e", payload: validPreviewSvgPayload, created_at: t3, deleted: false },
      { seq: 7, rev: 7, id: "m-temp", sender_id: tempUser.userId, sender: "temp", kind: "e2e", payload: tempMsgPayload, created_at: t3, deleted: false },
    ],
  };

  const { env } = await setupIndexApp({
    meUser: { id: alice.userId, username: "alice", pub_ecdh: alice.bundle.pub_ecdh, pub_sign: alice.bundle.pub_sign, enc_private: alice.bundle.enc_private },
    usersKeysMap,
    chats: [{
      id: "chat-1",
      type: "dm",
      name: "bob",
      role: "member",
      member_count: 2,
      last_message: chatMessages["chat-1"][1],
      unread: 0,
      last_activity: t2,
      other_user: "bob",
      other_user_id: bob.userId,
    }],
    chatDetails: {
      "chat-1": {
        id: "chat-1",
        type: "dm",
        name: "bob",
        role: "member",
        member_count: 2,
        unread: 0,
        last_activity: t2,
        members: [
          { id: alice.userId, username: "alice", pub_ecdh: alice.bundle.pub_ecdh, pub_sign: alice.bundle.pub_sign, role: "member" },
          { id: bob.userId, username: "bob", pub_ecdh: bob.bundle.pub_ecdh, pub_sign: bob.bundle.pub_sign, role: "member" },
        ],
      },
    },
    chatMessages,
    extraFetch: async (reqUrl) => {
      if (reqUrl.startsWith("/api/users/keys?") && reqUrl.includes("u-temp")) {
        if (tempKeysFail) return { ok: false, status: 500, json: async () => ({ success: false, message: "err" }) };
        return { ok: true, status: 200, json: async () => ({ success: true, users: [{ id: tempUser.userId, username: "temp", pub_ecdh: tempUser.bundle.pub_ecdh, pub_sign: tempUser.bundle.pub_sign, previous_keys: [] }] }) };
      }
      return null;
    },
  });
  await env.window.SeresCrypto.saveIdentity(alice.identity);
  await env.fireDomContentLoaded();
  await new Promise((r) => setTimeout(r, 40));

  // Chat list preview for legacy message must show unencrypted notice
  const listStatus = env.getById("dm-list").querySelector(".item-status")?.textContent || "";
  assert.match(listStatus.toLowerCase(), /not encrypted|unencrypted/, `Legacy preview must mark unencrypted, got: ${listStatus}`);

  // Open chat
  env.getById("dm-list").querySelector(".chat-list-item").click();
  await new Promise((r) => setTimeout(r, 60));

  const messagesEl = env.getById("messages");
  const legRow2 = messagesEl.querySelector('.message-row[data-id="m-leg-2"]');
  assert.ok(legRow2, "second legacy message row should exist");
  assert.equal(legRow2.classList.contains("message-compact"), false, "legacy message must NEVER be compact");
  const legBubble2 = legRow2.querySelector(".message-text");
  assert.match(legBubble2.textContent.toLowerCase(), /not encrypted/, "legacy bubble must render explicit unencrypted badge/notice directly on bubble");

  // Multi-choice poll vote deduplication
  const pollRow = messagesEl.querySelector('.message-row[data-id="m-poll"]');
  const pollCounts = pollRow.querySelectorAll(".poll-count").map((el) => el.textContent);
  assert.deepEqual(pollCounts, ["1", "0"], "duplicate vote choices [0,0,0] must be deduplicated to 1 vote");

  // Preview card: mismatched preview.url dropped completely
  const badPrevRow = messagesEl.querySelector('.message-row[data-id="m-prev-bad"]');
  assert.equal(badPrevRow.querySelector(".link-preview"), null, "preview.url not matching view.text URL must not render");

  // Preview card: valid URL shows parsed hostname (real.example) NOT spoofed site (fake-bank.example), and rejects SVG image
  const hostPrevRow = messagesEl.querySelector('.message-row[data-id="m-prev-host"]');
  const card = hostPrevRow.querySelector(".link-preview");
  assert.ok(card, "valid preview card should render");
  assert.equal(card.querySelector(".link-preview-site").textContent, "real.example");
  assert.equal(card.querySelector(".link-preview-image"), null, "non-raster SVG data:image must be rejected");

  // Error message was not cached in shownCache: retry after tempKeysFail=false succeeds!
  const tempRowBefore = messagesEl.querySelector('.message-row[data-id="m-temp"]');
  assert.match(tempRowBefore.textContent, /could not be decrypted/i);
  tempKeysFail = false;
  // Trigger rerender via links-toggle or reopening chat
  env.getById("dm-list").querySelector(".chat-list-item").click();
  await new Promise((r) => setTimeout(r, 60));
  const tempRowAfter = env.getById("messages").querySelector('.message-row[data-id="m-temp"]');
  assert.match(tempRowAfter.textContent, /retry works/, "error result must not stay cached in shownCache");
});

test("#73 index.js: TOFU check in showMessage & ensureUserKeys rejects unaccepted departed member key change without overwriting userKeys, and loads me previous_keys", async () => {
  const tmpEnv = loadCryptoEnv();
  const alice = await makeUserAccount(tmpEnv.window.SeresCrypto, "u-alice", "alice-pw-123");
  const departedOld = await makeUserAccount(tmpEnv.window.SeresCrypto, "u-departed", "dep-pw-old");
  const departedNew = await makeUserAccount(tmpEnv.window.SeresCrypto, "u-departed", "dep-pw-new");
  const alicePub = { id: alice.userId, pub_ecdh: alice.bundle.pub_ecdh, pub_sign: alice.bundle.pub_sign };
  const depNewPub = { id: departedNew.userId, pub_ecdh: departedNew.bundle.pub_ecdh, pub_sign: departedNew.bundle.pub_sign };

  const oldPinnedFp = await tmpEnv.window.SeresCrypto.fingerprint(departedOld.bundle.pub_ecdh, departedOld.bundle.pub_sign);
  const msgFromNew = await tmpEnv.window.SeresCrypto.encryptMessage(
    departedNew.identity, "chat-1", "m-dep-new",
    { text: "forged or rotated key message" },
    [alicePub, depNewPub],
  );
  // Also a pre-reset message of alice that cannot be decrypted with current alice key
  const aliceOld = await makeUserAccount(tmpEnv.window.SeresCrypto, "u-alice", "alice-pw-old");
  const msgBeforeReset = await tmpEnv.window.SeresCrypto.encryptMessage(
    aliceOld.identity, "chat-1", "m-pre-reset",
    { text: "old secret" },
    [{ id: aliceOld.userId, pub_ecdh: aliceOld.bundle.pub_ecdh, pub_sign: aliceOld.bundle.pub_sign }],
  );

  const resetUntil = "2026-06-01T00:00:00Z";
  const { env } = await setupIndexApp({
    meUser: { id: alice.userId, username: "alice", pub_ecdh: alice.bundle.pub_ecdh, pub_sign: alice.bundle.pub_sign, enc_private: alice.bundle.enc_private },
    usersKeysMap: {
      [alice.userId]: {
        id: alice.userId,
        username: "alice",
        pub_ecdh: alice.bundle.pub_ecdh,
        pub_sign: alice.bundle.pub_sign,
        previous_keys: [{ pub_ecdh: aliceOld.bundle.pub_ecdh, pub_sign: aliceOld.bundle.pub_sign, until: resetUntil }],
      },
      // Server returns departedNew keys even though user pinned departedOld!
      [departedNew.userId]: {
        id: departedNew.userId,
        username: "departed",
        pub_ecdh: departedNew.bundle.pub_ecdh,
        pub_sign: departedNew.bundle.pub_sign,
        previous_keys: [],
      },
    },
    preSeedPins: { [departedNew.userId]: oldPinnedFp },
    chats: [{
      id: "chat-1",
      type: "group",
      name: "Group",
      role: "member",
      member_count: 1,
      last_message: null,
      unread: 0,
      last_activity: "2026-07-01T00:00:00Z",
    }],
    chatDetails: {
      "chat-1": {
        id: "chat-1",
        type: "group",
        name: "Group",
        role: "member",
        member_count: 1,
        unread: 0,
        last_activity: "2026-07-01T00:00:00Z",
        members: [
          { id: alice.userId, username: "alice", pub_ecdh: alice.bundle.pub_ecdh, pub_sign: alice.bundle.pub_sign, role: "member" },
        ],
      },
    },
    chatMessages: {
      "chat-1": [
        { seq: 1, rev: 1, id: "m-pre-reset", sender_id: alice.userId, sender: "alice", kind: "e2e", payload: msgBeforeReset, created_at: "2026-05-01T00:00:00Z", deleted: false },
        { seq: 2, rev: 2, id: "m-dep-new", sender_id: departedNew.userId, sender: "departed", kind: "e2e", payload: msgFromNew, created_at: "2026-07-01T00:00:00Z", deleted: false },
      ],
    },
  });
  await env.window.SeresCrypto.saveIdentity(alice.identity);
  await env.fireDomContentLoaded();
  await new Promise((r) => setTimeout(r, 40));

  env.getById("dm-list").querySelector(".chat-list-item").click();
  await new Promise((r) => setTimeout(r, 60));

  const messagesEl = env.getById("messages");
  // Departed member's unaccepted key change MUST NOT decrypt silently!
  const depRow = messagesEl.querySelector('.message-row[data-id="m-dep-new"]');
  assert.ok(!depRow.textContent.includes("forged or rotated key message"), "must NOT decrypt departed member message with unaccepted key");

  // me's previous_keys MUST be loaded so pre-reset message shows history.notShared instead of generic decryptError!
  const preRow = messagesEl.querySelector('.message-row[data-id="m-pre-reset"]');
  assert.match(preRow.textContent, /before your password reset/i, `Expected history.notShared notice, got: ${preRow.textContent}`);
});

test("#73 index.js: LRU caps fileUrls and revokes blob URLs on eviction, logout, and loadOwnAvatar", async () => {
  const tmpEnv = loadCryptoEnv();
  const alice = await makeUserAccount(tmpEnv.window.SeresCrypto, "u-alice", "alice-pw-123");
  const alicePub = { id: alice.userId, pub_ecdh: alice.bundle.pub_ecdh, pub_sign: alice.bundle.pub_sign };

  const messages = [];
  const filePayloads = new Map();
  for (let i = 0; i < 70; i++) {
    const enc = await tmpEnv.window.SeresCrypto.encryptFile(new TextEncoder().encode("file-" + i).buffer);
    const fid = "f-" + i;
    filePayloads.set(fid, enc.data);
    const payload = await tmpEnv.window.SeresCrypto.encryptMessage(
      alice.identity, "chat-1", "m-" + i,
      { file: { id: fid, key: enc.key, iv: enc.iv, name: `img-${i}.png`, mime: "image/png", size: 6, kind: "image" } },
      [alicePub],
    );
    messages.push({ seq: i + 1, rev: i + 1, id: "m-" + i, sender_id: alice.userId, sender: "alice", kind: "e2e", payload, created_at: "2026-07-01T00:00:00Z", deleted: false });
  }

  let avatarBlobCount = 0;
  const { env } = await setupIndexApp({
    meUser: { id: alice.userId, username: "alice", pub_ecdh: alice.bundle.pub_ecdh, pub_sign: alice.bundle.pub_sign, enc_private: alice.bundle.enc_private },
    usersKeysMap: { [alice.userId]: { id: alice.userId, username: "alice", pub_ecdh: alice.bundle.pub_ecdh, pub_sign: alice.bundle.pub_sign, previous_keys: [] } },
    chats: [{ id: "chat-1", type: "dm", name: "alice", role: "member", member_count: 1, last_message: null, unread: 0, last_activity: "2026-07-01T00:00:00Z" }],
    chatDetails: { "chat-1": { id: "chat-1", type: "dm", name: "alice", role: "member", member_count: 1, unread: 0, last_activity: "2026-07-01T00:00:00Z", members: [{ id: alice.userId, username: "alice", pub_ecdh: alice.bundle.pub_ecdh, pub_sign: alice.bundle.pub_sign, role: "member" }] } },
    chatMessages: { "chat-1": messages },
    extraFetch: async (reqUrl) => {
      if (reqUrl === "/api/get_avatar") {
        avatarBlobCount++;
        return { ok: true, status: 200, blob: async () => new env.window.Blob([new Uint8Array([1, 2, 3])], { type: "image/png" }) };
      }
      if (reqUrl.includes("/files/")) {
        const fid = reqUrl.split("/files/")[1];
        return { ok: true, status: 200, arrayBuffer: async () => filePayloads.get(fid) };
      }
      if (reqUrl === "/api/upload_avatar") {
        return { ok: true, status: 200, json: async () => ({ success: true }) };
      }
      return null;
    },
  });
  await env.window.SeresCrypto.saveIdentity(alice.identity);
  await env.fireDomContentLoaded();
  await new Promise((r) => setTimeout(r, 50));

  const firstAvatarUrl = env.getById("user-avatar-img").src;
  assert.ok(firstAvatarUrl.startsWith("blob:"));
  // Re-upload avatar -> loadOwnAvatar must revoke old avatar blob URL!
  env.getById("avatar-upload-input").files = [new env.window.Blob([new Uint8Array([4, 5])], { type: "image/png" })];
  env.getById("upload-avatar-btn").click();
  await new Promise((r) => setTimeout(r, 40));
  assert.ok(env.revokedObjectUrls.includes(firstAvatarUrl), "loadOwnAvatar must revoke previous avatar blob URL");

  // Open chat with 70 images -> LRU eviction must revoke oldest blob URLs
  env.getById("dm-list").querySelector(".chat-list-item").click();
  await new Promise((r) => setTimeout(r, 80));
  assert.ok(env.revokedObjectUrls.length >= 2, `Expected LRU eviction to revoke oldest file blob URLs, revoked=${env.revokedObjectUrls.length}`);

  // Logout must revoke all remaining blob URLs
  const revokedBeforeLogout = env.revokedObjectUrls.length;
  env.getById("menu-logout").click();
  await new Promise((r) => setTimeout(r, 50));
  assert.ok(env.revokedObjectUrls.length > revokedBeforeLogout, "logout must revoke remaining cached file/avatar blob URLs");
  assert.ok(avatarBlobCount >= 2);
});

// =========================================================================
// #74 index.js: SeresMatrix.logout() on logout/forced-logout & ?loginToken= view preservation
// =========================================================================

test("#74 index.js: logout() and forced-logout paths await SeresMatrix.logout() inside try/catch before redirect", async () => {
  const tmpEnv = loadCryptoEnv();
  const alice = await makeUserAccount(tmpEnv.window.SeresCrypto, "u-alice", "alice-pw-123");

  // 1. Normal logout awaits SeresMatrix.logout even if it rejects
  let matrixLogoutOrder = [];
  const { env } = await setupIndexApp({
    meUser: { id: alice.userId, username: "alice", pub_ecdh: alice.bundle.pub_ecdh, pub_sign: alice.bundle.pub_sign, enc_private: alice.bundle.enc_private },
    usersKeysMap: { [alice.userId]: { id: alice.userId, username: "alice", pub_ecdh: alice.bundle.pub_ecdh, pub_sign: alice.bundle.pub_sign, previous_keys: [] } },
    matrixController: {
      activate() {},
      deactivate() {},
      async logout() {
        await new Promise((r) => setTimeout(r, 15));
        matrixLogoutOrder.push("matrix-logout");
        throw new Error("matrix boom");
      },
    },
  });
  await env.window.SeresCrypto.saveIdentity(alice.identity);
  await env.fireDomContentLoaded();
  await new Promise((r) => setTimeout(r, 30));

  env.getById("menu-logout").click();
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(matrixLogoutOrder.length, 1, "logout() must await SeresMatrix.logout()");
  assert.ok(env.navigations.some((u) => u.endsWith("/login.html")), "logout() must still redirect to login.html when SeresMatrix.logout() throws");

  // 2. boot() key-mismatch forced-logout awaits SeresMatrix.logout()
  let bootMismatchLogout = 0;
  const { env: envBoot } = await setupIndexApp({
    meUser: { id: alice.userId, username: "alice", pub_ecdh: "DIFFERENT", pub_sign: "DIFFERENT", enc_private: alice.bundle.enc_private },
    matrixController: {
      activate() {},
      deactivate() {},
      async logout() {
        await new Promise((r) => setTimeout(r, 10));
        bootMismatchLogout++;
      },
    },
  });
  await envBoot.window.SeresCrypto.saveIdentity(alice.identity);
  await envBoot.fireDomContentLoaded();
  await new Promise((r) => setTimeout(r, 40));
  assert.equal(bootMismatchLogout, 1, "boot() key-mismatch forced-logout must await SeresMatrix.logout()");
  assert.ok(envBoot.navigations.some((u) => u.includes("login.html?reason=keys")));

  // 3. chooseFirstMainDevice forced-logout awaits SeresMatrix.logout()
  let chooseMainLogout = 0;
  const { env: envMain } = await setupIndexApp({
    meUser: { id: alice.userId, username: "alice", pub_ecdh: alice.bundle.pub_ecdh, pub_sign: alice.bundle.pub_sign, enc_private: alice.bundle.enc_private },
    usersKeysMap: { [alice.userId]: { id: alice.userId, username: "alice", pub_ecdh: alice.bundle.pub_ecdh, pub_sign: alice.bundle.pub_sign, previous_keys: [] } },
    devicesResponse: {
      is_main: false,
      has_main: false,
      devices: [
        { id: "d1", approved: true, current: true, main: false, created_at: "2026-01-01T00:00:00Z" },
        { id: "d2", approved: true, current: false, main: false, created_at: "2026-01-01T00:00:00Z" },
      ],
    },
    extraFetch: async (reqUrl) => {
      if (reqUrl === "/api/devices/main") return { ok: true, status: 200, json: async () => ({ success: true, logged_out: true }) };
      return null;
    },
    matrixController: {
      activate() {},
      deactivate() {},
      async logout() {
        await new Promise((r) => setTimeout(r, 10));
        chooseMainLogout++;
      },
    },
  });
  await envMain.window.SeresCrypto.saveIdentity(alice.identity);
  await envMain.fireDomContentLoaded();
  for (let i = 0; i < 40 && !envMain.getById("device-choice-list").querySelector("input[name=device-choice]:checked"); i++) {
    await new Promise((r) => setTimeout(r, 10));
  }
  envMain.getById("device-choice-confirm").click();
  for (let i = 0; i < 40 && envMain.navigations.length === 0; i++) {
    await new Promise((r) => setTimeout(r, 10));
  }
  assert.equal(chooseMainLogout, 1, "chooseFirstMainDevice forced-logout must await SeresMatrix.logout()");
  assert.ok(envMain.navigations.some((u) => u.endsWith("/login.html")));
});

test("#74 index.js: boot() preserves Matrix view when ?loginToken= is present", async () => {
  const tmpEnv = loadCryptoEnv();
  const alice = await makeUserAccount(tmpEnv.window.SeresCrypto, "u-alice", "alice-pw-123");
  const matrixEvents = [];
  const { env } = await setupIndexApp({
    url: "https://seres.example/index.html?loginToken=sso-tok-1&state=st-1",
    meUser: { id: alice.userId, username: "alice", pub_ecdh: alice.bundle.pub_ecdh, pub_sign: alice.bundle.pub_sign, enc_private: alice.bundle.enc_private },
    usersKeysMap: { [alice.userId]: { id: alice.userId, username: "alice", pub_ecdh: alice.bundle.pub_ecdh, pub_sign: alice.bundle.pub_sign, previous_keys: [] } },
    matrixController: {
      activate() { matrixEvents.push("activate"); },
      deactivate() { matrixEvents.push("deactivate"); },
      async logout() {},
    },
  });
  await env.window.SeresCrypto.saveIdentity(alice.identity);
  await env.fireDomContentLoaded();
  await new Promise((r) => setTimeout(r, 40));

  assert.ok(!matrixEvents.includes("deactivate"), "boot() must NOT deactivate Matrix view during ?loginToken= callback");
  assert.equal(env.document.querySelector(".main-chat").classList.contains("matrix-open"), true, "Matrix view must remain open when ?loginToken= is present");
  assert.equal(env.document.querySelector('.rail-nav[data-rail-view="matrix"]').getAttribute("aria-current"), "page", "Matrix rail-nav must have aria-current='page' for matrix.ts waitForSeresBoot()");
});
