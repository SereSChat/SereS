const DB_NAME = 'opsecchat-device-keys';
const DB_VERSION = 1;
const STORE_NAME = 'records';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

let wasmModule;

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE_NAME);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('Der verschlüsselte Gerätespeicher konnte nicht geöffnet werden.'));
    request.onblocked = () => reject(new Error('Der Gerätespeicher wird noch von einem anderen Tab aktualisiert.'));
  });
}

function readRecord(db, key) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const request = tx.objectStore(STORE_NAME).get(key);
    request.onsuccess = () => resolve(request.result ?? null);
    request.onerror = () => reject(new Error('Der Gerätespeicher konnte nicht gelesen werden.'));
  });
}

function writeRecord(db, key, value) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onabort = tx.onerror = () => reject(new Error('Der verschlüsselte Gerätezustand konnte nicht dauerhaft gespeichert werden.'));
  });
}

function writeRecords(db, records) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    for (const [key, value] of records) store.put(value, key);
    tx.oncomplete = () => resolve();
    tx.onabort = tx.onerror = () => reject(new Error('Der verschlüsselte Gerätezustand konnte nicht dauerhaft gespeichert werden.'));
  });
}

function listRecordKeys(db, prefix) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const request = tx.objectStore(STORE_NAME).getAllKeys();
    request.onsuccess = () => resolve(request.result.filter((key) => typeof key === 'string' && key.startsWith(prefix)));
    request.onerror = () => reject(new Error('Der Gerätespeicher konnte nicht durchsucht werden.'));
  });
}

function deleteRecord(db, key) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).delete(key);
    tx.oncomplete = () => resolve();
    tx.onabort = tx.onerror = () => reject(new Error('Der ausstehende Schlüssel konnte nicht aus dem Gerätespeicher entfernt werden.'));
  });
}

async function cryptoModule() {
  if (!wasmModule) {
    wasmModule = import('./opsec-crypto/opsecchat_crypto.js').then(async (module) => {
      await module.default();
      return module;
    });
  }
  return wasmModule;
}

function withExclusiveDeviceLock(identity, callback) {
  if (!navigator.locks?.request) {
    throw new Error('Dieser Browser unterstützt keine sichere Sperre für den MLS-Gerätezustand.');
  }
  return navigator.locks.request(`opsecchat-mls:${identity}`, { mode: 'exclusive' }, callback);
}

async function loadSnapshot(db, identity) {
  const envelope = await readRecord(db, `state:${identity}`);
  if (!envelope) return null;
  const key = await readRecord(db, `wrap-key:${identity}`);
  if (!key) throw new Error('Der Schlüssel zum Entsperren dieses Geräts fehlt.');
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: Uint8Array.from(envelope.iv), additionalData: encoder.encode(identity) },
      key,
      Uint8Array.from(envelope.ciphertext),
    );
    return decoder.decode(plaintext);
  } catch {
    throw new Error('Der gespeicherte MLS-Zustand konnte nicht authentisch entschlüsselt werden.');
  }
}

async function saveSnapshot(db, identity, snapshot) {
  let key = await readRecord(db, `wrap-key:${identity}`);
  if (!key) {
    key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    await writeRecord(db, `wrap-key:${identity}`, key);
  }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode(identity) },
    key,
    encoder.encode(snapshot),
  );
  await writeRecord(db, `state:${identity}`, { iv: Array.from(iv), ciphertext: Array.from(new Uint8Array(ciphertext)) });
}

function historyRecordKey(identity, conversationId) {
  return `history:${identity}:${conversationId}`;
}

async function readEncryptedHistory(db, identity, conversationId) {
  const key = await readRecord(db, `wrap-key:${identity}`);
  const envelope = await readRecord(db, historyRecordKey(identity, conversationId));
  if (!envelope) return [];
  if (!key) throw new Error('Der Schlüssel zum Entsperren des lokalen Nachrichtenverlaufs fehlt.');
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: Uint8Array.from(envelope.iv), additionalData: encoder.encode(`${identity}:${conversationId}`) },
      key,
      Uint8Array.from(envelope.ciphertext),
    );
    const events = JSON.parse(decoder.decode(plaintext));
    return Array.isArray(events) ? events : [];
  } catch {
    throw new Error('Der lokale Nachrichtenverlauf konnte nicht authentisch entschlüsselt werden.');
  }
}

async function writeEncryptedHistory(db, identity, conversationId, events) {
  const key = await readRecord(db, `wrap-key:${identity}`);
  if (!key) throw new Error('Der Schlüssel zum Entsperren des lokalen Nachrichtenverlaufs fehlt.');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode(`${identity}:${conversationId}`) },
    key,
    encoder.encode(JSON.stringify(events)),
  );
  await writeRecord(db, historyRecordKey(identity, conversationId), { iv, ciphertext: new Uint8Array(ciphertext) });
}

export async function loadMlsEventCache(userId, deviceId, conversationId) {
  const identity = `${userId}:${deviceId}`;
  const db = await openDatabase();
  try { return await readEncryptedHistory(db, identity, conversationId); }
  finally { db.close(); }
}

export async function saveMlsEventCache(userId, deviceId, conversationId, entry) {
  const identity = `${userId}:${deviceId}`;
  const db = await openDatabase();
  try {
    if (!navigator.locks?.request) throw new Error('Dieser Browser unterstützt keine sichere Verlaufssynchronisierung.');
    return await navigator.locks.request(`opsecchat-history:${identity}:${conversationId}`, { mode: 'exclusive' }, async () => {
      const events = await readEncryptedHistory(db, identity, conversationId);
      const next = events.filter((item) => item?.event?.id !== entry?.event?.id);
      next.push({
        payload: entry.payload,
        event: {
          id: entry.event.id,
          sender_user_id: entry.event.sender_user_id,
          sender_device_id: entry.event.sender_device_id,
          created_at: entry.event.created_at,
          event_kind: entry.event.event_kind,
        },
      });
      next.sort((a, b) => (a?.event?.created_at || 0) - (b?.event?.created_at || 0) || String(a?.event?.id).localeCompare(String(b?.event?.id)));
      await writeEncryptedHistory(db, identity, conversationId, next.slice(-500));
    });
  } finally { db.close(); }
}

async function withDevice(identity, callback) {
  if (typeof identity !== 'string' || identity.length < 3 || identity.length > 300) {
    throw new Error('Ungültige MLS-Geräteidentität.');
  }
  const db = await openDatabase();
  try {
    return await withExclusiveDeviceLock(identity, async () => {
      const { MlsDevice } = await cryptoModule();
      const snapshot = await loadSnapshot(db, identity);
      const device = snapshot ? MlsDevice.restore(identity, snapshot) : new MlsDevice(identity);
      const result = await callback(device, snapshot === null, db);
      await saveSnapshot(db, identity, device.snapshot());
      return result;
    });
  } finally {
    db.close();
  }
}

export async function createMlsKeyPackage(identity) {
  return withDevice(identity, async (device, _isNew, db) => {
    const outboxKey = `keypackage-outbox:${identity}`;
    const queued = await readRecord(db, outboxKey);
    if (queued) return queued;
    const result = device.create_key_package();
    const queuedPackage = {
      keyPackage: Array.from(new Uint8Array(result.keyPackage)),
      hashRef: Array.from(new Uint8Array(result.hashRef)),
      signingPublicKey: Array.from(new Uint8Array(result.signingPublicKey)),
    };
    await writeRecord(db, outboxKey, queuedPackage);
    return queuedPackage;
  });
}

export async function markMlsKeyPackagePublished(identity) {
  const db = await openDatabase();
  try {
    return await withExclusiveDeviceLock(identity, () => deleteRecord(db, `keypackage-outbox:${identity}`));
  } finally {
    db.close();
  }
}

export async function ensureMlsDevice(userId) {
  if (!navigator.locks?.request) throw new Error('Dieser Browser unterstützt keine sichere Gerätesynchronisierung.');
  const db = await openDatabase();
  try {
    const deviceId = await navigator.locks.request(`opsecchat-device-id:${userId}`, { mode: 'exclusive' }, async () => {
      const key = `device-id:${userId}`;
      const stored = await readRecord(db, key);
      if (stored && await readRecord(db, `state:${userId}:${stored}`)) return stored;
      const generated = crypto.randomUUID();
      await writeRecord(db, key, generated);
      return generated;
    });
    const identity = `${userId}:${deviceId}`;
    const local = await withDevice(identity, async (device, _isNew, db) => ({
      pendingKeyPackage: await readRecord(db, `keypackage-outbox:${identity}`),
      signingPublicKey: Array.from(device.signing_public_key()),
    }));
    return { deviceId, identity, ...local };
  } finally {
    db.close();
  }
}

export async function exportMlsBackup(userId, passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < 12) throw new Error('Die Backup-Passphrase muss mindestens 12 Zeichen lang sein.');
  const device = await ensureMlsDevice(userId);
  const localState = await withDevice(device.identity, async (mlsDevice, _isNew, db) => {
    const historyKeys = await listRecordKeys(db, `history:${device.identity}:`);
    const eventCaches = [];
    for (const key of historyKeys) {
      const envelope = await readRecord(db, key);
      if (envelope) eventCaches.push([key, { iv: base64Url(Uint8Array.from(envelope.iv)), ciphertext: base64Url(Uint8Array.from(envelope.ciphertext)) }]);
    }
    return { snapshot: mlsDevice.snapshot(), eventCaches };
  });
  const processedPrefix = `opsecchat.processed.v1:${userId}:${device.deviceId}:`;
  const processedEvents = [];
  try {
    for (let index = 0; index < localStorage.length; index++) {
      const storageKey = localStorage.key(index);
      if (storageKey?.startsWith(processedPrefix)) processedEvents.push([storageKey, localStorage.getItem(storageKey)]);
    }
  } catch { /* The MLS snapshot can still be backed up if browser local storage is unavailable. */ }
  const backupPayload = JSON.stringify({ snapshot: localState.snapshot, processedEvents, eventCaches: localState.eventCaches });
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const material = await crypto.subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(device.identity) }, key, encoder.encode(backupPayload));
  return JSON.stringify({ format: 'opsecchat-mls-backup', version: 2, identity: device.identity, salt: base64Url(salt), iv: base64Url(iv), ciphertext: base64Url(new Uint8Array(ciphertext)) }, null, 2);
}

export async function importMlsBackup(userId, passphrase, backupText) {
  if (typeof passphrase !== 'string' || passphrase.length < 12) throw new Error('Die Backup-Passphrase muss mindestens 12 Zeichen lang sein.');
  if (typeof backupText !== 'string' || backupText.length > 45_000_000) throw new Error('Die Backup-Datei ist ungültig oder zu gross.');
  let backup;
  try { backup = JSON.parse(backupText); } catch { throw new Error('Die Backup-Datei ist kein gültiges JSON.'); }
  if (backup?.format !== 'opsecchat-mls-backup' || ![1, 2].includes(backup.version) || typeof backup.identity !== 'string' || !backup.identity.startsWith(`${userId}:`)) throw new Error('Dieses Backup gehört nicht zu diesem OpsecChat-Konto oder wird nicht unterstützt.');
  const db = await openDatabase();
  try {
    if (!navigator.locks?.request) throw new Error('Dieser Browser unterstützt keine sichere Wiederherstellungssperre.');
    await navigator.locks.request(`opsecchat-device-id:${userId}`, { mode: 'exclusive' }, () =>
      withExclusiveDeviceLock(backup.identity, async () => {
        const existing = await readRecord(db, `state:${backup.identity}`);
        if (existing) throw new Error('Auf diesem Gerät existiert bereits ein MLS-Schlüssel für dieses Konto.');
        const salt = fromBase64Url(backup.salt), iv = fromBase64Url(backup.iv), ciphertext = fromBase64Url(backup.ciphertext);
        if (salt.length !== 16 || iv.length !== 12 || ciphertext.length > 32_000_000) throw new Error('Die Backup-Datei hat ungültige Daten oder ist zu gross.');
        const material = await crypto.subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
        const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 }, material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
        let plaintext;
        try { plaintext = decoder.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(backup.identity) }, key, ciphertext)); }
        catch { throw new Error('Backup-Passphrase falsch oder Datei beschädigt.'); }
        let snapshot = plaintext;
        let processedEvents = [];
        let eventCaches = [];
        try {
          const payload = JSON.parse(plaintext);
          if (typeof payload?.snapshot === 'string') {
            snapshot = payload.snapshot;
            if (Array.isArray(payload.processedEvents)) processedEvents = payload.processedEvents;
            if (Array.isArray(payload.eventCaches)) eventCaches = payload.eventCaches;
          }
        } catch { /* Version 1 backups created before processed event metadata contain the raw snapshot. */ }
        const { MlsDevice } = await cryptoModule();
        MlsDevice.restore(backup.identity, snapshot);
        const wrapKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
        const snapshotIv = crypto.getRandomValues(new Uint8Array(12));
        const localCiphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: snapshotIv, additionalData: encoder.encode(backup.identity) }, wrapKey, encoder.encode(snapshot));
        await writeRecords(db, [
          [`wrap-key:${backup.identity}`, wrapKey],
          [`state:${backup.identity}`, { iv: Array.from(snapshotIv), ciphertext: Array.from(new Uint8Array(localCiphertext)) }],
          [`device-id:${userId}`, backup.identity.slice(userId.length + 1)],
          ...eventCaches.filter((entry) => Array.isArray(entry) && entry.length === 2 && typeof entry[0] === 'string' && entry[0].startsWith(`history:${backup.identity}:`) && typeof entry[1]?.iv === 'string' && typeof entry[1]?.ciphertext === 'string' && entry[1].iv.length <= 64 && entry[1].ciphertext.length <= 32_000_000).map(([key, envelope]) => [key, { iv: fromBase64Url(envelope.iv), ciphertext: fromBase64Url(envelope.ciphertext) }]),
        ]);
        for (const entry of processedEvents) {
          if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== 'string' || !entry[0].startsWith(`opsecchat.processed.v1:${userId}:`)) continue;
          try { if (typeof entry[1] === 'string') localStorage.setItem(entry[0], entry[1]); } catch { break; }
        }
      }),
    );
  } finally { db.close(); }
}

function base64Url(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  let binary = '';
  for (let offset = 0; offset < view.length; offset += 0x8000) {
    binary += String.fromCharCode(...view.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function fromBase64Url(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Ungültige Base64url-Daten vom OpsecChat-Server.');
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  const binary = atob(normalized + '='.repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function publishPendingPackage(device) {
  const queued = device.pendingKeyPackage;
  const result = await window.opsecchat.api(`/v1/devices/${encodeURIComponent(device.deviceId)}/key-packages`, {
    method: 'POST',
    body: {
      hash_ref: base64Url(queued.hashRef),
      key_package: base64Url(queued.keyPackage),
    },
  });
  await markMlsKeyPackagePublished(device.identity);
  return result.created === true;
}

export async function provisionMlsDevice(userId, label = 'OpsecChat Web') {
  const device = await ensureMlsDevice(userId);
  const registration = await window.opsecchat.api('/v1/devices', {
    method: 'POST',
    body: {
      device_id: device.deviceId,
      label,
      signing_public_key: base64Url(device.signingPublicKey),
    },
  });
  let available = registration.key_package_count;
  if (device.pendingKeyPackage) {
    if (await publishPendingPackage(device)) available += 1;
  }
  while (available < 5) {
    const queued = await createMlsKeyPackage(device.identity);
    device.pendingKeyPackage = queued;
    if (await publishPendingPackage(device)) available += 1;
  }
  return { deviceId: device.deviceId, keyPackagesPublished: available };
}

export async function createMlsGroup(userId, conversationId) {
  const provisioned = await provisionMlsDevice(userId);
  const identity = `${userId}:${provisioned.deviceId}`;
  await withDevice(identity, async (device) => device.create_group(conversationId));
  return { deviceId: provisioned.deviceId, conversationId };
}

export async function hasMlsGroup(userId, conversationId) {
  const device = await ensureMlsDevice(userId);
  return withDevice(device.identity, async (mlsDevice) => mlsDevice.has_group(conversationId));
}

export async function mlsGroupMemberCount(userId, conversationId) {
  const device = await ensureMlsDevice(userId);
  return withDevice(device.identity, async (mlsDevice) => mlsDevice.group_member_count(conversationId));
}

export async function addMlsMembers(userId, conversationId, directoryReply) {
  if (!directoryReply || typeof directoryReply.user_id !== 'string' || !Array.isArray(directoryReply.key_packages)) {
    throw new Error('Das Geräteverzeichnis ist ungültig.');
  }
  const provisioned = await provisionMlsDevice(userId);
  const identity = `${userId}:${provisioned.deviceId}`;
  const packages = directoryReply.key_packages.map((entry) => ({
    identity: `${entry.user_id || directoryReply.user_id}:${entry.device_id}`,
    signing_public_key: Array.from(fromBase64Url(entry.signing_public_key)),
    hash_ref: Array.from(fromBase64Url(entry.hash_ref)),
    key_package: Array.from(fromBase64Url(entry.key_package)),
  }));
  if (packages.length === 0) throw new Error('Die befreundete Person hat noch keine verfügbaren Geräteschlüssel veröffentlicht.');
  return withDevice(identity, async (device) => {
    const result = device.add_members(conversationId, JSON.stringify(packages));
    return {
      deviceId: provisioned.deviceId,
      recipientDeviceIds: directoryReply.key_packages.map((entry) => entry.device_id),
      commit: new Uint8Array(result.commit),
      welcome: new Uint8Array(result.welcome),
    };
  });
}

export async function joinMlsGroup(userId, conversationId, welcomeBytes) {
  if (!(welcomeBytes instanceof Uint8Array)) throw new Error('MLS-Welcome muss als Bytefolge vorliegen.');
  const provisioned = await provisionMlsDevice(userId);
  const identity = `${userId}:${provisioned.deviceId}`;
  await withDevice(identity, async (device) => device.join_group(conversationId, welcomeBytes));
  return { deviceId: provisioned.deviceId, conversationId };
}

export async function encryptMlsPayload(userId, conversationId, payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('MLS-Nutzdaten müssen ein Ereignisobjekt sein.');
  const bytes = encoder.encode(JSON.stringify(payload));
  const provisioned = await provisionMlsDevice(userId);
  const identity = `${userId}:${provisioned.deviceId}`;
  const ciphertext = await withDevice(identity, async (device) => new Uint8Array(device.create_application_message(conversationId, bytes)));
  return { deviceId: provisioned.deviceId, ciphertext };
}

export async function decryptMlsPayload(userId, conversationId, ciphertext) {
  if (!(ciphertext instanceof Uint8Array)) throw new Error('MLS-Ciphertext muss als Bytefolge vorliegen.');
  const provisioned = await ensureMlsDevice(userId);
  const identity = `${userId}:${provisioned.deviceId}`;
  const result = await withDevice(identity, async (device) => device.process_incoming_message(conversationId, ciphertext));
  if (result.kind !== 'application') return { kind: result.kind };
  try {
    return { kind: 'application', payload: JSON.parse(decoder.decode(result.plaintext)) };
  } catch {
    throw new Error('Der entschlüsselte MLS-Anwendungsinhalt ist kein gültiges OpsecChat-Ereignis.');
  }
}
