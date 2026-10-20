"use strict";
// Passkeys (WebAuthn) as second factor. Converts between the JSON the server
// sends (base64url strings) and the ArrayBuffers navigator.credentials needs.
// The browser lets the user pick a security key, Windows Hello / Touch ID, or
// "use a phone or tablet" (QR code), so a phone works as passkey.
const SeresPasskeys = (() => {
    function fromB64url(value) {
        const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++)
            bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    }
    function toB64url(buffer) {
        if (!buffer)
            return "";
        const bytes = new Uint8Array(buffer);
        let binary = "";
        for (let i = 0; i < bytes.length; i++)
            binary += String.fromCharCode(bytes[i]);
        return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }
    function supported() {
        return typeof window.PublicKeyCredential !== "undefined" && !!navigator.credentials;
    }
    function descriptors(list) {
        return (list || []).map((item) => ({ ...item, id: fromB64url(item.id) }));
    }
    /** Creates a new passkey from the server's registration options. */
    async function create(options) {
        const publicKey = {
            ...options,
            challenge: fromB64url(options.challenge),
            user: { ...options.user, id: fromB64url(options.user.id) },
            excludeCredentials: descriptors(options.excludeCredentials),
        };
        const credential = (await navigator.credentials.create({ publicKey }));
        if (!credential)
            throw new Error("cancelled");
        const response = credential.response;
        return {
            id: credential.id,
            rawId: toB64url(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: toB64url(response.clientDataJSON),
                attestationObject: toB64url(response.attestationObject),
                transports: typeof response.getTransports === "function" ? response.getTransports() : [],
            },
            clientExtensionResults: credential.getClientExtensionResults(),
        };
    }
    /** Signs the server's login challenge with one of the user's passkeys. */
    async function get(options) {
        const publicKey = {
            ...options,
            challenge: fromB64url(options.challenge),
            allowCredentials: descriptors(options.allowCredentials),
        };
        const credential = (await navigator.credentials.get({ publicKey }));
        if (!credential)
            throw new Error("cancelled");
        const response = credential.response;
        return {
            id: credential.id,
            rawId: toB64url(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: toB64url(response.clientDataJSON),
                authenticatorData: toB64url(response.authenticatorData),
                signature: toB64url(response.signature),
                userHandle: response.userHandle ? toB64url(response.userHandle) : null,
            },
            clientExtensionResults: credential.getClientExtensionResults(),
        };
    }
    return { supported, create, get };
})();
window.SeresPasskeys = SeresPasskeys;
