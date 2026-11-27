"use strict";
(() => {
    // ------------------------------------------------------------------ types
    class ApiError extends Error {
        constructor(message, status) {
            super(message);
            this.status = status;
        }
    }
    // ------------------------------------------------------------------ state
    let me;
    let identity;
    let chats = [];
    let friends = {
        friends: [],
        incoming: [],
        outgoing: [],
        blocked: [],
    };
    let current = null;
    let chatsSignature = "";
    let friendsSignature = "";
    let sending = false;
    // The own message that is being edited in the input field.
    let editing = null;
    // Invite token from a link like /?invite=..., kept across the login redirect.
    const pendingInvite = new URLSearchParams(window.location.search).get("invite");
    // Group invite from a link like /?join=..., kept across the login redirect as well.
    const pendingJoin = new URLSearchParams(window.location.search).get("join");
    let joinToAccept = null;
    // Set by the login page after a password reset ("code" or "mail").
    const recoveredBy = new URLSearchParams(window.location.search).get("recovered");
    let inviteToAccept = null;
    // Message that is being answered (shown above the input field).
    let replyTo = null;
    // Unsent text per chat. Kept in memory only, so no plaintext is stored on the device.
    const drafts = new Map();
    // Attachments picked but not sent yet.
    let pendingFiles = [];
    let showArchived = false;
    // Unread counts from the last refresh, to notice new messages for notifications.
    let lastUnread = null;
    // Decrypted attachments as blob: URLs, by file id.
    const fileUrls = new Map();
    const userKeys = new Map();
    /** The sender's keys that were valid when the message was written, verifying historical keys against local pins. */
    async function keysAt(user, createdAt) {
        const createdMs = Date.parse(createdAt);
        const history = readJsonStore("pin-history", {})[user.id] || [];
        let untrustedHistory = false;
        for (const old of user.previous_keys || []) {
            const oldUntilMs = Date.parse(old.until);
            if (!Number.isFinite(createdMs) || !Number.isFinite(oldUntilMs) || createdMs > oldUntilMs)
                continue;
            const fp = await SeresCrypto.fingerprint(old.pub_ecdh, old.pub_sign);
            const local = history.find((entry) => entry.fp === fp &&
                entry.pub_ecdh === old.pub_ecdh &&
                entry.pub_sign === old.pub_sign);
            const localUntilMs = local ? Date.parse(local.until) : NaN;
            if (!local || !Number.isFinite(localUntilMs) || oldUntilMs > localUntilMs) {
                untrustedHistory = true;
                continue;
            }
            return { pub_ecdh: old.pub_ecdh, pub_sign: old.pub_sign };
        }
        if (untrustedHistory) {
            return { pub_ecdh: null, pub_sign: null, untrustedHistory: true };
        }
        return { pub_ecdh: user.pub_ecdh, pub_sign: user.pub_sign };
    }
    const shownCache = new Map();
    const avatarState = new Map();
    const MESSAGE_LIMIT = 4000;
    const MAX_FILE_SIZE = 16 * 1024 * 1024;
    const DISAPPEAR_OPTIONS = [0, 3600, 86400, 7 * 86400, 90 * 86400];
    const t = SeresI18n.t;
    // ------------------------------------------------------------- utilities
    function $(id) {
        return document.getElementById(id);
    }
    function h(tag, options = {}, children = []) {
        const element = document.createElement(tag);
        if (options.className)
            element.className = options.className;
        if (options.text !== undefined)
            element.textContent = options.text;
        if (options.title)
            element.title = options.title;
        for (const [key, value] of Object.entries(options.attrs || {})) {
            element.setAttribute(key, value);
        }
        for (const child of children) {
            if (child)
                element.appendChild(child);
        }
        return element;
    }
    function button(text, className, onClick, title) {
        const btn = h("button", { className, text, title, attrs: { type: "button" } });
        btn.addEventListener("click", (event) => {
            event.preventDefault();
            event.stopPropagation();
            onClick(event);
        });
        return btn;
    }
    function goToLogin(reason) {
        const params = new URLSearchParams();
        if (reason)
            params.set("reason", reason);
        if (pendingInvite)
            params.set("invite", pendingInvite);
        if (pendingJoin)
            params.set("join", pendingJoin);
        // A link QR code opened in a browser that isn't logged in: the login page explains it.
        const linkToken = new URLSearchParams(window.location.search).get("link");
        if (linkToken)
            params.set("link", linkToken);
        const query = params.toString();
        window.location.href = "login.html" + (query ? "?" + query : "");
    }
    async function api(path, options = {}) {
        const response = await fetch(path, {
            method: options.method || (options.body ? "POST" : "GET"),
            headers: options.body ? { "Content-Type": "application/json" } : {},
            credentials: "same-origin",
            body: options.body ? JSON.stringify(options.body) : undefined,
        });
        if (response.status === 401) {
            goToLogin();
            throw new ApiError("Not logged in", 401);
        }
        const data = await response.json().catch(() => ({}));
        if (!response.ok || data.success === false) {
            throw new ApiError(data.message || t("common.requestFailed"), response.status);
        }
        return data;
    }
    function post(path, body = {}) {
        return api(path, { method: "POST", body });
    }
    function showAlert(message, duration = 4200) {
        const stack = $("toast-stack");
        const toast = h("div", { className: "app-toast", attrs: { role: "status" } }, [
            h("span", { className: "material-symbols-rounded app-toast-icon", text: "info" }),
            h("span", { className: "app-toast-message", text: message }),
        ]);
        const close = h("button", { className: "app-toast-close", attrs: { type: "button", "aria-label": t("common.close") } }, [
            h("span", { className: "material-symbols-rounded", text: "close" }),
        ]);
        toast.appendChild(close);
        stack.appendChild(toast);
        while (stack.childElementCount > 4)
            stack.firstElementChild?.remove();
        const dismiss = () => {
            toast.classList.add("app-toast-exit");
            window.setTimeout(() => toast.remove(), 220);
        };
        const timer = window.setTimeout(dismiss, duration);
        close.addEventListener("click", (event) => {
            event.stopPropagation();
            clearTimeout(timer);
            dismiss();
        });
        window.requestAnimationFrame(() => toast.classList.add("app-toast-visible"));
    }
    function errorText(error) {
        if (error instanceof ApiError)
            return error.message;
        if (error instanceof TypeError)
            return t("common.unreachable");
        return error instanceof Error ? error.message : String(error);
    }
    function colorFor(name) {
        const palette = ["#5865f2", "#00a884", "#eb459e", "#f0b232", "#3ba55d", "#ed4245", "#53bdeb", "#9b59b6"];
        let hash = 0;
        for (let i = 0; i < name.length; i++)
            hash = (hash * 31 + name.charCodeAt(i)) | 0;
        return palette[Math.abs(hash) % palette.length];
    }
    /** The name shown in the app; the @username only appears in the profile. */
    function nameOf(user) {
        return user.display_name || user.username;
    }
    /** Avatar of a user (picture loaded by username); label is the name the initial is taken from. */
    function avatarEl(name, options = {}) {
        const avatar = h("div", { className: options.className || "avatar" });
        avatar.style.backgroundColor = colorFor(name);
        const initial = h("span", { text: options.group ? "#" : (options.label || name).charAt(0).toUpperCase() || "?" });
        avatar.appendChild(initial);
        if (!options.group && avatarState.get(name) !== "no") {
            const img = h("img", { attrs: { alt: "" } });
            img.style.display = "none";
            img.addEventListener("load", () => {
                avatarState.set(name, "yes");
                img.style.display = "block";
                initial.style.display = "none";
            });
            img.addEventListener("error", () => {
                avatarState.set(name, "no");
                img.remove();
            });
            img.src = "/api/users/" + encodeURIComponent(name) + "/avatar";
            avatar.appendChild(img);
        }
        return avatar;
    }
    function parseTime(iso) {
        return new Date(iso);
    }
    function formatTime(iso) {
        return parseTime(iso).toLocaleTimeString(SeresI18n.getLanguage(), { hour: "2-digit", minute: "2-digit" });
    }
    function formatDay(date) {
        const today = new Date();
        const yesterday = new Date();
        yesterday.setDate(today.getDate() - 1);
        if (date.toDateString() === today.toDateString())
            return t("chat.today");
        if (date.toDateString() === yesterday.toDateString())
            return t("chat.yesterday");
        return date.toLocaleDateString(SeresI18n.getLanguage(), { day: "2-digit", month: "2-digit", year: "numeric" });
    }
    function formatListTime(iso) {
        const date = parseTime(iso);
        return date.toDateString() === new Date().toDateString()
            ? formatTime(iso)
            : date.toLocaleDateString(SeresI18n.getLanguage(), { day: "2-digit", month: "2-digit" });
    }
    function pinStoreKey(kind) {
        return "seres-" + kind + ":" + me.id;
    }
    function readJsonStore(kind, fallback) {
        try {
            const raw = localStorage.getItem(pinStoreKey(kind));
            return raw ? JSON.parse(raw) : fallback;
        }
        catch {
            return fallback;
        }
    }
    function writeJsonStore(kind, value) {
        try {
            localStorage.setItem(pinStoreKey(kind), JSON.stringify(value));
        }
        catch {
            /* storage unavailable */
        }
    }
    function readStore(kind) {
        return readJsonStore(kind, {});
    }
    function writeStore(kind, value) {
        writeJsonStore(kind, value);
    }
    async function memberFingerprint(member) {
        if (!member.pub_ecdh || !member.pub_sign)
            return null;
        return SeresCrypto.fingerprint(member.pub_ecdh, member.pub_sign);
    }
    function appendPinHistory(pinHistory, userId, oldKey, transitionIso, serverHistory) {
        const list = pinHistory[userId] || [];
        if (list.some((entry) => entry.fp === oldKey.fp))
            return;
        const transitionMs = Date.parse(transitionIso);
        const matched = (serverHistory || []).find((prev) => prev.pub_ecdh === oldKey.pub_ecdh && prev.pub_sign === oldKey.pub_sign);
        const matchedMs = matched ? Date.parse(matched.until) : NaN;
        const boundedUntil = matched && Number.isFinite(matchedMs) && Number.isFinite(transitionMs) && matchedMs <= transitionMs
            ? matched.until
            : transitionIso;
        list.push({
            fp: oldKey.fp,
            pub_ecdh: oldKey.pub_ecdh,
            pub_sign: oldKey.pub_sign,
            until: boundedUntil,
        });
        pinHistory[userId] = list;
    }
    /**
     * Trust on first use: remember every contact's key fingerprint and warn when
     * the server suddenly hands out a different key for the same person.
     */
    async function checkPins(members) {
        const pins = readStore("pins");
        const pinKeys = readJsonStore("pin-keys", {});
        const changed = [];
        const missing = [];
        let pinsDirty = false;
        let pinKeysDirty = false;
        for (const member of members) {
            if (member.id === me.id)
                continue;
            const fp = await memberFingerprint(member);
            if (!fp || !member.pub_ecdh || !member.pub_sign) {
                missing.push(member);
                continue;
            }
            if (!pins[member.id]) {
                pins[member.id] = fp;
                pinsDirty = true;
                pinKeys[member.id] = { fp, pub_ecdh: member.pub_ecdh, pub_sign: member.pub_sign };
                pinKeysDirty = true;
            }
            else if (pins[member.id] !== fp) {
                changed.push(member);
            }
            else if (!pinKeys[member.id] || pinKeys[member.id].fp !== fp) {
                pinKeys[member.id] = { fp, pub_ecdh: member.pub_ecdh, pub_sign: member.pub_sign };
                pinKeysDirty = true;
            }
        }
        if (pinsDirty)
            writeStore("pins", pins);
        if (pinKeysDirty)
            writeJsonStore("pin-keys", pinKeys);
        if (changed.length && typeof SeresCalls !== "undefined") {
            SeresCalls.clearSignKeys(changed.map((m) => m.id));
        }
        return { changed, missing };
    }
    async function acceptNewKeys(members) {
        const pins = readStore("pins");
        const verified = readStore("verified");
        const pinKeys = readJsonStore("pin-keys", {});
        const pinHistory = readJsonStore("pin-history", {});
        const transitionIso = new Date().toISOString();
        for (const member of members) {
            const fp = await memberFingerprint(member);
            if (!fp || !member.pub_ecdh || !member.pub_sign)
                continue;
            const oldFp = pins[member.id];
            const serverHistory = member.previous_keys || userKeys.get(member.id)?.previous_keys || [];
            if (oldFp && oldFp !== fp) {
                let oldKey = pinKeys[member.id]?.fp === oldFp ? pinKeys[member.id] : null;
                if (!oldKey) {
                    for (const prev of serverHistory) {
                        if ((await SeresCrypto.fingerprint(prev.pub_ecdh, prev.pub_sign)) === oldFp) {
                            oldKey = { fp: oldFp, pub_ecdh: prev.pub_ecdh, pub_sign: prev.pub_sign };
                            break;
                        }
                    }
                }
                if (oldKey) {
                    appendPinHistory(pinHistory, member.id, oldKey, transitionIso, serverHistory);
                }
            }
            pins[member.id] = fp;
            pinKeys[member.id] = { fp, pub_ecdh: member.pub_ecdh, pub_sign: member.pub_sign };
            userKeys.set(member.id, member);
            delete verified[member.id];
        }
        writeStore("pins", pins);
        writeStore("verified", verified);
        writeJsonStore("pin-keys", pinKeys);
        writeJsonStore("pin-history", pinHistory);
        shownCache.clear();
        if (typeof SeresCalls !== "undefined") {
            SeresCalls.clearSignKeys(members.map((m) => m.id));
        }
    }
    async function ensureUserKeys(ids) {
        const missing = [...new Set(ids)].filter((id) => id && !userKeys.has(id));
        if (!missing.length)
            return;
        const data = await api("/api/users/keys?ids=" + encodeURIComponent(missing.join(",")));
        for (const user of data.users)
            userKeys.set(user.id, user);
    }
    function callLength(seconds) {
        const h = Math.floor(seconds / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        const s = String(seconds % 60).padStart(2, "0");
        return h ? `${h}:${String(m).padStart(2, "0")}:${s}` : `${m}:${s}`;
    }
    function systemText(payload) {
        if (!payload)
            return "";
        switch (payload.event) {
            case "created":
            case "added":
            case "removed":
            case "left":
            case "renamed":
            case "pinned":
            case "keys_reset":
            case "history_shared":
            case "joined_link":
                return t("system." + payload.event, {
                    actor: payload.actor ?? "",
                    target: payload.target ?? "",
                    name: payload.name ?? "",
                });
            case "call":
                return typeof payload.seconds === "number"
                    ? t("system.call", { actor: payload.actor ?? "", time: callLength(payload.seconds) })
                    : t("system.callMissed", { actor: payload.actor ?? "" });
            case "disappearing":
                return payload.seconds
                    ? t("system.disappearingOn", { actor: payload.actor ?? "", time: disappearLabel(payload.seconds) })
                    : t("system.disappearingOff", { actor: payload.actor ?? "" });
            default:
                return "";
        }
    }
    function showMessage(chatId, message) {
        const cacheKey = message.id + ":" + message.rev + (message.share ? ":shared" : "");
        let shown = shownCache.get(cacheKey);
        if (!shown) {
            shown = (async () => {
                if (message.deleted)
                    return { type: "deleted", text: t("msg.deleted") };
                if (message.kind === "system")
                    return { type: "system", text: systemText(message.payload) };
                if (message.kind === "legacy")
                    return { type: "legacy", text: String(message.payload?.text ?? "") };
                try {
                    await ensureUserKeys([message.sender_id]);
                    const known = userKeys.get(message.sender_id);
                    const sender = known ? { id: known.id, ...(await keysAt(known, message.created_at)) } : null;
                    if (sender?.untrustedHistory) {
                        console.warn("Refused untrusted historical key for message", message.id);
                        return { type: "error", text: t("msg.untrustedHistoricalKey") };
                    }
                    if (!sender || !sender.pub_ecdh || !sender.pub_sign)
                        throw new Error("unknown sender");
                    const content = await SeresCrypto.decryptMessage(identity, chatId, message.id, { id: sender.id, pub_ecdh: sender.pub_ecdh, pub_sign: sender.pub_sign }, message.payload, message.share);
                    const parsed = content && typeof content === "object" ? content : {};
                    return { type: "text", text: String(parsed.text ?? ""), content: parsed };
                }
                catch (error) {
                    console.warn("Could not decrypt message", message.id, error);
                    // From before my own reset by e-mail and nobody shared it.
                    const resets = userKeys.get(me.id)?.previous_keys || [];
                    const lastReset = resets.length ? resets[resets.length - 1].until : "";
                    if (!message.share && message.created_at <= lastReset)
                        return { type: "error", text: t("history.notShared") };
                    return { type: "error", text: t("msg.decryptError") };
                }
            })();
            shownCache.set(cacheKey, shown);
        }
        return shown;
    }
    // ------------------------------------------------------------ chat list
    async function loadChats() {
        const data = await api("/api/chats");
        // Pinned chats first, otherwise by last activity (as sent by the server).
        chats = data.chats
            .map((chat, index) => ({ chat, index }))
            .sort((a, b) => Number(!!b.chat.pinned) - Number(!!a.chat.pinned) || a.index - b.index)
            .map((entry) => entry.chat);
        const previews = await Promise.all(chats.map(async (chat) => (chat.last_message ? showMessage(chat.id, chat.last_message) : null)));
        notifyNewMessages(previews);
        const signature = JSON.stringify([chats, previews.map((p) => p && p.text), [...drafts], showArchived]);
        updateBadges();
        if (signature === chatsSignature)
            return;
        chatsSignature = signature;
        renderChatList(previews);
        if (current) {
            const summary = chats.find((chat) => chat.id === current.id);
            if (!summary) {
                closeChat();
            }
            else if (current.details && summary.member_count !== current.details.member_count) {
                refreshCurrentDetails();
            }
        }
    }
    // ------------------------------------------------------- notifications
    function notificationsEnabled() {
        return ("Notification" in window && Notification.permission === "granted" && readStore("settings").notify === "on");
    }
    window.addEventListener("seres:notification", (event) => {
        if (!notificationsEnabled())
            return;
        const detail = event.detail;
        if (!detail)
            return;
        const body = readStore("settings").preview === "off" ? t("notify.newMessage") : detail.body;
        try {
            const note = new Notification(detail.title, { body, tag: detail.tag, icon: "assets/favicon.png" });
            note.onclick = () => {
                window.focus();
                detail.onClick?.();
                note.close();
            };
        }
        catch {
            /* Notifications may be unavailable in some browsers. */
        }
    });
    window.addEventListener("seres:open-matrix", () => switchView("matrix"));
    /** Shows a desktop notification for chats that got new messages while you were away. */
    function notifyNewMessages(previews) {
        const counts = new Map(chats.map((chat) => [chat.id, chat.unread]));
        const before = lastUnread;
        lastUnread = counts;
        if (!before || !notificationsEnabled())
            return;
        chats.forEach((chat, index) => {
            const old = before.get(chat.id) ?? 0;
            if (chat.unread <= old || chat.muted || chat.archived)
                return;
            if (document.visibilityState === "visible" && current && current.id === chat.id)
                return;
            const body = readStore("settings").preview === "off" ? t("notify.newMessage") : previewText(chat, previews[index]);
            try {
                const note = new Notification(chat.name, { body, tag: chat.id, icon: "assets/favicon.png" });
                note.onclick = () => {
                    window.focus();
                    switchView("chats");
                    openChat(chat.id);
                    note.close();
                };
            }
            catch {
                /* notifications not supported here (e.g. some mobile browsers) */
            }
        });
    }
    async function toggleNotifications() {
        const settings = readStore("settings");
        if (settings.notify === "on") {
            settings.notify = "off";
            unsubscribePush();
        }
        else {
            if (!("Notification" in window)) {
                // Safari on iPhone and iPad only allows notifications for installed apps.
                showAlert(t(isIos() && !isInstalled() ? "notify.installFirst" : "notify.unsupported"));
                return;
            }
            const permission = await Notification.requestPermission();
            if (permission !== "granted") {
                showAlert(t("notify.denied"));
                return;
            }
            settings.notify = "on";
            subscribePush().catch((error) => console.warn("Push not available", error));
        }
        writeStore("settings", settings);
        renderSettingsToggles();
    }
    function pushSupported() {
        return "serviceWorker" in navigator && "PushManager" in window;
    }
    function base64UrlBytes(value) {
        const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
        return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
    }
    /**
     * Push notifications while SereS is closed: this device subscribes with its
     * browser's push service and tells the server. Also run at every start, so
     * the subscription belongs to the current login of this device.
     */
    async function subscribePush() {
        if (!pushSupported())
            return;
        const registration = await navigator.serviceWorker.ready;
        const key = base64UrlBytes((await api("/api/push/key")).public_key);
        let subscription = await registration.pushManager.getSubscription();
        const usedKey = subscription?.options.applicationServerKey;
        if (subscription && usedKey && !new Uint8Array(usedKey).every((byte, i) => byte === key[i])) {
            // Made for another server key: start over.
            await subscription.unsubscribe();
            subscription = null;
        }
        subscription ?? (subscription = await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key }));
        await post("/api/push/subscribe", subscription.toJSON());
    }
    async function unsubscribePush() {
        if (!pushSupported())
            return;
        try {
            const registration = await navigator.serviceWorker.getRegistration();
            const subscription = await registration?.pushManager.getSubscription();
            if (!subscription)
                return;
            await post("/api/push/unsubscribe", { endpoint: subscription.endpoint }).catch(() => { });
            await subscription.unsubscribe();
        }
        catch (error) {
            console.warn("Could not unsubscribe from push", error);
        }
    }
    function previewText(chat, shown) {
        if (!chat.last_message || !shown)
            return chat.type === "group" ? t("list.members", { count: chat.member_count }) : t("list.noMessages");
        const message = chat.last_message;
        if (shown.type === "system")
            return shown.text;
        const prefix = message.sender_id === me.id ? t("list.you") : chat.type === "group" && message.sender ? (message.sender_display || message.sender) + ": " : "";
        if (shown.type === "deleted")
            return prefix + t("list.deleted");
        return prefix + contentPreview(shown);
    }
    /** One line describing a message: its text, or what was attached. */
    function contentPreview(shown) {
        const file = shown.content?.file;
        const text = SeresFormat.plain(shown.text);
        const poll = shown.content?.poll;
        if (poll && validPoll(poll))
            return "📊 " + String(poll.question);
        if (shown.content?.location)
            return "📍 " + t(shown.content.live ? "location.live" : "location.title");
        if (!file)
            return text;
        const label = file.kind === "image"
            ? t("file.photo")
            : file.kind === "video"
                ? t("file.video")
                : file.kind === "voice"
                    ? t("file.voice", { duration: formatDuration(file.duration || 0) })
                    : file.kind === "audio"
                        ? file.name
                        : file.name;
        return text ? label + " · " + text : label;
    }
    function formatDuration(seconds) {
        const s = Math.max(0, Math.round(seconds));
        return Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0");
    }
    function formatSize(bytes) {
        if (bytes < 1024)
            return bytes + " B";
        if (bytes < 1024 * 1024)
            return (bytes / 1024).toFixed(0) + " KB";
        return (bytes / 1024 / 1024).toFixed(1) + " MB";
    }
    function disappearLabel(seconds) {
        if (!seconds)
            return t("disappear.off");
        if (seconds < 86400)
            return t("disappear.hours", { count: seconds / 3600 });
        return t("disappear.days", { count: seconds / 86400 });
    }
    function renderChatList(previews) {
        const list = $("dm-list");
        const filter = ($("list-search").value || "").toLowerCase();
        list.textContent = "";
        const archivedCount = chats.filter((chat) => chat.archived).length;
        if (archivedCount && !filter) {
            const toggle = h("div", { className: "list-item archive-toggle" }, [
                h("div", { className: "avatar archive-icon" }, [h("span", { className: "material-symbols-rounded", text: showArchived ? "arrow_back" : "archive" })]),
                h("div", { className: "item-info" }, [
                    h("span", { className: "item-name", text: showArchived ? t("archive.back") : t("archive.title") }),
                    h("span", { className: "item-status", text: t("archive.count", { count: archivedCount }) }),
                ]),
            ]);
            toggle.addEventListener("click", () => {
                showArchived = !showArchived;
                chatsSignature = "";
                loadChats().catch(() => { });
            });
            list.appendChild(toggle);
        }
        chats.forEach((chat, index) => {
            if (filter && !chat.name.toLowerCase().includes(filter))
                return;
            // The search looks through all chats, otherwise only the current section is shown.
            if (!filter && !!chat.archived !== showArchived)
                return;
            const item = h("div", {
                className: "list-item chat-list-item" + (current && current.id === chat.id ? " active" : ""),
                attrs: { "data-chatid": chat.id },
            });
            const avatarName = chat.type === "dm" && chat.other_user ? chat.other_user : chat.name;
            item.appendChild(avatarEl(avatarName, { group: chat.type === "group", label: chat.name }));
            const nameRow = h("div", { className: "item-row" }, [
                h("span", { className: "item-name" }, [
                    document.createTextNode(chat.name),
                    chat.muted ? h("span", { className: "material-symbols-rounded muted-icon", text: "notifications_off", title: t("chat.muted") }) : null,
                    chat.disappear_seconds ? h("span", { className: "material-symbols-rounded muted-icon", text: "timer", title: t("disappear.title") }) : null,
                ]),
                h("span", { className: "item-time" }, [
                    chat.pinned ? h("span", { className: "material-symbols-rounded pin-icon", text: "push_pin", title: t("chatMenu.pinned") }) : null,
                    document.createTextNode(formatListTime(chat.last_activity)),
                ]),
            ]);
            const draft = current && current.id === chat.id ? "" : drafts.get(chat.id);
            const statusRow = h("div", { className: "item-row" }, [
                chat.typing && chat.typing.length
                    ? h("span", { className: "item-status typing", text: t("typing.short") })
                    : draft
                        ? h("span", { className: "item-status" }, [
                            h("span", { className: "draft-label", text: t("list.draft") }),
                            document.createTextNode(" " + draft.replace(/\s+/g, " ")),
                        ])
                        : h("span", { className: "item-status", text: previewText(chat, previews[index]) }),
                chat.unread > 0 ? h("span", { className: "unread-badge" + (chat.muted ? " muted" : ""), text: chat.unread > 99 ? "99+" : String(chat.unread) }) : null,
            ]);
            item.appendChild(h("div", { className: "item-info" }, [nameRow, statusRow]));
            item.addEventListener("click", () => openChat(chat.id));
            item.addEventListener("contextmenu", (event) => {
                event.preventDefault();
                openChatMenu(chat, event.clientX, event.clientY);
            });
            onLongPress(item, (x, y) => openChatMenu(chat, x, y));
            list.appendChild(item);
        });
        const hits = filter ? appendMessageHits(list, filter) : 0;
        if (!list.querySelector(".chat-list-item") && !hits) {
            list.appendChild(h("div", { className: "list-empty" }, [
                h("p", { text: t(filter ? "list.noChatsFound" : "list.noChats") }),
                !filter && friends.friends.length
                    ? button(t("list.startChat"), "pill-btn", () => openNewChatModal())
                    : !filter
                        ? button(t("list.addFriend"), "pill-btn", () => openModal("add-friend-modal"))
                        : null,
            ]));
        }
        applyTheme();
    }
    const SEARCH_DEPTH = 400;
    const messageIndex = new Map();
    let globalSearch = null;
    let globalSearchTimer = null;
    /** Text that can be searched: the message, a poll question and options, a file name. */
    function searchableText(view) {
        const content = view.content || {};
        const parts = [view.text];
        if (content.poll && validPoll(content.poll))
            parts.push(String(content.poll.question), ...content.poll.options.map(String));
        if (content.file?.name && content.file.kind !== "voice")
            parts.push(String(content.file.name));
        if (content.preview?.title)
            parts.push(String(content.preview.title));
        return parts.filter(Boolean).join(" \n");
    }
    async function indexChat(chat) {
        const cached = messageIndex.get(chat.id);
        if (cached && Date.now() - cached.at < 2 * 60 * 1000)
            return;
        const rows = [];
        let before = "";
        for (let loaded = 0; loaded < SEARCH_DEPTH;) {
            const data = await api(`/api/chats/${encodeURIComponent(chat.id)}/messages?limit=200${before}`);
            const messages = data.messages || [];
            loaded += messages.length;
            const views = await Promise.all(messages.map((m) => (m.silent || m.deleted ? null : showMessage(chat.id, m))));
            messages.forEach((message, i) => {
                const view = views[i];
                if (!view || (view.type !== "text" && view.type !== "legacy"))
                    return;
                const text = searchableText(view).trim();
                if (!text)
                    return;
                rows.push({
                    id: message.id,
                    seq: message.seq,
                    created_at: message.created_at,
                    sender: message.sender_id === me.id ? t("msg.you") : message.sender_display || message.sender || "",
                    text,
                    lower: text.toLowerCase(),
                });
            });
            if (!data.has_more || !messages.length)
                break;
            before = `&before_seq=${Math.min(...messages.map((m) => m.seq))}`;
        }
        messageIndex.set(chat.id, { at: Date.now(), rows });
    }
    function startGlobalSearch() {
        if (globalSearchTimer !== null)
            clearTimeout(globalSearchTimer);
        const query = ($("list-search").value || "").trim().toLowerCase();
        if (query.length < 2) {
            globalSearch = null;
            return;
        }
        globalSearchTimer = window.setTimeout(async () => {
            const list = chats.slice();
            const search = { query, running: true, done: 0, total: list.length };
            globalSearch = search;
            chatsSignature = "";
            loadChats().catch(() => { });
            // A few chats at a time, so the browser stays responsive.
            let next = 0;
            const worker = async () => {
                while (next < list.length && globalSearch === search) {
                    const chat = list[next++];
                    try {
                        await indexChat(chat);
                    }
                    catch {
                        // Skip a chat that can't be loaded.
                    }
                    search.done++;
                    if (search.done % 4 === 0 && globalSearch === search) {
                        chatsSignature = "";
                        loadChats().catch(() => { });
                    }
                }
            };
            await Promise.all([worker(), worker(), worker()]);
            if (globalSearch !== search)
                return;
            search.running = false;
            chatsSignature = "";
            loadChats().catch(() => { });
        }, 350);
    }
    function highlighted(text, query) {
        // A short piece around the first match, with the match marked.
        const index = text.toLowerCase().indexOf(query);
        const start = index > 18 ? index - 12 : 0;
        const piece = (start > 0 ? "…" : "") + text.slice(start, index + query.length + 80).replace(/\s+/g, " ");
        const span = h("span", { className: "item-status search-snippet" });
        const lower = piece.toLowerCase();
        const at = lower.indexOf(query);
        if (at < 0) {
            span.textContent = piece;
            return span;
        }
        span.append(document.createTextNode(piece.slice(0, at)), h("mark", { text: piece.slice(at, at + query.length) }), document.createTextNode(piece.slice(at + query.length)));
        return span;
    }
    /** Adds the matching messages below the chats; returns how many there are. */
    function appendMessageHits(list, filter) {
        const query = filter.trim();
        if (query.length < 2 || !globalSearch || globalSearch.query !== query)
            return 0;
        const hits = [];
        for (const chat of chats) {
            for (const row of messageIndex.get(chat.id)?.rows || []) {
                if (row.lower.includes(query))
                    hits.push({ chat, row });
            }
        }
        hits.sort((a, b) => (a.row.created_at < b.row.created_at ? 1 : -1));
        list.appendChild(h("div", { className: "list-section-title" }, [
            h("span", { text: t("search.messages") }),
            globalSearch.running ? h("span", { className: "search-progress", text: t("search.progress", { done: globalSearch.done, total: globalSearch.total }) }) : null,
        ]));
        for (const { chat, row } of hits.slice(0, 60)) {
            const item = h("div", { className: "list-item search-hit" });
            const avatarName = chat.type === "dm" && chat.other_user ? chat.other_user : chat.name;
            item.appendChild(avatarEl(avatarName, { group: chat.type === "group", label: chat.name }));
            item.appendChild(h("div", { className: "item-info" }, [
                h("div", { className: "item-row" }, [
                    h("span", { className: "item-name", text: chat.type === "group" && row.sender ? `${chat.name} · ${row.sender}` : chat.name }),
                    h("span", { className: "item-time", text: formatListTime(row.created_at) }),
                ]),
                h("div", { className: "item-row" }, [highlighted(row.text, query)]),
            ]));
            item.addEventListener("click", async () => {
                await openChat(chat.id);
                await jumpToMessage(row.id);
            });
            list.appendChild(item);
        }
        if (!hits.length && !globalSearch.running)
            list.appendChild(h("p", { className: "list-hint", text: t("search.noMessages") }));
        if (hits.length > 60)
            list.appendChild(h("p", { className: "list-hint", text: t("search.more", { count: hits.length - 60 }) }));
        list.appendChild(h("p", { className: "list-hint", text: t("search.depth", { count: SEARCH_DEPTH }) }));
        return hits.length || 1;
    }
    function updateBadges() {
        // Muted chats keep their own counter but don't count in the totals.
        const unread = chats.reduce((sum, chat) => sum + (chat.muted ? 0 : chat.unread), 0);
        const chatsBadge = $("chats-badge");
        chatsBadge.textContent = unread ? String(unread) : "";
        const requestsBadge = $("requests-badge");
        requestsBadge.textContent = friends.incoming.length ? String(friends.incoming.length) : "";
        document.title = unread ? `(${unread}) SereS` : "SereS";
        updateFavicon(unread);
    }
    let faviconImage = null;
    let faviconCount = 0;
    /** Draws a red badge with the number of unread messages onto the tab icon. */
    function updateFavicon(count) {
        if (count === faviconCount)
            return;
        faviconCount = count;
        const link = document.querySelector("link[rel~='icon']");
        if (!link)
            return;
        if (!count) {
            link.href = "assets/favicon.png";
            return;
        }
        const draw = () => {
            const canvas = document.createElement("canvas");
            canvas.width = canvas.height = 64;
            const ctx = canvas.getContext("2d");
            if (!ctx || !faviconImage || !faviconCount)
                return;
            ctx.drawImage(faviconImage, 0, 0, 64, 64);
            ctx.fillStyle = "#ea0038";
            ctx.beginPath();
            ctx.arc(44, 20, 20, 0, Math.PI * 2);
            ctx.fill();
            ctx.fillStyle = "#ffffff";
            ctx.font = "bold 26px sans-serif";
            ctx.textAlign = "center";
            ctx.textBaseline = "middle";
            ctx.fillText(faviconCount > 9 ? "9+" : String(faviconCount), 44, 21);
            link.href = canvas.toDataURL("image/png");
        };
        if (faviconImage && faviconImage.complete)
            return draw();
        faviconImage = new Image();
        faviconImage.onload = draw;
        faviconImage.src = "assets/favicon.png";
    }
    // --------------------------------------------------------- friends view
    async function loadFriends() {
        friends = await api("/api/friends");
        updateBadges();
        const signature = JSON.stringify(friends);
        if (signature === friendsSignature)
            return;
        friendsSignature = signature;
        renderFriends();
        renderRequests();
    }
    function sectionTitle(text) {
        return h("div", { className: "section-title", text });
    }
    function userRow(user, status, actions) {
        const avatar = avatarEl(user.username, { label: nameOf(user) });
        const info = h("div", { className: "item-info" }, [
            h("span", { className: "item-name", text: nameOf(user) }),
            h("span", { className: "item-status", text: status }),
        ]);
        [avatar, info].forEach((el) => el.addEventListener("click", () => openProfile(user.username)));
        const row = h("div", { className: "list-item request-list-item" }, [avatar, info, h("div", { className: "request-actions" }, actions)]);
        row.addEventListener("contextmenu", (event) => {
            event.preventDefault();
            openUserMenu(user, event);
        });
        onLongPress(row, () => openProfile(user.username));
        return row;
    }
    function action(label, fn, confirmText) {
        return async () => {
            if (confirmText && !window.confirm(confirmText))
                return;
            try {
                await fn();
            }
            catch (error) {
                showAlert(errorText(error));
            }
            await refreshAll();
        };
    }
    function renderFriends() {
        const list = $("friends-list");
        const filter = ($("list-search").value || "").toLowerCase();
        const match = (user) => !filter || user.username.toLowerCase().includes(filter) || nameOf(user).toLowerCase().includes(filter);
        list.textContent = "";
        list.appendChild(sectionTitle(t("friends.title", { count: friends.friends.length })));
        friends.friends.filter(match).forEach((friend) => {
            list.appendChild(userRow(friend, friend.status || t("friends.status"), [
                button(t("friends.message"), "request-action-btn accept", () => startDm(friend.username)),
                button("⋯", "request-action-btn more", (event) => openUserMenu(friend, event)),
            ]));
        });
        if (!friends.friends.length) {
            list.appendChild(h("div", { className: "list-empty" }, [
                h("p", { text: t("friends.none") }),
                button(t("list.addFriend"), "pill-btn", () => openModal("add-friend-modal")),
            ]));
        }
        if (friends.outgoing.length) {
            list.appendChild(sectionTitle(t("friends.sent")));
            friends.outgoing.filter(match).forEach((user) => {
                list.appendChild(userRow(user, t("friends.waiting"), [
                    button(t("common.cancel"), "request-action-btn discard", action("cancel", () => post("/api/friends/cancel", { username: user.username }))),
                ]));
            });
        }
        if (friends.blocked.length) {
            list.appendChild(sectionTitle(`${t("friends.blocked")} — ${friends.blocked.length}`));
            list.appendChild(h("p", { className: "list-hint", text: t("friends.blockedHint") }));
            friends.blocked.filter(match).forEach((user) => {
                list.appendChild(userRow(user, t("profile.blockedStatus"), [
                    button(t("friends.unblock"), "request-action-btn accept", () => unblockUser(user)),
                ]));
            });
        }
        applyTheme();
    }
    function openUserMenu(user, event) {
        closeFloatingMenus();
        const isFriend = friends.friends.some((friend) => friend.id === user.id);
        const isBlocked = friends.blocked.some((blocked) => blocked.id === user.id);
        const menu = h("div", { className: "floating-menu" }, [
            h("div", { className: "floating-title", text: nameOf(user) }),
            button(t("profile.view"), "floating-item", () => openProfile(user.username)),
            isBlocked ? button(t("friends.unblock"), "floating-item", () => {
                closeFloatingMenus();
                unblockUser(user);
            }) : null,
            isFriend ? button(t("friends.messageMenu"), "floating-item", () => {
                closeFloatingMenus();
                startDm(user.username);
            }) : null,
            isFriend ? button(t("friends.remove"), "floating-item", action("remove", () => post("/api/friends/remove", { username: user.username }), t("friends.removeConfirm", { name: nameOf(user) }))) : null,
            isBlocked ? null : button(t("friends.block"), "floating-item danger", action("block", () => post("/api/block", { username: user.username }), t("friends.blockConfirmLong", { name: nameOf(user) }))),
        ]);
        const rect = event.currentTarget.getBoundingClientRect();
        menu.style.top = Math.min(rect.bottom + 4, window.innerHeight - 140) + "px";
        menu.style.left = Math.max(8, rect.right - 180) + "px";
        document.body.appendChild(menu);
    }
    /** Right-click (or long-press) menu of a chat: delete a direct chat or leave a group. */
    function openChatMenu(chat, x, y) {
        closeFloatingMenus();
        const isGroup = chat.type === "group";
        const menu = h("div", { className: "floating-menu" }, [
            h("div", { className: "floating-title", text: chat.name }),
            !isGroup && chat.other_user
                ? button(t("profile.view"), "floating-item", () => openProfile(chat.other_user))
                : null,
            button(chat.pinned ? t("chatMenu.unpin") : t("chatMenu.pin"), "floating-item", action("pin", async () => {
                closeFloatingMenus();
                await post(`/api/chats/${encodeURIComponent(chat.id)}/prefs`, { pinned: !chat.pinned });
                chatsSignature = "";
            })),
            button(chat.archived ? t("chatMenu.unarchive") : t("chatMenu.archive"), "floating-item", action("archive", async () => {
                closeFloatingMenus();
                await post(`/api/chats/${encodeURIComponent(chat.id)}/prefs`, { archived: !chat.archived });
                chatsSignature = "";
            })),
            chat.unread
                ? button(t("chatMenu.markRead"), "floating-item", () => {
                    closeFloatingMenus();
                    const seq = chat.last_message ? chat.last_message.seq : 0;
                    // The server caps the position at the newest message.
                    post(`/api/chats/${encodeURIComponent(chat.id)}/read`, { seq: Math.max(seq, 2 ** 31 - 1) })
                        .then(() => loadChats())
                        .catch((error) => showAlert(errorText(error)));
                })
                : null,
            button(t(isGroup ? "info.leave" : "info.deleteChat"), "floating-item danger", action(isGroup ? "leave" : "delete", async () => {
                closeFloatingMenus();
                await post(`/api/chats/${encodeURIComponent(chat.id)}/${isGroup ? "leave" : "delete"}`);
                if (current && current.id === chat.id)
                    closeChat();
                chatsSignature = "";
            }, t(isGroup ? "info.leaveConfirm" : "info.deleteChatConfirm"))),
        ]);
        document.body.appendChild(menu);
        // Keep the menu inside the viewport.
        menu.style.left = Math.max(8, Math.min(x, window.innerWidth - menu.offsetWidth - 8)) + "px";
        menu.style.top = Math.max(8, Math.min(y, window.innerHeight - menu.offsetHeight - 8)) + "px";
    }
    /** Calls handler after a finger rests ~0.5s on the element (iOS has no contextmenu event). */
    function onLongPress(element, handler) {
        let timer = null;
        let fired = false;
        const cancel = () => {
            if (timer !== null)
                clearTimeout(timer);
            timer = null;
        };
        element.addEventListener("touchstart", (event) => {
            fired = false;
            const touch = event.touches[0];
            timer = window.setTimeout(() => {
                fired = true;
                if (navigator.vibrate)
                    navigator.vibrate(15);
                handler(touch.clientX, touch.clientY);
            }, 500);
        }, { passive: true });
        element.addEventListener("touchmove", cancel, { passive: true });
        element.addEventListener("touchend", (event) => {
            cancel();
            // Don't open the chat when the finger is lifted after the menu appeared.
            if (fired)
                event.preventDefault();
        });
        element.addEventListener("touchcancel", cancel);
    }
    function closeFloatingMenus() {
        document.querySelectorAll(".floating-menu").forEach((menu) => menu.remove());
    }
    function renderRequests() {
        const list = $("requests-list");
        const filter = ($("list-search").value || "").trim().toLowerCase();
        list.textContent = "";
        const incoming = friends.incoming.filter((user) => !filter || user.username.toLowerCase().includes(filter) || nameOf(user).toLowerCase().includes(filter));
        if (!incoming.length && filter) {
            list.appendChild(h("div", { className: "list-empty", text: t("search.none") }));
        }
        else if (!incoming.length) {
            list.appendChild(h("div", { className: "list-item request-list-item" }, [
                h("div", { className: "avatar", text: "!" }),
                h("div", { className: "item-info" }, [
                    h("span", { className: "item-name", text: t("requests.none") }),
                    h("span", { className: "item-status", text: t("requests.noneHint") }),
                ]),
            ]));
        }
        incoming.forEach((user) => {
            list.appendChild(userRow(user, t("requests.wants"), [
                button(t("requests.accept"), "request-action-btn accept", async () => {
                    try {
                        await post("/api/friends/accept", { username: user.username });
                        await startDm(user.username);
                    }
                    catch (error) {
                        showAlert(errorText(error));
                    }
                    await refreshAll();
                }),
                button(t("requests.decline"), "request-action-btn discard", action("decline", () => post("/api/friends/decline", { username: user.username }))),
                button(t("friends.blockShort"), "request-action-btn more", action("block", () => post("/api/block", { username: user.username }), t("friends.blockConfirm", { name: nameOf(user) }))),
            ]));
        });
        applyTheme();
    }
    function switchView(view) {
        document.querySelector(".list-container").scrollTop = 0;
        document.querySelectorAll(".list-view-toggle").forEach((btn) => {
            btn.classList.toggle("active", btn.dataset.view === view);
        });
        document.querySelectorAll(".list-view-panel").forEach((panel) => {
            panel.classList.toggle("active", panel.dataset.panel === view);
        });
        $("chats-header").style.display = view === "chats" ? "flex" : "none";
        $("friends-header").style.display = view === "friends" ? "flex" : "none";
        $("requests-header").style.display = view === "requests" ? "flex" : "none";
        $("list-search").parentElement.style.display = view === "matrix" ? "none" : "block";
        document.querySelectorAll(".rail-nav[data-rail-view]").forEach((button) => {
            const selected = button.dataset.railView === view;
            button.classList.toggle("active", selected);
            if (selected)
                button.setAttribute("aria-current", "page");
            else
                button.removeAttribute("aria-current");
        });
        const matrixOpen = view === "matrix";
        document.querySelector(".main-chat")?.classList.toggle("matrix-open", matrixOpen);
        $("matrix-app-root").classList.toggle("modal-hidden", !matrixOpen);
        const matrixController = window.SeresMatrix;
        if (matrixOpen)
            matrixController?.activate();
        else
            matrixController?.deactivate();
    }
    // ------------------------------------------------------------ open chat
    async function openChat(chatId) {
        cancelEdit();
        sendTyping(false);
        saveDraft();
        cancelReply();
        clearPendingFiles();
        closeSearch();
        closeEmojiPicker();
        current = {
            id: chatId,
            details: null,
            messages: new Map(),
            maxRev: 0,
            oldestSeq: Number.MAX_SAFE_INTEGER,
            hasMore: false,
            lastReadSent: 0,
            changedKeys: [],
            missingKeys: [],
            subtitle: "",
            typing: [],
            receipts: null,
            search: null,
        };
        const opened = current;
        $("pinned-bar").classList.add("modal-hidden");
        $("search-btn").classList.remove("modal-hidden");
        $("call-btn")?.classList.remove("modal-hidden");
        document.querySelectorAll(".chat-list-item").forEach((item) => {
            item.classList.toggle("active", item.dataset.chatid === chatId);
        });
        const summary = chats.find((chat) => chat.id === chatId);
        $("current-chat-name").textContent = summary ? summary.name : "";
        $("current-chat-sub").textContent = "";
        $("chat-input-area").classList.remove("modal-hidden");
        $("chat-info-btn").classList.remove("modal-hidden");
        $("messages").textContent = "";
        const input = $("message-input-field");
        input.value = drafts.get(chatId) || "";
        autoGrow(input);
        updateSendButton();
        if (window.innerWidth <= 768)
            document.querySelector(".sidebar")?.classList.remove("open");
        try {
            await refreshCurrentDetails();
            scheduled = null;
            renderScheduledBar();
            loadScheduled(opened);
            const data = await api(`/api/chats/${encodeURIComponent(chatId)}/messages?limit=50`);
            if (current !== opened)
                return;
            opened.receipts = data.receipts || null;
            mergeMessages(data.messages);
            opened.hasMore = data.has_more;
            await renderMessages({ forceBottom: true });
            markRead();
            $("message-input-field").focus();
        }
        catch (error) {
            showAlert(errorText(error));
        }
    }
    /** Remembers what was typed in the open chat (in memory only). */
    function saveDraft() {
        if (!current || editing)
            return;
        const text = $("message-input-field").value;
        if (text.trim())
            drafts.set(current.id, text);
        else
            drafts.delete(current.id);
        chatsSignature = "";
    }
    function closeChat() {
        cancelEdit();
        sendTyping(false);
        saveDraft();
        cancelReply();
        clearPendingFiles();
        closeSearch();
        closeEmojiPicker();
        $("message-input-field").value = "";
        $("pinned-bar").classList.add("modal-hidden");
        $("search-btn").classList.add("modal-hidden");
        $("call-btn")?.classList.add("modal-hidden");
        $("jump-bottom").classList.add("modal-hidden");
        $("typing-bubble").classList.add("modal-hidden");
        current = null;
        $("current-chat-name").textContent = t("app.welcomeUser", { name: nameOf(me) });
        $("current-chat-sub").textContent = "";
        $("chat-input-area").classList.add("modal-hidden");
        $("chat-info-btn").classList.add("modal-hidden");
        $("key-warning").classList.add("modal-hidden");
        const container = $("messages");
        container.textContent = "";
        container.appendChild(emptyState());
    }
    function emptyState() {
        return h("div", { className: "empty-state" }, [
            h("div", { className: "empty-state-icon material-symbols-rounded", text: "chat_bubble" }),
            h("h2", { text: "SereS" }),
            h("p", { text: t("app.emptyState") }),
        ]);
    }
    async function refreshCurrentDetails() {
        if (!current)
            return;
        const opened = current;
        const data = await api(`/api/chats/${encodeURIComponent(opened.id)}`);
        if (current !== opened)
            return;
        const details = data.chat;
        opened.details = details;
        for (const member of details.members || [])
            userKeys.set(member.id, member);
        const { changed, missing } = await checkPins(details.members || []);
        opened.changedKeys = changed;
        opened.missingKeys = missing;
        $("current-chat-name").textContent = details.name;
        $("call-btn")?.classList.toggle("modal-hidden", !!details.blocked);
        opened.subtitle =
            details.type === "group"
                ? t("chat.groupSub", { count: details.member_count })
                : details.blocked
                    ? t("chat.blocked")
                    : details.presence
                        ? presenceText(details.presence)
                        : t("chat.dmSub");
        if (details.disappear_seconds)
            opened.subtitle = disappearLabel(details.disappear_seconds) + " · " + opened.subtitle;
        renderSubtitle();
        renderKeyWarning();
        renderPinnedBar().catch(() => { });
    }
    /** "online" or "last seen today at 12:30". */
    function presenceText(presence) {
        if (presence.online)
            return t("presence.online");
        const date = parseTime(presence.last_seen);
        const day = formatDay(date);
        return t("presence.lastSeen", { day: day.toLowerCase(), time: formatTime(presence.last_seen) });
    }
    // ------------------------------------------------------- pinned messages
    /** Loads a message that is not in the loaded window (pinned or quoted). */
    async function fetchMessage(opened, messageId) {
        const loaded = opened.messages.get(messageId);
        if (loaded)
            return loaded;
        try {
            const data = await api(`/api/chats/${encodeURIComponent(opened.id)}/messages/${encodeURIComponent(messageId)}`);
            return data.message;
        }
        catch {
            return null;
        }
    }
    async function renderPinnedBar() {
        const opened = current;
        const bar = $("pinned-bar");
        const pins = opened && opened.details ? opened.details.pins || [] : [];
        if (!opened || !pins.length) {
            bar.classList.add("modal-hidden");
            return;
        }
        const message = await fetchMessage(opened, pins[0].message_id);
        if (current !== opened)
            return;
        const shown = message ? await showMessage(opened.id, message) : null;
        bar.textContent = "";
        bar.append(h("span", { className: "material-symbols-rounded pinned-icon", text: "push_pin" }), h("div", { className: "pinned-text" }, [
            h("strong", { text: pins.length > 1 ? t("pins.count", { count: pins.length }) : t("pins.one") }),
            h("span", { text: shown ? contentPreview(shown) : "…" }),
        ]));
        bar.classList.remove("modal-hidden");
    }
    async function openPinsModal() {
        const opened = current;
        if (!opened || !opened.details)
            return;
        const pins = opened.details.pins || [];
        const body = $("pins-body");
        body.textContent = "";
        if (!pins.length)
            body.appendChild(h("p", { className: "list-hint", text: t("pins.none") }));
        for (const pin of pins) {
            const message = await fetchMessage(opened, pin.message_id);
            if (!message)
                continue;
            const shown = await showMessage(opened.id, message);
            const row = h("div", { className: "pin-row" }, [
                h("div", { className: "pin-meta" }, [
                    h("strong", { text: message.sender_id === me.id ? t("msg.you") : message.sender_display || message.sender || "" }),
                    h("span", { text: formatDateTime(message.created_at) }),
                ]),
                h("div", { className: "pin-preview", text: contentPreview(shown) }),
                h("div", { className: "pin-actions" }, [
                    button(t("pins.jump"), "pill-btn", () => {
                        closeAllModals();
                        jumpToMessage(pin.message_id);
                    }),
                    button(t("pins.unpin"), "pill-btn secondary", async () => {
                        await togglePin(opened, message, false);
                        openPinsModal();
                    }),
                ]),
            ]);
            body.appendChild(row);
        }
        openModal("pins-modal");
    }
    async function togglePin(opened, message, pinned) {
        try {
            const data = await post(`/api/chats/${encodeURIComponent(opened.id)}/pins`, { message_id: message.id, pinned });
            if (opened.details)
                opened.details.pins = data.pins;
            showAlert(t(pinned ? "pins.pinned" : "pins.unpinned"));
            await renderPinnedBar();
            await syncCurrent();
        }
        catch (error) {
            showAlert(errorText(error));
        }
    }
    /** Scrolls to a message, loading older pages if needed, and flashes it. */
    async function jumpToMessage(messageId) {
        const opened = current;
        if (!opened)
            return;
        for (let page = 0; page < 20 && !opened.messages.has(messageId) && opened.hasMore; page++) {
            await loadOlder();
            if (current !== opened)
                return;
        }
        const row = document.querySelector(`.message-row[data-id="${CSS.escape(messageId)}"]`);
        if (!row) {
            showAlert(t("msg.notFound"));
            return;
        }
        row.scrollIntoView({ behavior: "smooth", block: "center" });
        row.classList.remove("flash");
        void row.offsetWidth;
        row.classList.add("flash");
    }
    function typingText(users) {
        if (users.length === 1)
            return t("typing.one", { name: nameOf(users[0]) });
        if (users.length === 2)
            return t("typing.two", { first: nameOf(users[0]), second: nameOf(users[1]) });
        return t("typing.many");
    }
    /** The line under the chat name: who is typing, otherwise members / encryption. */
    function renderSubtitle() {
        if (!current)
            return;
        const sub = $("current-chat-sub");
        sub.textContent = current.typing.length ? typingText(current.typing) : current.subtitle;
        sub.classList.toggle("typing", current.typing.length > 0);
        // Animated bubble above the input field.
        $("typing-bubble-text").textContent = current.typing.length ? typingText(current.typing) : "";
        $("typing-bubble").classList.toggle("modal-hidden", current.typing.length === 0);
    }
    // Tell the others that we are typing (at most every 3 seconds, stops after sending).
    let typingSentAt = 0;
    let typingChat = null;
    function sendTyping(typing) {
        if (!current)
            return;
        const now = Date.now();
        if (typing && typingChat === current.id && now - typingSentAt < 3000)
            return;
        if (!typing && typingChat === null)
            return;
        const chatId = typing ? current.id : typingChat;
        typingSentAt = typing ? now : 0;
        typingChat = typing ? current.id : null;
        post(`/api/chats/${encodeURIComponent(chatId)}/typing`, { typing }).catch(() => { });
    }
    function renderKeyWarning() {
        const box = $("key-warning");
        box.textContent = "";
        if (!current)
            return;
        if (current.changedKeys.length) {
            const names = current.changedKeys.map(nameOf).join(", ");
            box.appendChild(h("span", {
                text: t("chat.keyChanged", { names }),
            }));
            box.appendChild(button(t("chat.acceptKey"), "pill-btn", async () => {
                if (!current)
                    return;
                await acceptNewKeys(current.changedKeys);
                await refreshCurrentDetails();
                await renderMessages({ keepPosition: true });
            }));
            box.appendChild(button(t("app.chatInfo"), "pill-btn secondary", () => openChatInfo()));
        }
        else if (current.missingKeys.length) {
            const names = current.missingKeys.map(nameOf).join(", ");
            box.appendChild(h("span", {
                text: t("chat.keyMissing", { names }),
            }));
        }
        else {
            renderHistoryNotice(box, current);
        }
        box.classList.toggle("modal-hidden", !box.childElementCount);
    }
    /** Someone reset their password by e-mail and can't read the older messages. */
    function renderHistoryNotice(box, opened) {
        const members = opened.details?.members || [];
        if (members.find((m) => m.id === me.id)?.history_reset) {
            box.appendChild(h("span", { text: t("history.mine") }));
            return;
        }
        const waiting = members.filter((m) => m.id !== me.id && m.history_reset && m.pub_ecdh);
        if (!waiting.length)
            return;
        box.appendChild(h("span", { text: t("history.others", { names: waiting.map(nameOf).join(", ") }) }));
        for (const member of waiting) {
            const label = waiting.length > 1 ? t("history.shareWith", { name: nameOf(member) }) : t("history.share");
            const shareButton = button(label, "pill-btn", async () => {
                shareButton.disabled = true;
                shareButton.textContent = t("history.sharing");
                try {
                    const count = await shareHistory(opened, member);
                    showAlert(t("history.shared", { name: nameOf(member), count }));
                }
                catch (error) {
                    showAlert(errorText(error));
                }
                if (current === opened)
                    await refreshCurrentDetails().catch(() => { });
            });
            box.appendChild(shareButton);
        }
    }
    /**
     * Gives a member who reset their password by e-mail the older messages back:
     * every message key this account can read is wrapped again for their new
     * keys. The messages themselves are not sent again and stay end-to-end encrypted.
     */
    async function shareHistory(opened, member) {
        const pins = readStore("pins");
        const memberFp = await memberFingerprint(member);
        if (!memberFp || pins[member.id] !== memberFp) {
            throw new Error(t("msg.keyChanged"));
        }
        const range = member.history_reset;
        const recipient = { id: member.id, pub_ecdh: member.pub_ecdh };
        const url = `/api/chats/${encodeURIComponent(opened.id)}/history/${encodeURIComponent(member.id)}`;
        let keys = {};
        let count = 0;
        let sawUntrustedHistory = false;
        let before = range.until_seq + 1;
        for (;;) {
            const data = await api(`/api/chats/${encodeURIComponent(opened.id)}/messages?limit=200&before_seq=${before}`);
            const page = data.messages;
            for (const message of page) {
                if (message.seq <= range.from_seq || message.kind !== "e2e" || message.deleted || !message.payload)
                    continue;
                try {
                    await ensureUserKeys([message.sender_id]);
                    const known = userKeys.get(message.sender_id);
                    const sender = known ? { id: known.id, ...(await keysAt(known, message.created_at)) } : null;
                    if (sender?.untrustedHistory) {
                        sawUntrustedHistory = true;
                        console.warn("Refused untrusted historical key while sharing message", message.id);
                        continue;
                    }
                    if (!sender || !sender.pub_ecdh || !sender.pub_sign)
                        continue;
                    keys[message.id] = await SeresCrypto.shareMessageKey(identity, opened.id, message.id, { id: sender.id, pub_ecdh: sender.pub_ecdh, pub_sign: sender.pub_sign }, message.payload, recipient, message.share);
                    count++;
                }
                catch (error) {
                    // Messages this account can't read itself can't be shared.
                    console.warn("Could not share message", message.id, error);
                }
                if (Object.keys(keys).length >= 200) {
                    await post(url, { keys });
                    keys = {};
                }
            }
            if (!data.has_more || !page.length || page[0].seq <= range.from_seq)
                break;
            before = page[0].seq;
        }
        await post(url, { keys, done: true });
        if (sawUntrustedHistory)
            showAlert(t("msg.untrustedHistoricalKey"));
        return count;
    }
    /** Adds new or changed messages. Unknown messages older than the loaded window are skipped. */
    function mergeMessages(list, includeOlder = false) {
        if (!current)
            return false;
        let changed = false;
        for (const message of list) {
            current.maxRev = Math.max(current.maxRev, message.rev);
            const known = current.messages.get(message.id);
            if (!known && !includeOlder && current.messages.size && message.seq < current.oldestSeq)
                continue;
            if (!known || known.rev !== message.rev) {
                current.messages.set(message.id, message);
                changed = true;
            }
            current.oldestSeq = Math.min(current.oldestSeq, message.seq);
        }
        return changed;
    }
    async function loadOlder() {
        if (!current || !current.hasMore)
            return;
        const opened = current;
        const data = await api(`/api/chats/${encodeURIComponent(opened.id)}/messages?limit=50&before_seq=${opened.oldestSeq}`);
        if (current !== opened)
            return;
        mergeMessages(data.messages, true);
        opened.hasMore = data.has_more;
        await renderMessages({ keepPosition: true });
    }
    async function syncCurrent() {
        if (!current)
            return;
        const opened = current;
        const data = await api(`/api/chats/${encodeURIComponent(opened.id)}/messages?since_rev=${opened.maxRev}&limit=200`);
        if (current !== opened)
            return;
        opened.typing = data.typing || [];
        renderSubtitle();
        const receiptsChanged = JSON.stringify(data.receipts || null) !== JSON.stringify(opened.receipts);
        opened.receipts = data.receipts || null;
        const events = data.messages
            .filter((message) => message.kind === "system" && !opened.messages.has(message.id))
            .map((message) => message.payload || {});
        if (events.some((event) => event.event === "history_shared" && event.target_id === me.id)) {
            // My old messages are back: load the chat again from the start.
            await openChat(opened.id);
            return;
        }
        if (events.some((event) => event.event === "keys_reset" || event.event === "history_shared")) {
            refreshCurrentDetails().catch(() => { });
        }
        if (mergeMessages(data.messages) || receiptsChanged) {
            await renderMessages({});
            markRead();
        }
    }
    function markRead() {
        if (!current || document.visibilityState !== "visible")
            return;
        let maxSeq = 0;
        current.messages.forEach((message) => (maxSeq = Math.max(maxSeq, message.seq)));
        if (maxSeq <= current.lastReadSent)
            return;
        current.lastReadSent = maxSeq;
        const chat = chats.find((c) => c.id === current.id);
        if (chat && chat.unread) {
            chat.unread = 0;
            updateBadges();
            chatsSignature = "";
        }
        post(`/api/chats/${encodeURIComponent(current.id)}/read`, { seq: maxSeq })
            .then(() => loadChats())
            .catch(() => { });
    }
    async function renderMessages(options) {
        if (!current)
            return;
        const opened = current;
        const container = $("messages");
        const all = [...opened.messages.values()].filter((m) => !m.deleted).sort((a, b) => a.seq - b.seq);
        const allShown = await Promise.all(all.map((message) => showMessage(opened.id, message)));
        if (current !== opened)
            return;
        // Reactions are silent messages; collect them instead of showing them as rows.
        const reactions = new Map();
        const votes = new Map();
        const liveUpdates = new Map();
        const ordered = [];
        const shown = [];
        all.forEach((message, index) => {
            const view = allShown[index];
            if (message.silent) {
                const content = view.content;
                if (content && content.type === "reaction" && content.target && message.sender_id) {
                    const perSender = reactions.get(content.target) || new Map();
                    const previous = perSender.get(message.sender_id);
                    if (!previous || previous.seq < message.seq)
                        perSender.set(message.sender_id, { emoji: content.emoji || "", seq: message.seq });
                    reactions.set(content.target, perSender);
                }
                if (content && content.type === "vote" && content.target && message.sender_id && Array.isArray(content.choices)) {
                    const perSender = votes.get(content.target) || new Map();
                    const previous = perSender.get(message.sender_id);
                    const choices = content.choices.filter((n) => Number.isInteger(n) && n >= 0);
                    if (!previous || previous.seq < message.seq)
                        perSender.set(message.sender_id, { choices, seq: message.seq });
                    votes.set(content.target, perSender);
                }
                if (content && content.type === "location" && content.target && message.sender_id) {
                    const previous = liveUpdates.get(content.target);
                    if (!previous || previous.seq < message.seq) {
                        liveUpdates.set(content.target, {
                            sender: message.sender_id,
                            seq: message.seq,
                            at: message.created_at,
                            lat: Number(content.lat),
                            lng: Number(content.lng),
                            acc: Number(content.acc) || undefined,
                            stopped: !!content.stopped,
                        });
                    }
                }
                return;
            }
            ordered.push(message);
            shown.push(view);
        });
        const distanceFromBottom = container.scrollHeight - container.scrollTop - container.clientHeight;
        const nearBottom = distanceFromBottom < 120;
        const fragment = document.createDocumentFragment();
        const banner = h("div", { className: "e2e-banner" }, [
            h("span", { text: t("chat.banner") }),
        ]);
        banner.addEventListener("click", () => openChatInfo());
        fragment.appendChild(banner);
        if (opened.hasMore) {
            fragment.appendChild(button(t("chat.loadOlder"), "pill-btn load-older", () => {
                loadOlder().catch((error) => showAlert(errorText(error)));
            }));
        }
        let lastDay = "";
        let previous = null;
        ordered.forEach((message, index) => {
            const date = parseTime(message.created_at);
            const day = date.toDateString();
            if (day !== lastDay) {
                fragment.appendChild(h("div", { className: "date-separator" }, [h("span", { text: formatDay(date) })]));
                lastDay = day;
                previous = null;
            }
            const view = shown[index];
            if (view.type === "system") {
                fragment.appendChild(h("div", { className: "system-message" }, [h("span", { text: view.text })]));
                previous = null;
                return;
            }
            const compact = previous !== null &&
                previous.sender_id === message.sender_id &&
                date.getTime() - parseTime(previous.created_at).getTime() < 5 * 60 * 1000;
            fragment.appendChild(messageRow(opened, message, view, compact, reactions.get(message.id), votes.get(message.id), liveUpdates.get(message.id)));
            previous = message;
        });
        container.textContent = "";
        container.appendChild(fragment);
        applyTheme();
        markSearchHits();
        if (options.keepPosition) {
            container.scrollTop = container.scrollHeight - container.clientHeight - distanceFromBottom;
        }
        else if (options.forceBottom || nearBottom) {
            container.scrollTop = container.scrollHeight;
        }
        updateJumpButton();
    }
    function messageRow(opened, message, view, compact, reactions, votes, liveUpdate) {
        const own = message.sender_id === me.id;
        const sender = message.sender_display || message.sender || t("msg.unknown");
        const content = view.content || {};
        const row = h("div", {
            className: "message-row" + (own ? " message-own" : "") + (compact ? " message-compact" : ""),
            attrs: { "data-id": message.id },
        });
        const avatar = compact ? h("div", { className: "message-avatar spacer" }) : avatarEl(message.sender || sender, { className: "message-avatar", label: sender });
        if (!compact && message.sender)
            avatar.addEventListener("click", () => openProfile(message.sender));
        row.appendChild(avatar);
        const wrapper = h("div", { className: "message-content-wrapper" });
        if (!compact) {
            const header = h("div", { className: "message-header" }, [
                h("span", { className: "message-sender clickable", text: own ? t("msg.you") : sender }),
                h("span", { className: "message-timestamp", text: formatTime(message.created_at) }),
            ]);
            if (view.type === "legacy") {
                header.appendChild(h("span", {
                    className: "message-flag",
                    text: t("msg.notEncrypted"),
                    title: t("msg.notEncryptedHint"),
                }));
            }
            if (message.sender)
                header.firstElementChild.addEventListener("click", () => openProfile(message.sender));
            wrapper.appendChild(header);
        }
        const bubble = h("div", { className: "message-text" });
        if (content.forwarded)
            bubble.appendChild(h("div", { className: "message-forwarded", text: t("msg.forwarded") }));
        if (content.reply)
            bubble.appendChild(replyQuote(opened, content.reply));
        if (content.file)
            bubble.appendChild(renderFile(opened, content.file));
        if (content.poll && view.type === "text")
            bubble.appendChild(renderPoll(opened, message, content.poll, votes));
        if (content.location && view.type === "text") {
            const update = liveUpdate && liveUpdate.sender === message.sender_id ? liveUpdate : undefined;
            const card = renderLocation(opened, message, content, update);
            if (card)
                bubble.appendChild(card);
        }
        if (view.type === "deleted" || view.type === "error") {
            bubble.classList.add("message-muted");
            bubble.appendChild(document.createTextNode(view.text));
        }
        else if (view.text) {
            const myNames = [me.username.toLowerCase(), nameOf(me).toLowerCase()];
            const formatted = SeresFormat.render(view.text, { myNames, onMention: (name) => openProfile(name) });
            const body = h("div", { className: "message-body" + (formatted.emojiOnly && !content.file ? " emoji-only" : "") });
            body.appendChild(formatted.fragment);
            bubble.appendChild(body);
            if (formatted.mentioned && !own)
                row.classList.add("mentioned");
        }
        if (content.preview && view.type === "text" && linkPreviewsOn()) {
            const card = previewCard(content.preview);
            if (card)
                bubble.insertBefore(card, bubble.querySelector(".message-body"));
        }
        const meta = h("span", { className: "message-meta" });
        if (message.expires_at)
            meta.appendChild(h("span", { className: "material-symbols-rounded message-expiry", text: "timer", title: t("disappear.expires", { time: formatDateTime(message.expires_at) }) }));
        if (message.edited_at)
            meta.appendChild(h("span", { className: "message-edited", text: t("msg.edited") }));
        if (compact)
            meta.appendChild(h("span", { className: "message-time-inline", text: formatTime(message.created_at) }));
        if (own && message.kind === "e2e")
            meta.appendChild(ticks(opened, message));
        bubble.appendChild(meta);
        bubble.title = parseTime(message.created_at).toLocaleString(SeresI18n.getLanguage());
        wrapper.appendChild(bubble);
        if (reactions) {
            const chips = reactionChips(opened, message, reactions);
            if (chips)
                wrapper.appendChild(chips);
        }
        row.appendChild(wrapper);
        row.addEventListener("contextmenu", (event) => {
            if (event.target.closest("a, audio, video"))
                return;
            event.preventDefault();
            openMessageMenu(opened, message, view, event.clientX, event.clientY);
        });
        row.addEventListener("dblclick", (event) => {
            if (event.target.closest("a, audio, video, .md-spoiler, img"))
                return;
            if (view.type === "text" || view.type === "legacy")
                startReply(opened, message, view);
        });
        onLongPress(row, (x, y) => openMessageMenu(opened, message, view, x, y));
        onSwipe(row, {
            // Swipe right to answer, swipe left (own messages) for the info, like WhatsApp.
            right: view.type === "text" || view.type === "legacy" ? () => startReply(opened, message, view) : undefined,
            left: own && message.kind === "e2e" ? () => openMessageInfo(opened, message, view) : undefined,
        });
        return row;
    }
    function replyQuote(opened, reply) {
        const original = opened.messages.get(reply.id);
        const author = reply.sender_id === me.id
            ? t("msg.you")
            : original
                ? original.sender_display || original.sender || ""
                : memberName(opened, reply.sender_id);
        const quote = h("div", { className: "reply-quote" }, [
            h("strong", { text: author }),
            h("span", { text: reply.preview }),
        ]);
        quote.addEventListener("click", (event) => {
            event.stopPropagation();
            jumpToMessage(reply.id);
        });
        return quote;
    }
    function memberName(opened, userId) {
        const member = opened.details?.members?.find((m) => m.id === userId);
        return member ? nameOf(member) : "";
    }
    function reactionChips(opened, message, perSender) {
        const groups = new Map();
        perSender.forEach((value, senderId) => {
            if (!value.emoji)
                return;
            const names = groups.get(value.emoji) || [];
            names.push(senderId);
            groups.set(value.emoji, names);
        });
        if (!groups.size)
            return null;
        const box = h("div", { className: "reactions" });
        const mine = perSender.get(me.id)?.emoji || "";
        groups.forEach((senderIds, emoji) => {
            const names = senderIds.map((id) => (id === me.id ? t("msg.you") : memberName(opened, id) || "?")).join(", ");
            const chip = button(emoji + (senderIds.length > 1 ? " " + senderIds.length : ""), "reaction-chip" + (emoji === mine ? " mine" : ""), () => sendReaction(opened, message, emoji === mine ? "" : emoji), names);
            box.appendChild(chip);
        });
        return box;
    }
    async function sendReaction(opened, message, emoji) {
        if (!opened.details || opened.changedKeys.length || opened.missingKeys.length) {
            showAlert(t(opened.changedKeys.length ? "msg.keyChanged" : "msg.missingKeys"));
            return;
        }
        try {
            const members = (opened.details.members || []).map((m) => ({ id: m.id, pub_ecdh: m.pub_ecdh, pub_sign: m.pub_sign }));
            const id = newMessageId();
            const payload = await SeresCrypto.encryptMessage(identity, opened.id, id, { type: "reaction", target: message.id, emoji }, members);
            await post(`/api/chats/${encodeURIComponent(opened.id)}/messages`, { id, payload, silent: true });
            if (emoji)
                SeresEmoji.remember(emoji);
            await syncCurrent();
        }
        catch (error) {
            if (error instanceof ApiError && error.status === 409)
                await refreshCurrentDetails().catch(() => { });
            showAlert(errorText(error));
        }
    }
    // ---------------------------------------------------------- link previews
    // Fetched (through the SereS server) while the sender types; the result is
    // sent inside the encrypted message. Can be turned off in the settings.
    const URL_PATTERN = /\bhttps?:\/\/[^\s<>"')\]]+/i;
    const previewCache = new Map();
    let linkPreview = null;
    let linkTimer = null;
    function linkPreviewsOn() {
        return readStore("settings").links !== "off";
    }
    function firstUrl(text) {
        const match = URL_PATTERN.exec(text);
        if (!match)
            return null;
        // Punctuation at the end belongs to the sentence.
        return match[0].replace(/[.,;:!?]+$/, "");
    }
    /** Links to this SereS (like group invites) need no preview. */
    function isOwnLink(url) {
        try {
            return new URL(url).origin === window.location.origin;
        }
        catch {
            return false;
        }
    }
    function safeUrl(value) {
        try {
            const url = new URL(String(value));
            return url.protocol === "https:" || url.protocol === "http:" ? url.href : null;
        }
        catch {
            return null;
        }
    }
    /** Makes the picture small, so the message stays small. */
    function shrinkImage(dataUrl) {
        return new Promise((resolve) => {
            const img = new Image();
            img.onload = () => {
                // Encrypted messages are limited to 64 KB, so the picture stays small.
                const scale = Math.min(1, 240 / Math.max(img.width, img.height));
                const canvas = document.createElement("canvas");
                canvas.width = Math.max(1, Math.round(img.width * scale));
                canvas.height = Math.max(1, Math.round(img.height * scale));
                const ctx = canvas.getContext("2d");
                if (!ctx)
                    return resolve(null);
                ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
                const small = canvas.toDataURL("image/jpeg", 0.7);
                resolve(small.length <= 24000 ? small : null);
            };
            img.onerror = () => resolve(null);
            img.src = dataUrl;
        });
    }
    function fetchPreview(url) {
        let pending = previewCache.get(url);
        if (!pending) {
            pending = (async () => {
                try {
                    const data = await api(`/api/link-preview?url=${encodeURIComponent(url)}`);
                    const href = safeUrl(data.url) || url;
                    const image = typeof data.image === "string" && data.image.startsWith("data:image/") ? await shrinkImage(data.image) : null;
                    return {
                        url: href,
                        title: String(data.title || "").slice(0, 200),
                        description: data.description ? String(data.description).slice(0, 300) : null,
                        site: data.site ? String(data.site).slice(0, 80) : null,
                        image,
                    };
                }
                catch {
                    return null;
                }
            })();
            previewCache.set(url, pending);
            if (previewCache.size > 50)
                previewCache.delete(previewCache.keys().next().value);
        }
        return pending;
    }
    /** The preview for the link in a message about to be sent (waits a little if needed). */
    async function previewFor(text) {
        if (!linkPreviewsOn())
            return null;
        const url = firstUrl(text);
        if (!url || isOwnLink(url))
            return null;
        if (linkPreview && linkPreview.url === url && linkPreview.dismissed)
            return null;
        const timeout = new Promise((resolve) => window.setTimeout(() => resolve(null), 3000));
        return Promise.race([fetchPreview(url), timeout]);
    }
    function clearLinkPreview() {
        linkPreview = null;
        renderLinkPreviewBar();
    }
    function watchLinkPreview() {
        if (linkTimer !== null)
            clearTimeout(linkTimer);
        linkTimer = window.setTimeout(() => {
            const url = linkPreviewsOn() && !editing ? firstUrl($("message-input-field").value) : null;
            if (!url || isOwnLink(url))
                return clearLinkPreview();
            if (linkPreview?.url === url)
                return;
            linkPreview = { url, data: null, dismissed: false };
            renderLinkPreviewBar();
            fetchPreview(url).then((data) => {
                if (linkPreview?.url !== url)
                    return;
                linkPreview.data = data;
                renderLinkPreviewBar();
            });
        }, 500);
    }
    function renderLinkPreviewBar() {
        const bar = $("link-preview-bar");
        const content = $("link-preview-bar-content");
        content.textContent = "";
        const show = !!linkPreview && !linkPreview.dismissed && !!linkPreview.data;
        bar.classList.toggle("modal-hidden", !show);
        if (show) {
            const card = previewCard(linkPreview.data, false);
            if (card)
                content.appendChild(card);
        }
    }
    function previewCard(preview, clickable = true) {
        const url = safeUrl(preview?.url);
        if (!url || !preview.title)
            return null;
        const image = typeof preview.image === "string" && preview.image.startsWith("data:image/") ? preview.image : null;
        let host = "";
        try {
            host = new URL(url).hostname.replace(/^www\./, "");
        }
        catch {
            // checked above
        }
        const card = h(clickable ? "a" : "div", { className: "link-preview" + (image ? "" : " no-image") }, [
            image ? h("img", { className: "link-preview-image", attrs: { src: image, alt: "", loading: "lazy" } }) : null,
            h("div", { className: "link-preview-text" }, [
                h("span", { className: "link-preview-site", text: String(preview.site || host) }),
                h("strong", { className: "link-preview-title", text: String(preview.title) }),
                preview.description ? h("span", { className: "link-preview-desc", text: String(preview.description) }) : null,
            ]),
        ]);
        if (clickable) {
            card.setAttribute("href", url);
            card.setAttribute("target", "_blank");
            card.setAttribute("rel", "noopener noreferrer");
        }
        return card;
    }
    // --------------------------------------------------------------- location
    // A location goes end-to-end encrypted like a message. A live location is a
    // message with an end time; while this tab is open it sends silent updates.
    // The map is made of OpenStreetMap tiles, loaded by the browser that shows it.
    const LIVE_INTERVAL_MS = 30 * 1000;
    const LIVE_DURATIONS = [15 * 60, 60 * 60, 8 * 60 * 60];
    const liveShares = new Map();
    function validCoords(lat, lng) {
        return typeof lat === "number" && typeof lng === "number" && Number.isFinite(lat) && Number.isFinite(lng) && Math.abs(lat) <= 90 && Math.abs(lng) <= 180;
    }
    function round(value, digits = 6) {
        const f = 10 ** digits;
        return Math.round(value * f) / f;
    }
    function mapLinks(lat, lng) {
        return {
            osm: `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lng}#map=17/${lat}/${lng}`,
            google: `https://www.google.com/maps/search/?api=1&query=${lat},${lng}`,
            apple: `https://maps.apple.com/?ll=${lat},${lng}&q=${encodeURIComponent(t("location.title"))}`,
        };
    }
    /** A small map: OpenStreetMap tiles around the point, with a pin in the middle. */
    function staticMap(lat, lng, width = 260, height = 150, zoom = 16) {
        const scale = 256 * 2 ** zoom;
        const px = ((lng + 180) / 360) * scale;
        const sin = Math.sin((lat * Math.PI) / 180);
        const py = (0.5 - Math.log((1 + sin) / (1 - sin)) / (4 * Math.PI)) * scale;
        const left = px - width / 2;
        const top = py - height / 2;
        const map = h("div", { className: "location-map", attrs: { style: `width:${width}px;height:${height}px` } });
        const max = 2 ** zoom;
        for (let tx = Math.floor(left / 256); tx <= Math.floor((left + width) / 256); tx++) {
            for (let ty = Math.floor(top / 256); ty <= Math.floor((top + height) / 256); ty++) {
                if (ty < 0 || ty >= max)
                    continue;
                const x = ((tx % max) + max) % max;
                const img = h("img", {
                    className: "location-tile",
                    attrs: {
                        src: `https://tile.openstreetmap.org/${zoom}/${x}/${ty}.png`,
                        alt: "",
                        loading: "lazy",
                        draggable: "false",
                        // The tile servers ask for a referrer; the page itself sends none.
                        referrerpolicy: "strict-origin-when-cross-origin",
                        style: `left:${Math.round(tx * 256 - left)}px;top:${Math.round(ty * 256 - top)}px`,
                    },
                });
                // Offline or blocked: the plain background instead of a broken picture.
                img.addEventListener("error", () => img.remove(), { once: true });
                map.appendChild(img);
            }
        }
        map.appendChild(h("span", { className: "location-pin material-symbols-rounded", text: "location_on" }));
        map.appendChild(h("span", { className: "location-attribution", text: "© OpenStreetMap" }));
        return map;
    }
    function renderLocation(opened, message, content, update) {
        const base = content.location;
        if (!base || !validCoords(base.lat, base.lng))
            return null;
        let lat = base.lat;
        let lng = base.lng;
        let acc = base.acc;
        let updatedAt = message.created_at;
        // The last update (a "stopped" one carries the last position too).
        if (update && validCoords(update.lat, update.lng)) {
            lat = update.lat;
            lng = update.lng;
            acc = update.acc;
            updatedAt = update.at;
        }
        const live = content.live && typeof content.live.until === "string" ? content.live : null;
        const until = live ? parseTime(live.until).getTime() : 0;
        const running = !!live && !update?.stopped && until > Date.now();
        const links = mapLinks(lat, lng);
        const box = h("div", { className: "location" + (live ? " live" : "") + (running ? " running" : "") });
        const map = h("a", { className: "location-map-link", attrs: { href: links.osm, target: "_blank", rel: "noopener noreferrer" } }, [staticMap(lat, lng)]);
        box.appendChild(map);
        const title = live
            ? running
                ? t("location.liveUntil", { time: formatTime(live.until) })
                : t("location.liveEnded")
            : t("location.title");
        box.appendChild(h("div", { className: "location-info" }, [
            h("span", { className: "location-title" }, [
                h("span", { className: "material-symbols-rounded", text: live ? "share_location" : "location_on" }),
                document.createTextNode(" " + title),
            ]),
            h("span", {
                className: "location-meta",
                text: live
                    ? t("location.updated", { time: formatTime(updatedAt) }) + (acc ? ` · ±${Math.round(acc)} m` : "")
                    : acc
                        ? `±${Math.round(acc)} m`
                        : "",
            }),
        ]));
        const actions = h("div", { className: "location-actions" }, [
            h("a", { text: "Google Maps", attrs: { href: links.google, target: "_blank", rel: "noopener noreferrer" } }),
            h("a", { text: t("location.apple"), attrs: { href: links.apple, target: "_blank", rel: "noopener noreferrer" } }),
            h("a", { text: "OpenStreetMap", attrs: { href: links.osm, target: "_blank", rel: "noopener noreferrer" } }),
        ]);
        box.appendChild(actions);
        if (running && message.sender_id === me.id) {
            box.appendChild(button(t("location.stop"), "pill-btn danger location-stop", () => stopLive(opened.id, message.id)));
            // Started in another tab or before a reload: this tab can't send updates.
            if (!liveShares.has(message.id))
                box.appendChild(h("span", { className: "location-meta", text: t("location.otherTab") }));
        }
        return box;
    }
    function currentPosition() {
        return new Promise((resolve, reject) => {
            if (!navigator.geolocation)
                return reject(new Error(t("location.unsupported")));
            navigator.geolocation.getCurrentPosition(resolve, (error) => {
                reject(new Error(error.code === error.PERMISSION_DENIED ? t("location.denied") : t("location.failed")));
            }, { enableHighAccuracy: true, timeout: 15000, maximumAge: 10000 });
        });
    }
    let locationDraft = null;
    async function openLocationDialog() {
        closeFloatingMenus();
        if (!current)
            return;
        locationDraft = null;
        const preview = $("location-preview");
        preview.textContent = "";
        preview.appendChild(h("p", { className: "list-hint", text: t("location.finding") }));
        $("location-warning").textContent = "";
        $("location-send").disabled = true;
        $("location-live").disabled = true;
        const select = $("location-duration");
        select.textContent = "";
        for (const seconds of LIVE_DURATIONS) {
            const option = document.createElement("option");
            option.value = String(seconds);
            option.textContent = seconds < 3600 ? t("location.minutes", { count: seconds / 60 }) : t("location.hours", { count: seconds / 3600 });
            select.appendChild(option);
        }
        select.value = String(60 * 60);
        openModal("location-modal");
        try {
            const pos = await currentPosition();
            locationDraft = pos;
            preview.textContent = "";
            preview.appendChild(staticMap(pos.coords.latitude, pos.coords.longitude, 300, 170));
            preview.appendChild(h("p", { className: "list-hint", text: t("location.accuracy", { meters: Math.round(pos.coords.accuracy) }) }));
            $("location-send").disabled = false;
            $("location-live").disabled = false;
        }
        catch (error) {
            preview.textContent = "";
            $("location-warning").textContent = errorText(error);
        }
    }
    function coords(pos) {
        return { lat: round(pos.coords.latitude), lng: round(pos.coords.longitude), acc: Math.round(pos.coords.accuracy) };
    }
    async function sendLocation(live) {
        if (!current || !locationDraft)
            return;
        const opened = current;
        const content = { location: coords(locationDraft) };
        let seconds = 0;
        if (live) {
            seconds = Number($("location-duration").value) || 3600;
            content.live = { until: new Date(Date.now() + seconds * 1000).toISOString() };
        }
        try {
            const id = await sendContent(opened, content);
            $("location-modal").classList.add("modal-hidden");
            if (live)
                startLive(opened, id, Date.now() + seconds * 1000, locationDraft);
            await syncCurrent();
            chatsSignature = "";
            loadChats().catch(() => { });
        }
        catch (error) {
            $("location-warning").textContent = errorText(error);
        }
    }
    function startLive(opened, messageId, until, first) {
        const share = { chatId: opened.id, until, watch: -1, last: Date.now(), pos: first, details: opened.details };
        share.watch = navigator.geolocation.watchPosition((pos) => {
            share.pos = pos;
        }, () => { }, { enableHighAccuracy: true, maximumAge: 15000 });
        liveShares.set(messageId, share);
    }
    /** Every few seconds: send the newest position of each live share that is due. */
    async function tickLive() {
        for (const [messageId, share] of liveShares) {
            if (Date.now() >= share.until) {
                navigator.geolocation.clearWatch(share.watch);
                liveShares.delete(messageId);
                continue;
            }
            if (!share.pos || Date.now() - share.last < LIVE_INTERVAL_MS)
                continue;
            share.last = Date.now();
            try {
                await sendLiveContent(share, messageId, { type: "location", target: messageId, ...coords(share.pos) });
            }
            catch {
                // Next try in a moment.
            }
        }
    }
    /**
     * Sends a silent live location message: through the open chat (with its key
     * checks), or with the members from when sharing started.
     */
    async function sendLiveContent(share, messageId, content) {
        if (current && current.id === share.chatId) {
            await sendContent(current, content, { silent: true });
            share.details = current.details;
            syncCurrent().catch(() => { });
            return;
        }
        if (!share.details)
            return;
        const id = newMessageId();
        const payload = await SeresCrypto.encryptMessage(identity, share.chatId, id, content, encryptionMembers(share.details));
        try {
            await post(`/api/chats/${encodeURIComponent(share.chatId)}/messages`, { id, payload, silent: true, files: [] });
        }
        catch (error) {
            // The members changed: wait until the chat is open and checked again.
            if (error instanceof ApiError && error.status === 409)
                share.details = null;
            throw error;
        }
    }
    async function stopLive(chatId, messageId) {
        const share = liveShares.get(messageId);
        if (share) {
            navigator.geolocation.clearWatch(share.watch);
            liveShares.delete(messageId);
        }
        if (!current || current.id !== chatId)
            return;
        try {
            const last = share?.pos ? coords(share.pos) : {};
            await sendContent(current, { type: "location", target: messageId, stopped: true, ...last }, { silent: true });
            await syncCurrent();
        }
        catch (error) {
            showAlert(errorText(error));
        }
    }
    function openAttachMenu(event) {
        closeFloatingMenus();
        const menu = h("div", { className: "floating-menu attach-menu" });
        for (const [icon, label, fn] of [
            ["attach_file", t("attach.file"), () => $("attach-input").click()],
            ["location_on", t("location.title"), () => openLocationDialog()],
            ["ballot", t("poll.button"), () => openPollDialog()],
        ]) {
            const entry = button("", "floating-item", () => {
                closeFloatingMenus();
                fn();
            });
            entry.append(h("span", { className: "material-symbols-rounded", text: icon }), document.createTextNode(" " + label));
            menu.appendChild(entry);
        }
        document.body.appendChild(menu);
        const rect = event.currentTarget.getBoundingClientRect();
        placeMenu(menu, rect.left, rect.top - menu.offsetHeight - 6);
    }
    // ------------------------------------------------------------------ polls
    function validPoll(poll) {
        return !!poll && typeof poll.question === "string" && Array.isArray(poll.options) && poll.options.length >= 2;
    }
    function renderPoll(opened, message, poll, perSender) {
        const box = h("div", { className: "poll" });
        if (!validPoll(poll))
            return box;
        const options = poll.options.slice(0, 12).map(String);
        const counts = options.map(() => []);
        let voters = 0;
        perSender?.forEach((vote, senderId) => {
            const valid = vote.choices.filter((n) => n < options.length);
            if (!valid.length)
                return;
            voters++;
            for (const n of poll.multi ? valid : valid.slice(0, 1))
                counts[n].push(senderId);
        });
        const mine = new Set((perSender?.get(me.id)?.choices || []).filter((n) => n < options.length));
        box.appendChild(h("div", { className: "poll-question", text: String(poll.question) }));
        box.appendChild(h("div", { className: "poll-kind", text: t(poll.multi ? "poll.multi" : "poll.single") }));
        options.forEach((option, index) => {
            const share = voters ? counts[index].length / voters : 0;
            const names = counts[index].map((id) => (id === me.id ? t("msg.you") : memberName(opened, id) || "?")).join(", ");
            const row = button("", "poll-option" + (mine.has(index) ? " chosen" : ""), () => {
                const next = new Set(mine);
                if (poll.multi) {
                    if (next.has(index))
                        next.delete(index);
                    else
                        next.add(index);
                }
                else if (next.has(index)) {
                    next.clear();
                }
                else {
                    next.clear();
                    next.add(index);
                }
                sendVote(opened, message, [...next].sort((a, b) => a - b));
            }, names);
            row.append(h("span", { className: "poll-check material-symbols-rounded", text: mine.has(index) ? (poll.multi ? "check_box" : "radio_button_checked") : poll.multi ? "check_box_outline_blank" : "radio_button_unchecked" }), h("span", { className: "poll-label", text: option }), h("span", { className: "poll-count", text: String(counts[index].length) }), h("span", { className: "poll-bar", attrs: { style: `width:${Math.round(share * 100)}%` } }));
            box.appendChild(row);
        });
        box.appendChild(h("div", { className: "poll-total", text: t(voters === 1 ? "poll.votesOne" : "poll.votes", { count: voters }) }));
        return box;
    }
    async function sendVote(opened, message, choices) {
        try {
            await sendContent(opened, { type: "vote", target: message.id, choices }, { silent: true });
            await syncCurrent();
        }
        catch (error) {
            if (error instanceof ApiError && error.status === 409)
                await refreshCurrentDetails().catch(() => { });
            showAlert(errorText(error));
        }
    }
    function addPollOption(value = "") {
        const list = $("poll-options");
        if (list.children.length >= 12)
            return;
        const input = h("input", { className: "poll-option-input", attrs: { type: "text", maxlength: "100", placeholder: t("poll.option", { n: list.children.length + 1 }) } });
        input.value = value;
        input.addEventListener("input", () => {
            // A new empty field appears as soon as the last one is used.
            const inputs = [...list.querySelectorAll("input")];
            if (inputs[inputs.length - 1].value.trim())
                addPollOption();
        });
        list.appendChild(input);
    }
    function openPollDialog() {
        if (!current)
            return;
        $("poll-question").value = "";
        $("poll-multi").checked = false;
        $("poll-warning").textContent = "";
        $("poll-options").textContent = "";
        addPollOption();
        addPollOption();
        openModal("poll-modal");
        $("poll-question").focus();
    }
    async function createPoll() {
        if (!current)
            return;
        const opened = current;
        const question = $("poll-question").value.trim();
        const options = [...$("poll-options").querySelectorAll("input")].map((i) => i.value.trim()).filter(Boolean);
        if (!question || options.length < 2) {
            $("poll-warning").textContent = t("poll.needMore");
            return;
        }
        if (new Set(options.map((o) => o.toLowerCase())).size !== options.length) {
            $("poll-warning").textContent = t("poll.duplicate");
            return;
        }
        try {
            await sendContent(opened, { poll: { question, options, multi: $("poll-multi").checked } });
            $("poll-modal").classList.add("modal-hidden");
            await syncCurrent();
            chatsSignature = "";
            loadChats().catch(() => { });
        }
        catch (error) {
            $("poll-warning").textContent = errorText(error);
        }
    }
    // ------------------------------------------------------------ attachments
    const IMAGE_TYPES = ["image/png", "image/jpeg", "image/gif", "image/webp", "image/avif", "image/bmp"];
    const VIDEO_TYPES = ["video/mp4", "video/webm", "video/ogg", "video/quicktime"];
    /** Downloads and decrypts an attachment once; returns a blob: URL. */
    function fileUrl(chatId, file) {
        let url = fileUrls.get(file.id);
        if (!url) {
            url = (async () => {
                const response = await fetch(`/api/chats/${encodeURIComponent(chatId)}/files/${encodeURIComponent(file.id)}`, {
                    credentials: "same-origin",
                });
                if (!response.ok)
                    throw new Error(t("file.missing"));
                const plain = await SeresCrypto.decryptFile(await response.arrayBuffer(), file.key, file.iv);
                // Only media types the page shows itself keep their type; everything else is a plain download.
                const media = IMAGE_TYPES.includes(file.mime) || VIDEO_TYPES.includes(file.mime) || file.mime.startsWith("audio/");
                return URL.createObjectURL(new Blob([plain], { type: media ? file.mime : "application/octet-stream" }));
            })();
            fileUrls.set(file.id, url);
            url.catch(() => fileUrls.delete(file.id));
        }
        return url;
    }
    function renderFile(opened, file) {
        const chatId = opened.id;
        if (file.kind === "image" && IMAGE_TYPES.includes(file.mime)) {
            const wrap = h("div", { className: "message-image loading" });
            if (file.width && file.height)
                wrap.style.aspectRatio = `${file.width} / ${file.height}`;
            const img = h("img", { attrs: { alt: file.name } });
            wrap.appendChild(img);
            fileUrl(chatId, file)
                .then((url) => {
                img.src = url;
                wrap.classList.remove("loading");
            })
                .catch(() => {
                wrap.classList.remove("loading");
                wrap.classList.add("failed");
                wrap.textContent = t("file.missing");
            });
            wrap.addEventListener("click", (event) => {
                event.stopPropagation();
                if (img.src)
                    openLightbox(img.src, file);
            });
            return wrap;
        }
        if ((file.kind === "voice" || file.kind === "audio" || file.kind === "video") && (file.mime.startsWith("audio/") || VIDEO_TYPES.includes(file.mime))) {
            const isVideo = file.kind === "video";
            const media = h(isVideo ? "video" : "audio", { className: isVideo ? "message-video" : "message-audio", attrs: { controls: "", preload: "metadata" } });
            const wrap = h("div", { className: "message-media" + (file.kind === "voice" ? " voice" : "") }, [
                file.kind === "voice" ? h("span", { className: "material-symbols-rounded voice-icon", text: "mic" }) : null,
                media,
            ]);
            fileUrl(chatId, file)
                .then((url) => (media.src = url))
                .catch(() => wrap.appendChild(h("span", { className: "list-hint", text: t("file.missing") })));
            return wrap;
        }
        const card = h("div", { className: "file-card" }, [
            h("span", { className: "material-symbols-rounded file-icon", text: "description" }),
            h("div", { className: "file-info" }, [
                h("strong", { text: file.name }),
                h("span", { text: formatSize(file.size) }),
            ]),
            button(t("file.download"), "pill-btn", async () => {
                try {
                    downloadUrl(await fileUrl(chatId, file), file.name);
                }
                catch (error) {
                    showAlert(errorText(error));
                }
            }),
        ]);
        return card;
    }
    function downloadUrl(url, name) {
        const link = h("a", { attrs: { href: url, download: name || "file" } });
        document.body.appendChild(link);
        link.click();
        link.remove();
    }
    function openLightbox(url, file) {
        const box = $("lightbox");
        $("lightbox-img").src = url;
        $("lightbox-name").textContent = file.name;
        $("lightbox-download").onclick = (event) => {
            event.stopPropagation();
            downloadUrl(url, file.name);
        };
        box.classList.remove("modal-hidden");
    }
    /** Phones: swiping a message left or right (like in WhatsApp) calls the handler. */
    function onSwipe(element, handlers) {
        if (!handlers.left && !handlers.right)
            return;
        const MAX = 90;
        const TRIGGER = 60;
        let startX = 0;
        let startY = 0;
        let dx = 0;
        let mode = "idle";
        element.addEventListener("touchstart", (event) => {
            startX = event.touches[0].clientX;
            startY = event.touches[0].clientY;
            dx = 0;
            mode = "idle";
            element.style.transition = "none";
        }, { passive: true });
        element.addEventListener("touchmove", (event) => {
            const moveX = event.touches[0].clientX - startX;
            const moveY = event.touches[0].clientY - startY;
            if (mode === "idle" && Math.abs(moveX) + Math.abs(moveY) > 8) {
                const horizontal = Math.abs(moveX) > Math.abs(moveY);
                const allowed = moveX < 0 ? !!handlers.left : !!handlers.right;
                mode = horizontal && allowed ? "swipe" : "scroll";
            }
            if (mode !== "swipe")
                return;
            dx = Math.max(handlers.left ? -MAX : 0, Math.min(handlers.right ? MAX : 0, moveX));
            element.style.transform = `translateX(${dx}px)`;
            element.classList.toggle("swipe-ready", Math.abs(dx) >= TRIGGER);
        }, { passive: true });
        const end = () => {
            if (mode === "swipe" && dx <= -TRIGGER && handlers.left)
                handlers.left();
            if (mode === "swipe" && dx >= TRIGGER && handlers.right)
                handlers.right();
            element.style.transition = "transform 0.2s ease-out";
            element.style.transform = "";
            element.classList.remove("swipe-ready");
            mode = "idle";
        };
        element.addEventListener("touchend", end);
        element.addEventListener("touchcancel", end);
    }
    /** Symbol indicators show sent, delivered, and read status. */
    function ticks(opened, message) {
        const receipts = opened.receipts;
        const read = !!receipts && receipts.read_seq >= message.seq;
        const delivered = read || (!!receipts && receipts.delivered_seq >= message.seq);
        return h("span", {
            className: "message-ticks material-symbols-rounded" + (read ? " read" : delivered ? " delivered" : ""),
            text: delivered ? "done_all" : "check",
            title: t(read ? "msgInfo.read" : delivered ? "msgInfo.delivered" : "msgInfo.sent"),
        });
    }
    /** Right-click / long-press menu of a message: react, reply, copy, forward, pin, edit, info, delete. */
    function openMessageMenu(opened, message, view, x, y) {
        closeFloatingMenus();
        if (view.type === "system" || view.type === "deleted")
            return;
        const own = message.sender_id === me.id && message.kind === "e2e";
        const readable = view.type === "text" || view.type === "legacy";
        const pinned = !!opened.details?.pins?.some((pin) => pin.message_id === message.id);
        const url = `/api/chats/${encodeURIComponent(opened.id)}/messages/${encodeURIComponent(message.id)}`;
        const item = (label, fn, danger = false) => button(label, "floating-item" + (danger ? " danger" : ""), () => {
            closeFloatingMenus();
            fn();
        });
        const quick = h("div", { className: "quick-reactions" });
        if (readable) {
            for (const emoji of SeresEmoji.QUICK) {
                quick.appendChild(button(emoji, "quick-reaction", () => {
                    closeFloatingMenus();
                    sendReaction(opened, message, emoji);
                }));
            }
            quick.appendChild(button("＋", "quick-reaction more", () => {
                const picker = SeresEmoji.picker((emoji) => {
                    closeFloatingMenus();
                    sendReaction(opened, message, emoji);
                }, t("emoji.recent"));
                menu.textContent = "";
                menu.appendChild(picker);
                placeMenu(menu, x, y);
            }, t("emoji.more")));
        }
        const text = view.text;
        const menu = h("div", { className: "floating-menu message-menu" }, [
            readable ? quick : null,
            readable ? item(t("msg.menuReply"), () => startReply(opened, message, view)) : null,
            readable && text
                ? item(t("msg.menuCopy"), () => {
                    navigator.clipboard
                        .writeText(text)
                        .then(() => showAlert(t("msg.copied")))
                        .catch(() => showAlert(t("msg.copyFailed")));
                })
                : null,
            readable && message.kind === "e2e" ? item(t("msg.menuForward"), () => openForwardModal(opened, message, view)) : null,
            readable ? item(pinned ? t("msg.menuUnpin") : t("msg.menuPin"), () => togglePin(opened, message, !pinned)) : null,
            own && view.type === "text" && !view.content?.file?.kind?.startsWith("voice") && !view.content?.poll
                ? item(t("msg.menuEdit"), () => startEdit(opened, message, view))
                : null,
            own ? item(t("msg.menuInfo"), () => openMessageInfo(opened, message, view)) : null,
            own
                ? item(t("msg.menuDelete"), async () => {
                    if (!window.confirm(t("msg.deleteConfirm")))
                        return;
                    try {
                        await post(url + "/delete");
                        if (editing && editing.message.id === message.id)
                            cancelEdit();
                        await syncCurrent();
                        chatsSignature = "";
                        loadChats().catch(() => { });
                    }
                    catch (error) {
                        showAlert(errorText(error));
                    }
                }, true)
                : null,
        ]);
        document.body.appendChild(menu);
        placeMenu(menu, x, y);
    }
    /** Keeps a floating menu inside the viewport. */
    function placeMenu(menu, x, y) {
        menu.style.left = Math.max(8, Math.min(x, window.innerWidth - menu.offsetWidth - 8)) + "px";
        menu.style.top = Math.max(8, Math.min(y, window.innerHeight - menu.offsetHeight - 8)) + "px";
    }
    function formatDateTime(iso) {
        return parseTime(iso).toLocaleString(SeresI18n.getLanguage(), { dateStyle: "short", timeStyle: "short" });
    }
    /** When the message was sent, delivered to and seen by each member. */
    async function openMessageInfo(opened, message, view) {
        let data;
        try {
            data = await api(`/api/chats/${encodeURIComponent(opened.id)}/messages/${encodeURIComponent(message.id)}/info`);
        }
        catch (error) {
            showAlert(errorText(error));
            return;
        }
        $("message-info-preview").textContent = view.text;
        const body = $("message-info-body");
        body.textContent = "";
        const line = (icon, label, done, at) => h("div", { className: "info-line" + (done ? " done" : "") }, [
            h("span", { className: "info-icon material-symbols-rounded", text: icon }),
            h("span", { className: "info-label", text: label }),
            h("span", { className: "info-time" }, [done ? (at ? document.createTextNode(formatDateTime(at)) : h("span", { className: "material-symbols-rounded", text: "check" })) : document.createTextNode(t("msgInfo.notYet"))]),
        ]);
        body.appendChild(line("schedule", t("msgInfo.sent"), true, data.sent_at));
        if (!data.members.length)
            body.appendChild(h("p", { className: "list-hint", text: t("msgInfo.noRecipients") }));
        for (const member of data.members) {
            body.appendChild(h("div", { className: "info-member" }, [
                h("div", { className: "info-member-head" }, [
                    avatarEl(member.username, { label: nameOf(member) }),
                    h("strong", { text: nameOf(member) }),
                ]),
                line("check", t("msgInfo.delivered"), member.delivered, member.delivered_at),
                line("done_all", t("msgInfo.read"), member.read, member.read_at),
            ]));
        }
        openModal("message-info-modal");
    }
    function startEdit(opened, message, view) {
        cancelReply();
        editing = { chatId: opened.id, message, content: view.content || {} };
        const input = $("message-input-field");
        input.value = view.text;
        autoGrow(input);
        updateSendButton();
        $("edit-bar").classList.remove("modal-hidden");
        input.focus();
    }
    function cancelEdit() {
        if (!editing)
            return;
        editing = null;
        const input = $("message-input-field");
        input.value = "";
        autoGrow(input);
        updateSendButton();
        $("edit-bar").classList.add("modal-hidden");
    }
    function startReply(opened, message, view) {
        cancelEdit();
        const preview = contentPreview(view).slice(0, 120) || "…";
        replyTo = { chatId: opened.id, message, preview };
        const author = message.sender_id === me.id ? t("msg.you") : message.sender_display || message.sender || "";
        $("reply-bar-name").textContent = t("reply.to", { name: author });
        $("reply-bar-text").textContent = preview;
        $("reply-bar").classList.remove("modal-hidden");
        $("message-input-field").focus();
    }
    function cancelReply() {
        replyTo = null;
        $("reply-bar").classList.add("modal-hidden");
    }
    // ---------------------------------------------------------------- send
    function newMessageId() {
        if (typeof crypto.randomUUID === "function")
            return crypto.randomUUID();
        const bytes = crypto.getRandomValues(new Uint8Array(16));
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
        return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    }
    function encryptionMembers(details) {
        return (details.members || []).map((m) => ({ id: m.id, pub_ecdh: m.pub_ecdh, pub_sign: m.pub_sign }));
    }
    /** Throws when the open chat can't receive encrypted messages right now. */
    async function readyToSend(opened, refresh) {
        if (!opened.details || refresh)
            await refreshCurrentDetails();
        if (current !== opened || !opened.details)
            throw new Error(t("common.requestFailed"));
        if (opened.changedKeys.length)
            throw new Error(t("msg.keyChanged"));
        if (opened.missingKeys.length)
            throw new Error(t("msg.missingKeys"));
        return opened.details;
    }
    /**
     * Encrypts content for the members of the open chat and sends it (or replaces
     * an own message). If the member list changed meanwhile (409) it encrypts again.
     */
    async function sendContent(opened, content, extra = {}) {
        for (let attempt = 0;; attempt++) {
            const details = await readyToSend(opened, attempt > 0);
            const messageId = extra.editId || newMessageId();
            const payload = await SeresCrypto.encryptMessage(identity, opened.id, messageId, content, encryptionMembers(details));
            try {
                if (extra.editId) {
                    await post(`/api/chats/${encodeURIComponent(opened.id)}/messages/${encodeURIComponent(messageId)}/edit`, { payload });
                }
                else {
                    await post(`/api/chats/${encodeURIComponent(opened.id)}/messages`, {
                        id: messageId,
                        payload,
                        silent: !!extra.silent,
                        files: extra.files || [],
                    });
                }
                return messageId;
            }
            catch (error) {
                if (error instanceof ApiError && error.status === 409 && attempt === 0)
                    continue;
                throw error;
            }
        }
    }
    async function sendMessage() {
        const input = $("message-input-field");
        const text = input.value.trim();
        if (!current || sending)
            return;
        if (!text && !pendingFiles.length)
            return;
        if (text.length > MESSAGE_LIMIT) {
            showAlert(t("msg.tooLong", { limit: MESSAGE_LIMIT }));
            return;
        }
        const opened = current;
        sending = true;
        $("send-btn").disabled = true;
        closeEmojiPicker();
        closeMentionList();
        try {
            const edit = editing && editing.chatId === opened.id ? editing : null;
            if (edit) {
                if (!text && !edit.content.file)
                    return;
                await sendContent(opened, { ...edit.content, text }, { editId: edit.message.id });
                cancelEdit();
            }
            else {
                const reply = replyTo && replyTo.chatId === opened.id
                    ? { id: replyTo.message.id, sender_id: replyTo.message.sender_id, preview: replyTo.preview }
                    : undefined;
                const files = pendingFiles.slice();
                if (files.length) {
                    // One message per file; the text goes with the last one.
                    for (let i = 0; i < files.length; i++) {
                        const ref = await uploadFile(opened.id, files[i], files[i].name);
                        const content = { file: ref };
                        if (i === 0 && reply)
                            content.reply = reply;
                        if (i === files.length - 1 && text)
                            content.text = text;
                        await sendContent(opened, content, { files: [ref.id] });
                    }
                    clearPendingFiles();
                }
                else {
                    const content = reply ? { text, reply } : { text };
                    const preview = await previewFor(text);
                    if (preview)
                        content.preview = preview;
                    await sendContent(opened, content);
                }
                cancelReply();
                clearLinkPreview();
            }
            input.value = "";
            drafts.delete(opened.id);
            autoGrow(input);
            updateSendButton();
            typingChat = null; // the server forgets it when a message arrives
            await syncCurrent();
            chatsSignature = "";
            loadChats().catch(() => { });
        }
        catch (error) {
            showAlert(errorText(error));
        }
        finally {
            sending = false;
            $("send-btn").disabled = false;
        }
    }
    function fileKind(mime) {
        if (IMAGE_TYPES.includes(mime))
            return "image";
        if (VIDEO_TYPES.includes(mime))
            return "video";
        if (mime.startsWith("audio/"))
            return "audio";
        return "file";
    }
    /** Encrypts a file in the browser and uploads only the ciphertext. */
    async function uploadFile(chatId, blob, name, extra = {}) {
        if (blob.size > MAX_FILE_SIZE)
            throw new Error(t("file.tooLarge", { name }));
        const mime = (blob.type || "application/octet-stream").split(";")[0];
        const kind = extra.kind || fileKind(mime);
        let width;
        let height;
        if (kind === "image") {
            try {
                const bitmap = await createImageBitmap(blob);
                width = bitmap.width;
                height = bitmap.height;
                bitmap.close();
            }
            catch {
                /* size unknown, the image is shown without a placeholder */
            }
        }
        const encrypted = await SeresCrypto.encryptFile(await blob.arrayBuffer());
        const response = await fetch(`/api/chats/${encodeURIComponent(chatId)}/files`, {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/octet-stream" },
            body: encrypted.data,
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok || !data.success)
            throw new ApiError(data.message || t("file.uploadFailed"), response.status);
        const ref = {
            id: data.file_id,
            key: encrypted.key,
            iv: encrypted.iv,
            name: name.slice(0, 200) || "file",
            mime,
            size: blob.size,
            kind,
            ...extra,
        };
        if (width && height) {
            ref.width = width;
            ref.height = height;
        }
        // Show own uploads right away without downloading them again.
        const media = kind !== "file";
        fileUrls.set(ref.id, Promise.resolve(URL.createObjectURL(media ? blob : new Blob([blob], { type: "application/octet-stream" }))));
        return ref;
    }
    // ------------------------------------------------- picking attachments
    function addPendingFiles(files) {
        if (!current)
            return;
        for (const file of Array.from(files)) {
            if (file.size > MAX_FILE_SIZE) {
                showAlert(t("file.tooLarge", { name: file.name }));
                continue;
            }
            if (pendingFiles.length >= 10)
                break;
            pendingFiles.push(file);
        }
        renderPendingFiles();
    }
    function clearPendingFiles() {
        pendingFiles = [];
        renderPendingFiles();
    }
    function renderPendingFiles() {
        const bar = $("attach-bar");
        bar.textContent = "";
        pendingFiles.forEach((file, index) => {
            const chip = h("div", { className: "attach-chip" });
            if (IMAGE_TYPES.includes(file.type)) {
                const img = h("img", { attrs: { alt: "" } });
                img.src = URL.createObjectURL(file);
                img.addEventListener("load", () => URL.revokeObjectURL(img.src), { once: true });
                chip.appendChild(img);
            }
            else {
                chip.appendChild(h("span", { className: "file-icon", text: "📄" }));
            }
            chip.appendChild(h("span", { className: "attach-name", text: file.name }));
            chip.appendChild(h("span", { className: "attach-size", text: formatSize(file.size) }));
            chip.appendChild(button("✕", "attach-remove", () => {
                pendingFiles.splice(index, 1);
                renderPendingFiles();
            }, t("common.cancel")));
            bar.appendChild(chip);
        });
        bar.classList.toggle("modal-hidden", !pendingFiles.length);
        updateSendButton();
    }
    /** Shows the microphone when there is nothing to send (like WhatsApp). */
    function updateSendButton() {
        const text = $("message-input-field").value.trim();
        const empty = !text && !pendingFiles.length && !editing;
        $("send-btn").classList.toggle("modal-hidden", empty && voiceSupported());
        $("record-btn").classList.toggle("modal-hidden", !(empty && voiceSupported()));
        // Only text can be scheduled (attachments are uploaded when they are sent).
        $("schedule-btn").classList.toggle("modal-hidden", !text || !!editing || pendingFiles.length > 0);
    }
    let scheduled = null;
    async function loadScheduled(opened) {
        try {
            const data = await api(`/api/chats/${encodeURIComponent(opened.id)}/scheduled`);
            if (current !== opened)
                return;
            scheduled = { chatId: opened.id, items: data.messages || [] };
        }
        catch {
            scheduled = null;
        }
        renderScheduledBar();
    }
    function renderScheduledBar() {
        const count = scheduled && current && scheduled.chatId === current.id ? scheduled.items.length : 0;
        $("scheduled-bar").classList.toggle("modal-hidden", !count);
        $("scheduled-bar-text").textContent = t(count === 1 ? "schedule.barOne" : "schedule.bar", { count });
    }
    function localInputValue(date) {
        const pad = (n) => String(n).padStart(2, "0");
        return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
    }
    function openScheduleDialog() {
        const text = $("message-input-field").value.trim();
        if (!current || !text || editing || pendingFiles.length)
            return;
        $("schedule-preview").textContent = text.length > 160 ? text.slice(0, 160) + "…" : text;
        $("schedule-warning").textContent = "";
        const input = $("schedule-time");
        const soon = new Date(Date.now() + 60 * 60 * 1000);
        input.min = localInputValue(new Date(Date.now() + 2 * 60 * 1000));
        input.value = localInputValue(soon);
        const tomorrow = new Date();
        tomorrow.setDate(tomorrow.getDate() + 1);
        tomorrow.setHours(8, 0, 0, 0);
        const quick = $("schedule-quick");
        quick.textContent = "";
        for (const [label, date] of [
            [t("schedule.inHour"), soon],
            [t("schedule.tomorrow"), tomorrow],
        ]) {
            quick.appendChild(button(label, "pill-btn secondary", () => (input.value = localInputValue(date))));
        }
        openModal("schedule-modal");
    }
    async function scheduleMessage() {
        const input = $("message-input-field");
        const text = input.value.trim();
        const when = new Date($("schedule-time").value);
        if (!current || !text)
            return;
        if (Number.isNaN(when.getTime()) || when.getTime() < Date.now() + 60 * 1000) {
            $("schedule-warning").textContent = t("schedule.tooSoon");
            return;
        }
        const opened = current;
        const reply = replyTo && replyTo.chatId === opened.id
            ? { id: replyTo.message.id, sender_id: replyTo.message.sender_id, preview: replyTo.preview }
            : undefined;
        const linkPreview = await previewFor(text);
        try {
            for (let attempt = 0;; attempt++) {
                const details = await readyToSend(opened, attempt > 0);
                const id = newMessageId();
                const content = reply ? { text, reply } : { text };
                if (linkPreview)
                    content.preview = linkPreview;
                const payload = await SeresCrypto.encryptMessage(identity, opened.id, id, content, encryptionMembers(details));
                try {
                    await post(`/api/chats/${encodeURIComponent(opened.id)}/scheduled`, { id, payload, send_at: when.toISOString() });
                    break;
                }
                catch (error) {
                    // The members changed: encrypt again for the current ones.
                    if (error instanceof ApiError && error.status === 409 && attempt === 0)
                        continue;
                    throw error;
                }
            }
            $("schedule-modal").classList.add("modal-hidden");
            input.value = "";
            drafts.delete(opened.id);
            autoGrow(input);
            cancelReply();
            clearLinkPreview();
            updateSendButton();
            showAlert(t("schedule.done", { time: formatDateTime(when.toISOString()) }));
            await loadScheduled(opened);
        }
        catch (error) {
            $("schedule-warning").textContent = errorText(error);
        }
    }
    async function openScheduledList() {
        if (!current || !scheduled)
            return;
        const opened = current;
        const list = $("scheduled-list");
        list.textContent = "";
        for (const item of scheduled.items) {
            let text = t("msg.decryptError");
            try {
                const content = await SeresCrypto.decryptMessage(identity, opened.id, item.id, { id: me.id, pub_ecdh: me.pub_ecdh, pub_sign: me.pub_sign }, item.payload);
                text = String(content?.text ?? "");
            }
            catch {
                // Encrypted with keys from before a password reset.
            }
            const row = h("div", { className: "scheduled-item" }, [
                h("div", { className: "scheduled-info" }, [
                    h("span", { className: "scheduled-time", text: formatDateTime(item.send_at) }),
                    h("span", { className: "scheduled-text", text }),
                ]),
                button(t("schedule.cancel"), "request-action-btn discard", async () => {
                    try {
                        await api(`/api/chats/${encodeURIComponent(opened.id)}/scheduled/${encodeURIComponent(item.id)}`, { method: "DELETE" });
                        row.remove();
                        await loadScheduled(opened);
                        if (!scheduled?.items.length)
                            $("scheduled-modal").classList.add("modal-hidden");
                    }
                    catch (error) {
                        showAlert(errorText(error));
                    }
                }),
            ]);
            list.appendChild(row);
        }
        openModal("scheduled-modal");
    }
    // ------------------------------------------------------- voice messages
    let recording = null;
    const MAX_RECORDING_SECONDS = 300;
    function voiceSupported() {
        return typeof MediaRecorder !== "undefined" && !!navigator.mediaDevices?.getUserMedia;
    }
    async function startRecording() {
        if (!current || recording)
            return;
        const opened = current;
        let stream;
        try {
            stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        }
        catch {
            showAlert(t("voice.noMicrophone"));
            return;
        }
        const type = ["audio/webm;codecs=opus", "audio/webm", "audio/mp4", "audio/ogg;codecs=opus"].find((candidate) => MediaRecorder.isTypeSupported(candidate));
        const recorder = new MediaRecorder(stream, type ? { mimeType: type } : undefined);
        const state = {
            recorder,
            stream,
            chunks: [],
            started: Date.now(),
            timer: 0,
            send: false,
        };
        recording = state;
        recorder.addEventListener("dataavailable", (event) => {
            if (event.data.size)
                state.chunks.push(event.data);
        });
        recorder.addEventListener("stop", async () => {
            stream.getTracks().forEach((track) => track.stop());
            clearInterval(state.timer);
            recording = null;
            $("record-bar").classList.add("modal-hidden");
            $("chat-input-area").classList.remove("recording");
            if (!state.send || current !== opened)
                return;
            const duration = (Date.now() - state.started) / 1000;
            if (duration < 0.7)
                return;
            const mime = (recorder.mimeType || type || "audio/webm").split(";")[0];
            const blob = new Blob(state.chunks, { type: mime });
            try {
                const ref = await uploadFile(opened.id, blob, t("voice.fileName") + "." + (mime.split("/")[1] || "webm"), {
                    kind: "voice",
                    duration,
                });
                await sendContent(opened, { file: ref }, { files: [ref.id] });
                await syncCurrent();
                loadChats().catch(() => { });
            }
            catch (error) {
                showAlert(errorText(error));
            }
        });
        recorder.start(250);
        $("record-time").textContent = "0:00";
        $("record-bar").classList.remove("modal-hidden");
        $("chat-input-area").classList.add("recording");
        state.timer = window.setInterval(() => {
            const seconds = (Date.now() - state.started) / 1000;
            $("record-time").textContent = formatDuration(seconds);
            if (seconds >= MAX_RECORDING_SECONDS)
                stopRecording(true);
        }, 250);
    }
    function stopRecording(send) {
        if (!recording)
            return;
        recording.send = send;
        if (recording.recorder.state !== "inactive")
            recording.recorder.stop();
    }
    // ------------------------------------------------------------ forwarding
    let forwarding = null;
    function openForwardModal(opened, message, view) {
        forwarding = { from: opened, message, view };
        const list = $("forward-list");
        list.textContent = "";
        $("warning-forward").textContent = "";
        for (const chat of chats) {
            if (chat.blocked)
                continue;
            const checkbox = h("input", { attrs: { type: "checkbox", value: chat.id } });
            list.appendChild(h("label", { className: "picker-item" }, [
                checkbox,
                avatarEl(chat.type === "dm" && chat.other_user ? chat.other_user : chat.name, { group: chat.type === "group", label: chat.name }),
                h("span", { className: "item-name", text: chat.name }),
            ]));
        }
        $("forward-preview").textContent = contentPreview(view);
        openModal("forward-modal");
    }
    async function confirmForward() {
        if (!forwarding)
            return;
        const { from, view } = forwarding;
        const targets = [...$("forward-list").querySelectorAll("input:checked")].map((box) => box.value);
        const warning = $("warning-forward");
        if (!targets.length) {
            warning.textContent = t("forward.pick");
            return;
        }
        warning.textContent = t("forward.sending");
        let sent = 0;
        for (const chatId of targets) {
            try {
                const data = await api(`/api/chats/${encodeURIComponent(chatId)}`);
                const details = data.chat;
                const { changed, missing } = await checkPins(details.members || []);
                if (changed.length || missing.length)
                    throw new Error(t(changed.length ? "msg.keyChanged" : "msg.missingKeys"));
                const content = { forwarded: true };
                if (view.text)
                    content.text = view.text;
                const files = [];
                const file = view.content?.file;
                if (file) {
                    // Re-upload the same ciphertext into the other chat; key and iv stay the same.
                    const response = await fetch(`/api/chats/${encodeURIComponent(from.id)}/files/${encodeURIComponent(file.id)}`, {
                        credentials: "same-origin",
                    });
                    if (!response.ok)
                        throw new Error(t("file.missing"));
                    const upload = await fetch(`/api/chats/${encodeURIComponent(chatId)}/files`, {
                        method: "POST",
                        credentials: "same-origin",
                        headers: { "Content-Type": "application/octet-stream" },
                        body: await response.arrayBuffer(),
                    });
                    const uploaded = await upload.json().catch(() => ({}));
                    if (!upload.ok || !uploaded.success)
                        throw new Error(uploaded.message || t("file.uploadFailed"));
                    content.file = { ...file, id: uploaded.file_id };
                    files.push(uploaded.file_id);
                }
                const id = newMessageId();
                const payload = await SeresCrypto.encryptMessage(identity, chatId, id, content, encryptionMembers(details));
                await post(`/api/chats/${encodeURIComponent(chatId)}/messages`, { id, payload, files });
                sent++;
            }
            catch (error) {
                const chat = chats.find((c) => c.id === chatId);
                showAlert((chat ? chat.name + ": " : "") + errorText(error));
            }
        }
        forwarding = null;
        closeAllModals();
        if (sent)
            showAlert(t("forward.done", { count: sent }));
        if (current && targets.includes(current.id))
            await syncCurrent();
        chatsSignature = "";
        loadChats().catch(() => { });
    }
    // ----------------------------------------------------------- emoji picker
    function toggleEmojiPicker() {
        const slot = $("emoji-slot");
        if (slot.childElementCount) {
            closeEmojiPicker();
            return;
        }
        const input = $("message-input-field");
        slot.appendChild(SeresEmoji.picker((emoji) => {
            const start = input.selectionStart ?? input.value.length;
            const end = input.selectionEnd ?? input.value.length;
            input.value = input.value.slice(0, start) + emoji + input.value.slice(end);
            input.selectionStart = input.selectionEnd = start + emoji.length;
            autoGrow(input);
            updateSendButton();
            input.focus();
        }, t("emoji.recent")));
        slot.classList.remove("modal-hidden");
    }
    function closeEmojiPicker() {
        const slot = $("emoji-slot");
        slot.textContent = "";
        slot.classList.add("modal-hidden");
    }
    // --------------------------------------------------------------- mentions
    /** In groups, typing "@na" suggests members; Tab/Enter or a click inserts the username. */
    function updateMentionList() {
        const input = $("message-input-field");
        const list = $("mention-list");
        const details = current?.details;
        const before = input.value.slice(0, input.selectionStart ?? input.value.length);
        const match = /(?:^|\s)@([A-Za-z0-9_-]{0,32})$/.exec(before);
        if (!details || details.type !== "group" || !match) {
            closeMentionList();
            return;
        }
        const query = match[1].toLowerCase();
        const members = (details.members || []).filter((m) => m.id !== me.id && (m.username.toLowerCase().startsWith(query) || nameOf(m).toLowerCase().startsWith(query)));
        list.textContent = "";
        if (!members.length) {
            closeMentionList();
            return;
        }
        members.slice(0, 6).forEach((member, index) => {
            const item = h("div", { className: "mention-item" + (index === 0 ? " active" : ""), attrs: { "data-username": member.username } }, [
                avatarEl(member.username, { label: nameOf(member) }),
                h("strong", { text: nameOf(member) }),
                h("span", { text: "@" + member.username }),
            ]);
            item.addEventListener("mousedown", (event) => {
                event.preventDefault();
                insertMention(member.username);
            });
            list.appendChild(item);
        });
        list.classList.remove("modal-hidden");
    }
    function insertMention(username) {
        const input = $("message-input-field");
        const caret = input.selectionStart ?? input.value.length;
        const before = input.value.slice(0, caret).replace(/@([A-Za-z0-9_-]{0,32})$/, "@" + username + " ");
        input.value = before + input.value.slice(caret);
        input.selectionStart = input.selectionEnd = before.length;
        closeMentionList();
        input.focus();
    }
    function closeMentionList() {
        $("mention-list").classList.add("modal-hidden");
        $("mention-list").textContent = "";
    }
    // ---------------------------------------------------------------- search
    function openSearch() {
        if (!current)
            return;
        $("search-bar").classList.remove("modal-hidden");
        const input = $("search-input");
        input.value = "";
        $("search-count").textContent = "";
        input.focus();
    }
    function closeSearch() {
        $("search-bar").classList.add("modal-hidden");
        if (current)
            current.search = null;
        markSearchHits();
    }
    let searchTimer = null;
    function onSearchInput() {
        if (searchTimer !== null)
            clearTimeout(searchTimer);
        searchTimer = window.setTimeout(() => runSearch().catch((error) => showAlert(errorText(error))), 250);
    }
    /** Searches the decrypted messages on this device; older history is loaded for it (up to ~1000 messages). */
    async function runSearch() {
        const opened = current;
        if (!opened)
            return;
        const query = $("search-input").value.trim().toLowerCase();
        if (!query) {
            opened.search = null;
            $("search-count").textContent = "";
            markSearchHits();
            return;
        }
        $("search-count").textContent = t("search.searching");
        for (let page = 0; page < 20 && opened.hasMore; page++) {
            await loadOlder();
            if (current !== opened)
                return;
        }
        const ordered = [...opened.messages.values()].filter((m) => !m.deleted && !m.silent && m.kind !== "system").sort((a, b) => a.seq - b.seq);
        const hits = [];
        for (const message of ordered) {
            const view = await showMessage(opened.id, message);
            const haystack = (view.text + " " + (view.content?.file?.name || "")).toLowerCase();
            if (haystack.includes(query))
                hits.push(message.id);
        }
        if (current !== opened)
            return;
        opened.search = { query, hits, index: hits.length - 1 };
        showSearchHit();
    }
    function moveSearch(step) {
        const search = current?.search;
        if (!search || !search.hits.length)
            return;
        search.index = (search.index + step + search.hits.length) % search.hits.length;
        showSearchHit();
    }
    function showSearchHit() {
        const search = current?.search;
        if (!search)
            return;
        $("search-count").textContent = search.hits.length
            ? t("search.count", { index: search.index + 1, total: search.hits.length })
            : t("search.none");
        markSearchHits();
        const id = search.hits[search.index];
        if (id) {
            document.querySelector(`.message-row[data-id="${CSS.escape(id)}"]`)?.scrollIntoView({ behavior: "smooth", block: "center" });
        }
    }
    function markSearchHits() {
        const search = current?.search;
        const hits = new Set(search ? search.hits : []);
        const selected = search ? search.hits[search.index] : null;
        document.querySelectorAll(".message-row").forEach((row) => {
            row.classList.toggle("search-hit", hits.has(row.dataset.id));
            row.classList.toggle("search-current", row.dataset.id === selected);
        });
    }
    // ---------------------------------------------------------- jump button
    function updateJumpButton() {
        const container = $("messages");
        const away = container.scrollHeight - container.scrollTop - container.clientHeight > 300;
        $("jump-bottom").classList.toggle("modal-hidden", !current || !away);
    }
    function autoGrow(textarea) {
        textarea.style.height = "auto";
        // While the input area is hidden there is nothing to measure.
        if (!textarea.scrollHeight)
            return;
        textarea.style.height = Math.min(textarea.scrollHeight, 160) + "px";
    }
    // --------------------------------------------------------- new chats
    async function startDm(username) {
        try {
            const data = await post("/api/chats", { type: "dm", username });
            closeAllModals();
            switchView("chats");
            chatsSignature = "";
            await loadChats();
            await openChat(data.chat_id);
        }
        catch (error) {
            showAlert(errorText(error));
        }
    }
    function friendCheckboxes(container, exclude) {
        container.textContent = "";
        const available = friends.friends.filter((friend) => !exclude.has(friend.id));
        if (!available.length) {
            container.appendChild(h("p", { text: t("chat.noFriendsToAdd") }));
        }
        available.forEach((friend) => {
            const checkbox = h("input", { attrs: { type: "checkbox", value: friend.username } });
            container.appendChild(h("label", { className: "picker-item" }, [
                checkbox,
                avatarEl(friend.username, { label: nameOf(friend) }),
                h("span", { className: "item-name", text: nameOf(friend) }),
            ]));
        });
    }
    function checkedUsernames(container) {
        return [...container.querySelectorAll("input[type=checkbox]:checked")].map((box) => box.value);
    }
    // Closes an earlier pick that was dismissed without a button (e.g. Escape).
    let endCallPick = null;
    /** Friends to add to a call (picked in a dialog), or null when cancelled. */
    function pickCallPeople(excludeIds) {
        endCallPick?.();
        const list = $("call-add-list");
        $("warning-call-add").textContent = "";
        friendCheckboxes(list, new Set(excludeIds));
        openModal("call-add-modal");
        return new Promise((resolve) => {
            const finish = (result) => {
                endCallPick = null;
                $("call-add-modal").classList.add("modal-hidden");
                confirm.removeEventListener("click", onConfirm);
                cancel.removeEventListener("click", onCancel);
                resolve(result);
            };
            const onConfirm = () => {
                const usernames = checkedUsernames(list);
                if (!usernames.length) {
                    $("warning-call-add").textContent = t("newChat.pickOne");
                    return;
                }
                finish(usernames);
            };
            const onCancel = () => finish(null);
            endCallPick = onCancel;
            const confirm = $("confirm-call-add");
            const cancel = $("cancel-call-add");
            confirm.addEventListener("click", onConfirm);
            cancel.addEventListener("click", onCancel);
        });
    }
    function openNewChatModal() {
        const list = $("new-chat-list");
        const nameInput = $("new-chat-name");
        nameInput.value = "";
        nameInput.classList.add("modal-hidden");
        $("warning-new-chat").textContent = "";
        friendCheckboxes(list, new Set());
        if (!friends.friends.length) {
            list.textContent = "";
            list.appendChild(h("p", { text: t("chat.noFriends") }));
        }
        openModal("new-chat-modal");
    }
    /** The group name is only needed when more than one friend is picked. */
    function updateNewChatName() {
        $("new-chat-name").classList.toggle("modal-hidden", checkedUsernames($("new-chat-list")).length < 2);
    }
    async function startNewChat() {
        const usernames = checkedUsernames($("new-chat-list"));
        const warning = $("warning-new-chat");
        if (!usernames.length) {
            warning.textContent = t("newChat.pickOne");
            return;
        }
        if (usernames.length === 1)
            return startDm(usernames[0]);
        let name = $("new-chat-name").value.trim();
        if (!name) {
            // Without a name the group is called after its members.
            const names = usernames.map((u) => {
                const friend = friends.friends.find((f) => f.username === u);
                return friend ? nameOf(friend) : u;
            });
            name = [nameOf(me), ...names].join(", ").slice(0, 64);
        }
        try {
            const data = await post("/api/chats", { type: "group", name, usernames });
            closeAllModals();
            switchView("chats");
            chatsSignature = "";
            await loadChats();
            await openChat(data.chat_id);
        }
        catch (error) {
            warning.textContent = errorText(error);
        }
    }
    async function addFriend() {
        const input = $("friends-username-input");
        const warning = $("warning-add-friend");
        const username = input.value.trim();
        if (!username)
            return;
        warning.textContent = "";
        try {
            const data = await post("/api/friends/request", { username });
            input.value = "";
            closeAllModals();
            showAlert(t(data.status === "friends" ? "friends.nowFriends" : "friends.requestSent", { name: username }));
            await refreshAll();
        }
        catch (error) {
            warning.textContent = errorText(error);
        }
    }
    // ----------------------------------------------------------- chat info
    async function openChatInfo() {
        if (!current)
            return;
        try {
            await refreshCurrentDetails();
        }
        catch (error) {
            showAlert(errorText(error));
            return;
        }
        const opened = current;
        if (!opened || !opened.details)
            return;
        const details = opened.details;
        const body = $("chat-info-body");
        body.textContent = "";
        $("chat-info-title").textContent = details.name;
        const myFp = await SeresCrypto.fingerprint(identity.pubEcdh, identity.pubSign);
        const verified = readStore("verified");
        const members = details.members || [];
        // Shortcuts and the disappearing messages timer (for groups only the owner may change it).
        body.appendChild(h("div", { className: "info-actions" }, [
            button(t("pins.title") + (details.pins && details.pins.length ? ` (${details.pins.length})` : ""), "pill-btn secondary", () => {
                closeAllModals();
                openPinsModal();
            }),
            button(t("search.open"), "pill-btn secondary", () => {
                closeAllModals();
                openSearch();
            }),
        ]));
        const canChangeTimer = details.type === "dm" || details.role === "owner";
        const timer = h("select", { className: "language-select" });
        for (const seconds of DISAPPEAR_OPTIONS) {
            const option = h("option", { text: disappearLabel(seconds), attrs: { value: String(seconds) } });
            option.selected = seconds === (details.disappear_seconds || 0);
            timer.appendChild(option);
        }
        timer.disabled = !canChangeTimer;
        timer.addEventListener("change", async () => {
            try {
                await post(`/api/chats/${encodeURIComponent(details.id)}/disappearing`, { seconds: Number(timer.value) });
                await refreshCurrentDetails();
                await syncCurrent();
                chatsSignature = "";
                loadChats().catch(() => { });
            }
            catch (error) {
                showAlert(errorText(error));
            }
        });
        body.appendChild(h("div", { className: "settings-section" }, [
            h("p", { text: t("disappear.info") }),
            timer,
            canChangeTimer ? null : h("p", { className: "settings-hint", text: t("disappear.ownerOnly") }),
        ]));
        if (details.type === "dm") {
            const other = members.find((m) => m.id !== me.id);
            if (other) {
                body.appendChild(h("div", { className: "info-user" }, [avatarEl(other.username, { label: nameOf(other) }), h("strong", { text: nameOf(other) })]));
                const fp = await memberFingerprint(other);
                if (fp) {
                    const code = await SeresCrypto.safetyNumber(myFp, fp);
                    body.appendChild(h("p", { text: t("info.securityCode") }));
                    body.appendChild(h("code", { className: "safety-number", text: code }));
                    body.appendChild(verifyToggle(other.id, fp, verified));
                }
                const isBlocked = friends.blocked.some((b) => b.id === other.id);
                body.appendChild(h("div", { className: "info-actions" }, [
                    isBlocked
                        ? button(t("friends.unblock"), "pill-btn", async () => {
                            await unblockUser(other);
                            openChatInfo();
                        })
                        : button(t("friends.block"), "pill-btn danger", action("block", () => post("/api/block", { username: other.username }), t("friends.blockConfirm", { name: nameOf(other) }))),
                    button(t("info.deleteChat"), "pill-btn danger", action("delete", async () => {
                        await post(`/api/chats/${encodeURIComponent(details.id)}/delete`);
                        closeAllModals();
                        closeChat();
                    }, t("info.deleteChatConfirm"))),
                ]));
            }
        }
        else {
            const isOwner = details.role === "owner";
            if (isOwner) {
                const nameInput = h("input", { attrs: { type: "text", maxlength: "64", value: details.name } });
                body.appendChild(h("div", { className: "info-row" }, [
                    nameInput,
                    button(t("info.rename"), "pill-btn", action("rename", () => post(`/api/chats/${encodeURIComponent(details.id)}/rename`, { name: nameInput.value }))),
                ]));
                const invite = await groupInviteSection(details.id);
                if (invite)
                    body.appendChild(invite);
            }
            body.appendChild(h("p", { text: t("info.groupMembers", { count: members.length }) }));
            for (const member of members) {
                const fp = await memberFingerprint(member);
                const isMe = member.id === me.id;
                const memberAvatar = avatarEl(member.username, { label: nameOf(member) });
                memberAvatar.addEventListener("click", () => openProfile(member.username));
                const row = h("div", { className: "member-row" }, [
                    memberAvatar,
                    h("div", { className: "item-info" }, [
                        h("span", {
                            className: "item-name",
                            text: (isMe ? t("msg.you") : nameOf(member)) + (member.role === "owner" ? t("info.owner") : ""),
                        }),
                        h("span", {
                            className: "item-status",
                            text: fp ? t(isMe ? "info.yourKey" : "info.key") + fp.slice(0, 32).replace(/(.{4})/g, "$1 ").trim() : t("info.noKey"),
                        }),
                    ]),
                ]);
                if (!isMe && fp) {
                    const code = await SeresCrypto.safetyNumber(myFp, fp);
                    row.appendChild(button(t("info.code"), "request-action-btn more", () => {
                        showAlert(t("info.codeAlert", { name: nameOf(member), code }), 10000);
                    }));
                    row.appendChild(verifyToggle(member.id, fp, verified, true));
                }
                if (isOwner && !isMe) {
                    row.appendChild(button(t("info.remove"), "request-action-btn discard", action("remove", async () => {
                        await post(`/api/chats/${encodeURIComponent(details.id)}/members/remove`, { username: member.username });
                        await openChatInfo();
                    }, t("info.removeConfirm", { name: nameOf(member) }))));
                }
                body.appendChild(row);
            }
            const memberIds = new Set(members.map((m) => m.id));
            const addBox = h("div", { className: "picker-list" });
            friendCheckboxes(addBox, memberIds);
            body.appendChild(h("p", { text: t("info.addHint") }));
            body.appendChild(addBox);
            body.appendChild(h("div", { className: "info-actions" }, [
                button(t("info.addSelected"), "pill-btn", action("add", async () => {
                    for (const username of checkedUsernames(addBox)) {
                        await post(`/api/chats/${encodeURIComponent(details.id)}/members`, { username });
                    }
                    await openChatInfo();
                })),
                button(t("info.leave"), "pill-btn danger", action("leave", async () => {
                    await post(`/api/chats/${encodeURIComponent(details.id)}/leave`);
                    closeAllModals();
                    closeChat();
                }, t("info.leaveConfirm"))),
            ]));
        }
        openModal("chat-info-modal");
    }
    function verifyToggle(userId, fp, verified, compact = false, onChange = openChatInfo) {
        const isVerified = verified[userId] === fp;
        return button(t(isVerified ? "info.verified" : compact ? "info.verify" : "info.markVerified"), "pill-btn" + (isVerified ? " verified" : " secondary"), () => {
            const store = readStore("verified");
            if (store[userId] === fp)
                delete store[userId];
            else
                store[userId] = fp;
            writeStore("verified", store);
            onChange();
        });
    }
    // ------------------------------------------------------------ profile
    /** Asks, unblocks and tells whether the friendship came back. */
    async function unblockUser(user) {
        if (!window.confirm(t("profile.unblockConfirm", { name: nameOf(user) })))
            return;
        try {
            const data = await post("/api/unblock", { username: user.username });
            showAlert(t(data.friends ? "profile.unblockedFriend" : "profile.unblocked", { name: nameOf(user) }));
        }
        catch (error) {
            showAlert(errorText(error));
        }
        chatsSignature = "";
        await refreshAll();
    }
    async function openProfile(username, showCode = false) {
        closeFloatingMenus();
        let data;
        try {
            data = await api(`/api/users/${encodeURIComponent(username)}/profile`);
        }
        catch (error) {
            showAlert(errorText(error));
            return;
        }
        const user = data.user;
        const name = nameOf(user);
        const reopen = () => openProfile(username, showCode);
        const status = data.is_me
            ? t("profile.you")
            : data.blocked
                ? t("profile.blockedStatus")
                : data.friend
                    ? t("profile.friend")
                    : data.request === "outgoing"
                        ? t("profile.requestOutgoing")
                        : data.request === "incoming"
                            ? t("profile.requestIncoming")
                            : t("profile.notFriend");
        const head = $("profile-head");
        head.textContent = "";
        head.append(avatarEl(user.username, { className: "avatar profile-avatar", label: name }), h("h3", { className: "profile-name", text: name }), h("span", { className: "profile-username", text: "@" + user.username }), h("p", { className: "profile-about" + (user.status ? "" : " modal-hidden"), text: user.status || "" }), h("span", { className: "profile-status" }, [data.muted ? h("span", { className: "material-symbols-rounded", text: "notifications_off" }) : null, document.createTextNode(status)]));
        if (data.presence) {
            head.appendChild(h("span", { className: "profile-presence" + (data.presence.online ? " online" : ""), text: presenceText(data.presence) }));
        }
        const actions = $("profile-actions");
        actions.textContent = "";
        const codeBox = $("profile-code");
        codeBox.textContent = "";
        codeBox.classList.add("modal-hidden");
        if (!data.is_me) {
            if (data.friend) {
                actions.append(button(t("friends.messageMenu"), "pill-btn", () => startDm(user.username)));
            }
            else if (!data.blocked && data.request !== "outgoing") {
                actions.append(button(t("profile.addFriend"), "pill-btn", async () => {
                    const url = data.request === "incoming" ? "/api/friends/accept" : "/api/friends/request";
                    try {
                        await post(url, { username: user.username });
                    }
                    catch (error) {
                        showAlert(errorText(error));
                    }
                    await refreshAll();
                    reopen();
                }));
            }
            const fp = await memberFingerprint(user);
            if (fp) {
                actions.append(button(t(showCode ? "profile.hideCode" : "profile.showCode"), "pill-btn secondary", () => openProfile(username, !showCode)));
                if (showCode) {
                    const myFp = await SeresCrypto.fingerprint(identity.pubEcdh, identity.pubSign);
                    codeBox.append(h("p", { text: t("info.securityCode") }), h("code", { className: "safety-number", text: await SeresCrypto.safetyNumber(myFp, fp) }), verifyToggle(user.id, fp, readStore("verified"), false, reopen));
                    codeBox.classList.remove("modal-hidden");
                }
            }
            actions.append(button(t(data.muted ? "profile.unmute" : "profile.mute"), "pill-btn secondary", async () => {
                try {
                    await post("/api/users/mute", { username: user.username, muted: !data.muted });
                    showAlert(t(data.muted ? "profile.unmuted" : "profile.muted", { name }));
                }
                catch (error) {
                    showAlert(errorText(error));
                }
                chatsSignature = "";
                await refreshAll();
                reopen();
            }), data.blocked
                ? button(t("friends.unblock"), "pill-btn", async () => {
                    await unblockUser(user);
                    reopen();
                })
                : button(t("friends.block"), "pill-btn danger", action("block", async () => {
                    await post("/api/block", { username: user.username });
                    reopen();
                }, t("friends.blockConfirmLong", { name }))));
        }
        $("profile-modal").classList.remove("modal-hidden");
    }
    // ------------------------------------------------------------- modals
    function openModal(id) {
        closeFloatingMenus();
        $(id).classList.remove("modal-hidden");
        const input = $(id).querySelector("[data-autofocus]") || $(id).querySelector("input[type=text]");
        if (input)
            setTimeout(() => input.focus(), 30);
    }
    /** Closes one of the small dialogs opened from the settings; the settings stay open. */
    function closeSubModal(id) {
        $(id).classList.add("modal-hidden");
    }
    function openSubModal(id) {
        $(id).querySelectorAll(".settings-notice").forEach((notice) => (notice.textContent = ""));
        if (id === "display-name-modal")
            $("display-name-input").value = nameOf(me);
        if (id === "status-modal")
            $("status-input").value = me.status || "";
        if (id === "avatar-modal")
            $("avatar-upload-input").value = "";
        if (id === "password-modal") {
            ["old-password", "new-password", "new-password-repeat"].forEach((field) => ($(field).value = ""));
        }
        openModal(id);
    }
    function closeAllModals() {
        // The device dialogs (choosing the main device, allowing a login) wait for
        // an answer; they close only through their own buttons.
        document.querySelectorAll(".modal-overlay:not([data-locked])").forEach((modal) => modal.classList.add("modal-hidden"));
    }
    // ------------------------------------------------------------ settings
    async function uploadAvatar() {
        const input = $("avatar-upload-input");
        const warning = $("avatar-warning");
        warning.textContent = "";
        const file = input.files && input.files[0];
        if (!file) {
            warning.textContent = t("settings.chooseFile");
            return;
        }
        if (file.size > 2 * 1024 * 1024) {
            warning.textContent = t("settings.fileTooLarge");
            return;
        }
        const form = new FormData();
        form.append("avatar_img", file);
        try {
            const response = await fetch("/api/upload_avatar", { method: "POST", body: form, credentials: "same-origin" });
            const data = await response.json().catch(() => ({}));
            if (!response.ok || !data.success)
                throw new Error(data.message || t("settings.uploadFailed"));
            input.value = "";
            avatarState.delete(me.username);
            loadOwnAvatar();
            closeSubModal("avatar-modal");
            showAlert(t("settings.avatarUpdated"));
        }
        catch (error) {
            warning.textContent = errorText(error);
        }
    }
    /** Thrown when the password prompt was cancelled; nothing to report then. */
    class PromptCancelled extends Error {
    }
    // Cancels an earlier prompt that was closed some other way.
    let endPasswordPrompt = null;
    /**
     * Asks for the current password in a small dialog, only when a setting is
     * about to change. Resolves with the password, or null when cancelled.
     */
    function askPassword(reason) {
        endPasswordPrompt?.();
        const modal = $("password-prompt-modal");
        const form = $("password-prompt-form");
        const input = $("password-prompt-input");
        const cancel = $("password-prompt-cancel");
        $("password-prompt-text").textContent = reason;
        $("password-prompt-warning").textContent = "";
        $("password-prompt-username").value = me.username;
        input.value = "";
        modal.classList.remove("modal-hidden");
        setTimeout(() => input.focus(), 30);
        return new Promise((resolve) => {
            const finish = (result) => {
                endPasswordPrompt = null;
                input.value = "";
                modal.classList.add("modal-hidden");
                form.removeEventListener("submit", onSubmit);
                cancel.removeEventListener("click", onCancel);
                modal.removeEventListener("click", onOutside);
                input.removeEventListener("keydown", onKey);
                resolve(result);
            };
            const onSubmit = (event) => {
                event.preventDefault();
                if (!input.value) {
                    $("password-prompt-warning").textContent = t("twofa.needPassword");
                    input.focus();
                    return;
                }
                finish(input.value);
            };
            const onCancel = () => finish(null);
            const onOutside = (event) => {
                if (event.target === modal)
                    finish(null);
            };
            // Escape only closes this prompt, not the settings behind it.
            const onKey = (event) => {
                if (event.key !== "Escape")
                    return;
                event.stopPropagation();
                finish(null);
            };
            endPasswordPrompt = onCancel;
            form.addEventListener("submit", onSubmit);
            cancel.addEventListener("click", onCancel);
            modal.addEventListener("click", onOutside);
            input.addEventListener("keydown", onKey);
        });
    }
    async function changePassword() {
        const warning = $("password-warning");
        const oldPw = $("old-password").value;
        const newPw = $("new-password").value;
        const repeat = $("new-password-repeat").value;
        warning.textContent = "";
        if (!oldPw) {
            warning.textContent = t("twofa.needPassword");
            return;
        }
        if (newPw.length < 8) {
            warning.textContent = t("settings.passwordShort");
            return;
        }
        if (newPw !== repeat) {
            warning.textContent = t("settings.passwordMismatch");
            return;
        }
        warning.textContent = t("settings.changingPassword");
        try {
            const fresh = (await api("/api/me")).user;
            const pre = await post("/api/prelogin", { nameomail: me.username });
            const oldKeys = await SeresCrypto.deriveAccountKeys(oldPw, pre.kdf_salt, pre.kdf_iterations);
            const salt = SeresCrypto.newSalt();
            const newKeys = await SeresCrypto.deriveAccountKeys(newPw, salt, SeresCrypto.DEFAULT_ITERATIONS);
            let encPrivate;
            try {
                encPrivate = await SeresCrypto.rewrapPrivateKeys(fresh.enc_private, oldKeys.wrapKey, newKeys.wrapKey);
            }
            catch {
                throw new Error(t("settings.wrongPassword"));
            }
            await post("/api/change_password", {
                old_auth_hash: oldKeys.authHash,
                auth_hash: newKeys.authHash,
                kdf_salt: salt,
                kdf_iterations: SeresCrypto.DEFAULT_ITERATIONS,
                enc_private: encPrivate,
            });
            ["old-password", "new-password", "new-password-repeat"].forEach((id) => ($(id).value = ""));
            warning.textContent = "";
            closeSubModal("password-modal");
            showAlert(t("settings.passwordChanged"));
        }
        catch (error) {
            warning.textContent = errorText(error);
        }
    }
    // ------------------------------------------------------------- invites
    function inviteUrl(token) {
        return new URL("/?invite=" + encodeURIComponent(token), window.location.origin).href;
    }
    async function openInviteModal(renew = false) {
        $("user-dropdown-menu").classList.add("modal-hidden");
        try {
            const data = renew ? await post("/api/invite/renew") : await api("/api/invite");
            const url = inviteUrl(data.token);
            $("invite-link").value = url;
            const box = $("invite-qr");
            box.textContent = "";
            box.appendChild(SeresQR.toSvg(url));
            $("invite-share").style.display = typeof navigator.share === "function" ? "" : "none";
            closeAllModals();
            openModal("invite-modal");
        }
        catch (error) {
            showAlert(errorText(error));
        }
    }
    async function copyInvite() {
        const input = $("invite-link");
        try {
            await navigator.clipboard.writeText(input.value);
        }
        catch {
            // Older browsers or no clipboard permission.
            input.select();
            document.execCommand("copy");
        }
        showAlert(t("invite.copied"));
    }
    function shareInvite() {
        const url = $("invite-link").value;
        navigator.share({ title: "SereS", text: t("invite.shareText"), url }).catch(() => { });
    }
    /** Asks whether to send a friend request to the owner of an opened invite link. */
    async function showInvite(token) {
        try {
            const data = await api("/api/invite/" + encodeURIComponent(token));
            const name = nameOf(data.user);
            if (data.status === "self")
                return showAlert(t("invite.self"));
            if (data.status === "friends")
                return showAlert(t("invite.alreadyFriends", { name }));
            inviteToAccept = { token, name };
            const userBox = $("invite-accept-user");
            userBox.textContent = "";
            userBox.append(avatarEl(data.user.username, { label: name }), h("strong", { text: name }));
            $("invite-accept-text").textContent = t("invite.acceptText", { name });
            $("warning-invite").textContent = "";
            openModal("invite-accept-modal");
        }
        catch (error) {
            showAlert(error instanceof ApiError && error.status === 404 ? t("invite.invalid") : errorText(error));
        }
    }
    async function acceptInvite() {
        if (!inviteToAccept)
            return;
        try {
            const { token, name } = inviteToAccept;
            const data = await post("/api/invite/" + encodeURIComponent(token) + "/accept");
            closeAllModals();
            showAlert(t(data.status === "friends" ? "friends.nowFriends" : "friends.requestSent", { name }));
            inviteToAccept = null;
            await refreshAll();
        }
        catch (error) {
            $("warning-invite").textContent = errorText(error);
        }
    }
    // ------------------------------------------------------- group invites
    function groupInviteUrl(token) {
        return new URL("/?join=" + encodeURIComponent(token), window.location.origin).href;
    }
    /** The owner's part of the group info: make, copy, renew or turn off the link. */
    async function groupInviteSection(chatId) {
        const box = h("div", { className: "settings-section group-invite" });
        box.appendChild(h("p", { text: t("groupInvite.title") }));
        let token = null;
        try {
            token = (await api(`/api/chats/${encodeURIComponent(chatId)}/invite`)).token;
        }
        catch {
            return null;
        }
        const render = () => {
            box.querySelectorAll(":scope > :not(p:first-child)").forEach((node) => node.remove());
            if (!token) {
                box.appendChild(h("p", { className: "settings-hint", text: t("groupInvite.none") }));
                box.appendChild(button(t("groupInvite.create"), "pill-btn", () => change("create")));
                return;
            }
            const url = groupInviteUrl(token);
            const input = h("input", { className: "group-invite-link", attrs: { type: "text", readonly: "true", value: url } });
            input.value = url;
            box.appendChild(input);
            const qr = h("div", { className: "group-invite-qr" });
            qr.appendChild(SeresQR.toSvg(url));
            box.appendChild(qr);
            box.appendChild(h("div", { className: "info-actions" }, [
                button(t("groupInvite.copy"), "pill-btn", async () => {
                    try {
                        await navigator.clipboard.writeText(url);
                    }
                    catch {
                        input.select();
                        document.execCommand("copy");
                    }
                    showAlert(t("invite.copied"));
                }),
                typeof navigator.share === "function"
                    ? button(t("invite.share"), "pill-btn", () => navigator.share({ title: "SereS", url }).catch(() => { }))
                    : null,
                button(t("groupInvite.renew"), "pill-btn", () => {
                    if (window.confirm(t("groupInvite.renewConfirm")))
                        change("create");
                }),
                button(t("groupInvite.off"), "pill-btn danger", () => {
                    if (window.confirm(t("groupInvite.offConfirm")))
                        change("delete");
                }),
            ]));
            box.appendChild(h("p", { className: "settings-hint", text: t("groupInvite.hint") }));
        };
        const change = async (what) => {
            try {
                const data = await api(`/api/chats/${encodeURIComponent(chatId)}/invite`, { method: what === "create" ? "POST" : "DELETE", body: what === "create" ? {} : undefined });
                token = data.token;
                render();
            }
            catch (error) {
                showAlert(errorText(error));
            }
        };
        render();
        return box;
    }
    /** Someone opened a group invite link: show the group and ask. */
    async function showGroupInvite(token) {
        try {
            const data = await api("/api/invites/" + encodeURIComponent(token));
            if (data.member && data.chat_id) {
                switchView("chats");
                await openChat(data.chat_id);
                return;
            }
            joinToAccept = token;
            const box = $("group-join-group");
            box.textContent = "";
            box.append(avatarEl(data.name, { group: true, label: data.name }), h("div", { className: "item-info" }, [
                h("strong", { text: data.name }),
                h("span", { className: "item-status", text: t("groupInvite.members", { count: data.member_count }) }),
            ]));
            $("warning-group-join").textContent = "";
            openModal("group-join-modal");
        }
        catch (error) {
            showAlert(error instanceof ApiError && error.status === 404 ? t("groupInvite.invalid") : errorText(error));
        }
    }
    async function joinGroup() {
        if (!joinToAccept)
            return;
        try {
            const data = await post("/api/invites/" + encodeURIComponent(joinToAccept) + "/join");
            joinToAccept = null;
            closeAllModals();
            await loadChats();
            switchView("chats");
            await openChat(data.chat_id);
        }
        catch (error) {
            $("warning-group-join").textContent = errorText(error);
        }
    }
    function showOwnName() {
        $("my-username-display").textContent = nameOf(me);
        $("password-username").value = me.username;
        $("mobile-username").textContent = nameOf(me);
        if (!current)
            $("current-chat-name").textContent = t("app.welcomeUser", { name: nameOf(me) });
    }
    async function saveDisplayName() {
        const warning = $("display-name-warning");
        warning.textContent = "";
        try {
            const data = await post("/api/profile/display_name", {
                display_name: $("display-name-input").value,
            });
            me.display_name = data.display_name;
            $("display-name-input").value = data.display_name;
            $("display-name-current").textContent = data.display_name;
            showOwnName();
            loadOwnAvatar();
            closeSubModal("display-name-modal");
            showAlert(t("settings.displayNameSaved"));
        }
        catch (error) {
            warning.textContent = errorText(error);
        }
    }
    function showOwnStatus() {
        $("status-current").textContent = me.status || t("status.none");
        $("status-current").classList.toggle("empty", !me.status);
    }
    async function saveStatus(status) {
        const warning = $("status-warning");
        warning.textContent = "";
        try {
            const data = await post("/api/profile/status", { status });
            me.status = data.status;
            showOwnStatus();
            closeSubModal("status-modal");
            showAlert(t(data.status ? "status.saved" : "status.removed"));
        }
        catch (error) {
            warning.textContent = errorText(error);
        }
    }
    function showCookieStatus() {
        const consent = SeresI18n.getConsent();
        $("cookie-status").textContent = t(consent === "accepted" ? "settings.cookiesAccepted" : consent === "denied" ? "settings.cookiesDenied" : "settings.cookiesUndecided");
    }
    /** Texts of the on/off switches in the settings. */
    function renderSettingsToggles() {
        const settings = readStore("settings");
        $("privacy-toggle").textContent = t(me.show_last_seen === false ? "privacy.showOff" : "privacy.showOn");
        $("notify-toggle").textContent = t(settings.notify === "on" && notificationsEnabled() ? "notify.on" : "notify.off");
        $("notify-preview-toggle").textContent = t(settings.preview === "off" ? "notify.previewOff" : "notify.previewOn");
        $("links-toggle").textContent = t(settings.links === "off" ? "links.off" : "links.on");
        $("notify-preview-toggle").classList.toggle("modal-hidden", settings.notify !== "on");
    }
    async function togglePrivacy() {
        try {
            const data = await post("/api/profile/privacy", { show_last_seen: me.show_last_seen === false });
            me.show_last_seen = data.show_last_seen;
            renderSettingsToggles();
            showAlert(t(data.show_last_seen ? "privacy.savedOn" : "privacy.savedOff"));
        }
        catch (error) {
            showAlert(errorText(error));
        }
    }
    // ------------------------------------------------------------------ 2FA
    /** Asks for the current password and turns it into the hash the server checks. */
    async function twofaPasswordHash() {
        const password = await askPassword(t("pwPrompt.twofa"));
        if (password === null)
            throw new PromptCancelled();
        const pre = await post("/api/prelogin", { nameomail: me.username });
        const keys = await SeresCrypto.deriveAccountKeys(password, pre.kdf_salt, pre.kdf_iterations);
        return keys.authHash;
    }
    async function loadTwofa() {
        const list = $("twofa-list");
        list.textContent = "";
        let data;
        try {
            data = await api("/api/2fa");
        }
        catch {
            return;
        }
        $("twofa-status").textContent = t(data.enabled ? "twofa.statusOn" : "twofa.statusOff");
        $("twofa-status").classList.toggle("on", data.enabled);
        for (const passkey of data.passkeys) {
            list.appendChild(h("div", { className: "twofa-item" }, [
                h("span", {}, [h("span", { className: "material-symbols-rounded", text: "passkey" }), document.createTextNode(" " + passkey.name)]),
                h("span", {
                    className: "twofa-meta",
                    text: passkey.last_used_at ? t("twofa.lastUsed", { date: formatDateTime(passkey.last_used_at) }) : t("twofa.neverUsed"),
                }),
                button(t("twofa.remove"), "request-action-btn discard", () => removePasskey(passkey.id, passkey.name)),
            ]));
        }
        if (data.totp) {
            list.appendChild(h("div", { className: "twofa-item" }, [
                h("span", { text: t("twofa.totpOn") }),
                h("span", { className: "twofa-meta" }),
                button(t("twofa.remove"), "request-action-btn discard", disableTotp),
            ]));
        }
        $("twofa-totp-button").classList.toggle("modal-hidden", data.totp);
        $("twofa-add-passkey").classList.toggle("modal-hidden", !SeresPasskeys.supported());
    }
    async function twofaAction(work) {
        const warning = $("twofa-warning");
        warning.textContent = "";
        try {
            await work();
        }
        catch (error) {
            if (error instanceof PromptCancelled)
                return;
            warning.textContent =
                error instanceof DOMException ? t("twofa.passkeyCancelled") : errorText(error);
        }
        await loadTwofa();
    }
    function addPasskey() {
        return twofaAction(async () => {
            const authHash = await twofaPasswordHash();
            const name = window.prompt(t("twofa.passkeyName"), t("twofa.passkeyDefault")) || t("twofa.passkeyDefault");
            const start = await post("/api/2fa/passkeys/options", { old_auth_hash: authHash });
            const credential = await SeresPasskeys.create(start.options);
            await post("/api/2fa/passkeys/register", { token: start.token, credential, name });
            showAlert(t("twofa.passkeyAdded"));
        });
    }
    function removePasskey(id, name) {
        if (!window.confirm(t("twofa.removeConfirm", { name })))
            return;
        return twofaAction(async () => {
            await post("/api/2fa/passkeys/delete", { id, old_auth_hash: await twofaPasswordHash() });
            showAlert(t("twofa.removed"));
        });
    }
    function startTotp() {
        return twofaAction(async () => {
            const data = await post("/api/2fa/totp/setup", { old_auth_hash: await twofaPasswordHash() });
            const qr = $("twofa-qr");
            qr.textContent = "";
            qr.appendChild(SeresQR.toSvg(data.uri));
            $("twofa-secret").textContent = data.secret.replace(/(.{4})/g, "$1 ").trim();
            $("twofa-code").value = "";
            $("twofa-totp-setup").classList.remove("modal-hidden");
            $("twofa-code").focus();
        });
    }
    function confirmTotp() {
        return twofaAction(async () => {
            await post("/api/2fa/totp/enable", { code: $("twofa-code").value.replace(/\s/g, "") });
            $("twofa-totp-setup").classList.add("modal-hidden");
            $("twofa-qr").textContent = "";
            $("twofa-secret").textContent = "";
            showAlert(t("twofa.totpEnabled"));
        });
    }
    function disableTotp() {
        if (!window.confirm(t("twofa.totpRemoveConfirm")))
            return;
        return twofaAction(async () => {
            await post("/api/2fa/totp/disable", { old_auth_hash: await twofaPasswordHash() });
            showAlert(t("twofa.removed"));
        });
    }
    async function loadCodesStatus() {
        try {
            const data = await api("/api/recovery/codes");
            $("codes-status").textContent = data.total
                ? t("settings.codesLeft", { unused: data.unused, total: data.total })
                : t("settings.codesNone");
            $("codes-status").classList.toggle("warn", !data.unused);
        }
        catch {
            $("codes-status").textContent = "";
        }
    }
    /** Makes 10 new backup codes (old ones stop working) and shows them once. */
    async function generateCodes() {
        const warning = $("codes-warning");
        warning.textContent = "";
        const password = await askPassword(t("pwPrompt.codes"));
        if (password === null)
            return;
        const button = $("codes-generate");
        button.disabled = true;
        warning.textContent = t("settings.codesCreating");
        try {
            const fresh = (await api("/api/me")).user;
            const pre = await post("/api/prelogin", { nameomail: me.username });
            const keys = await SeresCrypto.deriveAccountKeys(password, pre.kdf_salt, pre.kdf_iterations);
            let created;
            try {
                created = await SeresCrypto.createRecoveryCodes(fresh.enc_private, keys.wrapKey);
            }
            catch {
                throw new Error(t("settings.codesWrongPassword"));
            }
            await post("/api/recovery/codes", { old_auth_hash: keys.authHash, codes: created.stored });
            warning.textContent = "";
            await loadCodesStatus();
            SeresCodes.show(created.codes, me.username);
        }
        catch (error) {
            warning.textContent = errorText(error);
        }
        finally {
            button.disabled = false;
        }
    }
    async function openSettings() {
        loadCodesStatus();
        loadTwofa();
        $("devices-warning").textContent = "";
        loadDevices().catch(() => { });
        $("twofa-totp-setup").classList.add("modal-hidden");
        renderSettingsToggles();
        $("user-dropdown-menu").classList.add("modal-hidden");
        ["display-name-warning", "avatar-warning", "twofa-warning", "codes-warning", "password-warning"].forEach((id) => {
            $(id).textContent = "";
        });
        $("display-name-current").textContent = nameOf(me);
        showOwnStatus();
        ["display-name-modal", "status-modal", "avatar-modal", "password-modal"].forEach(closeSubModal);
        showCookieStatus();
        openModal("settings-modal");
        const fp = await SeresCrypto.fingerprint(identity.pubEcdh, identity.pubSign);
        $("my-fingerprint").textContent = fp.replace(/(.{4})/g, "$1 ").trim();
    }
    function loadOwnAvatar() {
        const text = $("user-avatar-text");
        const img = $("user-avatar-img");
        text.textContent = nameOf(me).charAt(0).toUpperCase();
        $("user-avatar").style.backgroundColor = colorFor(me.username);
        fetch("/api/get_avatar", { credentials: "same-origin" })
            .then((response) => {
            if (!response.ok)
                throw new Error("no avatar");
            return response.blob();
        })
            .then((blob) => {
            img.src = URL.createObjectURL(blob);
            img.classList.remove("hidden-el");
            text.style.display = "none";
        })
            .catch(() => {
            img.classList.add("hidden-el");
            text.style.display = "block";
        });
    }
    async function logout() {
        try {
            const state = await loadDevices();
            const others = state.devices.filter((device) => device.approved && !device.current);
            if (state.isMain && others.length) {
                const id = await chooseDevice({
                    title: t("devices.handoverTitle"),
                    text: t("devices.handoverText"),
                    devices: others,
                    cancellable: true,
                });
                if (!id)
                    return;
                await post("/api/devices/main", { id });
            }
        }
        catch (error) {
            if (error instanceof ApiError && error.status !== 401) {
                showAlert(errorText(error));
                return;
            }
        }
        try {
            await unsubscribePush();
            await fetch("/api/logout", { method: "POST", credentials: "same-origin" });
        }
        finally {
            await SeresCrypto.clearIdentities();
            window.location.href = "login.html";
        }
    }
    // --------------------------------------------------------------- theme
    function applyTheme() {
        const isBright = SeresI18n.getPreference("theme") === "bright";
        document.body.classList.toggle("bright-body", isBright);
        const single = [
            [".sidebar", "bright-sidebar"],
            [".sidebar-header", "bright-sidebar-header"],
            [".main-chat", "bright-main-chat"],
            [".chat-header", "bright-chat-header"],
            [".input-container", "bright-input-container"],
            [".input-box", "bright-input-box"],
            [".user-menu-container", "bright-user-menu-container"],
            [".user-dropdown", "bright-user-dropdown"],
        ];
        single.forEach(([selector, cls]) => document.querySelector(selector)?.classList.toggle(cls, isBright));
        const many = [
            [".section-title", "bright-section-title"],
            [".list-item", "bright-list-item"],
            [".item-name", "bright-item-name"],
            [".item-status", "bright-item-status"],
            [".dropdown-divider", "bright-dropdown-divider"],
            [".dropdown-item", "bright-dropdown-item"],
            [".modal-overlay", "bright-modal-overlay"],
            [".modal-box", "bright-modal-box"],
            [".cancel-btn", "bright-cancel-btn"],
        ];
        many.forEach(([selector, cls]) => document.querySelectorAll(selector).forEach((el) => el.classList.toggle(cls, isBright)));
    }
    function toggleTheme() {
        const newTheme = SeresI18n.getPreference("theme") === "bright" ? "dark" : "bright";
        SeresI18n.setPreference("theme", newTheme);
        applyTheme();
    }
    /** Renders all generated texts again after the language was switched. */
    function rerenderLanguage() {
        shownCache.clear();
        showCookieStatus();
        chatsSignature = "";
        friendsSignature = "";
        if (current) {
            refreshCurrentDetails().catch(() => { });
            renderMessages({}).catch(() => { });
        }
        else {
            closeChat();
        }
        refreshAll();
    }
    // --------------------------------------------------------------- intro
    // The intro animation (assets/animation.mp4/.mov) is no longer played; the
    // files are kept. Only the "?login=true" marker of the login redirect is removed.
    function cleanLoginRedirect() {
        if (new URLSearchParams(window.location.search).get("login") === "true") {
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    }
    // ---------------------------------------------------------------- boot
    async function refreshAll() {
        await Promise.all([loadFriends(), loadChats()]).catch((error) => {
            if (!(error instanceof ApiError && error.status === 401))
                console.error(error);
        });
        if (current)
            await refreshCurrentDetails().catch(() => { });
        // Scheduled messages that went out disappear from the bar.
        if (current && scheduled?.items.length)
            loadScheduled(current);
    }
    function bindEvents() {
        const resizer = $("pane-resizer");
        const savedWidth = Number(localStorage.getItem("seres-sidebar-width")) || 450;
        document.documentElement.style.setProperty("--sidebar-width", `${Math.min(640, Math.max(340, savedWidth))}px`);
        const resizeAt = (clientX) => {
            const width = Math.min(640, Math.max(340, clientX - 72));
            document.documentElement.style.setProperty("--sidebar-width", `${width}px`);
            resizer.setAttribute("aria-valuenow", String(width));
            localStorage.setItem("seres-sidebar-width", String(width));
        };
        resizer.addEventListener("pointerdown", (event) => {
            resizer.setPointerCapture(event.pointerId);
            resizeAt(event.clientX);
        });
        resizer.addEventListener("pointermove", (event) => {
            if (resizer.hasPointerCapture(event.pointerId))
                resizeAt(event.clientX);
        });
        resizer.addEventListener("keydown", (event) => {
            if (!["ArrowLeft", "ArrowRight"].includes(event.key))
                return;
            event.preventDefault();
            const delta = event.key === "ArrowLeft" ? -20 : 20;
            const currentWidth = parseInt(getComputedStyle(document.documentElement).getPropertyValue("--sidebar-width"), 10) || 450;
            resizeAt(currentWidth + delta + 72);
        });
        $("btn-add-friend").addEventListener("click", () => {
            $("warning-add-friend").textContent = "";
            openModal("add-friend-modal");
        });
        $("confirm-add-friend").addEventListener("click", addFriend);
        $("friends-username-input").addEventListener("keydown", (event) => {
            if (event.key === "Enter")
                addFriend();
        });
        $("btn-new-chat").addEventListener("click", openNewChatModal);
        $("new-chat-list").addEventListener("change", updateNewChatName);
        $("confirm-new-chat").addEventListener("click", startNewChat);
        $("chat-info-btn").addEventListener("click", openChatInfo);
        document.querySelector(".chat-title").addEventListener("click", () => {
            if (current && current.details && current.details.type === "dm" && current.details.other_user) {
                openProfile(current.details.other_user);
            }
        });
        $("send-btn").addEventListener("click", sendMessage);
        $("edit-cancel").addEventListener("click", cancelEdit);
        $("reply-cancel").addEventListener("click", cancelReply);
        $("record-btn").addEventListener("click", startRecording);
        $("record-cancel").addEventListener("click", () => stopRecording(false));
        $("record-send").addEventListener("click", () => stopRecording(true));
        $("emoji-btn").addEventListener("click", (event) => {
            event.stopPropagation();
            toggleEmojiPicker();
        });
        $("attach-btn").addEventListener("click", (event) => {
            event.stopPropagation();
            openAttachMenu(event);
        });
        $("location-send").addEventListener("click", () => sendLocation(false));
        $("location-live").addEventListener("click", () => sendLocation(true));
        window.setInterval(() => {
            tickLive().catch(() => { });
        }, 5000);
        $("poll-btn").addEventListener("click", openPollDialog);
        $("poll-cancel").addEventListener("click", () => $("poll-modal").classList.add("modal-hidden"));
        $("poll-form").addEventListener("submit", (event) => {
            event.preventDefault();
            createPoll();
        });
        $("attach-input").addEventListener("change", () => {
            const picker = $("attach-input");
            if (picker.files)
                addPendingFiles(picker.files);
            picker.value = "";
        });
        $("search-btn").addEventListener("click", openSearch);
        $("call-btn")?.addEventListener("click", () => {
            if (current && typeof SeresCalls !== "undefined")
                SeresCalls.start(current.id);
        });
        $("search-input").addEventListener("input", onSearchInput);
        $("search-input").addEventListener("keydown", (event) => {
            const key = event.key;
            if (key === "Enter")
                moveSearch(event.shiftKey ? 1 : -1);
            if (key === "Escape")
                closeSearch();
        });
        $("search-prev").addEventListener("click", () => moveSearch(-1));
        $("search-next").addEventListener("click", () => moveSearch(1));
        $("search-close").addEventListener("click", closeSearch);
        $("pinned-bar").addEventListener("click", openPinsModal);
        $("confirm-forward").addEventListener("click", confirmForward);
        $("jump-bottom").addEventListener("click", () => {
            const container = $("messages");
            container.scrollTo({ top: container.scrollHeight, behavior: "smooth" });
        });
        $("messages").addEventListener("scroll", updateJumpButton, { passive: true });
        $("lightbox").addEventListener("click", () => $("lightbox").classList.add("modal-hidden"));
        $("privacy-toggle").addEventListener("click", togglePrivacy);
        $("links-toggle").addEventListener("click", () => {
            const settings = readStore("settings");
            settings.links = settings.links === "off" ? "on" : "off";
            writeStore("settings", settings);
            renderSettingsToggles();
            clearLinkPreview();
            if (current)
                renderMessages({ keepPosition: true });
        });
        $("message-input-field").addEventListener("input", watchLinkPreview);
        $("link-preview-cancel").addEventListener("click", () => {
            if (linkPreview)
                linkPreview.dismissed = true;
            renderLinkPreviewBar();
        });
        $("notify-toggle").addEventListener("click", () => toggleNotifications().catch(() => { }));
        $("notify-preview-toggle").addEventListener("click", () => {
            const settings = readStore("settings");
            settings.preview = settings.preview === "off" ? "on" : "off";
            writeStore("settings", settings);
            renderSettingsToggles();
        });
        // Drop files onto the chat or paste images to attach them.
        const chatArea = document.querySelector(".main-chat");
        chatArea.addEventListener("dragover", (event) => {
            if (chatArea.classList.contains("matrix-open") || !current || !event.dataTransfer?.types.includes("Files"))
                return;
            event.preventDefault();
            chatArea.classList.add("drag-over");
        });
        chatArea.addEventListener("dragleave", (event) => {
            if (event.target === chatArea || !chatArea.contains(event.relatedTarget))
                chatArea.classList.remove("drag-over");
        });
        chatArea.addEventListener("drop", (event) => {
            chatArea.classList.remove("drag-over");
            if (chatArea.classList.contains("matrix-open") || !current || !event.dataTransfer?.files.length)
                return;
            event.preventDefault();
            addPendingFiles(event.dataTransfer.files);
        });
        document.querySelectorAll(".rail-nav[data-rail-view]").forEach((button) => button.addEventListener("click", () => switchView(button.dataset.railView)));
        $("rail-settings").addEventListener("click", openSettings);
        $("user-menu-trigger").addEventListener("click", () => $("user-dropdown-menu").classList.toggle("modal-hidden"));
        $("menu-logout").addEventListener("click", (event) => {
            event.preventDefault();
            logout();
        });
        $("link-code-btn").addEventListener("click", openLinkCodeDialog);
        $("link-code-cancel").addEventListener("click", () => $("link-code-modal").classList.add("modal-hidden"));
        $("link-code-form").addEventListener("submit", (event) => {
            event.preventDefault();
            const code = $("link-code-input").value.trim();
            if (!code)
                return;
            $("link-code-modal").classList.add("modal-hidden");
            linkDevice({ code });
        });
        $("menu-install").addEventListener("click", (event) => {
            event.preventDefault();
            $("user-dropdown-menu").classList.add("modal-hidden");
            installApp();
        });
        $("menu-invite").addEventListener("click", (event) => {
            event.preventDefault();
            openInviteModal();
        });
        $("add-friend-invite").addEventListener("click", () => openInviteModal());
        document.addEventListener("click", (event) => {
            const link = event.target.closest?.("a[href]");
            if (!link || event.ctrlKey || event.metaKey)
                return;
            try {
                const url = new URL(link.href);
                const token = url.origin === window.location.origin ? url.searchParams.get("join") : null;
                if (!token)
                    return;
                event.preventDefault();
                event.stopPropagation();
                showGroupInvite(token);
            }
            catch {
                // not a URL
            }
        }, true);
        $("confirm-group-join").addEventListener("click", () => joinGroup());
        $("confirm-invite").addEventListener("click", acceptInvite);
        $("invite-copy").addEventListener("click", copyInvite);
        $("invite-share").addEventListener("click", shareInvite);
        $("invite-renew").addEventListener("click", () => {
            if (window.confirm(t("invite.renewConfirm")))
                openInviteModal(true);
        });
        $("invite-link").addEventListener("focus", () => $("invite-link").select());
        $("profile-close").addEventListener("click", () => $("profile-modal").classList.add("modal-hidden"));
        $("status-form").addEventListener("submit", (event) => {
            event.preventDefault();
            saveStatus($("status-input").value);
        });
        $("status-clear").addEventListener("click", () => saveStatus(""));
        $("schedule-btn").addEventListener("click", openScheduleDialog);
        // Right-click (or long press) on "Send" also schedules.
        $("send-btn").addEventListener("contextmenu", (event) => {
            event.preventDefault();
            openScheduleDialog();
        });
        $("schedule-cancel").addEventListener("click", () => $("schedule-modal").classList.add("modal-hidden"));
        $("schedule-form").addEventListener("submit", (event) => {
            event.preventDefault();
            scheduleMessage();
        });
        $("scheduled-bar").addEventListener("click", () => openScheduledList());
        $("display-name-form").addEventListener("submit", (event) => {
            event.preventDefault();
            saveDisplayName();
        });
        document.querySelectorAll("[data-open-sub]").forEach((btn) => {
            btn.addEventListener("click", () => openSubModal(btn.dataset.openSub));
        });
        document.querySelectorAll("[data-close-sub]").forEach((btn) => {
            btn.addEventListener("click", () => closeSubModal(btn.closest(".modal-overlay").id));
        });
        $("upload-avatar-btn").addEventListener("click", uploadAvatar);
        $("theme-toggle-btn").addEventListener("click", toggleTheme);
        $("twofa-form").addEventListener("submit", (event) => event.preventDefault());
        $("twofa-add-passkey").addEventListener("click", addPasskey);
        $("twofa-totp-button").addEventListener("click", startTotp);
        $("twofa-totp-confirm").addEventListener("click", confirmTotp);
        $("twofa-code").addEventListener("keydown", (event) => {
            if (event.key === "Enter")
                confirmTotp();
        });
        $("codes-form").addEventListener("submit", (event) => {
            event.preventDefault();
            if (window.confirm(t("settings.codesConfirm")))
                generateCodes();
        });
        $("password-form").addEventListener("submit", (event) => {
            event.preventDefault();
            changePassword();
        });
        // Shows the cookie banner again (above the settings) to change the decision.
        $("cookie-settings-btn").addEventListener("click", () => {
            SeresConsent.show(() => {
                showCookieStatus();
                showAlert(t("settings.cookiesSaved"));
            });
        });
        $("language-select-slot").appendChild(SeresI18n.languageSelect(rerenderLanguage));
        document.querySelectorAll(".list-view-toggle").forEach((btn) => {
            btn.addEventListener("click", () => switchView(btn.dataset.view));
        });
        $("list-search").addEventListener("input", () => {
            startGlobalSearch();
            chatsSignature = "";
            loadChats().catch(() => { });
            renderFriends();
            renderRequests();
        });
        document.querySelectorAll("[data-close-modal]").forEach((btn) => {
            btn.addEventListener("click", closeAllModals);
        });
        document.querySelectorAll(".modal-overlay").forEach((overlay) => {
            overlay.addEventListener("click", (event) => {
                if (event.target !== overlay || overlay.hasAttribute("data-locked"))
                    return;
                // A click next to a small settings dialog only closes that dialog.
                if (overlay.classList.contains("sub-modal"))
                    closeSubModal(overlay.id);
                else
                    closeAllModals();
            });
        });
        const input = $("message-input-field");
        input.addEventListener("keydown", (event) => {
            const mentionOpen = !$("mention-list").classList.contains("modal-hidden");
            if (mentionOpen && (event.key === "Enter" || event.key === "Tab")) {
                const first = $("mention-list").querySelector(".mention-item");
                if (first) {
                    event.preventDefault();
                    insertMention(first.dataset.username);
                    return;
                }
            }
            if (event.key === "Escape") {
                closeMentionList();
                if (replyTo)
                    cancelReply();
                else if (editing)
                    cancelEdit();
            }
            if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                sendMessage();
            }
            // Arrow up in an empty field edits the own last message (like Discord).
            if (event.key === "ArrowUp" && !input.value && current) {
                const own = [...current.messages.values()]
                    .filter((m) => m.sender_id === me.id && m.kind === "e2e" && !m.deleted && !m.silent)
                    .sort((a, b) => b.seq - a.seq)[0];
                const opened = current;
                if (own) {
                    event.preventDefault();
                    showMessage(opened.id, own).then((view) => {
                        if (view.type === "text" && current === opened)
                            startEdit(opened, own, view);
                    });
                }
            }
        });
        input.addEventListener("input", () => {
            autoGrow(input);
            updateSendButton();
            updateMentionList();
            sendTyping(input.value.trim().length > 0);
        });
        input.addEventListener("paste", (event) => {
            const files = [...(event.clipboardData?.files || [])];
            if (files.length) {
                event.preventDefault();
                addPendingFiles(files);
            }
        });
        document.addEventListener("click", (event) => {
            const target = event.target;
            if (!target.closest(".floating-menu"))
                closeFloatingMenus();
            if (!target.closest("#emoji-slot") && !target.closest("#emoji-btn"))
                closeEmojiPicker();
            if (!target.closest(".user-menu-container"))
                $("user-dropdown-menu").classList.add("modal-hidden");
            const sidebar = document.querySelector(".sidebar");
            if (sidebar &&
                sidebar.classList.contains("open") &&
                window.innerWidth <= 768 &&
                !sidebar.contains(target) &&
                !target.closest(".menu-toggle") &&
                !target.closest(".modal-overlay") &&
                current) {
                sidebar.classList.remove("open");
            }
        });
        document.addEventListener("keydown", (event) => {
            if (event.key === "Escape") {
                closeAllModals();
                closeFloatingMenus();
                closeEmojiPicker();
                $("lightbox").classList.add("modal-hidden");
            }
        });
        document.addEventListener("visibilitychange", () => {
            if (document.visibilityState === "visible") {
                refreshAll();
                syncCurrent().catch(() => { });
                markRead();
            }
        });
    }
    let devicesState = null;
    // Logins already answered here, so they don't ask again.
    const answeredLogins = new Set();
    let deviceDialogOpen = false;
    function deviceName(userAgent) {
        const device = SeresDevices.describe(userAgent);
        return `${t("devices.type." + device.type)} · ${device.os} · ${device.browser}`;
    }
    async function loadDevices() {
        const data = await api("/api/devices");
        devicesState = { isMain: !!data.is_main, hasMain: !!data.has_main, devices: data.devices || [] };
        renderDevices();
        return devicesState;
    }
    function renderDevices() {
        const list = $("devices-list");
        if (!devicesState)
            return;
        list.textContent = "";
        const state = devicesState;
        for (const device of state.devices) {
            const info = SeresDevices.describe(device.user_agent);
            const badges = [];
            if (device.current)
                badges.push(t("devices.thisDevice"));
            if (device.main)
                badges.push(t("devices.main"));
            if (!device.approved)
                badges.push(t("devices.waiting"));
            const actions = h("div", { className: "device-actions" });
            if (state.isMain && !device.current) {
                if (!device.approved) {
                    actions.append(button(t("devices.allow"), "request-action-btn", () => answerLogin(device.id, true)), button(t("devices.deny"), "request-action-btn discard", () => answerLogin(device.id, false)));
                }
                else {
                    actions.append(button(t("devices.makeMain"), "request-action-btn", () => makeMainDevice(device)), button(t("devices.logOut"), "request-action-btn discard", () => logOutDevice(device)));
                }
            }
            list.appendChild(h("div", { className: "device-item" + (device.main ? " main" : "") }, [
                h("span", { className: "material-symbols-rounded device-icon", text: info.icon }),
                h("div", { className: "device-info" }, [
                    h("strong", { text: `${t("devices.type." + info.type)} · ${info.os}` }),
                    h("span", {
                        className: "device-meta",
                        text: `${info.browser} · ${t("devices.lastActive", { time: formatDateTime(device.last_seen || device.created_at) })}`,
                    }),
                    badges.length ? h("span", { className: "device-badges", text: badges.join(" · ") }) : null,
                ]),
                actions,
            ]));
        }
        $("link-code-btn").classList.toggle("modal-hidden", !state.isMain);
    }
    async function deviceAction(work) {
        $("devices-warning").textContent = "";
        try {
            await work();
        }
        catch (error) {
            $("devices-warning").textContent = errorText(error);
        }
        await loadDevices().catch(() => { });
    }
    function answerLogin(id, allow) {
        answeredLogins.add(id);
        return deviceAction(() => post("/api/devices/approve", { id, allow }));
    }
    function makeMainDevice(device) {
        if (!window.confirm(t("devices.makeMainConfirm", { device: deviceName(device.user_agent) })))
            return;
        return deviceAction(async () => {
            await post("/api/devices/main", { id: device.id });
            showAlert(t("devices.mainChanged"));
        });
    }
    function logOutDevice(device) {
        if (!window.confirm(t("devices.logOutConfirm", { device: deviceName(device.user_agent) })))
            return;
        return deviceAction(() => post("/api/devices/logout", { id: device.id }));
    }
    /** Lets the user pick one of `devices`; null when cancelled. */
    function chooseDevice(options) {
        const modal = $("device-choice-modal");
        const list = $("device-choice-list");
        $("device-choice-title").textContent = options.title;
        $("device-choice-text").textContent = options.text;
        $("device-choice-warning").textContent = "";
        $("device-choice-cancel").classList.toggle("modal-hidden", !options.cancellable);
        list.textContent = "";
        options.devices.forEach((device, index) => {
            const radio = h("input", { attrs: { type: "radio", name: "device-choice", value: device.id } });
            radio.checked = device.current || (index === 0 && !options.devices.some((d) => d.current));
            const info = SeresDevices.describe(device.user_agent);
            list.appendChild(h("label", { className: "picker-item" }, [
                radio,
                h("span", { className: "material-symbols-rounded device-icon", text: info.icon }),
                h("span", { className: "device-info" }, [
                    h("strong", { text: deviceName(device.user_agent) + (device.current ? ` (${t("devices.thisDevice")})` : "") }),
                    h("span", { className: "device-meta", text: t("devices.lastActive", { time: formatDateTime(device.last_seen || device.created_at) }) }),
                ]),
            ]));
        });
        modal.classList.remove("modal-hidden");
        deviceDialogOpen = true;
        let cleanup = () => { };
        return new Promise((resolve) => {
            const finish = (result) => {
                deviceDialogOpen = false;
                cleanup();
                modal.classList.add("modal-hidden");
                $("device-choice-confirm").removeEventListener("click", onConfirm);
                $("device-choice-cancel").removeEventListener("click", onCancel);
                resolve(result);
            };
            const onConfirm = () => {
                const picked = list.querySelector("input[name=device-choice]:checked");
                if (picked)
                    finish(picked.value);
            };
            const onCancel = () => finish(null);
            const onOutside = (event) => {
                if (event.target === modal && options.cancellable)
                    finish(null);
            };
            const onKey = (event) => {
                if (event.key === "Escape" && options.cancellable)
                    finish(null);
            };
            $("device-choice-confirm").addEventListener("click", onConfirm);
            $("device-choice-cancel").addEventListener("click", onCancel);
            modal.addEventListener("click", onOutside);
            document.addEventListener("keydown", onKey);
            cleanup = () => {
                modal.removeEventListener("click", onOutside);
                document.removeEventListener("keydown", onKey);
            };
        });
    }
    /** Asks the main device about a new login or a device to link: true = allow, false = refuse, null = closed. */
    function askAboutDevice(options) {
        const modal = $("device-request-modal");
        $("device-request-icon").textContent = options.icon;
        $("device-request-title").textContent = options.title;
        $("device-request-text").textContent = options.text;
        $("device-request-check").textContent = options.check || "";
        $("device-request-warning").textContent = "";
        modal.classList.remove("modal-hidden");
        deviceDialogOpen = true;
        return new Promise((resolve) => {
            const finish = (result) => {
                deviceDialogOpen = false;
                modal.classList.add("modal-hidden");
                $("device-request-allow").removeEventListener("click", onAllow);
                $("device-request-deny").removeEventListener("click", onDeny);
                modal.removeEventListener("click", onOutside);
                document.removeEventListener("keydown", onKey);
                resolve(result);
            };
            const onKey = (event) => {
                if (event.key === "Escape")
                    finish(null);
            };
            document.addEventListener("keydown", onKey);
            const onAllow = () => finish(true);
            const onDeny = () => finish(false);
            const onOutside = (event) => {
                if (event.target === modal)
                    finish(null);
            };
            $("device-request-allow").addEventListener("click", onAllow);
            $("device-request-deny").addEventListener("click", onDeny);
            modal.addEventListener("click", onOutside);
        });
    }
    /** First start with several devices and no main device: pick one, the others are logged out. */
    async function chooseFirstMainDevice(state) {
        const devices = state.devices.filter((device) => device.approved);
        const id = await chooseDevice({
            title: t("devices.chooseTitle"),
            text: t("devices.chooseText"),
            devices,
            cancellable: false,
        });
        if (!id)
            return;
        try {
            const result = await post("/api/devices/main", { id });
            if (result.logged_out) {
                // Another device is the main device now; this one was logged out.
                await SeresCrypto.clearIdentities();
                window.location.href = "login.html";
                return;
            }
            showAlert(t("devices.chosen"));
        }
        catch (error) {
            showAlert(errorText(error));
        }
        await loadDevices().catch(() => { });
    }
    /** Checked regularly: picking a main device, and new logins waiting for the main device. */
    async function checkDevices() {
        if (deviceDialogOpen)
            return;
        const state = await loadDevices().catch(() => null);
        if (!state)
            return;
        if (!state.hasMain) {
            await chooseFirstMainDevice(state);
            return;
        }
        if (!state.isMain)
            return;
        const waiting = state.devices.find((device) => !device.approved && !answeredLogins.has(device.id));
        if (!waiting)
            return;
        answeredLogins.add(waiting.id);
        const allow = await askAboutDevice({
            icon: SeresDevices.describe(waiting.user_agent).icon,
            title: t("devices.requestTitle"),
            text: t("devices.requestText", { device: deviceName(waiting.user_agent), time: formatDateTime(waiting.created_at) }),
        });
        if (allow !== null)
            await deviceAction(() => post("/api/devices/approve", { id: waiting.id, allow }));
    }
    /**
     * The main device links a new device: from the QR code / link (token) or
     * the typed code. The account keys go sealed for the new device.
     */
    async function linkDevice(query) {
        try {
            const state = devicesState || (await loadDevices());
            if (!state.isMain) {
                showAlert(t("link.mainOnly"));
                return;
            }
            const found = await post("/api/link/find", query);
            const check = await SeresCrypto.linkCheckCode(found.pub);
            const allow = await askAboutDevice({
                icon: "qr_code_2",
                title: t("link.confirmTitle"),
                text: t("link.confirmText", { device: deviceName(found.user_agent) }),
                check: t("link.checkCompare", { code: check }),
            });
            if (allow === null)
                return;
            if (!allow) {
                await post("/api/link/deny", { id: found.id });
                return;
            }
            const password = await askPassword(t("link.needPassword"));
            if (password === null)
                return;
            const pre = await post("/api/prelogin", { nameomail: me.username });
            const keys = await SeresCrypto.deriveAccountKeys(password, pre.kdf_salt, pre.kdf_iterations);
            const fresh = (await api("/api/me")).user;
            let sealed;
            try {
                sealed = await SeresCrypto.sealPrivateKeys(fresh.enc_private, keys.wrapKey, found.pub);
            }
            catch {
                showAlert(t("settings.wrongPassword"));
                return;
            }
            await post("/api/link/approve", { id: found.id, sealed });
            showAlert(t("link.done"));
        }
        catch (error) {
            showAlert(errorText(error));
        }
        loadDevices().catch(() => { });
    }
    function openLinkCodeDialog() {
        const modal = $("link-code-modal");
        const input = $("link-code-input");
        input.value = "";
        $("link-code-warning").textContent = "";
        modal.classList.remove("modal-hidden");
        setTimeout(() => input.focus(), 30);
    }
    // ------------------------------------------------------------- app
    // The browser's own install dialog (Chrome, Edge), kept until the menu entry is used.
    let installPrompt = null;
    function isInstalled() {
        return window.matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
    }
    function isIos() {
        return /iphone|ipad|ipod/i.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
    }
    /** SereS as an installable app: the service worker and the "Install app" menu entry. */
    function setupApp() {
        if ("serviceWorker" in navigator) {
            navigator.serviceWorker.register("/sw.js").catch((error) => console.warn("Service worker not registered", error));
        }
        window.addEventListener("beforeinstallprompt", (event) => {
            event.preventDefault();
            installPrompt = event;
            $("menu-install").classList.remove("modal-hidden");
        });
        window.addEventListener("appinstalled", () => {
            installPrompt = null;
            $("menu-install").classList.add("modal-hidden");
        });
        // Safari on iPhone and iPad has no install dialog, only "Add to Home Screen".
        if (isIos() && !isInstalled())
            $("menu-install").classList.remove("modal-hidden");
    }
    async function installApp() {
        if (installPrompt) {
            const prompt = installPrompt;
            installPrompt = null;
            prompt.prompt();
            await prompt.userChoice.catch(() => null);
            $("menu-install").classList.add("modal-hidden");
        }
        else if (isIos()) {
            showAlert(t("app.installIos"));
        }
    }
    async function boot() {
        SeresI18n.apply();
        $("my-username-display").textContent = t("common.loading");
        $("mobile-username").textContent = t("common.loading");
        $("current-chat-name").textContent = t("app.welcome");
        cleanLoginRedirect();
        applyTheme();
        setupApp();
        try {
            me = (await api("/api/me")).user;
        }
        catch {
            goToLogin();
            return;
        }
        const stored = await SeresCrypto.loadIdentity(me.id);
        if (!stored || stored.pubEcdh !== me.pub_ecdh || stored.pubSign !== me.pub_sign) {
            // No unlocked keys on this device (or they don't match the account): log in again.
            await fetch("/api/logout", { method: "POST", credentials: "same-origin" }).catch(() => { });
            await SeresCrypto.clearIdentities();
            goToLogin("keys");
            return;
        }
        identity = stored;
        userKeys.set(me.id, { id: me.id, username: me.username, pub_ecdh: me.pub_ecdh, pub_sign: me.pub_sign });
        const meFp = await SeresCrypto.fingerprint(me.pub_ecdh, me.pub_sign);
        const pinKeys = readJsonStore("pin-keys", {});
        if (pinKeys[me.id] && pinKeys[me.id].fp !== meFp) {
            const pinHistory = readJsonStore("pin-history", {});
            appendPinHistory(pinHistory, me.id, pinKeys[me.id], new Date().toISOString());
            writeJsonStore("pin-history", pinHistory);
        }
        pinKeys[me.id] = { fp: meFp, pub_ecdh: me.pub_ecdh, pub_sign: me.pub_sign };
        writeJsonStore("pin-keys", pinKeys);
        showOwnName();
        loadOwnAvatar();
        bindEvents();
        switchView("chats");
        if (window.innerWidth <= 768)
            document.querySelector(".sidebar")?.classList.add("open");
        await refreshAll();
        if (recoveredBy === "code") {
            // Point to the backup codes, one of them was just used.
            await openSettings();
            $("codes-warning").textContent = t("recover.doneCode");
            $("codes-form").scrollIntoView({ block: "center" });
        }
        if (notificationsEnabled())
            subscribePush().catch((error) => console.warn("Push not available", error));
        // Opened from the QR code / link of a new device: link it.
        const linkToken = new URLSearchParams(window.location.search).get("link");
        if (linkToken) {
            window.history.replaceState({}, document.title, window.location.pathname);
            await loadDevices().catch(() => { });
            await linkDevice({ token: linkToken });
        }
        checkDevices().catch(() => { });
        window.setInterval(() => {
            if (document.visibilityState === "visible")
                checkDevices().catch(() => { });
        }, 8000);
        // Opened from a notification: show that chat.
        const chatFromNotification = new URLSearchParams(window.location.search).get("chat");
        if (chatFromNotification) {
            window.history.replaceState({}, document.title, window.location.pathname);
            if (chats.some((chat) => chat.id === chatFromNotification))
                openChat(chatFromNotification);
        }
        navigator.serviceWorker?.addEventListener("message", (event) => {
            if (event.data?.type === "open-chat" && chats.some((chat) => chat.id === event.data.chat)) {
                switchView("chats");
                openChat(event.data.chat);
            }
        });
        if (pendingInvite || pendingJoin) {
            // Remove the token from the address bar so a reload doesn't ask again.
            window.history.replaceState({}, document.title, window.location.pathname);
            if (pendingInvite)
                showInvite(pendingInvite);
            else if (pendingJoin)
                showGroupInvite(pendingJoin);
        }
        // A cached page from before calls existed doesn't load calls.js.
        if (typeof SeresCalls !== "undefined")
            SeresCalls.init({
                api,
                post,
                me: () => me,
                identity: () => identity,
                signKey: async (userId) => {
                    if (!userId || userId === me.id)
                        return null;
                    const pins = readStore("pins");
                    const pinnedFp = pins[userId];
                    if (!pinnedFp)
                        return null;
                    await ensureUserKeys([userId]).catch(() => { });
                    const known = userKeys.get(userId);
                    if (!known)
                        return null;
                    const fp = await memberFingerprint(known);
                    if (!fp || fp !== pinnedFp)
                        return null;
                    return known.pub_sign;
                },
                showAlert,
                errorText,
                pickPeople: pickCallPeople,
                chatCreated: () => {
                    chatsSignature = "";
                    loadChats().catch(() => { });
                },
                openChat: (chatId) => {
                    if (current?.id !== chatId)
                        openChat(chatId);
                },
                avatar: (username, label) => avatarEl(username, { label }),
            });
        window.setInterval(() => {
            if (document.visibilityState === "visible")
                syncCurrent().catch(() => { });
        }, 2500);
        window.setInterval(() => {
            if (document.visibilityState === "visible")
                refreshAll();
        }, 6000);
        // In the background only the chat list is checked, for desktop notifications.
        window.setInterval(() => {
            if (document.visibilityState !== "visible" && notificationsEnabled())
                loadChats().catch(() => { });
        }, 20000);
    }
    document.addEventListener("DOMContentLoaded", () => {
        boot().catch((error) => {
            console.error(error);
            showAlert(errorText(error));
        });
    });
})();
