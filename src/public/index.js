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
    let currentView = "chats";
    let current = null;
    let chatsSignature = "";
    let friendsSignature = "";
    let sending = false;
    const userKeys = new Map();
    const shownCache = new Map();
    const avatarState = new Map();
    const MESSAGE_LIMIT = 4000;
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
    async function api(path, options = {}) {
        const response = await fetch(path, {
            method: options.method || (options.body ? "POST" : "GET"),
            headers: options.body ? { "Content-Type": "application/json" } : {},
            credentials: "same-origin",
            body: options.body ? JSON.stringify(options.body) : undefined,
        });
        if (response.status === 401) {
            window.location.href = "login.html";
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
    let alertTimer = null;
    function showAlert(message) {
        const box = $("alert");
        $("alert-text").textContent = message;
        box.classList.remove("hidden");
        if (alertTimer !== null)
            clearTimeout(alertTimer);
        alertTimer = window.setTimeout(() => box.classList.add("hidden"), 4000);
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
    function avatarEl(name, options = {}) {
        const avatar = h("div", { className: options.className || "avatar" });
        avatar.style.backgroundColor = colorFor(name);
        const initial = h("span", { text: options.group ? "#" : name.charAt(0).toUpperCase() || "?" });
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
    /** Text with clickable http(s) links, built without innerHTML. */
    function richText(text) {
        const fragment = document.createDocumentFragment();
        const pattern = /\bhttps?:\/\/[^\s<>"]+/g;
        let last = 0;
        let match;
        while ((match = pattern.exec(text))) {
            if (match.index > last)
                fragment.appendChild(document.createTextNode(text.slice(last, match.index)));
            const link = h("a", {
                text: match[0],
                attrs: { href: match[0], target: "_blank", rel: "noopener noreferrer nofollow" },
            });
            fragment.appendChild(link);
            last = match.index + match[0].length;
        }
        if (last < text.length)
            fragment.appendChild(document.createTextNode(text.slice(last)));
        return fragment;
    }
    // ------------------------------------------------------------------ keys
    function pinStoreKey(kind) {
        return "seres-" + kind + ":" + me.id;
    }
    function readStore(kind) {
        try {
            return JSON.parse(localStorage.getItem(pinStoreKey(kind)) || "{}");
        }
        catch {
            return {};
        }
    }
    function writeStore(kind, value) {
        try {
            localStorage.setItem(pinStoreKey(kind), JSON.stringify(value));
        }
        catch {
            /* storage unavailable */
        }
    }
    async function memberFingerprint(member) {
        if (!member.pub_ecdh || !member.pub_sign)
            return null;
        return SeresCrypto.fingerprint(member.pub_ecdh, member.pub_sign);
    }
    /**
     * Trust on first use: remember every contact's key fingerprint and warn when
     * the server suddenly hands out a different key for the same person.
     */
    async function checkPins(members) {
        const pins = readStore("pins");
        const changed = [];
        const missing = [];
        let dirty = false;
        for (const member of members) {
            if (member.id === me.id)
                continue;
            const fp = await memberFingerprint(member);
            if (!fp) {
                missing.push(member);
                continue;
            }
            if (!pins[member.id]) {
                pins[member.id] = fp;
                dirty = true;
            }
            else if (pins[member.id] !== fp) {
                changed.push(member);
            }
        }
        if (dirty)
            writeStore("pins", pins);
        return { changed, missing };
    }
    async function acceptNewKeys(members) {
        const pins = readStore("pins");
        const verified = readStore("verified");
        for (const member of members) {
            const fp = await memberFingerprint(member);
            if (fp)
                pins[member.id] = fp;
            delete verified[member.id];
        }
        writeStore("pins", pins);
        writeStore("verified", verified);
    }
    async function ensureUserKeys(ids) {
        const missing = [...new Set(ids)].filter((id) => id && !userKeys.has(id));
        if (!missing.length)
            return;
        const data = await api("/api/users/keys?ids=" + encodeURIComponent(missing.join(",")));
        for (const user of data.users)
            userKeys.set(user.id, user);
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
                return t("system." + payload.event, {
                    actor: payload.actor ?? "",
                    target: payload.target ?? "",
                    name: payload.name ?? "",
                });
            default:
                return "";
        }
    }
    function showMessage(chatId, message) {
        const cacheKey = message.id + ":" + message.rev;
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
                    const sender = userKeys.get(message.sender_id);
                    if (!sender || !sender.pub_ecdh || !sender.pub_sign)
                        throw new Error("unknown sender");
                    const content = await SeresCrypto.decryptMessage(identity, chatId, message.id, { id: sender.id, pub_ecdh: sender.pub_ecdh, pub_sign: sender.pub_sign }, message.payload);
                    return { type: "text", text: String(content.text ?? "") };
                }
                catch (error) {
                    console.warn("Could not decrypt message", message.id, error);
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
        chats = data.chats;
        const previews = await Promise.all(chats.map(async (chat) => (chat.last_message ? showMessage(chat.id, chat.last_message) : null)));
        const signature = JSON.stringify([chats, previews.map((p) => p && p.text)]);
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
    function previewText(chat, shown) {
        if (!chat.last_message || !shown)
            return chat.type === "group" ? t("list.members", { count: chat.member_count }) : t("list.noMessages");
        const message = chat.last_message;
        if (shown.type === "system")
            return shown.text;
        const prefix = message.sender_id === me.id ? t("list.you") : chat.type === "group" && message.sender ? message.sender + ": " : "";
        if (shown.type === "deleted")
            return prefix + t("list.deleted");
        return prefix + shown.text.replace(/\s+/g, " ");
    }
    function renderChatList(previews) {
        const list = $("dm-list");
        const filter = ($("list-search").value || "").toLowerCase();
        list.textContent = "";
        chats.forEach((chat, index) => {
            if (filter && !chat.name.toLowerCase().includes(filter))
                return;
            const item = h("div", {
                className: "list-item chat-list-item" + (current && current.id === chat.id ? " active" : ""),
                attrs: { "data-chatid": chat.id },
            });
            item.appendChild(avatarEl(chat.name, { group: chat.type === "group" }));
            const nameRow = h("div", { className: "item-row" }, [
                h("span", { className: "item-name", text: chat.name }),
                h("span", { className: "item-time", text: formatListTime(chat.last_activity) }),
            ]);
            const statusRow = h("div", { className: "item-row" }, [
                h("span", { className: "item-status", text: previewText(chat, previews[index]) }),
                chat.unread > 0 ? h("span", { className: "unread-badge", text: chat.unread > 99 ? "99+" : String(chat.unread) }) : null,
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
        if (!list.childElementCount) {
            list.appendChild(h("div", { className: "list-empty" }, [
                h("p", { text: t(filter ? "list.noChatsFound" : "list.noChats") }),
                !filter && friends.friends.length
                    ? button(t("list.startChat"), "pill-btn", () => openNewDmModal())
                    : !filter
                        ? button(t("list.addFriend"), "pill-btn", () => openModal("add-friend-modal"))
                        : null,
            ]));
        }
        applyTheme();
    }
    function updateBadges() {
        const unread = chats.reduce((sum, chat) => sum + chat.unread, 0);
        const chatsBadge = $("chats-badge");
        chatsBadge.textContent = unread ? String(unread) : "";
        const requestsBadge = $("requests-badge");
        requestsBadge.textContent = friends.incoming.length ? String(friends.incoming.length) : "";
        document.title = unread ? `(${unread}) SereS` : "SereS";
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
        return h("div", { className: "list-item request-list-item" }, [
            avatarEl(user.username),
            h("div", { className: "item-info" }, [
                h("span", { className: "item-name", text: user.username }),
                h("span", { className: "item-status", text: status }),
            ]),
            h("div", { className: "request-actions" }, actions),
        ]);
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
        const match = (user) => !filter || user.username.toLowerCase().includes(filter);
        list.textContent = "";
        list.appendChild(sectionTitle(t("friends.title", { count: friends.friends.length })));
        friends.friends.filter(match).forEach((friend) => {
            list.appendChild(userRow(friend, t("friends.status"), [
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
            list.appendChild(sectionTitle(t("friends.blocked")));
            friends.blocked.filter(match).forEach((user) => {
                list.appendChild(userRow(user, t("friends.blocked"), [
                    button(t("friends.unblock"), "request-action-btn discard", action("unblock", () => post("/api/unblock", { username: user.username }))),
                ]));
            });
        }
        applyTheme();
    }
    function openUserMenu(user, event) {
        closeFloatingMenus();
        const menu = h("div", { className: "floating-menu" }, [
            button(t("friends.messageMenu"), "floating-item", () => {
                closeFloatingMenus();
                startDm(user.username);
            }),
            button(t("friends.remove"), "floating-item", action("remove", () => post("/api/friends/remove", { username: user.username }), t("friends.removeConfirm", { name: user.username }))),
            button(t("friends.block"), "floating-item danger", action("block", () => post("/api/block", { username: user.username }), t("friends.blockConfirmLong", { name: user.username }))),
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
            button(isGroup ? "🚪 " + t("info.leave") : "🗑️ " + t("info.deleteChat"), "floating-item danger", action(isGroup ? "leave" : "delete", async () => {
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
        list.textContent = "";
        if (!friends.incoming.length) {
            list.appendChild(h("div", { className: "list-item request-list-item" }, [
                h("div", { className: "avatar", text: "!" }),
                h("div", { className: "item-info" }, [
                    h("span", { className: "item-name", text: t("requests.none") }),
                    h("span", { className: "item-status", text: t("requests.noneHint") }),
                ]),
            ]));
        }
        friends.incoming.forEach((user) => {
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
                button(t("friends.blockShort"), "request-action-btn more", action("block", () => post("/api/block", { username: user.username }), t("friends.blockConfirm", { name: user.username }))),
            ]));
        });
        applyTheme();
    }
    function switchView(view) {
        currentView = view;
        document.querySelectorAll(".list-view-toggle").forEach((btn) => {
            btn.classList.toggle("active", btn.dataset.view === view);
        });
        document.querySelectorAll(".list-view-panel").forEach((panel) => {
            panel.classList.toggle("active", panel.dataset.panel === view);
        });
        $("chats-header").style.display = view === "chats" ? "flex" : "none";
        $("list-search").parentElement.style.display = view === "requests" ? "none" : "block";
    }
    // ------------------------------------------------------------ open chat
    async function openChat(chatId) {
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
        };
        const opened = current;
        document.querySelectorAll(".chat-list-item").forEach((item) => {
            item.classList.toggle("active", item.dataset.chatid === chatId);
        });
        const summary = chats.find((chat) => chat.id === chatId);
        $("current-chat-name").textContent = summary ? summary.name : "";
        $("current-chat-sub").textContent = "";
        $("chat-input-area").classList.remove("modal-hidden");
        $("chat-info-btn").classList.remove("modal-hidden");
        $("messages").textContent = "";
        if (window.innerWidth <= 768)
            document.querySelector(".sidebar")?.classList.remove("open");
        try {
            await refreshCurrentDetails();
            const data = await api(`/api/chats/${encodeURIComponent(chatId)}/messages?limit=50`);
            if (current !== opened)
                return;
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
    function closeChat() {
        current = null;
        $("current-chat-name").textContent = t("app.welcomeUser", { name: me.username });
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
            h("div", { className: "empty-state-icon", text: "💬" }),
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
        $("current-chat-sub").textContent =
            details.type === "group"
                ? t("chat.groupSub", { count: details.member_count })
                : details.blocked
                    ? t("chat.blocked")
                    : t("chat.dmSub");
        renderKeyWarning();
    }
    function renderKeyWarning() {
        const box = $("key-warning");
        box.textContent = "";
        if (!current)
            return;
        if (current.changedKeys.length) {
            const names = current.changedKeys.map((m) => m.username).join(", ");
            box.appendChild(h("span", {
                text: t("chat.keyChanged", { names }),
            }));
            box.appendChild(button(t("chat.acceptKey"), "pill-btn", async () => {
                if (!current)
                    return;
                await acceptNewKeys(current.changedKeys);
                await refreshCurrentDetails();
            }));
            box.appendChild(button(t("app.chatInfo"), "pill-btn secondary", () => openChatInfo()));
        }
        else if (current.missingKeys.length) {
            const names = current.missingKeys.map((m) => m.username).join(", ");
            box.appendChild(h("span", {
                text: t("chat.keyMissing", { names }),
            }));
        }
        box.classList.toggle("modal-hidden", !box.childElementCount);
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
        if (mergeMessages(data.messages)) {
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
        const ordered = [...opened.messages.values()].sort((a, b) => a.seq - b.seq);
        const shown = await Promise.all(ordered.map((message) => showMessage(opened.id, message)));
        if (current !== opened)
            return;
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
            fragment.appendChild(messageRow(opened, message, view, compact));
            previous = message;
        });
        container.textContent = "";
        container.appendChild(fragment);
        applyTheme();
        if (options.keepPosition) {
            container.scrollTop = container.scrollHeight - container.clientHeight - distanceFromBottom;
        }
        else if (options.forceBottom || nearBottom) {
            container.scrollTop = container.scrollHeight;
        }
    }
    function messageRow(opened, message, view, compact) {
        const own = message.sender_id === me.id;
        const sender = message.sender || t("msg.unknown");
        const row = h("div", {
            className: "message-row" + (own ? " message-own" : "") + (compact ? " message-compact" : ""),
            attrs: { "data-id": message.id },
        });
        row.appendChild(compact ? h("div", { className: "message-avatar spacer" }) : avatarEl(sender, { className: "message-avatar" }));
        const wrapper = h("div", { className: "message-content-wrapper" });
        if (!compact) {
            const header = h("div", { className: "message-header" }, [
                h("span", { className: "message-sender", text: own ? t("msg.you") : sender }),
                h("span", { className: "message-timestamp", text: formatTime(message.created_at) }),
            ]);
            if (view.type === "legacy") {
                header.appendChild(h("span", {
                    className: "message-flag",
                    text: t("msg.notEncrypted"),
                    title: t("msg.notEncryptedHint"),
                }));
            }
            wrapper.appendChild(header);
        }
        const textDiv = h("div", { className: "message-text" });
        if (view.type === "deleted" || view.type === "error") {
            textDiv.classList.add("message-muted");
            textDiv.textContent = view.type === "deleted" ? "🚫 " + view.text : view.text;
        }
        else {
            textDiv.appendChild(richText(view.text));
        }
        textDiv.title = parseTime(message.created_at).toLocaleString(SeresI18n.getLanguage());
        wrapper.appendChild(textDiv);
        if (own && !message.deleted && message.kind === "e2e") {
            wrapper.appendChild(button(t("msg.delete"), "message-delete", async () => {
                if (!window.confirm(t("msg.deleteConfirm")))
                    return;
                try {
                    await post(`/api/chats/${encodeURIComponent(opened.id)}/messages/${encodeURIComponent(message.id)}/delete`);
                    await syncCurrent();
                }
                catch (error) {
                    showAlert(errorText(error));
                }
            }, t("msg.deleteTitle")));
        }
        row.appendChild(wrapper);
        return row;
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
    async function sendMessage() {
        const input = $("message-input-field");
        const text = input.value.trim();
        if (!text || !current || sending)
            return;
        if (text.length > MESSAGE_LIMIT) {
            showAlert(t("msg.tooLong", { limit: MESSAGE_LIMIT }));
            return;
        }
        const opened = current;
        sending = true;
        $("send-btn").disabled = true;
        try {
            for (let attempt = 0; attempt < 2; attempt++) {
                if (!opened.details || attempt > 0)
                    await refreshCurrentDetails();
                if (current !== opened || !opened.details)
                    return;
                if (opened.changedKeys.length) {
                    showAlert(t("msg.keyChanged"));
                    return;
                }
                if (opened.missingKeys.length) {
                    showAlert(t("msg.missingKeys"));
                    return;
                }
                const members = (opened.details.members || []).map((m) => ({
                    id: m.id,
                    pub_ecdh: m.pub_ecdh,
                    pub_sign: m.pub_sign,
                }));
                const messageId = newMessageId();
                const payload = await SeresCrypto.encryptMessage(identity, opened.id, messageId, { text }, members);
                try {
                    await post(`/api/chats/${encodeURIComponent(opened.id)}/messages`, { id: messageId, payload });
                    input.value = "";
                    autoGrow(input);
                    await syncCurrent();
                    loadChats().catch(() => { });
                    return;
                }
                catch (error) {
                    // 409: the member list changed in the meantime, encrypt again for the new members.
                    if (error instanceof ApiError && error.status === 409 && attempt === 0)
                        continue;
                    throw error;
                }
            }
        }
        catch (error) {
            showAlert(errorText(error));
        }
        finally {
            sending = false;
            $("send-btn").disabled = false;
        }
    }
    function autoGrow(textarea) {
        textarea.style.height = "auto";
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
    function openNewDmModal() {
        const list = $("new-dm-list");
        list.textContent = "";
        $("warning-new-dm").textContent = "";
        if (!friends.friends.length) {
            list.appendChild(h("p", { text: t("chat.noFriends") }));
        }
        friends.friends.forEach((friend) => {
            const row = h("div", { className: "picker-item" }, [
                avatarEl(friend.username),
                h("span", { className: "item-name", text: friend.username }),
            ]);
            row.addEventListener("click", () => startDm(friend.username));
            list.appendChild(row);
        });
        openModal("new-dm-modal");
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
                avatarEl(friend.username),
                h("span", { className: "item-name", text: friend.username }),
            ]));
        });
    }
    function checkedUsernames(container) {
        return [...container.querySelectorAll("input[type=checkbox]:checked")].map((box) => box.value);
    }
    function openNewGroupModal() {
        $("new-group-name").value = "";
        $("warning-new-group").textContent = "";
        friendCheckboxes($("new-group-list"), new Set());
        openModal("new-group-modal");
    }
    async function createGroup() {
        const name = $("new-group-name").value.trim();
        const usernames = checkedUsernames($("new-group-list"));
        const warning = $("warning-new-group");
        if (!name) {
            warning.textContent = t("chat.groupNameMissing");
            return;
        }
        if (!usernames.length) {
            warning.textContent = t("chat.pickFriend");
            return;
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
        if (details.type === "dm") {
            const other = members.find((m) => m.id !== me.id);
            if (other) {
                body.appendChild(h("div", { className: "info-user" }, [avatarEl(other.username), h("strong", { text: other.username })]));
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
                        ? button(t("friends.unblock"), "pill-btn", action("unblock", () => post("/api/unblock", { username: other.username })))
                        : button(t("friends.block"), "pill-btn danger", action("block", () => post("/api/block", { username: other.username }), t("friends.blockConfirm", { name: other.username }))),
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
            }
            body.appendChild(h("p", { text: t("info.groupMembers", { count: members.length }) }));
            for (const member of members) {
                const fp = await memberFingerprint(member);
                const isMe = member.id === me.id;
                const row = h("div", { className: "member-row" }, [
                    avatarEl(member.username),
                    h("div", { className: "item-info" }, [
                        h("span", {
                            className: "item-name",
                            text: (isMe ? t("msg.you") : member.username) + (member.role === "owner" ? t("info.owner") : ""),
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
                        window.alert(t("info.codeAlert", { name: member.username, code }));
                    }));
                    row.appendChild(verifyToggle(member.id, fp, verified, true));
                }
                if (isOwner && !isMe) {
                    row.appendChild(button(t("info.remove"), "request-action-btn discard", action("remove", async () => {
                        await post(`/api/chats/${encodeURIComponent(details.id)}/members/remove`, { username: member.username });
                        await openChatInfo();
                    }, t("info.removeConfirm", { name: member.username }))));
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
    function verifyToggle(userId, fp, verified, compact = false) {
        const isVerified = verified[userId] === fp;
        return button(t(isVerified ? "info.verified" : compact ? "info.verify" : "info.markVerified"), "pill-btn" + (isVerified ? " verified" : " secondary"), () => {
            const store = readStore("verified");
            if (store[userId] === fp)
                delete store[userId];
            else
                store[userId] = fp;
            writeStore("verified", store);
            openChatInfo();
        });
    }
    // ------------------------------------------------------------- modals
    function openModal(id) {
        closeFloatingMenus();
        $(id).classList.remove("modal-hidden");
        const input = $(id).querySelector("input[type=text]");
        if (input)
            setTimeout(() => input.focus(), 30);
    }
    function closeAllModals() {
        document.querySelectorAll(".modal-overlay").forEach((modal) => modal.classList.add("modal-hidden"));
    }
    // ------------------------------------------------------------ settings
    async function uploadAvatar() {
        const input = $("avatar-upload-input");
        const warning = $("settings-warning");
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
            showAlert(t("settings.avatarUpdated"));
        }
        catch (error) {
            warning.textContent = errorText(error);
        }
    }
    async function changePassword() {
        const warning = $("settings-warning");
        const oldPw = $("old-password").value;
        const newPw = $("new-password").value;
        const repeat = $("new-password-repeat").value;
        warning.textContent = "";
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
            showAlert(t("settings.passwordChanged"));
        }
        catch (error) {
            warning.textContent = errorText(error);
        }
    }
    async function openSettings() {
        $("user-dropdown-menu").classList.add("modal-hidden");
        $("settings-warning").textContent = "";
        openModal("settings-modal");
        const fp = await SeresCrypto.fingerprint(identity.pubEcdh, identity.pubSign);
        $("my-fingerprint").textContent = fp.replace(/(.{4})/g, "$1 ").trim();
    }
    function loadOwnAvatar() {
        const text = $("user-avatar-text");
        const img = $("user-avatar-img");
        text.textContent = me.username.charAt(0).toUpperCase();
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
    function loadAnimation() {
        const introLayer = $("intro-layer");
        const introVideo = $("intro-video");
        const removeOverlay = () => {
            introLayer.style.opacity = "0";
            setTimeout(() => introLayer.remove(), 500);
        };
        const params = new URLSearchParams(window.location.search);
        const isLoginRedirect = params.get("login") === "true";
        const firstLoad = sessionStorage.getItem("sessionStarted") === null;
        if (isLoginRedirect)
            window.history.replaceState({}, document.title, window.location.pathname);
        if (!isLoginRedirect && !firstLoad) {
            introLayer.remove();
            return;
        }
        sessionStorage.setItem("sessionStarted", "true");
        if (!introVideo) {
            introLayer.remove();
            return;
        }
        const safety = setTimeout(removeOverlay, 5000);
        introVideo.play().catch(() => {
            clearTimeout(safety);
            introLayer.remove();
        });
        introVideo.onended = () => {
            clearTimeout(safety);
            setTimeout(removeOverlay, 1000);
        };
    }
    // ---------------------------------------------------------------- boot
    async function refreshAll() {
        await Promise.all([loadFriends(), loadChats()]).catch((error) => {
            if (!(error instanceof ApiError && error.status === 401))
                console.error(error);
        });
        if (current)
            await refreshCurrentDetails().catch(() => { });
    }
    function bindEvents() {
        $("btn-add-friend").addEventListener("click", () => {
            $("warning-add-friend").textContent = "";
            openModal("add-friend-modal");
        });
        $("confirm-add-friend").addEventListener("click", addFriend);
        $("friends-username-input").addEventListener("keydown", (event) => {
            if (event.key === "Enter")
                addFriend();
        });
        $("btn-new-dm").addEventListener("click", openNewDmModal);
        $("btn-new-group").addEventListener("click", openNewGroupModal);
        $("confirm-new-group").addEventListener("click", createGroup);
        $("chat-info-btn").addEventListener("click", openChatInfo);
        $("send-btn").addEventListener("click", sendMessage);
        $("menu-toggle").addEventListener("click", () => document.querySelector(".sidebar")?.classList.toggle("open"));
        $("user-menu-trigger").addEventListener("click", () => $("user-dropdown-menu").classList.toggle("modal-hidden"));
        $("menu-settings").addEventListener("click", (event) => {
            event.preventDefault();
            openSettings();
        });
        $("menu-logout").addEventListener("click", (event) => {
            event.preventDefault();
            logout();
        });
        $("upload-avatar-btn").addEventListener("click", uploadAvatar);
        $("theme-toggle-btn").addEventListener("click", toggleTheme);
        $("change-password-btn").addEventListener("click", changePassword);
        $("cookie-settings-btn").addEventListener("click", () => {
            closeAllModals();
            SeresConsent.show();
        });
        $("language-select-slot").appendChild(SeresI18n.languageSelect(rerenderLanguage));
        document.querySelectorAll(".list-view-toggle").forEach((btn) => {
            btn.addEventListener("click", () => switchView(btn.dataset.view));
        });
        $("list-search").addEventListener("input", () => {
            chatsSignature = "";
            loadChats().catch(() => { });
            renderFriends();
        });
        document.querySelectorAll("[data-close-modal]").forEach((btn) => {
            btn.addEventListener("click", closeAllModals);
        });
        document.querySelectorAll(".modal-overlay").forEach((overlay) => {
            overlay.addEventListener("click", (event) => {
                if (event.target === overlay)
                    closeAllModals();
            });
        });
        const input = $("message-input-field");
        input.addEventListener("keydown", (event) => {
            if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                sendMessage();
            }
        });
        input.addEventListener("input", () => autoGrow(input));
        document.addEventListener("click", (event) => {
            const target = event.target;
            if (!target.closest(".floating-menu"))
                closeFloatingMenus();
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
    async function boot() {
        SeresI18n.apply();
        $("my-username-display").textContent = t("common.loading");
        $("mobile-username").textContent = t("common.loading");
        $("current-chat-name").textContent = t("app.welcome");
        loadAnimation();
        applyTheme();
        try {
            me = (await api("/api/me")).user;
        }
        catch {
            window.location.href = "login.html";
            return;
        }
        const stored = await SeresCrypto.loadIdentity(me.id);
        if (!stored || stored.pubEcdh !== me.pub_ecdh || stored.pubSign !== me.pub_sign) {
            // No unlocked keys on this device (or they don't match the account): log in again.
            await fetch("/api/logout", { method: "POST", credentials: "same-origin" }).catch(() => { });
            await SeresCrypto.clearIdentities();
            window.location.href = "login.html?reason=keys";
            return;
        }
        identity = stored;
        userKeys.set(me.id, { id: me.id, username: me.username, pub_ecdh: me.pub_ecdh, pub_sign: me.pub_sign });
        $("my-username-display").textContent = me.username;
        $("mobile-username").textContent = me.username;
        $("current-chat-name").textContent = t("app.welcomeUser", { name: me.username });
        loadOwnAvatar();
        bindEvents();
        switchView("chats");
        if (window.innerWidth <= 768)
            document.querySelector(".sidebar")?.classList.add("open");
        await refreshAll();
        window.setInterval(() => {
            if (document.visibilityState === "visible")
                syncCurrent().catch(() => { });
        }, 2500);
        window.setInterval(() => {
            if (document.visibilityState === "visible")
                refreshAll();
        }, 6000);
    }
    document.addEventListener("DOMContentLoaded", () => {
        boot().catch((error) => {
            console.error(error);
            showAlert(errorText(error));
        });
    });
})();
