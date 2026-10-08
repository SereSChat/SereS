(() => {
  // ------------------------------------------------------------------ types

  interface UserRef {
    id: string;
    username: string;
  }

  interface Me extends UserRef {
    email: string;
    pub_ecdh: string;
    pub_sign: string;
    enc_private: string;
  }

  interface Member extends UserRef {
    pub_ecdh: string | null;
    pub_sign: string | null;
    role: string;
  }

  interface Message {
    seq: number;
    rev: number;
    id: string;
    sender_id: string | null;
    sender: string | null;
    kind: "e2e" | "legacy" | "system";
    payload: any;
    created_at: string;
    deleted: boolean;
  }

  interface ChatSummary {
    id: string;
    type: "dm" | "group";
    name: string;
    role: string;
    member_count: number;
    last_message: Message | null;
    unread: number;
    last_activity: string;
    other_user?: string;
    other_user_id?: string;
    blocked?: boolean;
    members?: Member[];
    owner_id?: string;
  }

  interface Shown {
    type: "text" | "legacy" | "system" | "deleted" | "error";
    text: string;
  }

  interface OpenChat {
    id: string;
    details: ChatSummary | null;
    messages: Map<string, Message>;
    maxRev: number;
    oldestSeq: number;
    hasMore: boolean;
    lastReadSent: number;
    changedKeys: Member[];
    missingKeys: Member[];
  }

  class ApiError extends Error {
    constructor(
      message: string,
      public status: number,
    ) {
      super(message);
    }
  }

  // ------------------------------------------------------------------ state

  let me: Me;
  let identity: SeresIdentity;
  let chats: ChatSummary[] = [];
  let friends = {
    friends: [] as UserRef[],
    incoming: [] as UserRef[],
    outgoing: [] as UserRef[],
    blocked: [] as UserRef[],
  };
  let currentView: "chats" | "friends" | "requests" = "chats";
  let current: OpenChat | null = null;
  let chatsSignature = "";
  let friendsSignature = "";
  let sending = false;

  const userKeys = new Map<string, { id: string; username: string; pub_ecdh: string | null; pub_sign: string | null }>();
  const shownCache = new Map<string, Promise<Shown>>();
  const avatarState = new Map<string, "yes" | "no">();

  const MESSAGE_LIMIT = 4000;

  // ------------------------------------------------------------- utilities

  function $(id: string): HTMLElement {
    return document.getElementById(id) as HTMLElement;
  }

  function h<K extends keyof HTMLElementTagNameMap>(
    tag: K,
    options: { className?: string; text?: string; title?: string; attrs?: Record<string, string> } = {},
    children: (Node | null | undefined | false)[] = [],
  ): HTMLElementTagNameMap[K] {
    const element = document.createElement(tag);
    if (options.className) element.className = options.className;
    if (options.text !== undefined) element.textContent = options.text;
    if (options.title) element.title = options.title;
    for (const [key, value] of Object.entries(options.attrs || {})) {
      element.setAttribute(key, value);
    }
    for (const child of children) {
      if (child) element.appendChild(child);
    }
    return element;
  }

  function button(text: string, className: string, onClick: (event: MouseEvent) => void, title?: string) {
    const btn = h("button", { className, text, title, attrs: { type: "button" } });
    btn.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      onClick(event);
    });
    return btn;
  }

  async function api(path: string, options: { method?: string; body?: object } = {}): Promise<any> {
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
      throw new ApiError(data.message || "Request failed", response.status);
    }
    return data;
  }

  function post(path: string, body: object = {}) {
    return api(path, { method: "POST", body });
  }

  let alertTimer: number | null = null;
  function showAlert(message: string) {
    const box = $("alert");
    $("alert-text").textContent = message;
    box.classList.remove("hidden");
    if (alertTimer !== null) clearTimeout(alertTimer);
    alertTimer = window.setTimeout(() => box.classList.add("hidden"), 4000);
  }

  function errorText(error: unknown) {
    if (error instanceof ApiError) return error.message;
    if (error instanceof TypeError) return "Server unreachable. Please try again later.";
    return error instanceof Error ? error.message : String(error);
  }

  function colorFor(name: string) {
    const palette = ["#5865f2", "#00a884", "#eb459e", "#f0b232", "#3ba55d", "#ed4245", "#53bdeb", "#9b59b6"];
    let hash = 0;
    for (let i = 0; i < name.length; i++) hash = (hash * 31 + name.charCodeAt(i)) | 0;
    return palette[Math.abs(hash) % palette.length];
  }

  function avatarEl(name: string, options: { group?: boolean; className?: string } = {}) {
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

  function parseTime(iso: string) {
    return new Date(iso);
  }

  function formatTime(iso: string) {
    return parseTime(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  function formatDay(date: Date) {
    const today = new Date();
    const yesterday = new Date();
    yesterday.setDate(today.getDate() - 1);
    if (date.toDateString() === today.toDateString()) return "Today";
    if (date.toDateString() === yesterday.toDateString()) return "Yesterday";
    return date.toLocaleDateString([], { day: "2-digit", month: "2-digit", year: "numeric" });
  }

  function formatListTime(iso: string) {
    const date = parseTime(iso);
    return date.toDateString() === new Date().toDateString()
      ? formatTime(iso)
      : date.toLocaleDateString([], { day: "2-digit", month: "2-digit" });
  }

  /** Text with clickable http(s) links, built without innerHTML. */
  function richText(text: string) {
    const fragment = document.createDocumentFragment();
    const pattern = /\bhttps?:\/\/[^\s<>"]+/g;
    let last = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(text))) {
      if (match.index > last) fragment.appendChild(document.createTextNode(text.slice(last, match.index)));
      const link = h("a", {
        text: match[0],
        attrs: { href: match[0], target: "_blank", rel: "noopener noreferrer nofollow" },
      });
      fragment.appendChild(link);
      last = match.index + match[0].length;
    }
    if (last < text.length) fragment.appendChild(document.createTextNode(text.slice(last)));
    return fragment;
  }

  // ------------------------------------------------------------------ keys

  function pinStoreKey(kind: string) {
    return "seres-" + kind + ":" + me.id;
  }

  function readStore(kind: string): Record<string, string> {
    try {
      return JSON.parse(localStorage.getItem(pinStoreKey(kind)) || "{}");
    } catch {
      return {};
    }
  }

  function writeStore(kind: string, value: Record<string, string>) {
    try {
      localStorage.setItem(pinStoreKey(kind), JSON.stringify(value));
    } catch {
      /* storage unavailable */
    }
  }

  async function memberFingerprint(member: { pub_ecdh: string | null; pub_sign: string | null }) {
    if (!member.pub_ecdh || !member.pub_sign) return null;
    return SeresCrypto.fingerprint(member.pub_ecdh, member.pub_sign);
  }

  /**
   * Trust on first use: remember every contact's key fingerprint and warn when
   * the server suddenly hands out a different key for the same person.
   */
  async function checkPins(members: Member[]) {
    const pins = readStore("pins");
    const changed: Member[] = [];
    const missing: Member[] = [];
    let dirty = false;
    for (const member of members) {
      if (member.id === me.id) continue;
      const fp = await memberFingerprint(member);
      if (!fp) {
        missing.push(member);
        continue;
      }
      if (!pins[member.id]) {
        pins[member.id] = fp;
        dirty = true;
      } else if (pins[member.id] !== fp) {
        changed.push(member);
      }
    }
    if (dirty) writeStore("pins", pins);
    return { changed, missing };
  }

  async function acceptNewKeys(members: Member[]) {
    const pins = readStore("pins");
    const verified = readStore("verified");
    for (const member of members) {
      const fp = await memberFingerprint(member);
      if (fp) pins[member.id] = fp;
      delete verified[member.id];
    }
    writeStore("pins", pins);
    writeStore("verified", verified);
  }

  async function ensureUserKeys(ids: string[]) {
    const missing = [...new Set(ids)].filter((id) => id && !userKeys.has(id));
    if (!missing.length) return;
    const data = await api("/api/users/keys?ids=" + encodeURIComponent(missing.join(",")));
    for (const user of data.users) userKeys.set(user.id, user);
  }

  function systemText(payload: any) {
    if (!payload) return "";
    switch (payload.event) {
      case "created":
        return `${payload.actor} created the group "${payload.name}"`;
      case "added":
        return `${payload.actor} added ${payload.target}`;
      case "removed":
        return `${payload.actor} removed ${payload.target}`;
      case "left":
        return `${payload.actor} left the group`;
      case "renamed":
        return `${payload.actor} renamed the group to "${payload.name}"`;
      default:
        return "";
    }
  }

  function showMessage(chatId: string, message: Message): Promise<Shown> {
    const cacheKey = message.id + ":" + message.rev;
    let shown = shownCache.get(cacheKey);
    if (!shown) {
      shown = (async (): Promise<Shown> => {
        if (message.deleted) return { type: "deleted", text: "This message was deleted" };
        if (message.kind === "system") return { type: "system", text: systemText(message.payload) };
        if (message.kind === "legacy") return { type: "legacy", text: String(message.payload?.text ?? "") };
        try {
          await ensureUserKeys([message.sender_id!]);
          const sender = userKeys.get(message.sender_id!);
          if (!sender || !sender.pub_ecdh || !sender.pub_sign) throw new Error("unknown sender");
          const content = await SeresCrypto.decryptMessage(
            identity,
            chatId,
            message.id,
            { id: sender.id, pub_ecdh: sender.pub_ecdh, pub_sign: sender.pub_sign },
            message.payload,
          );
          return { type: "text", text: String(content.text ?? "") };
        } catch (error) {
          console.warn("Could not decrypt message", message.id, error);
          return { type: "error", text: "⚠ This message could not be decrypted or verified." };
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
    const previews = await Promise.all(
      chats.map(async (chat) => (chat.last_message ? showMessage(chat.id, chat.last_message) : null)),
    );
    const signature = JSON.stringify([chats, previews.map((p) => p && p.text)]);
    updateBadges();
    if (signature === chatsSignature) return;
    chatsSignature = signature;
    renderChatList(previews);
    if (current) {
      const summary = chats.find((chat) => chat.id === current!.id);
      if (!summary) {
        closeChat();
      } else if (current.details && summary.member_count !== current.details.member_count) {
        refreshCurrentDetails();
      }
    }
  }

  function previewText(chat: ChatSummary, shown: Shown | null) {
    if (!chat.last_message || !shown) return chat.type === "group" ? `${chat.member_count} members` : "No messages yet";
    const message = chat.last_message;
    if (shown.type === "system") return shown.text;
    const prefix = message.sender_id === me.id ? "You: " : chat.type === "group" && message.sender ? message.sender + ": " : "";
    if (shown.type === "deleted") return prefix + "🚫 deleted message";
    return prefix + shown.text.replace(/\s+/g, " ");
  }

  function renderChatList(previews: (Shown | null)[]) {
    const list = $("dm-list");
    const filter = (($("list-search") as HTMLInputElement).value || "").toLowerCase();
    list.textContent = "";
    chats.forEach((chat, index) => {
      if (filter && !chat.name.toLowerCase().includes(filter)) return;
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
      list.appendChild(item);
    });
    if (!list.childElementCount) {
      list.appendChild(
        h("div", { className: "list-empty" }, [
          h("p", { text: filter ? "No chats found." : "No chats yet." }),
          !filter && friends.friends.length
            ? button("Start a chat", "pill-btn", () => openNewDmModal())
            : !filter
              ? button("Add a friend", "pill-btn", () => openModal("add-friend-modal"))
              : null,
        ]),
      );
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
    if (signature === friendsSignature) return;
    friendsSignature = signature;
    renderFriends();
    renderRequests();
  }

  function sectionTitle(text: string) {
    return h("div", { className: "section-title", text });
  }

  function userRow(user: UserRef, status: string, actions: HTMLElement[]) {
    return h("div", { className: "list-item request-list-item" }, [
      avatarEl(user.username),
      h("div", { className: "item-info" }, [
        h("span", { className: "item-name", text: user.username }),
        h("span", { className: "item-status", text: status }),
      ]),
      h("div", { className: "request-actions" }, actions),
    ]);
  }

  function action(label: string, fn: () => Promise<unknown>, confirmText?: string) {
    return async () => {
      if (confirmText && !window.confirm(confirmText)) return;
      try {
        await fn();
      } catch (error) {
        showAlert(errorText(error));
      }
      await refreshAll();
    };
  }

  function renderFriends() {
    const list = $("friends-list");
    const filter = (($("list-search") as HTMLInputElement).value || "").toLowerCase();
    const match = (user: UserRef) => !filter || user.username.toLowerCase().includes(filter);
    list.textContent = "";

    list.appendChild(sectionTitle(`Friends — ${friends.friends.length}`));
    friends.friends.filter(match).forEach((friend) => {
      list.appendChild(
        userRow(friend, "Friend", [
          button("Message", "request-action-btn accept", () => startDm(friend.username)),
          button("⋯", "request-action-btn more", (event) => openUserMenu(friend, event)),
        ]),
      );
    });
    if (!friends.friends.length) {
      list.appendChild(
        h("div", { className: "list-empty" }, [
          h("p", { text: "No friends yet." }),
          button("Add a friend", "pill-btn", () => openModal("add-friend-modal")),
        ]),
      );
    }

    if (friends.outgoing.length) {
      list.appendChild(sectionTitle("Sent requests"));
      friends.outgoing.filter(match).forEach((user) => {
        list.appendChild(
          userRow(user, "Waiting for answer", [
            button("Cancel", "request-action-btn discard", action("cancel", () => post("/api/friends/cancel", { username: user.username }))),
          ]),
        );
      });
    }

    if (friends.blocked.length) {
      list.appendChild(sectionTitle("Blocked"));
      friends.blocked.filter(match).forEach((user) => {
        list.appendChild(
          userRow(user, "Blocked", [
            button("Unblock", "request-action-btn discard", action("unblock", () => post("/api/unblock", { username: user.username }))),
          ]),
        );
      });
    }
    applyTheme();
  }

  function openUserMenu(user: UserRef, event: MouseEvent) {
    closeFloatingMenus();
    const menu = h("div", { className: "floating-menu" }, [
      button("💬 Message", "floating-item", () => {
        closeFloatingMenus();
        startDm(user.username);
      }),
      button(
        "Remove friend",
        "floating-item",
        action("remove", () => post("/api/friends/remove", { username: user.username }), `Remove ${user.username} as a friend?`),
      ),
      button(
        "⛔ Block",
        "floating-item danger",
        action(
          "block",
          () => post("/api/block", { username: user.username }),
          `Block ${user.username}? They can't send you requests or direct messages anymore.`,
        ),
      ),
    ]);
    const rect = (event.currentTarget as HTMLElement).getBoundingClientRect();
    menu.style.top = Math.min(rect.bottom + 4, window.innerHeight - 140) + "px";
    menu.style.left = Math.max(8, rect.right - 180) + "px";
    document.body.appendChild(menu);
  }

  function closeFloatingMenus() {
    document.querySelectorAll(".floating-menu").forEach((menu) => menu.remove());
  }

  function renderRequests() {
    const list = $("requests-list");
    list.textContent = "";
    if (!friends.incoming.length) {
      list.appendChild(
        h("div", { className: "list-item request-list-item" }, [
          h("div", { className: "avatar", text: "!" }),
          h("div", { className: "item-info" }, [
            h("span", { className: "item-name", text: "No pending requests" }),
            h("span", { className: "item-status", text: "Friend requests you received will show here." }),
          ]),
        ]),
      );
    }
    friends.incoming.forEach((user) => {
      list.appendChild(
        userRow(user, "Wants to be your friend", [
          button("Accept", "request-action-btn accept", async () => {
            try {
              await post("/api/friends/accept", { username: user.username });
              await startDm(user.username);
            } catch (error) {
              showAlert(errorText(error));
            }
            await refreshAll();
          }),
          button("Decline", "request-action-btn discard", action("decline", () => post("/api/friends/decline", { username: user.username }))),
          button(
            "Block",
            "request-action-btn more",
            action("block", () => post("/api/block", { username: user.username }), `Block ${user.username}?`),
          ),
        ]),
      );
    });
    applyTheme();
  }

  function switchView(view: "chats" | "friends" | "requests") {
    currentView = view;
    document.querySelectorAll<HTMLElement>(".list-view-toggle").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.view === view);
    });
    document.querySelectorAll<HTMLElement>(".list-view-panel").forEach((panel) => {
      panel.classList.toggle("active", panel.dataset.panel === view);
    });
    $("chats-header").style.display = view === "chats" ? "flex" : "none";
    $("list-search").parentElement!.style.display = view === "requests" ? "none" : "block";
  }

  // ------------------------------------------------------------ open chat

  async function openChat(chatId: string) {
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
      item.classList.toggle("active", (item as HTMLElement).dataset.chatid === chatId);
    });
    const summary = chats.find((chat) => chat.id === chatId);
    $("current-chat-name").textContent = summary ? summary.name : "";
    $("current-chat-sub").textContent = "";
    $("chat-input-area").classList.remove("modal-hidden");
    $("chat-info-btn").classList.remove("modal-hidden");
    $("messages").textContent = "";

    if (window.innerWidth <= 768) document.querySelector(".sidebar")?.classList.remove("open");

    try {
      await refreshCurrentDetails();
      const data = await api(`/api/chats/${encodeURIComponent(chatId)}/messages?limit=50`);
      if (current !== opened) return;
      mergeMessages(data.messages);
      opened.hasMore = data.has_more;
      await renderMessages({ forceBottom: true });
      markRead();
      ($("message-input-field") as HTMLTextAreaElement).focus();
    } catch (error) {
      showAlert(errorText(error));
    }
  }

  function closeChat() {
    current = null;
    $("current-chat-name").textContent = "Welcome " + me.username;
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
      h("p", {
        text: "Pick a chat or start a new one.",
      }),
    ]);
  }

  async function refreshCurrentDetails() {
    if (!current) return;
    const opened = current;
    const data = await api(`/api/chats/${encodeURIComponent(opened.id)}`);
    if (current !== opened) return;
    const details: ChatSummary = data.chat;
    opened.details = details;
    for (const member of details.members || []) userKeys.set(member.id, member);
    const { changed, missing } = await checkPins(details.members || []);
    opened.changedKeys = changed;
    opened.missingKeys = missing;
    $("current-chat-name").textContent = details.name;
    $("current-chat-sub").textContent =
      details.type === "group"
        ? `🔒 ${details.member_count} members · end-to-end encrypted`
        : details.blocked
          ? "Blocked"
          : "🔒 end-to-end encrypted";
    renderKeyWarning();
  }

  function renderKeyWarning() {
    const box = $("key-warning");
    box.textContent = "";
    if (!current) return;
    if (current.changedKeys.length) {
      const names = current.changedKeys.map((m) => m.username).join(", ");
      box.appendChild(
        h("span", {
          text: `⚠ The security key of ${names} has changed. This can mean someone is trying to intercept your chat. Compare security codes in the chat info before you continue.`,
        }),
      );
      box.appendChild(
        button("Accept new key", "pill-btn", async () => {
          if (!current) return;
          await acceptNewKeys(current.changedKeys);
          await refreshCurrentDetails();
        }),
      );
      box.appendChild(button("Chat info", "pill-btn secondary", () => openChatInfo()));
    } else if (current.missingKeys.length) {
      const names = current.missingKeys.map((m) => m.username).join(", ");
      box.appendChild(
        h("span", {
          text: `${names} has not logged in since encryption was introduced. They have to log in once before you can send encrypted messages here.`,
        }),
      );
    }
    box.classList.toggle("modal-hidden", !box.childElementCount);
  }

  /** Adds new or changed messages. Unknown messages older than the loaded window are skipped. */
  function mergeMessages(list: Message[], includeOlder = false) {
    if (!current) return false;
    let changed = false;
    for (const message of list) {
      current.maxRev = Math.max(current.maxRev, message.rev);
      const known = current.messages.get(message.id);
      if (!known && !includeOlder && current.messages.size && message.seq < current.oldestSeq) continue;
      if (!known || known.rev !== message.rev) {
        current.messages.set(message.id, message);
        changed = true;
      }
      current.oldestSeq = Math.min(current.oldestSeq, message.seq);
    }
    return changed;
  }

  async function loadOlder() {
    if (!current || !current.hasMore) return;
    const opened = current;
    const data = await api(
      `/api/chats/${encodeURIComponent(opened.id)}/messages?limit=50&before_seq=${opened.oldestSeq}`,
    );
    if (current !== opened) return;
    mergeMessages(data.messages, true);
    opened.hasMore = data.has_more;
    await renderMessages({ keepPosition: true });
  }

  async function syncCurrent() {
    if (!current) return;
    const opened = current;
    const data = await api(
      `/api/chats/${encodeURIComponent(opened.id)}/messages?since_rev=${opened.maxRev}&limit=200`,
    );
    if (current !== opened) return;
    if (mergeMessages(data.messages)) {
      await renderMessages({});
      markRead();
    }
  }

  function markRead() {
    if (!current || document.visibilityState !== "visible") return;
    let maxSeq = 0;
    current.messages.forEach((message) => (maxSeq = Math.max(maxSeq, message.seq)));
    if (maxSeq <= current.lastReadSent) return;
    current.lastReadSent = maxSeq;
    const chat = chats.find((c) => c.id === current!.id);
    if (chat && chat.unread) {
      chat.unread = 0;
      updateBadges();
      chatsSignature = "";
    }
    post(`/api/chats/${encodeURIComponent(current.id)}/read`, { seq: maxSeq })
      .then(() => loadChats())
      .catch(() => {});
  }

  async function renderMessages(options: { forceBottom?: boolean; keepPosition?: boolean }) {
    if (!current) return;
    const opened = current;
    const container = $("messages");
    const ordered = [...opened.messages.values()].sort((a, b) => a.seq - b.seq);
    const shown = await Promise.all(ordered.map((message) => showMessage(opened.id, message)));
    if (current !== opened) return;

    const distanceFromBottom = container.scrollHeight - container.scrollTop - container.clientHeight;
    const nearBottom = distanceFromBottom < 120;

    const fragment = document.createDocumentFragment();
    const banner = h("div", { className: "e2e-banner" }, [
      h("span", {
        text: "🔒 Messages are end-to-end encrypted. No one outside of this chat, not even SereS, can read them.",
      }),
    ]);
    banner.addEventListener("click", () => openChatInfo());
    fragment.appendChild(banner);

    if (opened.hasMore) {
      fragment.appendChild(
        button("Load older messages", "pill-btn load-older", () => {
          loadOlder().catch((error) => showAlert(errorText(error)));
        }),
      );
    }

    let lastDay = "";
    let previous: Message | null = null;
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
      const compact =
        previous !== null &&
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
    } else if (options.forceBottom || nearBottom) {
      container.scrollTop = container.scrollHeight;
    }
  }

  function messageRow(opened: OpenChat, message: Message, view: Shown, compact: boolean) {
    const own = message.sender_id === me.id;
    const sender = message.sender || "Unknown";
    const row = h("div", {
      className: "message-row" + (own ? " message-own" : "") + (compact ? " message-compact" : ""),
      attrs: { "data-id": message.id },
    });
    row.appendChild(compact ? h("div", { className: "message-avatar spacer" }) : avatarEl(sender, { className: "message-avatar" }));

    const wrapper = h("div", { className: "message-content-wrapper" });
    if (!compact) {
      const header = h("div", { className: "message-header" }, [
        h("span", { className: "message-sender", text: own ? "You" : sender }),
        h("span", { className: "message-timestamp", text: formatTime(message.created_at) }),
      ]);
      if (view.type === "legacy") {
        header.appendChild(
          h("span", {
            className: "message-flag",
            text: "not encrypted",
            title: "Sent before end-to-end encryption was introduced",
          }),
        );
      }
      wrapper.appendChild(header);
    }

    const textDiv = h("div", { className: "message-text" });
    if (view.type === "deleted" || view.type === "error") {
      textDiv.classList.add("message-muted");
      textDiv.textContent = view.type === "deleted" ? "🚫 " + view.text : view.text;
    } else {
      textDiv.appendChild(richText(view.text));
    }
    textDiv.title = parseTime(message.created_at).toLocaleString();
    wrapper.appendChild(textDiv);

    if (own && !message.deleted && message.kind === "e2e") {
      wrapper.appendChild(
        button(
          "Delete",
          "message-delete",
          async () => {
            if (!window.confirm("Delete this message for everyone?")) return;
            try {
              await post(`/api/chats/${encodeURIComponent(opened.id)}/messages/${encodeURIComponent(message.id)}/delete`);
              await syncCurrent();
            } catch (error) {
              showAlert(errorText(error));
            }
          },
          "Delete for everyone",
        ),
      );
    }
    row.appendChild(wrapper);
    return row;
  }

  // ---------------------------------------------------------------- send

  function newMessageId() {
    if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  async function sendMessage() {
    const input = $("message-input-field") as HTMLTextAreaElement;
    const text = input.value.trim();
    if (!text || !current || sending) return;
    if (text.length > MESSAGE_LIMIT) {
      showAlert(`Messages can be at most ${MESSAGE_LIMIT} characters long.`);
      return;
    }
    const opened = current;
    sending = true;
    ($("send-btn") as HTMLButtonElement).disabled = true;
    try {
      for (let attempt = 0; attempt < 2; attempt++) {
        if (!opened.details || attempt > 0) await refreshCurrentDetails();
        if (current !== opened || !opened.details) return;
        if (opened.changedKeys.length) {
          showAlert("A security key in this chat changed. Check the warning above before sending.");
          return;
        }
        if (opened.missingKeys.length) {
          showAlert("Some members can't receive encrypted messages yet.");
          return;
        }
        const members = (opened.details.members || []).map((m) => ({
          id: m.id,
          pub_ecdh: m.pub_ecdh!,
          pub_sign: m.pub_sign!,
        }));
        const messageId = newMessageId();
        const payload = await SeresCrypto.encryptMessage(identity, opened.id, messageId, { text }, members);
        try {
          await post(`/api/chats/${encodeURIComponent(opened.id)}/messages`, { id: messageId, payload });
          input.value = "";
          autoGrow(input);
          await syncCurrent();
          loadChats().catch(() => {});
          return;
        } catch (error) {
          // 409: the member list changed in the meantime, encrypt again for the new members.
          if (error instanceof ApiError && error.status === 409 && attempt === 0) continue;
          throw error;
        }
      }
    } catch (error) {
      showAlert(errorText(error));
    } finally {
      sending = false;
      ($("send-btn") as HTMLButtonElement).disabled = false;
    }
  }

  function autoGrow(textarea: HTMLTextAreaElement) {
    textarea.style.height = "auto";
    textarea.style.height = Math.min(textarea.scrollHeight, 160) + "px";
  }

  // --------------------------------------------------------- new chats

  async function startDm(username: string) {
    try {
      const data = await post("/api/chats", { type: "dm", username });
      closeAllModals();
      switchView("chats");
      chatsSignature = "";
      await loadChats();
      await openChat(data.chat_id);
    } catch (error) {
      showAlert(errorText(error));
    }
  }

  function openNewDmModal() {
    const list = $("new-dm-list");
    list.textContent = "";
    $("warning-new-dm").textContent = "";
    if (!friends.friends.length) {
      list.appendChild(h("p", { text: "You don't have any friends yet. Add a friend first." }));
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

  function friendCheckboxes(container: HTMLElement, exclude: Set<string>) {
    container.textContent = "";
    const available = friends.friends.filter((friend) => !exclude.has(friend.id));
    if (!available.length) {
      container.appendChild(h("p", { text: "No friends available to add." }));
    }
    available.forEach((friend) => {
      const checkbox = h("input", { attrs: { type: "checkbox", value: friend.username } });
      container.appendChild(
        h("label", { className: "picker-item" }, [
          checkbox,
          avatarEl(friend.username),
          h("span", { className: "item-name", text: friend.username }),
        ]),
      );
    });
  }

  function checkedUsernames(container: HTMLElement) {
    return [...container.querySelectorAll<HTMLInputElement>("input[type=checkbox]:checked")].map((box) => box.value);
  }

  function openNewGroupModal() {
    ($("new-group-name") as HTMLInputElement).value = "";
    $("warning-new-group").textContent = "";
    friendCheckboxes($("new-group-list"), new Set());
    openModal("new-group-modal");
  }

  async function createGroup() {
    const name = ($("new-group-name") as HTMLInputElement).value.trim();
    const usernames = checkedUsernames($("new-group-list"));
    const warning = $("warning-new-group");
    if (!name) {
      warning.textContent = "Please enter a group name.";
      return;
    }
    if (!usernames.length) {
      warning.textContent = "Pick at least one friend.";
      return;
    }
    try {
      const data = await post("/api/chats", { type: "group", name, usernames });
      closeAllModals();
      switchView("chats");
      chatsSignature = "";
      await loadChats();
      await openChat(data.chat_id);
    } catch (error) {
      warning.textContent = errorText(error);
    }
  }

  async function addFriend() {
    const input = $("friends-username-input") as HTMLInputElement;
    const warning = $("warning-add-friend");
    const username = input.value.trim();
    if (!username) return;
    warning.textContent = "";
    try {
      const data = await post("/api/friends/request", { username });
      input.value = "";
      closeAllModals();
      showAlert(data.status === "friends" ? `You and ${username} are now friends!` : `Friend request sent to ${username}.`);
      await refreshAll();
    } catch (error) {
      warning.textContent = errorText(error);
    }
  }

  // ----------------------------------------------------------- chat info

  async function openChatInfo() {
    if (!current) return;
    try {
      await refreshCurrentDetails();
    } catch (error) {
      showAlert(errorText(error));
      return;
    }
    const opened = current;
    if (!opened || !opened.details) return;
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
          body.appendChild(h("p", { text: "Security code. Compare it with the one on your friend's device (in person or over a call). If they match, your chat is protected." }));
          body.appendChild(h("code", { className: "safety-number", text: code }));
          body.appendChild(verifyToggle(other.id, fp, verified));
        }
        const isBlocked = friends.blocked.some((b) => b.id === other.id);
        body.appendChild(
          h("div", { className: "info-actions" }, [
            isBlocked
              ? button("Unblock", "pill-btn", action("unblock", () => post("/api/unblock", { username: other.username })))
              : button(
                  "⛔ Block",
                  "pill-btn danger",
                  action("block", () => post("/api/block", { username: other.username }), `Block ${other.username}?`),
                ),
            button(
              "Delete chat",
              "pill-btn danger",
              action(
                "delete",
                async () => {
                  await post(`/api/chats/${encodeURIComponent(details.id)}/delete`);
                  closeAllModals();
                  closeChat();
                },
                "Delete this chat for you? The other person keeps their copy.",
              ),
            ),
          ]),
        );
      }
    } else {
      const isOwner = details.role === "owner";
      if (isOwner) {
        const nameInput = h("input", { attrs: { type: "text", maxlength: "64", value: details.name } });
        body.appendChild(
          h("div", { className: "info-row" }, [
            nameInput,
            button("Rename", "pill-btn", action("rename", () => post(`/api/chats/${encodeURIComponent(details.id)}/rename`, { name: nameInput.value }))),
          ]),
        );
      }
      body.appendChild(h("p", { text: `${members.length} members. Compare security codes to make sure nobody is intercepting the group.` }));
      for (const member of members) {
        const fp = await memberFingerprint(member);
        const isMe = member.id === me.id;
        const row = h("div", { className: "member-row" }, [
          avatarEl(member.username),
          h("div", { className: "item-info" }, [
            h("span", {
              className: "item-name",
              text: (isMe ? "You" : member.username) + (member.role === "owner" ? " · owner" : ""),
            }),
            h("span", {
              className: "item-status",
              text: fp ? (isMe ? "Your key: " : "Key: ") + fp.slice(0, 32).replace(/(.{4})/g, "$1 ").trim() : "No encryption key yet",
            }),
          ]),
        ]);
        if (!isMe && fp) {
          const code = await SeresCrypto.safetyNumber(myFp, fp);
          row.appendChild(
            button("Code", "request-action-btn more", () => {
              window.alert(`Security code with ${member.username}:\n\n${code}\n\nCompare it with the code ${member.username} sees for you.`);
            }),
          );
          row.appendChild(verifyToggle(member.id, fp, verified, true));
        }
        if (isOwner && !isMe) {
          row.appendChild(
            button(
              "Remove",
              "request-action-btn discard",
              action(
                "remove",
                async () => {
                  await post(`/api/chats/${encodeURIComponent(details.id)}/members/remove`, { username: member.username });
                  await openChatInfo();
                },
                `Remove ${member.username} from the group?`,
              ),
            ),
          );
        }
        body.appendChild(row);
      }

      const memberIds = new Set(members.map((m) => m.id));
      const addBox = h("div", { className: "picker-list" });
      friendCheckboxes(addBox, memberIds);
      body.appendChild(h("p", { text: "Add friends to the group (they will only see new messages):" }));
      body.appendChild(addBox);
      body.appendChild(
        h("div", { className: "info-actions" }, [
          button(
            "Add selected",
            "pill-btn",
            action("add", async () => {
              for (const username of checkedUsernames(addBox)) {
                await post(`/api/chats/${encodeURIComponent(details.id)}/members`, { username });
              }
              await openChatInfo();
            }),
          ),
          button(
            "Leave group",
            "pill-btn danger",
            action(
              "leave",
              async () => {
                await post(`/api/chats/${encodeURIComponent(details.id)}/leave`);
                closeAllModals();
                closeChat();
              },
              "Leave this group?",
            ),
          ),
        ]),
      );
    }
    openModal("chat-info-modal");
  }

  function verifyToggle(userId: string, fp: string, verified: Record<string, string>, compact = false) {
    const isVerified = verified[userId] === fp;
    return button(
      isVerified ? "✔ Verified" : compact ? "Verify" : "Mark as verified",
      "pill-btn" + (isVerified ? " verified" : " secondary"),
      () => {
        const store = readStore("verified");
        if (store[userId] === fp) delete store[userId];
        else store[userId] = fp;
        writeStore("verified", store);
        openChatInfo();
      },
    );
  }

  // ------------------------------------------------------------- modals

  function openModal(id: string) {
    closeFloatingMenus();
    $(id).classList.remove("modal-hidden");
    const input = $(id).querySelector<HTMLInputElement>("input[type=text]");
    if (input) setTimeout(() => input.focus(), 30);
  }

  function closeAllModals() {
    document.querySelectorAll(".modal-overlay").forEach((modal) => modal.classList.add("modal-hidden"));
  }

  // ------------------------------------------------------------ settings

  async function uploadAvatar() {
    const input = $("avatar-upload-input") as HTMLInputElement;
    const warning = $("settings-warning");
    warning.textContent = "";
    const file = input.files && input.files[0];
    if (!file) {
      warning.textContent = "Choose a picture first.";
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      warning.textContent = "File is too large! Maximum size is 2MB.";
      return;
    }
    const form = new FormData();
    form.append("avatar_img", file);
    try {
      const response = await fetch("/api/upload_avatar", { method: "POST", body: form, credentials: "same-origin" });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.success) throw new Error(data.message || "Upload failed");
      input.value = "";
      avatarState.delete(me.username);
      loadOwnAvatar();
      showAlert("Avatar updated successfully!");
    } catch (error) {
      warning.textContent = errorText(error);
    }
  }

  async function changePassword() {
    const warning = $("settings-warning");
    const oldPw = ($("old-password") as HTMLInputElement).value;
    const newPw = ($("new-password") as HTMLInputElement).value;
    const repeat = ($("new-password-repeat") as HTMLInputElement).value;
    warning.textContent = "";
    if (newPw.length < 8) {
      warning.textContent = "The new password must be at least 8 characters long.";
      return;
    }
    if (newPw !== repeat) {
      warning.textContent = "The new passwords don't match.";
      return;
    }
    warning.textContent = "Re-encrypting your keys...";
    try {
      const fresh: Me = (await api("/api/me")).user;
      const pre = await post("/api/prelogin", { nameomail: me.username });
      const oldKeys = await SeresCrypto.deriveAccountKeys(oldPw, pre.kdf_salt, pre.kdf_iterations);
      const salt = SeresCrypto.newSalt();
      const newKeys = await SeresCrypto.deriveAccountKeys(newPw, salt, SeresCrypto.DEFAULT_ITERATIONS);
      let encPrivate: string;
      try {
        encPrivate = await SeresCrypto.rewrapPrivateKeys(fresh.enc_private, oldKeys.wrapKey, newKeys.wrapKey);
      } catch {
        throw new Error("Current password is wrong");
      }
      await post("/api/change_password", {
        old_auth_hash: oldKeys.authHash,
        auth_hash: newKeys.authHash,
        kdf_salt: salt,
        kdf_iterations: SeresCrypto.DEFAULT_ITERATIONS,
        enc_private: encPrivate,
      });
      ["old-password", "new-password", "new-password-repeat"].forEach((id) => (($(id) as HTMLInputElement).value = ""));
      warning.textContent = "";
      showAlert("Password changed. Other devices have been logged out.");
    } catch (error) {
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
    const img = $("user-avatar-img") as HTMLImageElement;
    text.textContent = me.username.charAt(0).toUpperCase();
    $("user-avatar").style.backgroundColor = colorFor(me.username);
    fetch("/api/get_avatar", { credentials: "same-origin" })
      .then((response) => {
        if (!response.ok) throw new Error("no avatar");
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
    } finally {
      await SeresCrypto.clearIdentities();
      window.location.href = "login.html";
    }
  }

  // --------------------------------------------------------------- theme

  function getCookie(name: string) {
    const match = document.cookie.split("; ").find((part) => part.startsWith(name + "="));
    return match ? decodeURIComponent(match.slice(name.length + 1)) : undefined;
  }

  function applyTheme() {
    const isBright = getCookie("theme") === "bright";
    document.body.classList.toggle("bright-body", isBright);
    const single: [string, string][] = [
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
    const many: [string, string][] = [
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
    many.forEach(([selector, cls]) =>
      document.querySelectorAll(selector).forEach((el) => el.classList.toggle(cls, isBright)),
    );
  }

  function toggleTheme() {
    const newTheme = getCookie("theme") === "bright" ? "dark" : "bright";
    document.cookie = "theme=" + newTheme + "; path=/; max-age=31536000; SameSite=Lax";
    applyTheme();
  }

  // --------------------------------------------------------------- intro

  function loadAnimation() {
    const introLayer = $("intro-layer");
    const introVideo = $("intro-video") as HTMLVideoElement | null;
    const removeOverlay = () => {
      introLayer.style.opacity = "0";
      setTimeout(() => introLayer.remove(), 500);
    };
    const params = new URLSearchParams(window.location.search);
    const isLoginRedirect = params.get("login") === "true";
    const firstLoad = sessionStorage.getItem("sessionStarted") === null;
    if (isLoginRedirect) window.history.replaceState({}, document.title, window.location.pathname);
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
      if (!(error instanceof ApiError && error.status === 401)) console.error(error);
    });
    if (current) await refreshCurrentDetails().catch(() => {});
  }

  function bindEvents() {
    $("btn-add-friend").addEventListener("click", () => {
      $("warning-add-friend").textContent = "";
      openModal("add-friend-modal");
    });
    $("confirm-add-friend").addEventListener("click", addFriend);
    $("friends-username-input").addEventListener("keydown", (event) => {
      if ((event as KeyboardEvent).key === "Enter") addFriend();
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

    document.querySelectorAll<HTMLElement>(".list-view-toggle").forEach((btn) => {
      btn.addEventListener("click", () => switchView(btn.dataset.view as "chats" | "friends" | "requests"));
    });
    $("list-search").addEventListener("input", () => {
      chatsSignature = "";
      loadChats().catch(() => {});
      renderFriends();
    });

    document.querySelectorAll<HTMLElement>("[data-close-modal]").forEach((btn) => {
      btn.addEventListener("click", closeAllModals);
    });
    document.querySelectorAll<HTMLElement>(".modal-overlay").forEach((overlay) => {
      overlay.addEventListener("click", (event) => {
        if (event.target === overlay) closeAllModals();
      });
    });

    const input = $("message-input-field") as HTMLTextAreaElement;
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        sendMessage();
      }
    });
    input.addEventListener("input", () => autoGrow(input));

    document.addEventListener("click", (event) => {
      const target = event.target as Element;
      if (!target.closest(".floating-menu")) closeFloatingMenus();
      if (!target.closest(".user-menu-container")) $("user-dropdown-menu").classList.add("modal-hidden");
      const sidebar = document.querySelector(".sidebar");
      if (
        sidebar &&
        sidebar.classList.contains("open") &&
        window.innerWidth <= 768 &&
        !sidebar.contains(target) &&
        !target.closest(".menu-toggle") &&
        !target.closest(".modal-overlay") &&
        current
      ) {
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
        syncCurrent().catch(() => {});
        markRead();
      }
    });
  }

  async function boot() {
    loadAnimation();
    applyTheme();
    try {
      me = (await api("/api/me")).user;
    } catch {
      window.location.href = "login.html";
      return;
    }
    const stored = await SeresCrypto.loadIdentity(me.id);
    if (!stored || stored.pubEcdh !== me.pub_ecdh || stored.pubSign !== me.pub_sign) {
      // No unlocked keys on this device (or they don't match the account): log in again.
      await fetch("/api/logout", { method: "POST", credentials: "same-origin" }).catch(() => {});
      await SeresCrypto.clearIdentities();
      window.location.href = "login.html?reason=keys";
      return;
    }
    identity = stored;
    userKeys.set(me.id, { id: me.id, username: me.username, pub_ecdh: me.pub_ecdh, pub_sign: me.pub_sign });

    $("my-username-display").textContent = me.username;
    $("mobile-username").textContent = me.username;
    $("current-chat-name").textContent = "Welcome " + me.username;
    loadOwnAvatar();
    bindEvents();
    switchView("chats");
    if (window.innerWidth <= 768) document.querySelector(".sidebar")?.classList.add("open");

    await refreshAll();

    window.setInterval(() => {
      if (document.visibilityState === "visible") syncCurrent().catch(() => {});
    }, 2500);
    window.setInterval(() => {
      if (document.visibilityState === "visible") refreshAll();
    }, 6000);
  }

  document.addEventListener("DOMContentLoaded", () => {
    boot().catch((error) => {
      console.error(error);
      showAlert(errorText(error));
    });
  });
})();
