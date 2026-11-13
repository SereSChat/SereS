(() => {
  const SESSION_KEY = "seres.opsecchat.session.v1";
  const API_KEY = "seres.opsecchat.api.v1";
  const SEEN_KEY = "seres.opsecchat.seen.v1";
  const $ = (id) => document.getElementById(id);
  const root = $("opsec-integration");
  const loginForm = $("opsec-login");
  const connected = $("opsec-connected");
  const apiInput = $("opsec-api-url");
  const status = $("opsec-status");
  const friendsNode = $("opsec-friends");
  const requestsNode = $("opsec-requests");
  const messagesNode = $("opsec-messages");
  const sendForm = $("opsec-send");
  let apiBase = localStorage.getItem(API_KEY) || "";
  let session = readSession();
  let me = null;
  let friends = [];
  let conversations = [];
  let selected = null;
  let mls = null;
  let refreshTimer = 0;
  let refreshing = false;
  let previousView = "chats";

  function readSession() {
    try {
      const value = JSON.parse(sessionStorage.getItem(SESSION_KEY) || "null");
      return value && typeof value.token === "string" && value.user ? value : null;
    } catch { return null; }
  }

  function setStatus(message, isError = false) {
    status.textContent = message;
    status.classList.toggle("error", isError);
  }

  function normalizeApi(value) {
    const url = new URL(value);
    if (url.protocol !== "https:" && url.hostname !== "localhost" && url.hostname !== "127.0.0.1") {
      throw new Error("The OpsecChat server must use HTTPS.");
    }
    if (url.username || url.password || url.search || url.hash) throw new Error("Enter only the OpsecChat server URL.");
    return url.toString().replace(/\/$/, "");
  }

  async function api(path, { method = "GET", body, authenticated = true } = {}) {
    if (!apiBase) throw new Error("Enter the OpsecChat server URL first.");
    const headers = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (authenticated && session) headers.Authorization = `Bearer ${session.token}`;
    let response;
    try {
      response = await fetch(`${apiBase}${path}`, {
        method, headers, body: body === undefined ? undefined : JSON.stringify(body),
        credentials: "omit", cache: "no-store", mode: "cors",
      });
    } catch {
      throw new Error("Could not reach OpsecChat. Check the server URL and whether its administrator allows this SereS origin.");
    }
    const data = response.status === 204 ? {} : await response.json().catch(() => ({}));
    if (!response.ok) {
      const messages = {
        credentials_invalid: "The OpsecChat username or password is incorrect.",
        username_unavailable: "That OpsecChat username is already in use.",
        user_not_found: "No OpsecChat user was found with that username.",
        already_friends: "You are already OpsecChat friends.",
        request_already_sent: "A friend request is already pending.",
        origin_not_allowed: "The OpsecChat server has not allowed this SereS website origin yet.",
      };
      throw new Error(messages[data.error] || data.error || `OpsecChat request failed (${response.status}).`);
    }
    return data;
  }

  window.opsecchat = Object.freeze({ api });

  function base64ToBytes(value) {
    const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
    const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  function bytesToBase64(value) {
    let binary = "";
    for (let i = 0; i < value.length; i += 0x8000) binary += String.fromCharCode(...value.subarray(i, i + 0x8000));
    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  }

  function seenMessages(conversationId) {
    try { return JSON.parse(localStorage.getItem(SEEN_KEY) || "{}")[conversationId] || []; }
    catch { return []; }
  }

  function markSeen(conversationId, messageId) {
    const all = (() => { try { return JSON.parse(localStorage.getItem(SEEN_KEY) || "{}"); } catch { return {}; } })();
    const ids = new Set(all[conversationId] || []);
    ids.add(messageId);
    all[conversationId] = [...ids].slice(-1000);
    localStorage.setItem(SEEN_KEY, JSON.stringify(all));
  }

  function itemButton(text, className, onClick) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = className;
    button.textContent = text;
    button.addEventListener("click", onClick);
    return button;
  }

  function drawConversationList() {
    friendsNode.replaceChildren();
    const heading = document.createElement("h3");
    heading.textContent = "Conversations";
    friendsNode.append(heading);
    for (const conversation of conversations) {
      const other = conversation.members?.find((member) => member.id !== me?.id);
      const label = conversation.title || other?.display_name || other?.username || "Group conversation";
      const button = itemButton(`opsec:${label}`, "opsec-row", () => openConversation(conversation));
      friendsNode.append(button);
    }
    const title = document.createElement("h3");
    title.textContent = "Friends";
    friendsNode.append(title);
    for (const friend of friends) {
      const row = document.createElement("div");
      row.className = "opsec-friend-row";
      const name = document.createElement("span");
      name.textContent = `opsec:${friend.display_name || friend.username}`;
      row.append(name, itemButton("Chat", "opsec-button small", () => startConversation(friend.username)));
      friendsNode.append(row);
    }
    if (!friends.length) {
      const empty = document.createElement("p");
      empty.className = "opsec-muted";
      empty.textContent = "No OpsecChat friends yet.";
      friendsNode.append(empty);
    }
  }

  async function refreshLists() {
    const [friendData, conversationData] = await Promise.all([api("/v1/friends"), api("/v1/conversations")]);
    const relations = friendData.friends || [];
    friends = relations.filter((relation) => relation.status === "accepted").map((relation) => relation.user);
    conversations = conversationData.conversations || [];
    requestsNode.replaceChildren();
    for (const relation of relations.filter((entry) => entry.status === "pending" && entry.direction === "incoming")) {
      const request = relation.user;
      const row = document.createElement("div");
      row.className = "opsec-request-row";
      const label = document.createElement("span");
      label.textContent = `opsec:${request.username}`;
      row.append(label,
        itemButton("Accept", "opsec-button small", async () => {
          try { await api(`/v1/friends/requests/${encodeURIComponent(request.id)}/accept`, { method: "POST" }); await refreshLists(); }
          catch (error) { setStatus(error.message || "Could not accept the request.", true); }
        }),
        itemButton("Decline", "opsec-button secondary small", async () => {
          try { await api(`/v1/friends/requests/${encodeURIComponent(request.id)}/decline`, { method: "POST" }); await refreshLists(); }
          catch (error) { setStatus(error.message || "Could not decline the request.", true); }
        }));
      requestsNode.append(row);
    }
    drawConversationList();
  }

  async function provision() {
    if (!mls) mls = await import("./opsec-mls.js");
    const result = await mls.provisionMlsDevice(me.id, "SereS web");
    return result.deviceId;
  }

  async function createGroupFor(conversation, username) {
    if (!(await mls.hasMlsGroup(me.id, conversation.id))) await mls.createMlsGroup(me.id, conversation.id);
    if ((await mls.mlsGroupMemberCount(me.id, conversation.id)) > 1) return;
    const directory = await api(`/v1/users/${encodeURIComponent(username)}/key-packages`);
    const added = await mls.addMlsMembers(me.id, conversation.id, directory);
    const commit = await api(`/v1/conversations/${encodeURIComponent(conversation.id)}/messages`, {
      method: "POST", body: {
        device_id: added.deviceId, ciphertext: bytesToBase64(added.commit), protocol_version: 1, event_kind: "commit",
      },
    });
    markSeen(conversation.id, commit.id);
    const welcome = await api(`/v1/conversations/${encodeURIComponent(conversation.id)}/messages`, {
      method: "POST", body: {
        device_id: added.deviceId, ciphertext: bytesToBase64(added.welcome), protocol_version: 1,
        event_kind: "welcome", recipient_device_ids: added.recipientDeviceIds,
      },
    });
    markSeen(conversation.id, welcome.id);
  }

  async function startConversation(username) {
    try {
      setStatus("Preparing encrypted conversation…");
      await provision();
      const result = await api("/v1/conversations", { method: "POST", body: { member_usernames: [username] } });
      let conversation = conversations.find((item) => item.id === result.id);
      if (!conversation) {
        await refreshLists();
        conversation = conversations.find((item) => item.id === result.id);
      }
      if (!conversation) conversation = { id: result.id, kind: "direct", members: [{ id: "", username }] };
      if (result.created || (await mls.hasMlsGroup(me.id, conversation.id))) {
        await createGroupFor(conversation, username);
      } else {
        setStatus(`Waiting for opsec:${username} to finish setting up encryption…`);
      }
      await openConversation(conversation);
      await refreshLists();
    } catch (error) { setStatus(error.message || "Could not start the conversation.", true); }
  }

  async function openConversation(conversation) {
    try {
      selected = conversation;
      const other = conversation.members?.find((member) => member.id !== me.id);
      $("opsec-chat-title").textContent = conversation.title || `opsec:${other?.display_name || other?.username || "Conversation"}`;
      messagesNode.replaceChildren();
      await provision();
      sendForm.classList.toggle("hidden-el", !(await mls.hasMlsGroup(me.id, conversation.id)));
      await syncMessages(conversation);
      if (await mls.hasMlsGroup(me.id, conversation.id)) setStatus("");
    } catch (error) { setStatus(error.message || "Could not open the conversation.", true); }
  }

  function renderMessage(payload, senderId, timestamp) {
    if (!payload || typeof payload.text !== "string") return;
    const bubble = document.createElement("article");
    bubble.className = `opsec-message${senderId === me.id ? " own" : ""}`;
    const text = document.createElement("p");
    text.textContent = payload.text;
    const time = document.createElement("time");
    time.dateTime = new Date(timestamp * 1000).toISOString();
    time.textContent = new Date(timestamp * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    bubble.append(text, time);
    messagesNode.append(bubble);
  }

  async function getMessagePage(conversationId, deviceId, before) {
    const query = new URLSearchParams({ device_id: deviceId, limit: "100" });
    if (before) query.set("before", String(before));
    const response = await api(`/v1/conversations/${encodeURIComponent(conversationId)}/messages?${query}`);
    return response.messages || [];
  }

  async function syncMessages(conversation) {
    const deviceId = await provision();
    const seen = seenMessages(conversation.id);
    const hasGroup = await mls.hasMlsGroup(me.id, conversation.id);
    const messages = await getMessagePage(conversation.id, deviceId);
    if (!seen.length && hasGroup && messages.length) {
      messages.forEach((entry) => markSeen(conversation.id, entry.id));
      const notice = document.createElement("p");
      notice.className = "opsec-muted opsec-history-note";
      notice.textContent = "Earlier messages are not available on this device.";
      messagesNode.append(notice);
      return;
    }
    const seenSet = new Set(seen);
    const allMessages = new Map(messages.map((entry) => [entry.id, entry]));
    let page = messages;
    for (let pageNumber = 0; page.length === 100 && pageNumber < 100; pageNumber += 1) {
      const oldest = Math.min(...page.map((entry) => entry.created_at));
      const older = await getMessagePage(conversation.id, deviceId, oldest);
      if (!older.length) break;
      older.forEach((entry) => allMessages.set(entry.id, entry));
      page = older;
      if (seenSet.size && older.some((entry) => seenSet.has(entry.id))) break;
      if (!hasGroup && older.some((entry) => entry.event_kind === "welcome")) break;
    }
    const pending = [...allMessages.values()].filter((entry) => !seenSet.has(entry.id)).sort((a, b) => a.created_at - b.created_at || a.id.localeCompare(b.id));
    if (!hasGroup && !pending.some((entry) => entry.event_kind === "welcome")) {
      if (pending.length) setStatus("The MLS Welcome event was not found in the recent history. Try again or contact the OpsecChat server administrator.", true);
      return;
    }
    let welcomeCommit = null;
    for (const entry of pending) {
      const ciphertext = base64ToBytes(entry.ciphertext);
      if (entry.event_kind === "welcome" && !(await mls.hasMlsGroup(me.id, conversation.id))) {
        await mls.joinMlsGroup(me.id, conversation.id, ciphertext);
        welcomeCommit = { sender: entry.sender_user_id, timestamp: entry.created_at };
      } else {
        if (!(await mls.hasMlsGroup(me.id, conversation.id))) { markSeen(conversation.id, entry.id); continue; }
        if (entry.event_kind === "commit" && welcomeCommit && entry.sender_user_id === welcomeCommit.sender && entry.created_at === welcomeCommit.timestamp) {
          markSeen(conversation.id, entry.id);
          welcomeCommit = null;
          continue;
        }
        const result = await mls.decryptMlsPayload(me.id, conversation.id, ciphertext);
        if (result.kind === "application") renderMessage(result.payload, entry.sender_user_id, entry.created_at);
      }
      markSeen(conversation.id, entry.id);
    }
    const ready = await mls.hasMlsGroup(me.id, conversation.id);
    sendForm.classList.toggle("hidden-el", !ready);
    if (ready && status.classList.contains("error")) setStatus("");
    if (!ready && !status.textContent) setStatus("Waiting for the other OpsecChat member to finish setting up encryption.");
    messagesNode.scrollTop = messagesNode.scrollHeight;
  }

  async function establish(result) {
    if (!result.access_token || !result.user?.id) throw new Error("OpsecChat returned an invalid login session.");
    session = { token: result.access_token, user: result.user };
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
    me = result.user;
    await provision();
    loginForm.classList.add("hidden-el");
    connected.classList.remove("hidden-el");
    $("opsec-account").textContent = `Linked as opsec:${me.username}`;
    await refreshLists();
    setStatus("");
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = window.setInterval(async () => {
      if (!root.classList.contains("hidden-el") && session && !refreshing) {
        refreshing = true;
        try { await refreshLists(); if (selected) await syncMessages(selected); }
        catch (error) { setStatus(error.message, true); }
        finally { refreshing = false; }
      }
    }, 5000);
  }

  async function connectSavedSession() {
    if (!session) return;
    try {
      const result = await api("/v1/auth/me");
      me = result.user;
      await establish({ access_token: session.token, user: me });
    } catch (error) {
      sessionStorage.removeItem(SESSION_KEY);
      session = null;
      setStatus(error.message || "Reconnect your OpsecChat account.", true);
    }
  }

  $("btn-opsecchat").addEventListener("click", () => {
    const active = document.querySelector(".list-view-toggle.active");
    if (active && active.id !== "btn-opsecchat") previousView = active.id || active.dataset.view || "chats";
    document.querySelectorAll(".list-view-toggle").forEach((button) => button.classList.toggle("active", button.id === "btn-opsecchat"));
    root.classList.remove("hidden-el");
    if (session && !me) connectSavedSession();
  });
  $("opsec-close").addEventListener("click", () => {
    root.classList.add("hidden-el");
    document.querySelectorAll(".list-view-toggle").forEach((button) => button.classList.toggle("active", button.id === previousView || button.dataset.view === previousView));
  });

  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      apiBase = normalizeApi(apiInput.value.trim());
      localStorage.setItem(API_KEY, apiBase);
      setStatus("Connecting to OpsecChat…");
      const result = await api("/v1/auth/login", {
        method: "POST", authenticated: false,
        body: { username: $("opsec-username").value.trim(), password: $("opsec-password").value },
      });
      $("opsec-password").value = "";
      await establish(result);
    } catch (error) { setStatus(error.message || "Could not link the OpsecChat account.", true); }
  });

  $("opsec-add-friend").addEventListener("submit", async (event) => {
    event.preventDefault();
    const username = $("opsec-friend-name").value.trim().replace(/^opsec:/i, "");
    try {
      await api("/v1/friends/requests", { method: "POST", body: { username } });
      $("opsec-friend-name").value = "";
      setStatus(`Friend request sent to opsec:${username}.`);
      await refreshLists();
    } catch (error) { setStatus(error.message || "Could not send the request.", true); }
  });

  $("opsec-logout").addEventListener("click", async () => {
    try { await api("/v1/auth/logout", { method: "POST" }); } catch { /* Local unlink still works offline. */ }
    sessionStorage.removeItem(SESSION_KEY);
    session = null; me = null; selected = null;
    connected.classList.add("hidden-el");
    loginForm.classList.remove("hidden-el");
    sendForm.classList.add("hidden-el");
    $("opsec-account").textContent = "";
    messagesNode.replaceChildren();
    $("opsec-chat-title").textContent = "Choose an OpsecChat friend or conversation.";
    setStatus("OpsecChat account unlinked from this tab.");
    if (refreshTimer) clearInterval(refreshTimer);
  });

  sendForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!selected) return;
    const input = $("opsec-message");
    const text = input.value.trim();
    if (!text) return;
    try {
      const encrypted = await mls.encryptMlsPayload(me.id, selected.id, { text });
      const response = await api(`/v1/conversations/${encodeURIComponent(selected.id)}/messages`, {
        method: "POST", body: {
          device_id: encrypted.deviceId, ciphertext: bytesToBase64(encrypted.ciphertext), protocol_version: 1,
          event_kind: "application",
        },
      });
      markSeen(selected.id, response.id);
      renderMessage({ text }, me.id, response.created_at);
      input.value = "";
    } catch (error) { setStatus(error.message || "Message could not be sent.", true); }
  });

  apiInput.value = apiBase;
  if (session && apiBase) {
    try { apiBase = normalizeApi(apiBase); }
    catch { apiBase = ""; sessionStorage.removeItem(SESSION_KEY); session = null; }
  }
})();
