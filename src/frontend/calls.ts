// Voice calls in the browser.
//
// The server only knows who is called and who joined. The audio goes directly
// between the browsers with WebRTC (or through the TURN server when a direct
// connection isn't possible); WebRTC always encrypts it. In a group everyone
// is connected with everyone. Each connection offer is signed with the
// sender's account key (see SeresCrypto.signCall), so the server can't place
// itself in the middle.
//
// The browser asks the server every few seconds for calls and connection
// offers, every second while a call rings or runs.
//
// Video: every connection has a video slot from the start. Turning the
// camera or screen sharing on or off only swaps the picture in that slot
// (no new negotiation), and a small data channel tells the other side what
// it shows. Both aim for 60 frames per second.

interface CallParticipant {
  id: string;
  username: string;
  display_name: string;
  state: "ringing" | "joined" | "left" | "declined" | "missed";
}

interface CallInfo {
  id: string;
  chat_id: string;
  chat_name: string;
  chat_type: "dm" | "group";
  started_by: string;
  started_at: string;
  answered_at: string | null;
  participants: CallParticipant[];
}

interface CallSignal {
  id: number;
  call_id: string;
  from: string;
  kind: "offer" | "answer";
  data: { sdp: string; sig: string };
}

interface CallDeps {
  api(path: string): Promise<any>;
  post(path: string, body?: object): Promise<any>;
  me(): { id: string; username: string; display_name?: string | null };
  identity(): SeresIdentity;
  showAlert(message: string): void;
  errorText(error: unknown): string;
  /** Friends to add to a call, or null when cancelled. */
  pickPeople(excludeIds: string[]): Promise<string[] | null>;
  /** A call moved to a new group chat: show it in the chat list. */
  chatCreated(chatId: string): void;
  openChat(chatId: string): void;
  /** Profile picture (or initial) of a user, as in the chat list. */
  avatar(username: string, label: string): HTMLElement;
}

const SeresCalls = (() => {
  const t = SeresI18n.t;
  const ICE_WAIT_MS = 3000;
  let deps: CallDeps;
  let lastSignal = 0;
  let pollTimer: number | null = null;
  let polling = false;
  let calls: CallInfo[] = [];
  const signKeys = new Map<string, string>();
  // Calls I declined or that rang out here, so they don't ring again.
  const dismissed = new Set<string>();

  interface Peer {
    pc: RTCPeerConnection;
    audio: HTMLAudioElement;
    offerer: boolean;
    stream?: MediaStream;
    // How the audio travels: straight between the browsers or through TURN.
    route?: "direct" | "relay" | "relay-tcp";
    // When the connection dropped, to restart it if it doesn't come back.
    lostAt?: number;
    videoSender?: RTCRtpSender;
    video: HTMLVideoElement;
    // What the other side shows in its video slot.
    remoteVideo: VideoKind | null;
    channel?: RTCDataChannel;
  }

  type VideoKind = "camera" | "screen";

  interface Active {
    call: CallInfo;
    stream: MediaStream;
    ice: RTCIceServer[];
    peers: Map<string, Peer>;
    // Broken connections per person; after three tries it stops offering.
    failures: Map<string, number>;
    muted: boolean;
    timer: number;
    // My camera or shared screen, with a preview.
    video: { kind: VideoKind; track: MediaStreamTrack; preview: HTMLVideoElement } | null;
  }
  let active: Active | null = null;

  // ------------------------------------------------------------- polling

  function schedule() {
    if (pollTimer !== null) clearTimeout(pollTimer);
    const busy = active || calls.some((call) => myState(call) === "ringing");
    // While a connection is being set up, offers and answers are picked up faster.
    const connecting =
      active && [...active.peers.values()].some((peer) => peer.pc.connectionState !== "connected");
    pollTimer = window.setTimeout(poll, connecting ? 400 : busy ? 1000 : 3000);
  }

  async function poll() {
    if (polling) return;
    polling = true;
    try {
      const data = await deps.api(`/api/calls?after=${lastSignal}`);
      calls = data.calls || [];
      await update();
      for (const signal of (data.signals || []) as CallSignal[]) {
        lastSignal = Math.max(lastSignal, signal.id);
        await handleSignal(signal).catch((error) => console.warn("Call signal failed", error));
      }
    } catch (error) {
      console.warn("Could not check for calls", error);
    } finally {
      polling = false;
      schedule();
    }
  }

  function myState(call: CallInfo) {
    return call.participants.find((p) => p.id === deps.me().id)?.state;
  }

  async function update() {
    if (active) {
      const call = calls.find((c) => c.id === active!.call.id);
      if (!call || myState(call) !== "joined") {
        stopActive();
        deps.showAlert(t("call.ended"));
      } else {
        active.call = call;
        syncPeers();
      }
    }
    renderIncoming();
    renderPanel();
  }

  // --------------------------------------------------------------- WebRTC

  /** Everyone is connected with everyone; the one with the smaller id offers. */
  function syncPeers() {
    if (!active) return;
    const meId = deps.me().id;
    const joined = new Set(active.call.participants.filter((p) => p.state === "joined").map((p) => p.id));
    for (const [id, peer] of active.peers) {
      if (!joined.has(id)) closePeer(id, peer);
    }
    for (const id of joined) {
      if (id !== meId && !active.peers.has(id) && meId < id && (active.failures.get(id) || 0) < 3) {
        sendOffer(id).catch((error) => console.warn("Could not call", id, error));
      }
    }
  }

  function newPeer(userId: string, offerer: boolean): Peer {
    const current = active!;
    const pc = new RTCPeerConnection({
      iceServers: current.ice,
      // Audio and the rest share one connection, so only one route has to work.
      bundlePolicy: "max-bundle",
      rtcpMuxPolicy: "require",
      iceCandidatePoolSize: 2,
    });
    current.stream.getTracks().forEach((track) => {
      const sender = pc.addTrack(track, current.stream);
      if (track.kind === "audio") preferAudio(sender);
    });
    const audio = document.createElement("audio");
    audio.autoplay = true;
    const video = document.createElement("video");
    video.autoplay = true;
    video.playsInline = true;
    video.muted = true;
    video.className = "call-video";
    video.addEventListener("click", () => fullscreen(video));
    pc.ontrack = (event) => {
      if (event.track.kind === "video") {
        video.srcObject = new MediaStream([event.track]);
        video.play().catch(() => {});
        return;
      }
      audio.srcObject = event.streams[0];
      audio.play().catch(() => {});
      peer.stream = event.streams[0];
      watchLevel(userId, event.streams[0]);
    };
    const peer: Peer = { pc, audio, offerer, video, remoteVideo: null };
    // The side that offers creates the video slot; the other side gets it with the offer.
    if (offerer) {
      peer.videoSender = pc.addTransceiver(current.video?.track || "video", { direction: "sendrecv" }).sender;
      if (current.video) tuneVideo(peer.videoSender, current.video.kind);
    }
    openChannel(peer, pc.createDataChannel("control", { negotiated: true, id: 0 }));
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === "connected") {
        peer.lostAt = undefined;
        updateRoute(peer);
        if (peer.videoSender && active?.video) tuneVideo(peer.videoSender, active.video.kind);
      } else if (pc.connectionState === "disconnected") {
        peer.lostAt ??= Date.now();
      }
      renderPanel();
      // A broken connection is closed; the side that offers starts a new one
      // with the next check (see syncPeers).
      if (pc.connectionState === "failed" && active === current && current.peers.get(userId) === peer) {
        current.failures.set(userId, (current.failures.get(userId) || 0) + 1);
        closePeer(userId, peer);
      }
    };
    current.peers.set(userId, peer);
    return peer;
  }

  function closePeer(userId: string, peer: Peer) {
    unwatchLevel(userId);
    peer.pc.close();
    peer.audio.srcObject = null;
    peer.video.srcObject = null;
    if (active && active.peers.get(userId) === peer) active.peers.delete(userId);
  }

  /** The audio goes first on the network and gets enough bits for clear speech. */
  function preferAudio(sender: RTCRtpSender) {
    try {
      const parameters = sender.getParameters();
      parameters.encodings = parameters.encodings?.length ? parameters.encodings : [{}];
      for (const encoding of parameters.encodings as any[]) {
        encoding.priority = "high";
        encoding.networkPriority = "high";
        encoding.maxBitrate = 64000;
      }
      sender.setParameters(parameters).catch(() => {});
    } catch {
      // Older browsers: defaults.
    }
  }

  /**
   * Waits for the connection candidates that go into the description (no
   * trickling): until gathering is complete, or shortly after the first
   * candidate that works outside the local network (STUN/TURN) turned up.
   */
  function gathered(pc: RTCPeerConnection) {
    return new Promise<void>((resolve) => {
      if (pc.iceGatheringState === "complete") return resolve();
      const timer = window.setTimeout(resolve, ICE_WAIT_MS);
      let early: number | null = null;
      const done = () => {
        clearTimeout(timer);
        if (early !== null) clearTimeout(early);
        resolve();
      };
      pc.addEventListener("icegatheringstatechange", () => {
        if (pc.iceGatheringState === "complete") done();
      });
      pc.addEventListener("icecandidate", (event) => {
        const type = event.candidate?.type;
        if ((type === "srflx" || type === "relay") && early === null) early = window.setTimeout(done, 700);
      });
    });
  }

  /** Looks up the route the connection uses, shown in the call window. */
  async function updateRoute(peer: Peer) {
    try {
      const stats = await peer.pc.getStats();
      let pairId: string | undefined;
      stats.forEach((report: any) => {
        if (report.type === "transport" && report.selectedCandidatePairId) pairId = report.selectedCandidatePairId;
      });
      const pair: any = pairId ? stats.get(pairId) : [...stats.values()].find((r: any) => r.type === "candidate-pair" && r.nominated && r.state === "succeeded");
      const local: any = pair ? stats.get(pair.localCandidateId) : null;
      if (!local) return;
      peer.route = local.candidateType !== "relay" ? "direct" : local.relayProtocol === "udp" ? "relay" : "relay-tcp";
      tilesSignature = "";
      renderPanel();
    } catch {
      // No statistics in this browser.
    }
  }

  /** A connection that dropped for a few seconds is negotiated again (ICE restart). */
  function restartLostConnections() {
    if (!active) return;
    const current = active;
    for (const [userId, peer] of current.peers) {
      if (!peer.offerer || peer.lostAt === undefined || Date.now() - peer.lostAt < 3000) continue;
      peer.lostAt = Date.now() + 10000;
      (async () => {
        await peer.pc.setLocalDescription(await peer.pc.createOffer({ iceRestart: true }));
        if (active === current) await sendSignal(current.call.id, userId, "offer", peer.pc);
      })().catch((error) => console.warn("Could not restart the connection", error));
    }
  }

  async function sendSignal(callId: string, to: string, kind: "offer" | "answer", pc: RTCPeerConnection) {
    await gathered(pc);
    const sdp = pc.localDescription!.sdp;
    const sig = await SeresCrypto.signCall(deps.identity(), callId, to, kind, sdp);
    await deps.post(`/api/calls/${encodeURIComponent(callId)}/signal`, { to, kind, data: { sdp, sig } });
  }

  async function sendOffer(userId: string) {
    if (!active) return;
    const current = active;
    const peer = newPeer(userId, true);
    await peer.pc.setLocalDescription(await peer.pc.createOffer());
    if (active !== current) return;
    await sendSignal(current.call.id, userId, "offer", peer.pc);
  }

  async function signKey(userId: string) {
    if (!signKeys.has(userId)) {
      const data = await deps.api("/api/users/keys?ids=" + encodeURIComponent(userId));
      const user = (data.users || [])[0];
      if (user?.pub_sign) signKeys.set(userId, user.pub_sign);
    }
    return signKeys.get(userId) || null;
  }

  async function handleSignal(signal: CallSignal) {
    if (!active || signal.call_id !== active.call.id) return;
    const current = active;
    const key = await signKey(signal.from);
    const meId = deps.me().id;
    const valid =
      key && (await SeresCrypto.verifyCall(key, signal.call_id, signal.from, meId, signal.kind, signal.data.sdp, signal.data.sig));
    if (!valid) {
      console.warn("Ignored a call signal with a wrong signature from", signal.from);
      return;
    }
    if (active !== current) return;
    if (signal.kind === "offer") {
      const old = current.peers.get(signal.from);
      // An ICE restart of a connection that exists: answer it on the same connection.
      if (old && !old.offerer && old.pc.signalingState === "stable" && old.pc.connectionState !== "closed") {
        await old.pc.setRemoteDescription({ type: "offer", sdp: signal.data.sdp });
        await old.pc.setLocalDescription(await old.pc.createAnswer());
        await sendSignal(current.call.id, signal.from, "answer", old.pc);
        return;
      }
      if (old) closePeer(signal.from, old);
      const peer = newPeer(signal.from, false);
      await peer.pc.setRemoteDescription({ type: "offer", sdp: signal.data.sdp });
      takeVideoSlot(peer);
      await peer.pc.setLocalDescription(await peer.pc.createAnswer());
      await sendSignal(current.call.id, signal.from, "answer", peer.pc);
    } else {
      const peer = current.peers.get(signal.from);
      if (peer && peer.offerer && peer.pc.signalingState === "have-local-offer") {
        await peer.pc.setRemoteDescription({ type: "answer", sdp: signal.data.sdp });
        updateRoute(peer);
      }
    }
    renderPanel();
  }

  // ---------------------------------------------------------------- video

  /** The answering side sends its picture in the video slot that came with the offer. */
  function takeVideoSlot(peer: Peer) {
    const slot = peer.pc.getTransceivers().find((tx) => tx.receiver.track.kind === "video");
    if (!slot) return;
    slot.direction = "sendrecv";
    peer.videoSender = slot.sender;
    if (active?.video) {
      slot.sender.replaceTrack(active.video.track).catch(() => {});
      tuneVideo(slot.sender, active.video.kind);
    }
  }

  /**
   * 60 frames per second: with less bandwidth the browser lowers the
   * resolution rather than the frame rate, so motion stays smooth.
   */
  function tuneVideo(sender: RTCRtpSender, kind: VideoKind) {
    try {
      const parameters: any = sender.getParameters();
      if (!parameters.encodings?.length) return;
      for (const encoding of parameters.encodings) {
        encoding.maxFramerate = 60;
        encoding.maxBitrate = kind === "screen" ? 6_000_000 : 2_500_000;
        encoding.priority = "medium";
      }
      parameters.degradationPreference = "maintain-framerate";
      sender.setParameters(parameters).catch(() => {});
    } catch {
      // Older browsers: defaults.
    }
  }

  function openChannel(peer: Peer, channel: RTCDataChannel) {
    peer.channel = channel;
    channel.onopen = () => sendVideoState(peer);
    channel.onmessage = (event) => {
      try {
        const message = JSON.parse(String(event.data));
        if (message.type !== "video") return;
        peer.remoteVideo = message.video === "camera" || message.video === "screen" ? message.video : null;
        tilesSignature = "";
        renderPanel();
      } catch {
        // Not for us.
      }
    };
  }

  function sendVideoState(peer: Peer) {
    if (peer.channel?.readyState !== "open") return;
    peer.channel.send(JSON.stringify({ type: "video", video: active?.video?.kind ?? null }));
  }

  /** Shows my camera or screen to everyone in the call (null turns it off). */
  async function setVideo(kind: VideoKind | null, track: MediaStreamTrack | null) {
    if (!active) {
      track?.stop();
      return;
    }
    const old = active.video;
    if (old && old.track !== track) old.track.stop();
    if (kind && track) {
      const preview = old?.preview || document.createElement("video");
      preview.autoplay = true;
      preview.playsInline = true;
      preview.muted = true;
      preview.className = "call-video own" + (kind === "camera" ? " mirrored" : "");
      preview.srcObject = new MediaStream([track]);
      preview.play().catch(() => {});
      active.video = { kind, track, preview };
      // Stopped from the browser's own "Stop sharing" button.
      track.addEventListener("ended", () => {
        if (active?.video?.track === track) setVideo(null, null);
      });
    } else {
      if (old) old.preview.srcObject = null;
      active.video = null;
    }
    for (const peer of active.peers.values()) {
      if (!peer.videoSender) continue;
      await peer.videoSender.replaceTrack(track).catch(() => {});
      if (kind) tuneVideo(peer.videoSender, kind);
      sendVideoState(peer);
    }
    tilesSignature = "";
    renderPanel();
  }

  async function toggleCamera() {
    if (!active) return;
    if (active.video?.kind === "camera") return setVideo(null, null);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { width: { ideal: 1280 }, height: { ideal: 720 }, frameRate: { ideal: 60, max: 60 } },
      });
      const track = stream.getVideoTracks()[0];
      track.contentHint = "motion";
      await setVideo("camera", track);
    } catch {
      deps.showAlert(t("call.noCamera"));
    }
  }

  async function toggleScreen() {
    if (!active) return;
    if (active.video?.kind === "screen") return setVideo(null, null);
    try {
      const stream = await navigator.mediaDevices.getDisplayMedia({
        video: { width: { ideal: 1920 }, height: { ideal: 1080 }, frameRate: { ideal: 60, max: 60 } },
        audio: false,
      });
      const track = stream.getVideoTracks()[0];
      // Smooth motion (games, videos) rather than sharp still text.
      track.contentHint = "motion";
      await setVideo("screen", track);
    } catch (error) {
      if ((error as DOMException)?.name !== "NotAllowedError") deps.showAlert(t("call.noScreen"));
    }
  }

  function fullscreen(video: HTMLVideoElement) {
    if (video.ownerDocument.fullscreenElement) video.ownerDocument.exitFullscreen().catch(() => {});
    else video.requestFullscreen?.().catch(() => {});
  }

  // ------------------------------------------------------------- actions

  async function microphone() {
    try {
      return await navigator.mediaDevices.getUserMedia({
        audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
      });
    } catch (error) {
      throw new Error(t("call.noMicrophone"));
    }
  }

  async function enter(call: CallInfo, stream?: MediaStream) {
    const ice = (await deps.api("/api/calls/ice")).ice_servers as RTCIceServer[];
    if (active) stopActive(active.stream !== stream);
    active = {
      call,
      stream: stream || (await microphone()),
      ice,
      peers: new Map(),
      failures: new Map(),
      muted: false,
      video: null,
      timer: window.setInterval(() => {
        restartLostConnections();
        renderPanel();
      }, 1000),
    };
    calls = calls.filter((c) => c.id !== call.id).concat(call);
    watchLevel(deps.me().id, active.stream);
    syncPeers();
    renderIncoming();
    renderPanel();
    schedule();
  }

  /** Calls everyone in the chat, or joins the call running there. */
  async function start(chatId: string) {
    if (active && active.call.chat_id === chatId) return;
    try {
      const stream = await microphone();
      const data = await deps.post(`/api/chats/${encodeURIComponent(chatId)}/call`);
      await enter(data.call, stream);
    } catch (error) {
      deps.showAlert(deps.errorText(error));
    }
  }

  async function answer(call: CallInfo) {
    try {
      const stream = await microphone();
      const data = await deps.post(`/api/calls/${encodeURIComponent(call.id)}/answer`);
      await enter(data.call, stream);
      deps.openChat(call.chat_id);
    } catch (error) {
      deps.showAlert(deps.errorText(error));
    }
  }

  async function decline(call: CallInfo) {
    dismissed.add(call.id);
    renderIncoming();
    await deps.post(`/api/calls/${encodeURIComponent(call.id)}/decline`).catch(() => {});
  }

  async function hangUp() {
    if (!active) return;
    const id = active.call.id;
    stopActive();
    renderPanel();
    await deps.post(`/api/calls/${encodeURIComponent(id)}/leave`).catch(() => {});
  }

  function stopActive(stopMicrophone = true) {
    if (!active) return;
    if (active.video) {
      active.video.track.stop();
      active.video.preview.srcObject = null;
    }
    for (const [id, peer] of active.peers) closePeer(id, peer);
    unwatchLevel(deps.me().id);
    if (stopMicrophone) active.stream.getTracks().forEach((track) => track.stop());
    clearInterval(active.timer);
    active = null;
    stopTone();
    closeWindow();
  }

  function toggleMute() {
    if (!active) return;
    active.muted = !active.muted;
    active.stream.getAudioTracks().forEach((track) => (track.enabled = !active!.muted));
    renderPanel();
  }

  /** More people: the server makes a group with everyone and calls it. */
  async function addPeople() {
    if (!active) return;
    const current = active;
    const exclude = current.call.participants.filter((p) => p.state === "joined").map((p) => p.id);
    const usernames = await deps.pickPeople(exclude);
    if (!usernames || !usernames.length || active !== current) return;
    try {
      const data = await deps.post(`/api/calls/${encodeURIComponent(current.call.id)}/add`, { usernames });
      deps.chatCreated(data.chat_id);
      await enter(data.call, current.stream);
      deps.openChat(data.chat_id);
    } catch (error) {
      deps.showAlert(deps.errorText(error));
    }
  }

  // --------------------------------------------------------------- tones

  let audioContext: AudioContext | null = null;
  let toneTimer: number | null = null;
  let tone: "ring" | "back" | null = null;

  /** Plays short beeps: "ring" for an incoming call, "back" while my call rings. */
  function playTone(kind: "ring" | "back") {
    if (tone === kind) return;
    stopTone();
    tone = kind;
    const beep = () => {
      try {
        audioContext = audioContext || new AudioContext();
        audioContext.resume().catch(() => {});
        const pattern = kind === "ring" ? [0, 0.4] : [0];
        for (const offset of pattern) {
          const osc = audioContext.createOscillator();
          const gain = audioContext.createGain();
          osc.frequency.value = kind === "ring" ? 480 : 425;
          gain.gain.value = 0.08;
          osc.connect(gain).connect(audioContext.destination);
          const at = audioContext.currentTime + offset;
          osc.start(at);
          osc.stop(at + (kind === "ring" ? 0.3 : 1));
        }
      } catch {
        // No sound possible (e.g. before the page was clicked once).
      }
    };
    beep();
    toneTimer = window.setInterval(beep, kind === "ring" ? 2000 : 4000);
  }

  function stopTone() {
    if (toneTimer !== null) clearInterval(toneTimer);
    toneTimer = null;
    tone = null;
  }

  // ------------------------------------------------------------------ UI

  function el<K extends keyof HTMLElementTagNameMap>(tag: K, className = "", text = "") {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text) element.textContent = text;
    return element;
  }

  function actionButton(label: string, className: string, title: string, fn: () => void) {
    const button = el("button", "call-btn " + className, label);
    button.type = "button";
    button.title = title;
    button.setAttribute("aria-label", title);
    button.addEventListener("click", fn);
    return button;
  }

  function nameOf(p: { username: string; display_name?: string | null }) {
    return p.display_name || p.username;
  }

  function callerName(call: CallInfo) {
    const caller = call.participants.find((p) => p.id === call.started_by);
    return caller ? nameOf(caller) : "";
  }

  function duration(since: string) {
    const seconds = Math.max(0, Math.floor((Date.now() - Date.parse(since)) / 1000));
    const m = Math.floor(seconds / 60);
    return m + ":" + String(seconds % 60).padStart(2, "0");
  }

  const notified = new Set<string>();

  function renderIncoming() {
    let box = document.getElementById("call-incoming");
    const ringing = calls.find(
      (call) => myState(call) === "ringing" && !dismissed.has(call.id) && call.id !== active?.call.id,
    );
    if (!ringing) {
      box?.remove();
      if (tone === "ring") stopTone();
      return;
    }
    if (!box) {
      box = el("div", "call-incoming");
      box.id = "call-incoming";
      document.body.appendChild(box);
    }
    if (box.dataset.call === ringing.id) return;
    box.dataset.call = ringing.id;
    box.textContent = "";
    const title =
      ringing.chat_type === "group"
        ? t("call.incomingGroup", { name: callerName(ringing), group: ringing.chat_name })
        : t("call.incoming", { name: callerName(ringing) });
    box.append(
      el("div", "call-incoming-icon", "📞"),
      el("div", "call-incoming-title", title),
      el("div", "call-buttons"),
    );
    box.lastElementChild!.append(
      actionButton("✕", "call-decline", t("call.decline"), () => decline(ringing)),
      actionButton("📞", "call-accept", t("call.accept"), () => answer(ringing)),
    );
    if (!active) playTone("ring");
    if (document.hidden && !notified.has(ringing.id) && "Notification" in window && Notification.permission === "granted") {
      notified.add(ringing.id);
      const note = new Notification("SereS", { body: title, tag: "call-" + ringing.id });
      note.onclick = () => window.focus();
    }
  }

  // -------------------------------------------------- who is speaking

  // A green ring shows who is speaking: the loudness of each stream is
  // measured a few times per second (nothing is recorded or sent anywhere).
  const levels = new Map<string, { source: MediaStreamAudioSourceNode; analyser: AnalyserNode; heardAt: number }>();
  let levelTimer: number | null = null;

  function watchLevel(userId: string, stream: MediaStream) {
    unwatchLevel(userId);
    try {
      audioContext = audioContext || new AudioContext();
      audioContext.resume().catch(() => {});
      const source = audioContext.createMediaStreamSource(stream);
      const analyser = audioContext.createAnalyser();
      analyser.fftSize = 512;
      source.connect(analyser);
      levels.set(userId, { source, analyser, heardAt: 0 });
    } catch {
      return;
    }
    if (levelTimer === null) levelTimer = window.setInterval(showSpeaking, 120);
  }

  function unwatchLevel(userId: string) {
    const level = levels.get(userId);
    if (!level) return;
    level.source.disconnect();
    levels.delete(userId);
    if (!levels.size && levelTimer !== null) {
      clearInterval(levelTimer);
      levelTimer = null;
    }
  }

  function showSpeaking() {
    const now = Date.now();
    const samples = new Uint8Array(512);
    for (const [userId, level] of levels) {
      level.analyser.getByteTimeDomainData(samples);
      let sum = 0;
      for (const value of samples) sum += ((value - 128) / 128) ** 2;
      const loud = Math.sqrt(sum / samples.length) > 0.035;
      const muted = userId === deps.me().id && active?.muted;
      if (loud && !muted) level.heardAt = now;
      // Stays on a moment after the last sound, so the ring doesn't flicker.
      const speaking = now - level.heardAt < 400;
      windowEl?.querySelector(`[data-user="${CSS.escape(userId)}"]`)?.classList.toggle("speaking", speaking);
    }
  }

  // ------------------------------------------------------ call window

  let windowEl: HTMLElement | null = null;
  let parts: { title: HTMLElement; status: HTMLElement; tiles: HTMLElement; buttons: HTMLElement; popButton: HTMLButtonElement } | null = null;
  let tilesSignature = "";
  // The separate window, when the call was moved out of the page.
  let popup: Window | null = null;
  const POSITION_KEY = "seres-call-position";

  function createWindow() {
    const box = el("div", "call-window");
    const head = el("div", "call-window-head");
    const titles = el("div", "call-window-titles");
    const title = el("span", "call-window-title");
    title.title = t("call.openChat");
    const status = el("span", "call-window-status");
    titles.append(title, status);
    const popButton = el("button", "call-window-pop", "⧉") as HTMLButtonElement;
    popButton.type = "button";
    popButton.addEventListener("click", () => void (popup ? closeWindow(true) : popOut()));
    head.append(titles, popButton);
    const tiles = el("div", "call-tiles");
    const buttons = el("div", "call-buttons");
    box.append(head, tiles, buttons);
    makeDraggable(box, head);
    parts = { title, status, tiles, buttons, popButton };
    tilesSignature = "";
    return box;
  }

  /**
   * The window can be moved by its title bar; the place is remembered.
   * A click on the name without moving opens the chat.
   */
  function makeDraggable(box: HTMLElement, handle: HTMLElement) {
    let start: { x: number; y: number; left: number; top: number; onTitle: boolean; moved: boolean } | null = null;
    handle.addEventListener("pointerdown", (event) => {
      const target = event.target as Element;
      if (target.closest("button") || event.button !== 0) return;
      const rect = box.getBoundingClientRect();
      start = {
        x: event.clientX,
        y: event.clientY,
        left: rect.left,
        top: rect.top,
        onTitle: !!target.closest(".call-window-title"),
        moved: false,
      };
      if (popup) return;
      handle.setPointerCapture(event.pointerId);
      box.classList.add("dragging");
    });
    handle.addEventListener("pointermove", (event) => {
      if (!start) return;
      if (Math.abs(event.clientX - start.x) + Math.abs(event.clientY - start.y) > 4) start.moved = true;
      if (!popup && start.moved) place(box, start.left + event.clientX - start.x, start.top + event.clientY - start.y);
    });
    const stop = () => {
      if (!start) return;
      const { onTitle, moved } = start;
      start = null;
      box.classList.remove("dragging");
      if (!moved) {
        if (onTitle && active) {
          if (popup) window.focus();
          deps.openChat(active.call.chat_id);
        }
        return;
      }
      const rect = box.getBoundingClientRect();
      try {
        localStorage.setItem(POSITION_KEY, JSON.stringify({ left: rect.left, top: rect.top }));
      } catch {
        // Not saved (private window): it starts at the default place next time.
      }
    };
    handle.addEventListener("pointerup", stop);
    handle.addEventListener("pointercancel", stop);
  }

  /** Moves the window, but never (partly) out of the browser window. */
  function place(box: HTMLElement, left: number, top: number) {
    const maxLeft = window.innerWidth - box.offsetWidth - 8;
    const maxTop = window.innerHeight - box.offsetHeight - 8;
    box.style.left = Math.max(8, Math.min(left, maxLeft)) + "px";
    box.style.top = Math.max(8, Math.min(top, maxTop)) + "px";
    box.style.right = "auto";
    box.style.transform = "none";
  }

  function restorePosition(box: HTMLElement) {
    try {
      const saved = JSON.parse(localStorage.getItem(POSITION_KEY) || "null");
      if (saved && typeof saved.left === "number") place(box, saved.left, saved.top);
    } catch {
      // Default place from the stylesheet.
    }
  }

  window.addEventListener("resize", () => {
    if (windowEl && !popup && windowEl.style.left) {
      place(windowEl, parseFloat(windowEl.style.left), parseFloat(windowEl.style.top));
    }
  });

  /**
   * Moves the call into its own window: a picture-in-picture window that stays
   * on top (Chrome, Edge), otherwise a normal popup. The call keeps running in
   * this page; only the controls move.
   */
  async function popOut() {
    if (!windowEl || popup) return;
    const pip = (window as any).documentPictureInPicture;
    let win: Window | null = null;
    try {
      win = pip
        ? await pip.requestWindow({ width: 380, height: 360 })
        : window.open("", "seres-call", "popup,width=380,height=380");
    } catch {
      win = null;
    }
    if (!win || !windowEl) {
      deps.showAlert(t("call.popupBlocked"));
      return;
    }
    popup = win;
    const doc = win.document;
    doc.title = "SereS – " + (active?.call.chat_name || "");
    for (const link of document.querySelectorAll<HTMLLinkElement>('link[rel="stylesheet"]')) {
      const copy = doc.createElement("link");
      copy.rel = "stylesheet";
      copy.href = link.href;
      doc.head.appendChild(copy);
    }
    doc.body.className = document.body.className + " call-popup";
    doc.body.appendChild(windowEl);
    windowEl.removeAttribute("style");
    win.addEventListener("pagehide", () => {
      if (popup === win) closeWindow(true);
    });
    renderPanel();
  }

  /** Back into the page (back = true) or away completely (call ended). */
  function closeWindow(back = false) {
    const win = popup;
    popup = null;
    if (back && windowEl) {
      document.body.appendChild(windowEl);
      restorePosition(windowEl);
      renderPanel();
    }
    if (win && !win.closed) win.close();
  }

  function stateText(p: CallParticipant) {
    if (p.id === deps.me().id) return "";
    if (p.state === "ringing") return t("call.ringingShort");
    if (p.state !== "joined") return t("call.notThere");
    const peer = active?.peers.get(p.id);
    if (peer?.pc.connectionState === "disconnected") return t("call.reconnecting");
    if (peer?.pc.connectionState !== "connected") return t("call.connectingShort");
    // Through TURN over TCP the audio can lag: the UDP ports of the TURN server are closed.
    return peer.route === "relay-tcp" ? t("call.routeTcp") : peer.route === "relay" ? t("call.routeRelay") : "";
  }

  /** The video someone shows in the call, if any: mine is the preview. */
  function videoOf(p: CallParticipant): { element: HTMLVideoElement; kind: VideoKind } | null {
    if (!active) return null;
    if (p.id === deps.me().id) return active.video ? { element: active.video.preview, kind: active.video.kind } : null;
    const peer = active.peers.get(p.id);
    return peer && peer.remoteVideo && peer.pc.connectionState === "connected" ? { element: peer.video, kind: peer.remoteVideo } : null;
  }

  function renderTiles(people: CallParticipant[]) {
    if (!parts || !active) return;
    const signature =
      JSON.stringify(people.map((p) => [p.id, p.state, stateText(p), videoOf(p)?.kind ?? null])) + active.muted;
    if (signature === tilesSignature) return;
    tilesSignature = signature;
    parts.tiles.textContent = "";
    parts.tiles.classList.toggle("many", people.length > 4);
    const anyVideo = people.some((p) => videoOf(p));
    windowEl?.classList.toggle("has-video", anyVideo);
    const meId = deps.me().id;
    for (const p of people) {
      const video = videoOf(p);
      const tile = el(
        "div",
        "call-tile" + (p.state === "joined" ? "" : " waiting") + (video ? " with-video " + video.kind : ""),
      );
      tile.dataset.user = p.id;
      const picture = el("div", "call-tile-avatar");
      if (video) {
        picture.appendChild(video.element);
        video.element.play().catch(() => {});
      } else {
        const avatar = deps.avatar(p.username, nameOf(p));
        // Absolute addresses, so the pictures also load in the separate window.
        avatar.querySelectorAll("img").forEach((img) => (img.src = img.src));
        picture.appendChild(avatar);
      }
      if (p.id === meId && active.muted) picture.appendChild(el("span", "call-tile-muted", "🔇"));
      const name = el("div", "call-tile-name", p.id === meId ? t("call.you") : nameOf(p));
      tile.append(picture, name);
      const state = stateText(p);
      if (state) tile.appendChild(el("div", "call-tile-state", state));
      parts.tiles.appendChild(tile);
    }
  }

  function renderPanel() {
    if (!active) {
      windowEl?.remove();
      windowEl = null;
      parts = null;
      if (tone === "back") stopTone();
      return;
    }
    if (!windowEl) {
      windowEl = createWindow();
      document.body.appendChild(windowEl);
      restorePosition(windowEl);
    }
    const meId = deps.me().id;
    const others = active.call.participants.filter((p) => p.id !== meId && p.state !== "left");
    const joinedOthers = others.filter((p) => p.state === "joined");
    const connected = [...active.peers.values()].some((peer) => peer.pc.connectionState === "connected");
    let status: string;
    if (!joinedOthers.length) status = t("call.ringing");
    else if (!connected) status = t("call.connecting");
    else status = duration(active.call.answered_at || active.call.started_at);
    if (!joinedOthers.length && active.call.started_by === meId) playTone("back");
    else if (tone === "back") stopTone();

    const p = parts!;
    p.title.textContent = active.call.chat_name;
    p.status.textContent = status;
    p.popButton.textContent = popup ? "⇲" : "⧉";
    p.popButton.title = t(popup ? "call.popIn" : "call.popOut");
    if (popup) popup.document.title = "SereS – " + active.call.chat_name + " · " + status;

    const me = active.call.participants.find((x) => x.id === meId);
    renderTiles(me ? [me, ...others] : others);

    p.buttons.textContent = "";
    const camera = active.video?.kind === "camera";
    const screen = active.video?.kind === "screen";
    p.buttons.append(
      actionButton(active.muted ? "🔇" : "🎤", "call-mute" + (active.muted ? " on" : ""), t(active.muted ? "call.unmute" : "call.mute"), toggleMute),
      actionButton("📷", "call-camera" + (camera ? " on" : ""), t(camera ? "call.cameraOff" : "call.camera"), () => void toggleCamera()),
    );
    // Phones can't share their screen from the browser.
    if (navigator.mediaDevices && "getDisplayMedia" in navigator.mediaDevices) {
      p.buttons.append(
        actionButton("🖥️", "call-screen" + (screen ? " on" : ""), t(screen ? "call.screenOff" : "call.screen"), () => void toggleScreen()),
      );
    }
    p.buttons.append(
      actionButton("👤+", "call-add", t("call.addPeople"), () => {
        // Picking people happens in the page.
        if (popup) window.focus();
        void addPeople();
      }),
      actionButton("📞", "call-hangup", t("call.hangUp"), () => void hangUp()),
    );
  }

  function init(dependencies: CallDeps) {
    deps = dependencies;
    window.addEventListener("beforeunload", () => {
      if (active) navigator.sendBeacon?.(`/api/calls/${encodeURIComponent(active.call.id)}/leave`);
    });
    poll();
  }

  return {
    init,
    start,
    hangUp,
    /** The chat that has a running call I'm in, if any. */
    activeChat: () => active?.call.chat_id || null,
  };
})();

(window as any).SeresCalls = SeresCalls;
