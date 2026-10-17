// A small emoji picker (no external libraries, works with the strict CSP).

const SeresEmoji = (() => {
  const CATEGORIES: [string, string][] = [
    ["😀", "😀 😃 😄 😁 😆 😅 🤣 😂 🙂 🙃 😉 😊 😇 🥰 😍 🤩 😘 😗 😚 😙 😋 😛 😜 🤪 😝 🤑 🤗 🤭 🤫 🤔 🤐 🤨 😐 😑 😶 😏 😒 🙄 😬 😌 😔 😪 🤤 😴 😷 🤒 🤕 🤢 🤮 🥵 🥶 🥴 😵 🤯 🤠 🥳 😎 🤓 🧐 😕 😟 🙁 😮 😯 😲 😳 🥺 😦 😧 😨 😰 😥 😢 😭 😱 😖 😣 😞 😓 😩 😫 🥱 😤 😡 😠 🤬 😈 👿 💀 💩 🤡 👻 👽 🤖"],
    ["👍", "👍 👎 👌 🤌 ✌️ 🤞 🤟 🤘 🤙 👈 👉 👆 👇 ☝️ ✋ 🤚 🖐️ 🖖 👋 👏 🙌 👐 🤲 🤝 🙏 ✍️ 💪 🦾 👀 👁️ 🧠 🫶 💅 🤳"],
    ["❤️", "❤️ 🧡 💛 💚 💙 💜 🖤 🤍 🤎 💔 ❣️ 💕 💞 💓 💗 💖 💘 💝 💟 ♥️ 💯 💢 💥 💫 💦 💨 🔥 ✨ ⭐ 🌟 🎉 🎊"],
    ["🐶", "🐶 🐱 🐭 🐹 🐰 🦊 🐻 🐼 🐨 🐯 🦁 🐮 🐷 🐸 🐵 🙈 🙉 🙊 🐔 🐧 🐦 🦆 🦉 🐺 🐴 🦄 🐝 🐛 🦋 🐌 🐞 🐢 🐍 🐙 🐬 🐳 🦈 🌸 🌹 🌻 🌲 🍀 🌈 ☀️ 🌙 ⛄"],
    ["🍕", "🍏 🍎 🍐 🍊 🍋 🍌 🍉 🍇 🍓 🍒 🍑 🥭 🍍 🥥 🥝 🍅 🥑 🥦 🌶️ 🌽 🥕 🥐 🍞 🧀 🍳 🥓 🍔 🍟 🍕 🌭 🥪 🌮 🍝 🍣 🍜 🍩 🍪 🎂 🍰 🍫 🍿 ☕ 🍵 🥤 🍺 🍻 🥂 🍷"],
    ["⚽", "⚽ 🏀 🏈 ⚾ 🎾 🏐 🎱 🏓 🏸 🥅 🏒 ⛳ 🎣 🎽 🎿 🏆 🥇 🎮 🕹️ 🎲 🧩 🎯 🎳 🎸 🎹 🥁 🎤 🎧 🎬 🎨 🚗 🚕 🚌 🏎️ 🚓 🚑 🚒 🚲 🛴 ✈️ 🚀 🛸 🚢 🏠 🏝️ 🗺️"],
    ["💡", "⌚ 📱 💻 ⌨️ 🖥️ 🖨️ 🖱️ 💾 📷 📹 🎥 📞 📺 📻 ⏰ ⌛ 🔋 🔌 💡 🔦 🕯️ 💸 💵 💰 💳 💎 🔧 🔨 🛠️ 🔑 🔒 🔓 🛡️ 📦 📫 ✉️ 📝 📅 📌 📎 ✂️ 📚 🔍 🎁 🎈"],
    ["✅", "✅ ☑️ ✔️ ❌ ❎ ➕ ➖ ➗ ✖️ ❓ ❔ ❗ ❕ ‼️ ⁉️ 💤 🚫 ⛔ ⚠️ 🔞 ♻️ 🆗 🆕 🆒 🆘 🔴 🟠 🟡 🟢 🔵 🟣 ⚫ ⚪ ▶️ ⏸️ ⏹️ 🔁 🔀 🔔 🔕 🎵 🎶 💬 💭"],
  ];

  const RECENT_KEY = "seres-emoji-recent";

  function recent(): string[] {
    try {
      const list = JSON.parse(localStorage.getItem(RECENT_KEY) || "[]");
      return Array.isArray(list) ? list.filter((e) => typeof e === "string").slice(0, 24) : [];
    } catch {
      return [];
    }
  }

  function remember(emoji: string) {
    try {
      const list = [emoji, ...recent().filter((e) => e !== emoji)].slice(0, 24);
      localStorage.setItem(RECENT_KEY, JSON.stringify(list));
    } catch {
      /* storage unavailable */
    }
  }

  /** Builds a picker element; onPick is called with the chosen emoji. */
  function picker(onPick: (emoji: string) => void, recentLabel = "🕘"): HTMLElement {
    const root = document.createElement("div");
    root.className = "emoji-picker";
    const tabs = document.createElement("div");
    tabs.className = "emoji-tabs";
    const grid = document.createElement("div");
    grid.className = "emoji-grid";
    root.appendChild(tabs);
    root.appendChild(grid);

    const categories: [string, string[]][] = CATEGORIES.map(([icon, list]) => [icon, list.split(" ")]);
    const recents = recent();
    if (recents.length) categories.unshift([recentLabel, recents]);

    const show = (index: number) => {
      grid.textContent = "";
      tabs.querySelectorAll("button").forEach((tab, i) => tab.classList.toggle("active", i === index));
      for (const emoji of categories[index][1]) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "emoji-cell";
        btn.textContent = emoji;
        btn.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
          remember(emoji);
          onPick(emoji);
        });
        grid.appendChild(btn);
      }
    };
    categories.forEach(([icon], index) => {
      const tab = document.createElement("button");
      tab.type = "button";
      tab.className = "emoji-tab";
      tab.textContent = icon;
      tab.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        show(index);
      });
      tabs.appendChild(tab);
    });
    show(0);
    root.addEventListener("click", (event) => event.stopPropagation());
    return root;
  }

  /** The quick reactions shown in the message menu. */
  const QUICK = ["👍", "❤️", "😂", "😮", "😢", "🙏"];

  return { picker, remember, QUICK };
})();

(window as any).SeresEmoji = SeresEmoji;
