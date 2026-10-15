// Message formatting like Discord / WhatsApp, built with DOM nodes only (never innerHTML).
//
//   **bold**  *italic*  _italic_  ~~strike~~  `code`  ```code block```
//   ||spoiler||  > quote  https://links  @mentions
//
// Messages that only consist of 1-3 emoji are shown larger.

interface SeresFormatOptions {
  /** Lower-case usernames / display names that count as a mention of the reader. */
  myNames?: string[];
  /** Called with the mentioned name when a @mention is clicked. */
  onMention?: (name: string) => void;
}

const SeresFormat = (() => {
  const INLINE =
    /(`[^`\n]+`)|(\*\*[^*\n](?:[^\n]*?[^*\n])?\*\*)|(~~[^~\n]+~~)|(\|\|[^|\n]+\|\|)|(\*[^*\s](?:[^*\n]*?[^*\s])?\*)|((?:^|(?<=[\s(]))_[^_\s](?:[^_\n]*?[^_\s])?_(?=$|[\s.,!?)]))|(\bhttps?:\/\/[^\s<>"]+[^\s<>".,!?)\]])|((?:^|(?<=[\s(]))@[A-Za-z0-9_-]{2,32})/g;

  function el(tag: string, className?: string) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    return node;
  }

  function inline(text: string, options: SeresFormatOptions, state: { mentioned: boolean }, depth = 0): DocumentFragment {
    const fragment = document.createDocumentFragment();
    if (depth > 4) {
      fragment.appendChild(document.createTextNode(text));
      return fragment;
    }
    const pattern = new RegExp(INLINE.source, "g");
    let last = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(text))) {
      if (match.index > last) fragment.appendChild(document.createTextNode(text.slice(last, match.index)));
      const [token, code, bold, strike, spoiler, italic, underscore, url, mention] = match;
      let node: Node;
      if (code) {
        node = el("code", "md-code");
        node.textContent = code.slice(1, -1);
      } else if (bold) {
        node = el("strong");
        node.appendChild(inline(bold.slice(2, -2), options, state, depth + 1));
      } else if (strike) {
        node = el("s");
        node.appendChild(inline(strike.slice(2, -2), options, state, depth + 1));
      } else if (spoiler) {
        const span = el("span", "md-spoiler");
        span.title = "Spoiler";
        span.tabIndex = 0;
        span.appendChild(inline(spoiler.slice(2, -2), options, state, depth + 1));
        const reveal = (event: Event) => {
          event.stopPropagation();
          span.classList.add("revealed");
        };
        span.addEventListener("click", reveal);
        span.addEventListener("keydown", (event) => {
          if ((event as KeyboardEvent).key === "Enter") reveal(event);
        });
        node = span;
      } else if (italic || underscore) {
        node = el("em");
        node.appendChild(inline((italic || underscore).slice(1, -1), options, state, depth + 1));
      } else if (url) {
        const link = el("a") as HTMLAnchorElement;
        link.textContent = url;
        link.href = url;
        link.target = "_blank";
        link.rel = "noopener noreferrer nofollow";
        node = link;
      } else if (mention) {
        const name = mention.slice(1);
        const mine = (options.myNames || []).includes(name.toLowerCase());
        if (mine) state.mentioned = true;
        const span = el("span", "md-mention" + (mine ? " me" : ""));
        span.textContent = mention;
        if (options.onMention) {
          span.addEventListener("click", (event) => {
            event.stopPropagation();
            options.onMention!(name);
          });
        }
        node = span;
      } else {
        node = document.createTextNode(token);
      }
      fragment.appendChild(node);
      last = match.index + token.length;
    }
    if (last < text.length) fragment.appendChild(document.createTextNode(text.slice(last)));
    return fragment;
  }

  /** Lines starting with "> " become a quote block. */
  function blocks(text: string, options: SeresFormatOptions, state: { mentioned: boolean }) {
    const fragment = document.createDocumentFragment();
    const lines = text.split("\n");
    let quote: HTMLElement | null = null;
    lines.forEach((line, index) => {
      const isQuote = /^>\s?/.test(line);
      if (isQuote) {
        if (!quote) {
          quote = el("blockquote", "md-quote");
          fragment.appendChild(quote);
        } else {
          quote.appendChild(document.createTextNode("\n"));
        }
        quote.appendChild(inline(line.replace(/^>\s?/, ""), options, state));
        return;
      }
      quote = null;
      fragment.appendChild(inline(line, options, state));
      if (index < lines.length - 1 && !/^>\s?/.test(lines[index + 1])) fragment.appendChild(document.createTextNode("\n"));
    });
    return fragment;
  }

  const EMOJI_ONLY = /^(?:\p{Extended_Pictographic}(?:️|‍\p{Extended_Pictographic}|\p{Emoji_Modifier})*\s*){1,3}$/u;

  function isEmojiOnly(text: string) {
    return EMOJI_ONLY.test(text.trim());
  }

  /** Formats a message text. Returns the nodes and whether the reader was @mentioned. */
  function render(text: string, options: SeresFormatOptions = {}) {
    const state = { mentioned: false };
    const fragment = document.createDocumentFragment();
    const parts = text.split("```");
    parts.forEach((part, index) => {
      const isCode = index % 2 === 1 && index < parts.length - 1;
      if (isCode) {
        const pre = el("pre", "md-codeblock");
        // A language name on the first line (```js) is not shown.
        pre.textContent = part.replace(/^[a-z0-9+#-]*\n/i, "").replace(/\n$/, "");
        fragment.appendChild(pre);
        return;
      }
      // An unclosed ``` is shown as typed.
      let chunk = index % 2 === 1 ? "```" + part : part;
      if (index > 0 && index % 2 === 0) chunk = chunk.replace(/^\n/, "");
      if (index < parts.length - 1 && index % 2 === 0) chunk = chunk.replace(/\n$/, "");
      if (chunk) fragment.appendChild(blocks(chunk, options, state));
    });
    return { fragment, mentioned: state.mentioned, emojiOnly: isEmojiOnly(text) };
  }

  /** Plain text for previews: formatting characters removed. */
  function plain(text: string) {
    return text
      .replace(/```[a-z0-9+#-]*\n?/gi, "")
      .replace(/\|\|([^|\n]+)\|\|/g, "▒▒▒")
      .replace(/(\*\*|~~|`)(.+?)\1/g, "$2")
      .replace(/(^|\s)[*_](\S.*?\S|\S)[*_](?=\s|$)/g, "$1$2")
      .replace(/^>\s?/gm, "")
      .replace(/\s+/g, " ")
      .trim();
  }

  return { render, plain, isEmojiOnly };
})();

(window as any).SeresFormat = SeresFormat;
