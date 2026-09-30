// Lightweight syntax highlighter (PRD §36): keywords, strings, comments, numbers.
// Produces DOM nodes via textContent only — audited code is untrusted and never parsed as HTML.
(function () {
  const KEYWORDS = {
    Python: "and as assert async await break class continue def del elif else except False finally for from global if import in is lambda None nonlocal not or pass raise return self True try while with yield",
    JavaScript: "async await break case catch class const continue default delete do else export extends false finally for function if import in instanceof let new null of return super switch this throw true try typeof undefined var void while yield require module exports",
    PHP: "abstract and array as break case catch class clone const continue declare default do echo else elseif empty extends false final finally fn for foreach function global if implements include include_once instanceof interface isset list namespace new null or print private protected public require require_once return static switch throw trait true try unset use var while",
    Java: "abstract assert boolean break byte case catch char class const continue default do double else enum extends false final finally float for if implements import instanceof int interface long native new null package private protected public return short static super switch synchronized this throw throws true try void volatile while var",
    Go: "break case chan const continue default defer else fallthrough for func go goto if import interface map nil package range return select struct switch type var true false",
  };
  KEYWORDS.TypeScript = KEYWORDS.JavaScript + " interface type enum implements private public protected readonly declare namespace as";
  const sets = Object.fromEntries(Object.entries(KEYWORDS).map(([k, v]) => [k, new Set(v.split(" "))]));
  const HASH_COMMENT = new Set(["Python", "PHP"]);

  // Returns [{cls, text}] for one line; `state` carries an open /* */ comment across lines.
  function tokenize(line, language, state) {
    const kw = sets[language] || new Set();
    const out = [];
    let i = 0;
    const push = (cls, text) => { if (text) out.push({ cls, text }); };
    if (state.block) {
      const end = line.indexOf("*/");
      if (end === -1) { push("tok-com", line); return out; }
      push("tok-com", line.slice(0, end + 2));
      i = end + 2;
      state.block = false;
    }
    while (i < line.length) {
      const rest = line.slice(i);
      const ch = line[i];
      if (rest.startsWith("/*") && language !== "Python") {
        const end = line.indexOf("*/", i + 2);
        if (end === -1) { push("tok-com", rest); state.block = true; break; }
        push("tok-com", line.slice(i, end + 2)); i = end + 2; continue;
      }
      if (rest.startsWith("//") && language !== "Python") { push("tok-com", rest); break; }
      if (ch === "#" && HASH_COMMENT.has(language)) { push("tok-com", rest); break; }
      if (ch === "\"" || ch === "'" || ch === "`") {
        let j = i + 1;
        while (j < line.length && line[j] !== ch) j += line[j] === "\\" ? 2 : 1;
        push("tok-str", line.slice(i, j + 1)); i = j + 1; continue;
      }
      const num = /^\d[\d_]*(\.\d+)?/.exec(rest);
      if (num && !/[\w$]/.test(line[i - 1] || "")) { push("tok-num", num[0]); i += num[0].length; continue; }
      const word = /^[$A-Za-z_][\w$]*/.exec(rest);
      if (word) {
        const w = word[0];
        const cls = kw.has(w) ? "tok-kw" : (language === "PHP" && w.startsWith("$")) ? "tok-var"
          : line[i + w.length] === "(" ? "tok-fn" : null;
        push(cls, w); i += w.length; continue;
      }
      // Plain text up to the next interesting character.
      const plain = /^[^"'`#/$A-Za-z_\d]+/.exec(rest);
      const text = plain ? plain[0] : ch;
      push(null, text); i += text.length;
    }
    return out;
  }

  function highlightLine(line, language, state) {
    const frag = document.createDocumentFragment();
    for (const t of tokenize(line, language, state)) {
      if (t.cls) {
        const span = document.createElement("span");
        span.className = t.cls;
        span.textContent = t.text;
        frag.append(span);
      } else {
        frag.append(document.createTextNode(t.text));
      }
    }
    return frag;
  }

  window.Highlight = { highlightLine, newState: () => ({ block: false }) };
})();
