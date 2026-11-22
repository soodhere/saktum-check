// Everything a tested server sends is untrusted. Nothing reaches a terminal, report or log without passing through here.
const ANSI_CSI = /\u001b\[[0-9;?]*[ -\/]*[@-~]/g;            // e.g. colour, cursor movement, screen clearing
const ANSI_OSC = /\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)/g; // e.g. terminal title, hyperlinks
const OTHER_ESC = /\u001b[@-_]?/g;
const C0_C1 = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;      // control characters (keeps tab and newline)
export const INVISIBLE = /[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g; // zero-width and bidirectional controls

/** Make untrusted text safe to print: strip escape sequences and controls, reveal invisible characters, cap length. */
export function sanitizeText(text: unknown, maxLength = 240): string {
  let s = typeof text === "string" ? text : JSON.stringify(text ?? "");
  s = s.replace(ANSI_OSC, "").replace(ANSI_CSI, "").replace(OTHER_ESC, "").replace(C0_C1, "");
  s = s.replace(INVISIBLE, (c) => `<U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}>`);
  s = s.replace(/[\r\n\t]+/g, " ");
  return s.length > maxLength ? s.slice(0, maxLength - 1) + "\u2026" : s;
}

export function escapeHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/** Depth guard for untrusted JSON (deeply nested values can exhaust the stack in naive walkers). */
export function maxDepth(value: unknown, limit = 64): number {
  let deepest = 0;
  const walk = (v: unknown, d: number): void => {
    if (d > limit) throw new Error(`value nested deeper than ${limit} levels`);
    deepest = Math.max(deepest, d);
    if (v && typeof v === "object") for (const x of Object.values(v as Record<string, unknown>)) walk(x, d + 1);
  };
  walk(value, 0);
  return deepest;
}
