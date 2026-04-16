// Node 22+ ships an experimental `localStorage` global that shadows
// happy-dom's. On Node 25 its methods (`removeItem`, `clear`, etc.) are
// stubbed out and throw unless `--localstorage-file` is passed on the CLI,
// which breaks any test that depends on Web Storage semantics.
//
// Replace `localStorage` and `sessionStorage` with a plain in-memory shim so
// tests have a working, isolated Storage API regardless of the Node version.

import { beforeEach } from "vitest";

class MemStorage implements Storage {
  private map = new Map<string, string>();
  get length() {
    return this.map.size;
  }
  key(index: number): string | null {
    return [...this.map.keys()][index] ?? null;
  }
  getItem(key: string): string | null {
    return this.map.get(key) ?? null;
  }
  setItem(key: string, value: string): void {
    this.map.set(key, String(value));
  }
  removeItem(key: string): void {
    this.map.delete(key);
  }
  clear(): void {
    this.map.clear();
  }
}

const local = new MemStorage();
const session = new MemStorage();

function install(name: "localStorage" | "sessionStorage", value: Storage) {
  Object.defineProperty(globalThis, name, {
    configurable: true,
    writable: true,
    value,
  });
  const w = (globalThis as unknown as { window?: object }).window;
  if (w) {
    Object.defineProperty(w, name, {
      configurable: true,
      writable: true,
      value,
    });
  }
}

install("localStorage", local);
install("sessionStorage", session);

beforeEach(() => {
  local.clear();
  session.clear();
});
