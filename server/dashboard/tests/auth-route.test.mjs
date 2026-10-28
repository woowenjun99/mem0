import { afterEach, beforeEach, expect, mock, test } from "bun:test";

const stored = new Map();
const cookieStore = {
  get: (name) => (stored.has(name) ? { value: stored.get(name) } : undefined),
  set: (name, value) => {
    stored.set(name, value);
  },
  delete: (name) => {
    stored.delete(name);
  },
};
mock.module("next/headers", () => ({ cookies: async () => cookieStore }));

const { DELETE } = await import("../src/app/api/auth/refresh/route");
const originalFetch = globalThis.fetch;

beforeEach(() => {
  stored.set("mem0_refresh_token", "synthetic-refresh-token");
});
afterEach(() => {
  globalThis.fetch = originalFetch;
  stored.clear();
});

test("logout revokes the server session before clearing its cookie", async () => {
  const calls = [];
  globalThis.fetch = mock(async (url, init) => {
    calls.push({ url: String(url), body: JSON.parse(String(init?.body)) });
    expect(stored.has("mem0_refresh_token")).toBe(true);
    return Response.json({ message: "All browser sessions signed out." });
  });
  expect((await DELETE()).status).toBe(200);
  expect(calls).toHaveLength(1);
  expect(calls[0].url.endsWith("/auth/logout")).toBe(true);
  expect(calls[0].body).toEqual({ refresh_token: "synthetic-refresh-token" });
  expect(stored.has("mem0_refresh_token")).toBe(false);
});

test("logout retains the credential when server revocation fails", async () => {
  globalThis.fetch = mock(async () => new Response(null, { status: 503 }));
  expect((await DELETE()).status).toBe(502);
  expect(stored.has("mem0_refresh_token")).toBe(true);
});
