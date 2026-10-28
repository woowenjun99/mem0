import { afterEach, expect, mock, test } from "bun:test";
import {
  getAccessToken,
  refreshAccessToken,
  revokeSession,
  setAccessToken,
} from "../src/utils/api";

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
  setAccessToken(null);
});

test("concurrent callers share one refresh operation", async () => {
  let finish;
  globalThis.fetch = mock(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const first = refreshAccessToken();
  const second = refreshAccessToken();
  await Promise.resolve();
  expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  finish(Response.json({ access_token: "synthetic-access" }));
  expect(await Promise.all([first, second])).toEqual([
    "synthetic-access",
    "synthetic-access",
  ]);
  expect(getAccessToken()).toBe("synthetic-access");
});

test("logout waits for rotation and prevents another refresh from starting", async () => {
  let finish;
  const methods = [];
  globalThis.fetch = mock((_url, options) => {
    methods.push(options.method);
    if (options.method === "POST")
      return new Promise((resolve) => {
        finish = resolve;
      });
    return Promise.resolve(Response.json({ ok: true }));
  });
  const refresh = refreshAccessToken();
  await Promise.resolve();
  const logout = revokeSession();
  expect(await refreshAccessToken()).toBe(null);
  expect(methods).toEqual(["POST"]);
  finish(Response.json({ access_token: "revoked-access" }));
  await Promise.all([refresh, logout]);
  expect(methods).toEqual(["POST", "DELETE"]);
  expect(getAccessToken()).toBe(null);
});

test("failed revocation leaves the current session available for retry", async () => {
  setAccessToken("existing-access");
  globalThis.fetch = mock(async () => new Response(null, { status: 502 }));
  await expect(revokeSession()).rejects.toThrow("Could not revoke sessions");
  expect(getAccessToken()).toBe("existing-access");
});
