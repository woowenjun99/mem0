import { afterEach, expect, test } from "bun:test";
import {
  refreshAccessToken,
  setAccessToken,
  withSessionLock,
} from "../dashboard/src/utils/api";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
  setAccessToken(null);
});

test("concurrent refresh requests share one token rotation", async () => {
  let calls = 0;
  let finish!: (response: Response) => void;
  globalThis.fetch = (() => {
    calls++;
    return new Promise<Response>((resolve) => {
      finish = resolve;
    });
  }) as typeof fetch;

  const first = refreshAccessToken();
  const second = refreshAccessToken();
  await Promise.resolve();
  expect(calls).toBe(1);
  finish(Response.json({ access_token: "synthetic-token" }));
  expect(await Promise.all([first, second])).toEqual([
    "synthetic-token",
    "synthetic-token",
  ]);
});

test("session operations wait for the previous operation", async () => {
  let finish!: () => void;
  const events: string[] = [];
  const first = withSessionLock(async () => {
    events.push("start refresh");
    await new Promise<void>((resolve) => {
      finish = resolve;
    });
    events.push("end refresh");
  });
  const second = withSessionLock(async () => {
    events.push("logout");
  });
  await Promise.resolve();
  expect(events).toEqual(["start refresh"]);
  finish();
  await Promise.all([first, second]);
  expect(events).toEqual(["start refresh", "end refresh", "logout"]);
});
