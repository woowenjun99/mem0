import axios, { AxiosError, AxiosInstance } from "axios";

let cachedToken: string | null = null;
let revokingSession = false;
const LOGIN_PATH = "/login";

export const setAccessToken = (token: string | null) => {
  cachedToken = token;
};

export const getAccessToken = (): string | null => {
  return cachedToken;
};

const handleTokenError = () => {
  cachedToken = null;
};

const redirectToLogin = () => {
  if (typeof window !== "undefined") {
    window.location.href = LOGIN_PATH;
  }
};

let refreshPromise: Promise<string | null> | null = null;
let sessionQueue: Promise<void> = Promise.resolve();

export function withSessionLock<T>(action: () => Promise<T>): Promise<T> {
  const operation = sessionQueue.then(async () => {
    if (typeof navigator !== "undefined" && navigator.locks) {
      return await navigator.locks.request<Promise<T>>("mem0-session", action);
    }
    return action();
  });
  sessionQueue = operation.then(
    () => undefined,
    () => undefined,
  );
  return operation;
}

async function performRefresh() {
  const refreshResponse = await fetch("/api/auth/refresh", {
    method: "POST",
    credentials: "include",
  });

  if (!refreshResponse.ok) {
    return null;
  }

  const data = await refreshResponse.json();
  if (revokingSession) return null;
  setAccessToken(data.access_token);
  return data.access_token as string;
}

export function refreshAccessToken(): Promise<string | null> {
  if (revokingSession) return Promise.resolve(null);
  if (!refreshPromise) {
    refreshPromise = withSessionLock(performRefresh).finally(() => {
      refreshPromise = null;
    });
  }
  return refreshPromise;
}

export async function revokeSession() {
  revokingSession = true;
  try {
    await refreshPromise?.catch(() => null);
    const response = await withSessionLock(() =>
      fetch("/api/auth/refresh", { method: "DELETE" }),
    );
    if (!response.ok)
      throw new Error("Could not revoke sessions. Please retry signing out.");
    setAccessToken(null);
  } finally {
    revokingSession = false;
  }
}

const createApi = (): AxiosInstance & {
  postStream: (url: string, data: unknown) => Promise<Response>;
} => {
  const api = axios.create({
    baseURL: process.env.NEXT_PUBLIC_API_URL,
  });

  api.interceptors.request.use(
    async (config) => {
      if (cachedToken) {
        config.headers = config.headers ?? {};
        config.headers.Authorization = `Bearer ${cachedToken}`;
      }
      return config;
    },
    (error) => {
      return Promise.reject(error);
    },
  );

  api.interceptors.response.use(
    (response) => response,
    async (error: AxiosError<{ error?: string }>) => {
      if (
        error.response?.status === 401 &&
        !["/auth/login", "/auth/register"].includes(error.config?.url ?? "")
      ) {
        handleTokenError();

        try {
          const nextToken = await refreshAccessToken();
          if (nextToken && error.config) {
            error.config.headers = error.config.headers ?? {};
            error.config.headers.Authorization = `Bearer ${nextToken}`;
            return api.request(error.config);
          }
        } catch {}

        handleTokenError();
        redirectToLogin();
      }

      if (error.response?.data?.error) {
        return Promise.reject(error.response.data.error);
      }

      return Promise.reject(error);
    },
  );

  const postStream = async (url: string, data: unknown): Promise<Response> => {
    const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}${url}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: cachedToken ? `Bearer ${cachedToken}` : "",
      },
      body: JSON.stringify(data),
    });

    if (response.status === 401) {
      handleTokenError();
      redirectToLogin();
      throw new Error("Unauthorized");
    }

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || "Request failed");
    }

    return response;
  };

  return Object.assign(api, { postStream });
};

export const api = createApi();
