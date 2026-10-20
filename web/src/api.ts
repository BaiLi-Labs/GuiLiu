import type { Me } from './types';

export class ApiError extends Error {
  status: number;
  code?: string;
  constructor(status: number, message: string, code?: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

type Options = RequestInit & { skipAuthEvent?: boolean };

async function request<T>(path: string, opts: Options = {}): Promise<T> {
  const { skipAuthEvent: _skip, headers, ...rest } = opts;
  const init: RequestInit = {
    credentials: 'same-origin',
    ...rest,
    headers: {
      ...(rest.body ? { 'Content-Type': 'application/json' } : {}),
      ...(headers || {}),
    },
  };
  let res: Response;
  try {
    res = await fetch(path, init);
  } catch {
    throw new ApiError(0, '无法连接服务端');
  }
  const text = await res.text();
  let body: any = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
  }
  if (!res.ok) {
    const message = body?.error?.message || `${res.status} ${res.statusText}`;
    throw new ApiError(res.status, message, body?.error?.code);
  }
  return body as T;
}

export function api<T>(path: string, opts: Options = {}): Promise<T> {
  return request<T>(`/api/v1${path}`, opts);
}

export async function login(username: string, password: string): Promise<Me> {
  return request<Me>('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
}

export async function logout(): Promise<void> {
  await request('/api/v1/auth/logout', { method: 'POST' });
}

export function jsonBody(value: unknown): BodyInit {
  return JSON.stringify(value);
}
