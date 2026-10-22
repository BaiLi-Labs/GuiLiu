import type { Me, SourceError } from './types';

export class ApiError extends Error {
  status: number;
  code?: string;
  sourceError?: SourceError;
  constructor(status: number, message: string, code?: string, sourceError?: SourceError) {
    super(message);
    this.status = status;
    this.code = code;
    this.sourceError = sourceError;
  }
}

type Options = RequestInit & { skipAuthEvent?: boolean };

async function request<T>(path: string, opts: Options = {}, responseType: 'json' | 'text' = 'json'): Promise<T> {
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
    const messages: Record<string, string> = {
      unauthorized: '认证失败，请重新登录',
      forbidden: '权限不足',
      invalid_credentials: '用户名或密码错误',
      too_many_attempts: '请求过于频繁，请稍后再试',
      already_running: '该账号正在同步',
      sync_disabled: '同步未启用',
      conflict: '账号名称已存在',
    };
    const message = messages[body?.error?.code] || body?.error?.message || `${res.status} ${res.statusText}`;
    throw new ApiError(res.status, message, body?.error?.code, body?.error?.source_error);
  }
  return (responseType === 'text' ? text : body) as T;
}

export function api<T>(path: string, opts: Options = {}): Promise<T> {
  return request<T>(`/api/v1${path}`, opts);
}

// Source bytes must bypass JSON.parse/stringify, which rounds large integers.
export function sourceText(rawURL: string, opts: Options = {}): Promise<string> {
  return request<string>(rawURL, opts, 'text');
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
