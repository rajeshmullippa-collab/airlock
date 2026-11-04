// Minimal Clocked API client for the browser and Node 18+.
// Follows https://clocked.rezolve.ai/docs/errors: one Idempotency-Key per logical
// request, reused on retries; bounded exponential backoff on network errors,
// 429 and 5xx; never retries 400/401/402/403/422; stops when retryAsNew is set.

export const CLOCKED_BASE = 'https://clocked.rezolve.ai/clocked';

export class ClockedError extends Error {
  constructor(status, message, retryAsNew = false) {
    super(message);
    this.name = 'ClockedError';
    this.status = status;
    this.retryAsNew = retryAsNew;
  }
}

export function uuid() {
  const c = globalThis.crypto;
  if (c && typeof c.randomUUID === 'function') return c.randomUUID();
  const b = new Uint8Array(16);
  if (c && c.getRandomValues) c.getRandomValues(b); else for (let i = 0; i < 16; i++) b[i] = Math.floor(Math.random() * 256);
  b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map(x => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

export function friendlyError(status, msg) {
  switch (status) {
    case 401: case 403: return 'Clocked rejected the API key (' + status + '). Check the key on your Clocked account page.';
    case 402: return 'The Clocked account is out of credits (402).';
    case 413: return 'The text is too large for one request (413). Trim it and try again.';
    case 422: case 400: return 'Clocked could not accept this request (' + status + '): ' + msg;
    case 429: return 'Clocked is busy for this account (429, concurrency limit). Try again in a moment.';
    default: return msg || ('Clocked request failed with status ' + status);
  }
}

export class ClockedClient {
  constructor({ apiKey, baseUrl = CLOCKED_BASE, fetchImpl, maxAttempts = 4, timeoutMs = 115000 } = {}) {
    if (!apiKey) throw new Error('A Clocked API key is required.');
    this.apiKey = apiKey;
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.fetch = fetchImpl || globalThis.fetch.bind(globalThis);
    this.maxAttempts = maxAttempts;
    this.timeoutMs = timeoutMs;
    this.mode = 'live';
  }

  // Returns { data, credits, ms, requestId }. `step` is only a label for recording.
  async call(endpoint, body, step = endpoint) {
    const requestId = uuid();
    let lastErr;
    for (let attempt = 0; attempt < this.maxAttempts; attempt++) {
      if (attempt > 0) await sleep(Math.min(8000, 700 * 2 ** (attempt - 1)) + Math.random() * 250);
      const t0 = Date.now();
      let res;
      const ctl = typeof AbortController !== 'undefined' ? new AbortController() : null;
      const timer = ctl ? setTimeout(() => ctl.abort(), this.timeoutMs) : null;
      try {
        res = await this.fetch(`${this.baseUrl}/${endpoint}`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${this.apiKey}`,
            'Content-Type': 'application/json',
            'Idempotency-Key': requestId,
          },
          body: JSON.stringify(body),
          signal: ctl ? ctl.signal : undefined,
        });
      } catch (e) {
        lastErr = new ClockedError(0, 'Network error talking to Clocked: ' + (e && e.message || e));
        continue; // unknown outcome: retry with the same Idempotency-Key
      } finally {
        if (timer) clearTimeout(timer);
      }
      let payload = null;
      const text = await res.text();
      try { payload = text ? JSON.parse(text) : null; } catch { payload = { error: text.slice(0, 300) }; }
      if (res.ok) {
        const credits = Number(res.headers.get('X-Clocked-Credits')) || null;
        return { data: payload, credits, ms: Date.now() - t0, requestId };
      }
      const msg = (payload && (payload.error || payload.detail && JSON.stringify(payload.detail))) || res.statusText;
      const retryAsNew = !!(payload && payload.retryAsNew);
      lastErr = new ClockedError(res.status, friendlyError(res.status, msg), retryAsNew);
      const retryable = res.status === 429 || res.status === 409 || res.status >= 500;
      if (!retryable || retryAsNew) throw lastErr;
    }
    throw lastErr;
  }
}

// Wraps a client and records every step's request and response (for demo fixtures).
export class RecordingClient {
  constructor(inner) { this.inner = inner; this.steps = {}; this.mode = inner.mode; }
  async call(endpoint, body, step = endpoint) {
    try {
      const r = await this.inner.call(endpoint, body, step);
      this.steps[step] = { endpoint, request: body, response: r.data, credits: r.credits, ms: r.ms };
      return r;
    } catch (e) {
      this.steps[step] = { endpoint, request: body, error: { status: e.status, message: e.message } };
      throw e;
    }
  }
}

// Replays a recorded run: returns the saved response for each step, with a short delay.
export class ReplayClient {
  constructor(fixture, { delayMs = 350 } = {}) { this.fixture = fixture; this.delayMs = delayMs; this.mode = 'replay'; }
  async call(endpoint, body, step = endpoint) {
    await sleep(this.delayMs);
    const s = this.fixture.steps[step];
    if (!s) throw new ClockedError(0, `No recorded response for step "${step}".`);
    if (s.error) throw new ClockedError(s.error.status, s.error.message);
    return { data: s.response, credits: s.credits ?? null, ms: s.ms ?? null, requestId: 'recorded' };
  }
}
