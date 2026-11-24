import type { Finding, Severity } from './types.js';

const ZERO_WIDTH = /[​-‏⁠-⁤﻿­]/g;

/** NFKC + strip zero-width characters + lowercase + collapse whitespace. */
export function normalize(text: string): string {
  return text.normalize('NFKC').replace(ZERO_WIDTH, '').toLowerCase().replace(/\s+/g, ' ');
}

/** Decodes base64 runs long enough to hide an instruction. */
function decodedBase64(text: string): string[] {
  const out: string[] = [];
  for (const run of text.match(/[A-Za-z0-9+/]{24,}={0,2}/g) ?? []) {
    try {
      const decoded = atob(run);
      // keep only mostly-printable results, binary noise is not an instruction
      if (/^[\x20-\x7E\s]+$/.test(decoded)) out.push(decoded);
    } catch {
      // not base64
    }
  }
  return out;
}

const INJECTION_PATTERNS: Array<{ id: string; re: RegExp }> = [
  { id: 'ignore-instructions', re: /\b(ignore|disregard|forget|override)\b.{0,40}\b(instructions?|rules|guidelines|prompt|context)\b/ },
  { id: 'role-override', re: /\b(you are now|act as|from now on you|new instructions?:)/ },
  { id: 'system-prompt', re: /\b(system prompt|developer message|<\|im_start\|>\s*system|\[system\])/ },
  { id: 'hide-from-user', re: /\b(do not|don't|never) (tell|inform|mention|reveal|show)\b.{0,30}\b(user|human|operator)\b/ },
  { id: 'exfil-instruction', re: /\b(send|post|upload|forward|exfiltrate|transmit|leak)\b.{0,60}\b(https?:\/\/|webhook|endpoint|server|url)/ },
  { id: 'tool-coercion', re: /\b(call|invoke|use|run)\b.{0,20}\b(the )?(tool|function)\b.{0,40}\b(with|and)\b/ },
  { id: 'credential-request', re: /\b(api[ _-]?keys?|passwords?|secrets?|tokens?|credentials?)\b.{0,40}\b(dump|list|print|send|include|reveal)/ },
];

export function detectInjection(text: string): Finding[] {
  const candidates = [normalize(text), ...decodedBase64(text).map(normalize)];
  const hits = new Set<string>();
  for (const candidate of candidates) {
    for (const { id, re } of INJECTION_PATTERNS) if (re.test(candidate)) hits.add(id);
  }
  if (hits.size === 0) return [];
  return [
    {
      type: 'prompt_injection',
      severity: hits.size > 1 || hits.has('exfil-instruction') ? 'high' : 'medium',
      message: `Instructions aimed at the agent found in untrusted content (${[...hits].join(', ')})`,
      evidence: { patterns: [...hits], encoded: candidates.length > 1 },
    },
  ];
}

/** IBAN checksum (ISO 13616 mod 97). */
function ibanValid(raw: string): boolean {
  const iban = raw.replace(/\s/g, '');
  if (iban.length < 15 || iban.length > 34) return false;
  const moved = iban.slice(4) + iban.slice(0, 4);
  let rem = 0;
  for (const ch of moved) {
    const n = ch >= 'A' ? ch.charCodeAt(0) - 55 : Number(ch);
    rem = Number(`${rem}${n}`) % 97;
  }
  return rem === 1;
}

function luhn(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) d = d * 2 > 9 ? d * 2 - 9 : d * 2;
    sum += d;
  }
  return sum % 10 === 0;
}

const SECRET_PATTERNS: Array<{ id: string; re: RegExp; severity: Severity; check?: (m: string) => boolean }> = [
  { id: 'aws_access_key', re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, severity: 'critical' },
  { id: 'github_token', re: /\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b/g, severity: 'critical' },
  { id: 'llm_api_key', re: /\bsk-(ant-|proj-)?[A-Za-z0-9_-]{20,}\b/g, severity: 'critical' },
  { id: 'slack_token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, severity: 'critical' },
  { id: 'private_key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g, severity: 'critical' },
  { id: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, severity: 'high' },
  {
    id: 'payment_card',
    re: /\b(?:\d[ -]?){13,19}\b/g,
    severity: 'high',
    check: (m) => luhn(m.replace(/\D/g, '')),
  },
  { id: 'iban', re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b/g, severity: 'high', check: ibanValid },
  // bounded quantifiers: the unbounded form backtracks quadratically on long dotted input
  { id: 'email', re: /\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}\b/g, severity: 'medium' },
];

/** Any value as text without throwing: BigInt, circular objects and functions included. */
export function toText(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value === undefined || value === null) return '';
  try {
    return JSON.stringify(value, (_k, v) => (typeof v === 'bigint' ? v.toString() : v)) ?? String(value);
  } catch {
    return String(value);
  }
}

/** Finds secrets and personal data in any value (objects are JSON-stringified). */
export function detectSensitive(value: unknown): Finding[] {
  if (value === undefined || value === null) return [];
  const text = toText(value);
  const findings: Finding[] = [];
  for (const { id, re, severity, check } of SECRET_PATTERNS) {
    const matches = (text.match(re) ?? []).filter((m) => !check || check(m));
    if (matches.length === 0) continue;
    findings.push({
      type: `sensitive.${id}`,
      severity,
      message: `${matches.length} × ${id.replace(/_/g, ' ')}`,
      // never copy the secret itself into the evidence
      evidence: { count: matches.length, sample: `${matches[0].slice(0, 4)}…` },
    });
  }
  return findings;
}

/** Bits of entropy per character (Shannon). Random tokens sit above ~4.2, words and hex below. */
export function entropy(text: string): number {
  const freq = new Map<string, number>();
  for (const ch of text) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const n of freq.values()) bits -= (n / text.length) * Math.log2(n / text.length);
  return bits;
}

/** Long random-looking pieces of a URL (query values, path segments): how encoded data is smuggled out. */
export function highEntropyParts(url: string): string[] {
  let parts: string[];
  try {
    const u = new URL(url, 'http://x');
    parts = [...u.pathname.split('/'), ...[...u.searchParams.values()]];
  } catch {
    return [];
  }
  return parts.filter((p) => p.length >= 24 && entropy(p) >= 4.2);
}

/** A fake secret to plant in env vars, prompts or test data: if it ever leaves the app, something is exfiltrating. */
export function createCanary(prefix = 'sk-proj-'): string {
  const abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  return prefix + Array.from(crypto.getRandomValues(new Uint8Array(40)), (b) => abc[b % abc.length]).join('');
}

export function hostOf(url: string): string {
  try {
    // relative URLs resolve against the page in a browser (same origin is not egress)
    return new URL(url, (globalThis as { location?: { href: string } }).location?.href).hostname.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}

/** `*` matches any run of characters; `*.example.com` also matches `example.com`. */
export function globMatch(pattern: string, value: string): boolean {
  const p = pattern.toLowerCase();
  const v = value.toLowerCase();
  if (p.startsWith('*.') && v === p.slice(2)) return true;
  // two-pointer wildcard match: no RegExp, so no backtracking blow-up on attacker-chosen strings
  let pi = 0;
  let vi = 0;
  let star = -1;
  let mark = 0;
  while (vi < v.length) {
    if (pi < p.length && p[pi] !== '*' && p[pi] === v[vi]) {
      pi++;
      vi++;
    } else if (pi < p.length && p[pi] === '*') {
      star = pi++;
      mark = vi;
    } else if (star >= 0) {
      pi = star + 1;
      vi = ++mark;
    } else return false;
  }
  while (p[pi] === '*') pi++;
  return pi === p.length;
}

const ORDER: Severity[] = ['low', 'medium', 'high', 'critical'];
export const severityRank = (s: Severity): number => ORDER.indexOf(s);
export function maxSeverity(list: Severity[]): Severity | undefined {
  return list.reduce<Severity | undefined>((a, b) => (a === undefined || severityRank(b) > severityRank(a) ? b : a), undefined);
}

/** Replaces secrets with `[REDACTED:type]` and truncates, so stored events never hold the secret. */
export function redact(value: unknown, max = 2000): string {
  let text = toText(value);
  for (const { id, re, check } of SECRET_PATTERNS) {
    text = text.replace(re, (m) => (!check || check(m) ? `[REDACTED:${id}]` : m));
  }
  return text.length > max ? `${text.slice(0, max)}…` : text;
}
