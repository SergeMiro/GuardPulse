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
  { id: 'email', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, severity: 'medium' },
];

/** Finds secrets and personal data in any value (objects are JSON-stringified). */
export function detectSensitive(value: unknown): Finding[] {
  if (value === undefined || value === null) return [];
  const text = typeof value === 'string' ? value : JSON.stringify(value);
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

export function hostOf(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}

/** `*` matches any run of characters; `*.example.com` also matches `example.com`. */
export function globMatch(pattern: string, value: string): boolean {
  const p = pattern.toLowerCase();
  const v = value.toLowerCase();
  if (p.startsWith('*.') && v === p.slice(2)) return true;
  const re = new RegExp(`^${p.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`);
  return re.test(v);
}

const ORDER: Severity[] = ['low', 'medium', 'high', 'critical'];
export const severityRank = (s: Severity): number => ORDER.indexOf(s);
export function maxSeverity(list: Severity[]): Severity | undefined {
  return list.reduce<Severity | undefined>((a, b) => (a === undefined || severityRank(b) > severityRank(a) ? b : a), undefined);
}

/** Replaces secrets with `[REDACTED:type]` and truncates, so stored events never hold the secret. */
export function redact(value: unknown, max = 2000): string {
  if (value === undefined || value === null) return '';
  let text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const { id, re, check } of SECRET_PATTERNS) {
    text = text.replace(re, (m) => (!check || check(m) ? `[REDACTED:${id}]` : m));
  }
  return text.length > max ? `${text.slice(0, max)}…` : text;
}
