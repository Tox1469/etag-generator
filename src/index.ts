import { createHash } from "crypto";

export interface ETagOptions {
  weak?: boolean;
  algorithm?: "sha1" | "md5" | "sha256";
}

export function generateETag(body: string | Buffer | Uint8Array, options: ETagOptions = {}): string {
  const algo = options.algorithm ?? "sha1";
  const buf = typeof body === "string" ? Buffer.from(body) : Buffer.from(body);
  const hash = createHash(algo).update(buf).digest("base64").replace(/=+$/, "");
  const len = buf.length.toString(16);
  const tag = `"${len}-${hash}"`;
  return options.weak ? `W/${tag}` : tag;
}

export function parseIfNoneMatch(header: string | null | undefined): string[] {
  if (!header) return [];
  return header.split(",").map(s => s.trim()).filter(Boolean);
}

export function matchesETag(current: string, ifNoneMatch: string | null | undefined): boolean {
  const tags = parseIfNoneMatch(ifNoneMatch);
  if (!tags.length) return false;
  if (tags.includes("*")) return true;
  const norm = (t: string) => t.replace(/^W\//, "");
  const c = norm(current);
  return tags.some(t => norm(t) === c);
}

export function checkFreshness(req: { headers: Record<string, string | undefined> }, etag: string): boolean {
  return matchesETag(etag, req.headers["if-none-match"]);
}

export interface HandleResult {
  status: number;
  headers: Record<string, string>;
  body: string | Buffer | Uint8Array | null;
}

export function handleConditional(body: string | Buffer | Uint8Array, ifNoneMatch: string | null | undefined, opts: ETagOptions = {}): HandleResult {
  const etag = generateETag(body, opts);
  if (matchesETag(etag, ifNoneMatch)) {
    return { status: 304, headers: { ETag: etag }, body: null };
  }
  return { status: 200, headers: { ETag: etag }, body };
}
