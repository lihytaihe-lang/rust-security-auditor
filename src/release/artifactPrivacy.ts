/**
 * Sanitization happens on values, before JSON serialization. Replacing only a
 * serialized POSIX path misses Windows separators and JSON-escaped backslashes.
 */
export function sanitizeArtifactValue(value: unknown, localRoots: readonly string[]): unknown {
  if (typeof value === "string") return sanitizeArtifactString(value, localRoots);
  if (Array.isArray(value)) return value.map((item) => sanitizeArtifactValue(item, localRoots));
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, sanitizeArtifactValue(item, localRoots)])
    );
  }
  return value;
}

export function sanitizeArtifactString(value: string, localRoots: readonly string[]): string {
  let sanitized = value;
  for (const root of normalizedRoots(localRoots)) {
    sanitized = sanitized.split(root).join("<repo>");
  }

  return sanitized
    .replace(/(^|[^A-Za-z0-9_])(?:[A-Za-z]:[\\/])(?:[^\\/\r\n"]+(?:[\\/]|$))+/g, "$1<local-path>")
    .replace(/\\\\[A-Za-z0-9][A-Za-z0-9._-]*(?:[\\/][A-Za-z0-9][A-Za-z0-9._-]*)+/g, "<local-path>")
    .replace(/(^|[^\w/.])\/(?:Users|home|private|Volumes|var|tmp|root|srv|mnt|media|run)(?:\/[^/\r\n"'`\\]+)*/g, "$1<local-path>");
}

/** Returns stable labels for path-like content which must not ship. */
export function findArtifactPathLeaks(value: string, localRoots: readonly string[]): string[] {
  const normalized = value.replaceAll("\\\\", "\\");
  const candidates = [value, normalized].map((candidate) => candidate.replace(/^#!\/usr\/bin\/env(?: [^\r\n]+)?/m, ""));
  const leaks = new Set<string>();

  for (const root of normalizedRoots(localRoots)) {
    if (value.includes(root) || normalized.includes(root)) leaks.add("repository_path");
  }

  if (candidates.some((candidate) => /(^|[^A-Za-z0-9_])[A-Za-z]:\\[^\\/\r\n"]+(?:\\[^\\/\r\n"]+)*/.test(candidate))) {
    leaks.add("windows_path");
  }
  if (candidates.some((candidate) => /\\\\[A-Za-z0-9][A-Za-z0-9._-]*(?:[\\/][A-Za-z0-9][A-Za-z0-9._-]*)+/.test(candidate))) {
    leaks.add("unc_path");
  }
  if (candidates.some((candidate) => /(^|[^\w/.])\/(?:Users|home|private|Volumes|var|tmp|root|srv|mnt|media|run)(?:\/[A-Za-z0-9._-]+)*/.test(candidate))) {
    leaks.add("posix_path");
  }

  return [...leaks].sort();
}

function normalizedRoots(localRoots: readonly string[]): string[] {
  return [...new Set(localRoots.flatMap((root) => [root, root.replaceAll("/", "\\"), root.replaceAll("\\", "/")]))]
    .filter((root) => root.length > 1)
    .sort((left, right) => right.length - left.length);
}
