export interface ReleaseInfo {
  ok?: boolean;
  version: string;
  tag: string;
  name?: string;
  publishedAt?: string;
  htmlUrl?: string;
  body?: string;
  singBoxVersion?: string;
  singBoxTag?: string;
  singBoxUrl?: string;
}

export interface ParsedSemver {
  major: number;
  minor: number;
  patch: number;
  prerelease: string;
}

export function parseSemver(v: string | null | undefined): ParsedSemver | null {
  if (!v || typeof v !== 'string') return null;
  const trimmed = v.trim().replace(/^v/i, '');
  const m = trimmed.match(/^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/);
  if (!m) return null;
  return {
    major: parseInt(m[1], 10),
    minor: parseInt(m[2], 10),
    patch: parseInt(m[3], 10),
    prerelease: m[4] || ''
  };
}

/**
 * Returns true if `latest` is strictly newer than `current`.
 * Follows SemVer 2.0.0 rules:
 * - Compares major, minor, patch numerically.
 * - When major, minor, and patch are equal:
 *   a normal release (no prerelease) has higher precedence than a prerelease build.
 *   e.g. 1.7.26 is newer than 1.7.26-monitor.1.
 */
export function isNewerVersion(current: string | null | undefined, latest: string | null | undefined): boolean {
  const c = parseSemver(current);
  const l = parseSemver(latest);
  if (!c || !l) return false;

  if (l.major > c.major) return true;
  if (l.major < c.major) return false;
  if (l.minor > c.minor) return true;
  if (l.minor < c.minor) return false;
  if (l.patch > c.patch) return true;
  if (l.patch < c.patch) return false;

  // Major, minor, patch are equal:
  // Normal release is newer than a prerelease version
  if (c.prerelease && !l.prerelease) {
    return true;
  }
  return false;
}

export const OFFICIAL_PROBE_UPDATE_COMMAND =
  'curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/probe-install.sh | sudo sh -s -- --update';

export const OFFICIAL_PANEL_UPDATE_COMMAND =
  'curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh | sudo sh -s -- --update';

export const OFFICIAL_SINGBOX_UPDATE_COMMAND =
  'curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh | sudo sh -s -- --update-sing-box';

export function getProbeUpdateCommand(): string {
  return OFFICIAL_PROBE_UPDATE_COMMAND;
}

export function getPanelUpdateCommand(): string {
  return OFFICIAL_PANEL_UPDATE_COMMAND;
}

export function getSingBoxUpdateCommand(): string {
  return OFFICIAL_SINGBOX_UPDATE_COMMAND;
}

const RELEASE_CACHE_KEY = 'wukong_latest_release_cache';
const CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutes

interface CachedReleaseData {
  timestamp: number;
  data: ReleaseInfo;
}

export async function fetchLatestRelease(
  customFetch?: typeof fetch
): Promise<ReleaseInfo | null> {
  const f = customFetch || (typeof window !== 'undefined' ? window.fetch.bind(window) : fetch);

  // 1. Check local storage cache if available
  if (typeof localStorage !== 'undefined') {
    try {
      const cached = localStorage.getItem(RELEASE_CACHE_KEY);
      if (cached) {
        const parsed: CachedReleaseData = JSON.parse(cached);
        if (Date.now() - parsed.timestamp < CACHE_TTL_MS && parsed.data?.version) {
          return parsed.data;
        }
      }
    } catch {
      // Ignore localStorage read errors
    }
  }

  // 2. Fetch from backend proxy endpoint
  try {
    const res = await f('api/v1/system/latest-release', {
      credentials: 'same-origin',
      headers: { Accept: 'application/json' }
    });
    if (res.ok) {
      const json: ReleaseInfo = await res.json();
      if (json && json.version) {
        saveCache(json);
        return json;
      }
    }
  } catch {
    // Backend endpoint unreachable or network failed, fallback to direct GitHub query
  }

  // 3. Fallback: Fetch directly from GitHub Releases API
  try {
    const ghRes = await f('https://api.github.com/repos/252201/wukong-panel/releases/latest', {
      headers: { Accept: 'application/vnd.github.v3+json' }
    });
    if (ghRes.ok) {
      const gh = await ghRes.json();
      if (gh && gh.tag_name) {
        let sbVersion = '1.14.4';
        let sbTag = 'v1.14.4';
        let sbUrl = 'https://github.com/SagerNet/sing-box/releases/tag/v1.14.4';
        try {
          const sbRes = await f('https://api.github.com/repos/SagerNet/sing-box/releases/latest', {
            headers: { Accept: 'application/vnd.github.v3+json' }
          });
          if (sbRes.ok) {
            const sb = await sbRes.json();
            if (sb && sb.tag_name) {
              sbTag = sb.tag_name;
              sbVersion = sb.tag_name.replace(/^v/i, '');
              sbUrl = sb.html_url || sbUrl;
            }
          }
        } catch {
          // ignore sing-box fetch error, use fallback
        }

        const info: ReleaseInfo = {
          ok: true,
          version: gh.tag_name.replace(/^v/i, ''),
          tag: gh.tag_name,
          name: gh.name || gh.tag_name,
          publishedAt: gh.published_at,
          htmlUrl: gh.html_url,
          body: gh.body,
          singBoxVersion: sbVersion,
          singBoxTag: sbTag,
          singBoxUrl: sbUrl
        };
        saveCache(info);
        return info;
      }
    }
  } catch {
    // Both failed
  }

  // If both failed but we had an expired cache, return expired cache
  if (typeof localStorage !== 'undefined') {
    try {
      const cached = localStorage.getItem(RELEASE_CACHE_KEY);
      if (cached) {
        const parsed: CachedReleaseData = JSON.parse(cached);
        if (parsed.data?.version) {
          return parsed.data;
        }
      }
    } catch {
      // Ignore
    }
  }

  return null;
}

function saveCache(data: ReleaseInfo) {
  if (typeof localStorage !== 'undefined') {
    try {
      const cached: CachedReleaseData = {
        timestamp: Date.now(),
        data
      };
      localStorage.setItem(RELEASE_CACHE_KEY, JSON.stringify(cached));
    } catch {
      // Ignore localStorage write quota errors
    }
  }
}
