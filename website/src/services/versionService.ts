/**
 * Wukong Official Site - Version Service
 * Automatically synchronizes latest release version from GitHub with multi-tier fallback & caching.
 */

export interface VersionInfo {
  version: string; // e.g. "v2.4.1"
  cleanVersion: string; // e.g. "2.4.1"
  releaseTitle?: string;
  isLatest: boolean;
}

const CACHE_KEY = 'wukong_latest_version_cache';
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes cache TTL

// Default fallback version bundled at build-time
export const DEFAULT_VERSION = 'v2.4.1';

export type VersionListener = (info: VersionInfo) => void;

export class VersionService {
  private currentInfo: VersionInfo = {
    version: DEFAULT_VERSION,
    cleanVersion: DEFAULT_VERSION.replace(/^v/, ''),
    isLatest: false
  };

  private listeners: VersionListener[] = [];
  private fetchPromise: Promise<VersionInfo> | null = null;

  constructor() {
    this.loadFromCache();
  }

  public getVersion(): VersionInfo {
    return this.currentInfo;
  }

  public subscribe(listener: VersionListener): () => void {
    this.listeners.push(listener);
    try {
      listener(this.currentInfo);
    } catch (err) {
      console.error('[VersionService] listener error:', err);
    }
    return () => {
      this.listeners = this.listeners.filter((l) => l !== listener);
    };
  }

  private notify() {
    for (const listener of this.listeners) {
      try {
        listener(this.currentInfo);
      } catch (err) {
        console.error('[VersionService] listener error:', err);
      }
    }
  }

  private loadFromCache(): void {
    if (typeof window === 'undefined' || !window.localStorage) return;
    try {
      const cached = localStorage.getItem(CACHE_KEY);
      if (cached) {
        const parsed = JSON.parse(cached);
        if (parsed && parsed.timestamp && (Date.now() - parsed.timestamp < CACHE_TTL_MS) && parsed.version) {
          const v = parsed.version.startsWith('v') ? parsed.version : `v${parsed.version}`;
          this.currentInfo = {
            version: v,
            cleanVersion: v.replace(/^v/, ''),
            releaseTitle: parsed.releaseTitle,
            isLatest: true
          };
        }
      }
    } catch {
      // Ignore storage read errors
    }
  }

  private saveToCache(info: VersionInfo): void {
    if (typeof window === 'undefined' || !window.localStorage) return;
    try {
      localStorage.setItem(
        CACHE_KEY,
        JSON.stringify({
          version: info.version,
          cleanVersion: info.cleanVersion,
          releaseTitle: info.releaseTitle,
          timestamp: Date.now()
        })
      );
    } catch {
      // Ignore storage write errors (e.g. quota/incognito)
    }
  }

  public async fetchLatest(): Promise<VersionInfo> {
    if (this.fetchPromise) {
      return this.fetchPromise;
    }

    this.fetchPromise = (async () => {
      let resolvedVersion = '';
      let releaseTitle = '';

      // Tier 1: Query official GitHub Releases API with 3.5s timeout
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 3500);
        const res = await fetch('https://api.github.com/repos/252201/wukong-panel/releases/latest', {
          headers: { Accept: 'application/vnd.github.v3+json' },
          signal: controller.signal
        });
        clearTimeout(timer);

        if (res.ok) {
          const data = await res.json();
          if (data && typeof data.tag_name === 'string') {
            resolvedVersion = data.tag_name.trim();
            releaseTitle = typeof data.name === 'string' ? data.name : '';
          }
        }
      } catch {
        // Fallback to Tier 2 on network error, timeout, or rate limiting
      }

      // Tier 2: Query jsDelivr Fastly CDN mirror for package.json
      if (!resolvedVersion) {
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 3500);
          const res = await fetch(
            'https://fastly.jsdelivr.net/gh/252201/wukong-panel@main/web/package.json',
            { signal: controller.signal }
          );
          clearTimeout(timer);

          if (res.ok) {
            const data = await res.json();
            if (data && typeof data.version === 'string') {
              resolvedVersion = `v${data.version.trim().replace(/^v/, '')}`;
            }
          }
        } catch {
          // Both tiers failed, fallback gracefully to bundled version
        }
      }

      if (resolvedVersion) {
        const normalized = resolvedVersion.startsWith('v') ? resolvedVersion : `v${resolvedVersion}`;
        this.currentInfo = {
          version: normalized,
          cleanVersion: normalized.replace(/^v/, ''),
          releaseTitle,
          isLatest: true
        };
        this.saveToCache(this.currentInfo);
        this.notify();
      }

      return this.currentInfo;
    })();

    return this.fetchPromise;
  }
}

export const versionService = new VersionService();
