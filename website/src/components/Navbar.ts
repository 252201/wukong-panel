/**
 * Wukong Official Site - Navbar Component
 * Floating glassmorphic header, seal branding, audio wave toggle,
 * modern color-scheme dark/light switcher, language switcher, and star counters.
 */

import { audioHaptics } from './AudioHaptics';

export interface NavState {
  lang: 'zh' | 'en';
  theme: 'dark' | 'light';
  isAudioMuted: boolean;
}

export class Navbar {
  private element: HTMLElement;
  private state: NavState;
  private onStateChange: (state: NavState) => void;

  constructor(initialState: NavState, onStateChange: (state: NavState) => void) {
    this.state = { ...initialState };
    this.onStateChange = onStateChange;
    this.element = document.createElement('header');
    this.element.className = 'nav-header';
    this.render();
    this.bindEvents();
  }

  public getElement(): HTMLElement {
    return this.element;
  }

  public updateState(newState: Partial<NavState>) {
    this.state = { ...this.state, ...newState };
    this.render();
  }

  private render() {
    const isZh = this.state.lang === 'zh';
    const isDark = this.state.theme === 'dark';
    const isAudioActive = !this.state.isAudioMuted;

    this.element.innerHTML = `
      <div class="container nav-inner">
        <a href="#" class="brand-link" aria-label="Wukong Panel Home">
          <div class="brand-logo-seal">
            <svg width="34" height="34" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
              <rect x="1" y="1" width="62" height="62" rx="14" fill="${isDark ? '#090a09' : '#f7f4ec'}" stroke="${isDark ? '#d4ad57' : '#9e782f'}" stroke-width="2"/>
              <circle cx="32" cy="31" r="21" stroke="${isDark ? '#f5d77f' : '#b8860b'}" stroke-width="2.2" stroke-dasharray="90 30" stroke-linecap="round"/>
              <text x="32" y="40" fill="${isDark ? '#f3f4f6' : '#1c1b18'}" font-family="var(--font-kaiti)" font-size="28" font-weight="700" text-anchor="middle">悟</text>
              <circle cx="49.5" cy="16" r="3" fill="#c44635" stroke="#f1cf7d" stroke-width="1"/>
            </svg>
          </div>
          <span class="brand-title">${isZh ? '悟空面板' : 'Wukong Panel'}</span>
          <span class="brand-badge">v2.3.4</span>
        </a>

        <nav class="nav-links" aria-label="Main Navigation">
          <a href="#sandbox" class="nav-link">${isZh ? '实机沙箱' : 'Live Sandbox'}</a>
          <a href="#stories" class="nav-link">${isZh ? '五卷能力' : 'Epic Chapters'}</a>
          <a href="#performance" class="nav-link">${isZh ? '架构对决' : 'Performance'}</a>
          <a href="https://github.com/252201/wukong-panel#readme" target="_blank" rel="noopener noreferrer" class="nav-link">${isZh ? '技术文档' : 'Docs'}</a>
        </nav>

        <div class="nav-actions">
          <!-- Audio Haptics Toggle -->
          <button type="button" class="btn-icon-control btn-audio ${isAudioActive ? 'is-audio-active' : ''}" id="nav-audio-btn" aria-label="${isAudioActive ? (isZh ? '关闭音效' : 'Mute Audio') : (isZh ? '开启音效' : 'Enable Audio')}">
            <span class="sound-wave" aria-hidden="true">
              <span class="sound-bar"></span>
              <span class="sound-bar"></span>
              <span class="sound-bar"></span>
              <span class="sound-bar"></span>
            </span>
            <span class="nav-btn-label">${isAudioActive ? (isZh ? '音效：开' : 'Sound: ON') : (isZh ? '音效：关' : 'Sound: OFF')}</span>
          </button>

          <!-- Modern Theme Toggle -->
          <button type="button" class="btn-icon-control btn-theme" id="nav-theme-btn" aria-label="${isDark ? (isZh ? '切换宣纸浅色模式' : 'Switch to Light Mode') : (isZh ? '切换玄黑深色模式' : 'Switch to Dark Mode')}">
            <span aria-hidden="true">${isDark ? '🌙' : '☀️'}</span>
            <span class="nav-btn-label">${isDark ? (isZh ? '玄黑' : 'Dark') : (isZh ? '宣纸' : 'Xuan')}</span>
          </button>

          <!-- Language Switcher -->
          <button type="button" class="btn-icon-control btn-lang" id="nav-lang-btn" aria-label="${isZh ? 'Switch to English' : '切换为中文'}">
            <span class="nav-lang-symbol" aria-hidden="true">🌐</span>
            <span class="nav-btn-label">${isZh ? 'EN' : '中'}</span>
          </button>

          <!-- GitHub Repo Link -->
          <a href="https://github.com/252201/wukong-panel" target="_blank" rel="noopener noreferrer" class="btn-github" aria-label="Wukong Panel GitHub Repository">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
            </svg>
            <span id="nav-star-count" class="nav-btn-label">GitHub</span>
          </a>
        </div>
      </div>
    `;
  }

  private bindEvents() {
    // Scroll header blur
    window.addEventListener('scroll', () => {
      if (window.scrollY > 40) {
        this.element.classList.add('scrolled');
      } else {
        this.element.classList.remove('scrolled');
      }
    }, { passive: true });

    // Event delegation on nav element
    this.element.addEventListener('click', (e) => {
      const target = e.target as HTMLElement;

      // Audio toggle
      const audioBtn = target.closest('#nav-audio-btn');
      if (audioBtn) {
        const isMuted = audioHaptics.toggleMute();
        this.state.isAudioMuted = isMuted;
        this.render();
        this.onStateChange(this.state);
        return;
      }

      // Theme toggle
      const themeBtn = target.closest('#nav-theme-btn');
      if (themeBtn) {
        audioHaptics.playClick();
        const nextTheme = this.state.theme === 'dark' ? 'light' : 'dark';
        this.state.theme = nextTheme;

        // Modern Web Guidance: update meta[name="color-scheme"] and persist
        const meta = document.querySelector('meta[name="color-scheme"]');
        if (meta) {
          meta.setAttribute('content', nextTheme);
        }
        document.documentElement.style.colorScheme = nextTheme;
        localStorage.setItem('color-scheme', nextTheme);

        this.render();
        this.onStateChange(this.state);
        return;
      }

      // Lang toggle
      const langBtn = target.closest('#nav-lang-btn');
      if (langBtn) {
        audioHaptics.playClick();
        const nextLang = this.state.lang === 'zh' ? 'en' : 'zh';
        this.state.lang = nextLang;
        this.render();
        this.onStateChange(this.state);
        return;
      }
    });

    // Optional: fetch live GitHub stars
    this.fetchGitHubStars();
  }

  private async fetchGitHubStars() {
    try {
      const res = await fetch('https://api.github.com/repos/252201/wukong-panel');
      if (res.ok) {
        const data = await res.json();
        const countSpan = this.element.querySelector('#nav-star-count');
        if (countSpan && data.stargazers_count !== undefined) {
          countSpan.textContent = `★ ${data.stargazers_count}`;
        }
      }
    } catch {
      // Graceful fallback to static text
    }
  }
}
