/**
 * Wukong Official Site - Footer Component
 * Brand seal, release notes, license, open-source community links, and copyright.
 */

export class Footer {
  private element: HTMLElement;
  private lang: 'zh' | 'en' = 'zh';

  constructor(lang: 'zh' | 'en') {
    this.lang = lang;
    this.element = document.createElement('footer');
    this.element.className = 'site-footer';
    this.render();
  }

  public getElement(): HTMLElement {
    return this.element;
  }

  public setLang(lang: 'zh' | 'en') {
    this.lang = lang;
    this.render();
  }

  private render() {
    const isZh = this.lang === 'zh';

    this.element.innerHTML = `
      <div class="container">
        <div class="footer-top">
          <!-- Col 1: Brand Info -->
          <div>
            <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem;">
              <span class="cinnabar-seal">悟</span>
              <span style="font-family: var(--font-kaiti); font-size: 1.35rem; font-weight: 700;">
                ${isZh ? '悟空面板' : 'Wukong Panel'}
              </span>
              <span class="brand-badge">v2.3.5</span>
            </div>
            <p class="text-caption" style="max-width: 320px; line-height: 1.7;">
              ${isZh
                ? '面向个人与小型团队的自治 VPS 舰队控制台。将东方暗金哲学与现代超精密基础设施控制台深度融合。'
                : 'Autonomous VPS fleet mesh & console for developers. Fusing Eastern gold alchemy with hyper-precise infrastructure engineering.'}
            </p>
          </div>

          <!-- Col 2: Navigation Links -->
          <div>
            <h4 class="font-mono" style="font-size: 0.85rem; color: var(--gold-bright); margin-bottom: 1rem; text-transform: uppercase;">
              ${isZh ? '核心导航' : 'Navigation'}
            </h4>
            <div style="display: flex; flex-direction: column; gap: 0.6rem; font-size: 0.88rem;">
              <a href="#hero" class="nav-link">${isZh ? '返回顶部' : 'Back to Top'}</a>
              <a href="#sandbox" class="nav-link">${isZh ? '实机沙箱' : 'Live Sandbox'}</a>
              <a href="#stories" class="nav-link">${isZh ? '五卷能力' : 'Epic Chapters'}</a>
              <a href="#performance" class="nav-link">${isZh ? '架构对决' : 'Performance Matrix'}</a>
            </div>
          </div>

          <!-- Col 3: Protocols -->
          <div>
            <h4 class="font-mono" style="font-size: 0.85rem; color: var(--gold-bright); margin-bottom: 1rem; text-transform: uppercase;">
              ${isZh ? '核心驱动' : 'Protocols'}
            </h4>
            <div style="display: flex; flex-direction: column; gap: 0.6rem; font-size: 0.88rem; color: var(--text-secondary);" class="font-mono">
              <span>Hysteria 2 (BBR)</span>
              <span>VLESS REALITY</span>
              <span>Cloudflare Tunnel</span>
              <span>TUIC v5 / QUIC</span>
              <span>Shadowsocks 2022</span>
            </div>
          </div>

          <!-- Col 4: Community & Docs -->
          <div>
            <h4 class="font-mono" style="font-size: 0.85rem; color: var(--gold-bright); margin-bottom: 1rem; text-transform: uppercase;">
              ${isZh ? '开源生态' : 'Community'}
            </h4>
            <div style="display: flex; flex-direction: column; gap: 0.6rem; font-size: 0.88rem;">
              <a href="https://github.com/252201/wukong-panel" target="_blank" rel="noopener noreferrer" class="nav-link">GitHub Repository</a>
              <a href="https://github.com/252201/wukong-panel/releases" target="_blank" rel="noopener noreferrer" class="nav-link">${isZh ? '版本发布记录' : 'Releases & Changelog'}</a>
              <a href="https://github.com/252201/wukong-panel/blob/main/LICENSE" target="_blank" rel="noopener noreferrer" class="nav-link">MIT License</a>
              <a href="https://github.com/sagernet/sing-box" target="_blank" rel="noopener noreferrer" class="nav-link">sing-box Core</a>
            </div>
          </div>
        </div>

        <div class="footer-bottom">
          <div>
            © 2026 Wukong Panel Authors. Released under the MIT License.
          </div>
          <div class="font-mono text-caption" style="display: flex; align-items: center; gap: 1rem;">
            <span>Built with Go &amp; Modern Web Standards</span>
            <span style="color: var(--telemetry-green);">● All Systems Nominal</span>
          </div>
        </div>
      </div>
    `;
  }
}
