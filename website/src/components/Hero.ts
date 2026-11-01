/**
 * Wukong Official Site - Hero Component & 3D Terminal Install Deck
 * Grand Eastern alchemical branding, live curl install generator with arch toggle,
 * and 3D gyroscope/mouse parallax tilt card.
 */

import { audioHaptics } from './AudioHaptics';

export class Hero {
  private element: HTMLElement;
  private canvasBox: HTMLElement;
  private contentBox: HTMLElement;
  private lang: 'zh' | 'en' = 'zh';
  private arch: 'amd64' | 'arm64' = 'amd64';
  private isCopied: boolean = false;

  constructor(lang: 'zh' | 'en') {
    this.lang = lang;
    this.element = document.createElement('section');
    this.element.className = 'hero-section';
    this.element.id = 'hero';

    this.canvasBox = document.createElement('div');
    this.canvasBox.className = 'hero-canvas-container';
    this.canvasBox.id = 'hero-canvas-box';
    this.canvasBox.setAttribute('aria-hidden', 'true');
    this.element.appendChild(this.canvasBox);

    this.contentBox = document.createElement('div');
    this.contentBox.className = 'container hero-content';
    this.element.appendChild(this.contentBox);

    this.render();
    this.bindEvents();
  }

  public getElement(): HTMLElement {
    return this.element;
  }

  public setLang(lang: 'zh' | 'en') {
    this.lang = lang;
    this.render();
    this.bindEvents();
  }

  private getCommand(): string {
    return `curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh | sudo sh`;
  }

  private render() {
    const isZh = this.lang === 'zh';
    const cmd = this.getCommand();

    this.contentBox.innerHTML = `
        <!-- Left: Hero Headline & Narrative -->
        <div class="hero-narrative">
          <div class="hero-badge-pill">
            <span class="hero-pulse-dot" aria-hidden="true"></span>
            <span class="cinnabar-seal">悟</span>
            <span>${isZh ? 'v2.3.9 正式发布 · 全协议订阅穿透加固与双栈探针智选' : 'v2.3.9 Released · Subscription Tunnel Hardening & Dual-Stack Routing'}</span>
          </div>

          <h1 class="text-display">
            ${isZh ? '大圣降世' : 'Sovereign Fleet'}
            <br>
            <span class="gold-gradient-text">${isZh ? '万里云霄舰队归一' : 'Zero-Loss VPS Mesh'}</span>
          </h1>

          <p class="text-body-lead" style="margin-top: 1.5rem; max-width: 580px;">
            ${isZh
              ? '面向个人与极客团队的自治 VPS 控制台。Go 单二进制驱动，极低 25MB 内存开销；七大主流代理协议本机闭环握手，无感纳管 10 台远端舰队。'
              : 'Autonomous multi-host VPS fleet console. Powered by a single Go binary with <25MB RAM footprint; zero public inbound ports, 7-protocol closed-loop matrix, and instant device routing.'}
          </p>

          <div class="hero-actions">
            <a href="#sandbox" class="btn-primary">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <polygon points="5 3 19 12 5 21 5 3"></polygon>
              </svg>
              <span>${isZh ? '即刻把玩实机沙箱' : 'Explore Live Sandbox'}</span>
            </a>
            <a href="#stories" class="btn-secondary">
              <span>${isZh ? '五卷核心技术解构' : 'Five Epic Chapters'}</span>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M7 17l9.2-9.2M17 17V7H7"/>
              </svg>
            </a>
          </div>

          <div style="margin-top: 2.5rem; display: flex; align-items: center; gap: 1.5rem; color: var(--text-muted); font-size: 0.85rem;" class="font-mono">
            <div>✓ ${isZh ? '完全开源 (MIT)' : 'Open Source (MIT)'}</div>
            <div>✓ ${isZh ? '零公网端口暴露' : 'Zero Exposed Ports'}</div>
            <div>✓ ${isZh ? '秒级自动回滚' : 'Atomic Rollback'}</div>
          </div>
        </div>

        <!-- Right: 3D Parallax Tilt Terminal Install Deck -->
        <div class="hero-tilt-wrapper">
          <div class="terminal-deck" id="terminal-deck-card">
            <div class="terminal-header">
              <div class="terminal-dots" aria-hidden="true">
                <span class="terminal-dot dot-red"></span>
                <span class="terminal-dot dot-yellow"></span>
                <span class="terminal-dot dot-green"></span>
              </div>
              <span class="terminal-title">bash — wukong-deploy-v2.3.9</span>
              <div class="terminal-arch-toggle">
                <button type="button" class="arch-btn ${this.arch === 'amd64' ? 'active' : ''}" data-arch="amd64">amd64</button>
                <button type="button" class="arch-btn ${this.arch === 'arm64' ? 'active' : ''}" data-arch="arm64">arm64</button>
              </div>
            </div>

            <div class="terminal-body">
              <div style="color: #6b7280; font-size: 0.8rem; margin-bottom: 0.5rem;">
                # ${isZh ? '支持 Debian 11+, Ubuntu 22.04+, Alpine, Rocky' : 'Debian 11+, Ubuntu 22.04+, Alpine, Rocky'}
              </div>
              <div style="color: #9ca3af;">
                <span class="terminal-prompt">$</span> ${isZh ? '一键安装或无损热更 (单行即刻运行)' : 'One-line automatic install or safe hot-update'}
              </div>

              <div class="terminal-cmd-box">
                <code class="terminal-code-text" id="install-cmd-code">${cmd}</code>
                <button type="button" class="btn-copy ${this.isCopied ? 'copied' : ''}" id="btn-copy-install" aria-label="Copy Install Command">
                  <span id="copy-btn-icon">${this.isCopied ? '✓' : '⧉'}</span>
                  <span id="copy-btn-text">${this.isCopied ? (isZh ? '已复制' : 'Copied!') : (isZh ? '复制' : 'Copy')}</span>
                </button>
              </div>

              <div class="terminal-meta-specs">
                <div class="meta-spec-item">
                  <span class="meta-spec-label">${isZh ? '核心架构' : 'Binary Arch'}</span>
                  <span class="meta-spec-val">Go 1.24+ Single ELF</span>
                </div>
                <div class="meta-spec-item">
                  <span class="meta-spec-label">${isZh ? '闲置内存' : 'Idle Memory'}</span>
                  <span class="meta-spec-val" style="color: var(--telemetry-green);">&lt; 25 MB RAM</span>
                </div>
                <div class="meta-spec-item">
                  <span class="meta-spec-label">${isZh ? '数据引擎' : 'Storage Engine'}</span>
                  <span class="meta-spec-val">SQLite WAL Mode</span>
                </div>
              </div>
            </div>
          </div>
        </div>
    `;
  }

  private bindEvents() {
    // 3D Tilt Card Effect
    const card = this.element.querySelector('#terminal-deck-card') as HTMLElement;
    if (card) {
      const handleMouseMove = (e: MouseEvent) => {
        const rect = card.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        const centerX = rect.width / 2;
        const centerY = rect.height / 2;

        const rotateX = ((y - centerY) / centerY) * -10;
        const rotateY = ((x - centerX) / centerX) * 12;

        card.style.transform = `rotateX(${rotateX.toFixed(2)}deg) rotateY(${rotateY.toFixed(2)}deg) translateZ(10px)`;
      };

      const handleMouseLeave = () => {
        card.style.transform = `rotateX(0deg) rotateY(0deg) translateZ(0px)`;
      };

      card.addEventListener('mousemove', handleMouseMove);
      card.addEventListener('mouseleave', handleMouseLeave);
    }

    // Architecture switch buttons
    const archBtns = this.element.querySelectorAll('.arch-btn');
    archBtns.forEach((btn) => {
      btn.addEventListener('click', () => {
        audioHaptics.playClick();
        const targetArch = btn.getAttribute('data-arch') as 'amd64' | 'arm64';
        if (targetArch && targetArch !== this.arch) {
          this.arch = targetArch;
          archBtns.forEach((b) => b.classList.remove('active'));
          btn.classList.add('active');
        }
      });
    });

    // Copy command button
    const copyBtn = this.element.querySelector('#btn-copy-install');
    if (copyBtn) {
      copyBtn.addEventListener('click', async () => {
        audioHaptics.playSuccess();
        const cmd = this.getCommand();
        try {
          await navigator.clipboard.writeText(cmd);
          this.isCopied = true;
          const iconSpan = this.element.querySelector('#copy-btn-icon');
          const textSpan = this.element.querySelector('#copy-btn-text');
          copyBtn.classList.add('copied');
          if (iconSpan) iconSpan.textContent = '✓';
          if (textSpan) textSpan.textContent = this.lang === 'zh' ? '已复制' : 'Copied!';

          setTimeout(() => {
            this.isCopied = false;
            copyBtn.classList.remove('copied');
            if (iconSpan) iconSpan.textContent = '⧉';
            if (textSpan) textSpan.textContent = this.lang === 'zh' ? '复制' : 'Copy';
          }, 2400);
        } catch {
          // Fallback selection
          const codeEl = this.element.querySelector('#install-cmd-code');
          if (codeEl) {
            const range = document.createRange();
            range.selectNodeContents(codeEl);
            const sel = window.getSelection();
            sel?.removeAllRanges();
            sel?.addRange(range);
          }
        }
      });
    }
  }
}
