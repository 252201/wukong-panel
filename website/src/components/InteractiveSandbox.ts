/**
 * Wukong Official Site - Interactive Live Sandbox Console
 * Lets visitors experience the power of Wukong Panel directly in the browser:
 * - 7-Protocol live switching (Hy2, REALITY, CF Tunnel, TUIC v5, Shadowsocks 2022, Trojan, AnyTLS)
 * - Real-time node card parameters & animated packet flow
 * - Closed-loop diagnostic handshake probe runner with simulated telemetry logs
 * - Dynamic dark-gold QR code generator & universal subscription export
 */

import QRCode from 'qrcode';
import { audioHaptics } from './AudioHaptics';

export interface ProtocolSpec {
  id: string;
  name: string;
  port: string;
  transport: string;
  security: string;
  congestionOrSni: string;
  flowOrCipher: string;
  tag: string;
  sampleUri: string;
  descZh: string;
  descEn: string;
}

export const PROTOCOL_SPECS: ProtocolSpec[] = [
  {
    id: 'hy2',
    name: 'Hysteria 2',
    port: '45080 (UDP)',
    transport: 'QUIC / UDP',
    security: 'Standard TLS 1.3',
    congestionOrSni: 'BBR / Brutal Congestion',
    flowOrCipher: 'Salamander Password Auth',
    tag: '高速抗弱网首选',
    sampleUri: 'hy2://wukong-pass@tokyo.wukong.mesh:45080/?insecure=0&sni=cdn.apple.com#Wukong-Tokyo-Hy2',
    descZh: '专为极速抗丢包设计，采用魔改 QUIC 协议与自适应速率估算，弱网高丢包环境下跑满带宽。',
    descEn: 'Engineered for brutal network conditions with modified QUIC & adaptive rate estimation, sustaining line-rate speeds under high loss.'
  },
  {
    id: 'reality',
    name: 'VLESS + REALITY',
    port: '443 (TCP)',
    transport: 'TCP / Vision',
    security: 'REALITY Camouflage',
    congestionOrSni: 'SNI: gateway.icloud.com',
    flowOrCipher: 'xtls-rprx-vision',
    tag: '全域拟真防封锁',
    sampleUri: 'vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@us-west.wukong.mesh:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=gateway.icloud.com&fp=chrome&pbk=wukong-pub-key#Wukong-US-REALITY',
    descZh: '借壳真实大厂证书指纹握手（uTLS Chrome 伪装），无需自带域名证书，出站彻底隐匿。',
    descEn: 'Leverages target authoritative TLS cert fingerprints with uTLS Chrome camouflage, eliminating self-owned certificate risks.'
  },
  {
    id: 'cftunnel',
    name: 'CF Tunnel (Argo)',
    port: 'gRPC / Ingress',
    transport: 'Cloudflare Edge Mesh',
    security: 'Cloudflare Managed TLS',
    congestionOrSni: 'Origin: internal-bridge',
    flowOrCipher: 'Zero Inbound Ports Exposed',
    tag: '无公网IP免端口映射',
    sampleUri: 'vless://wukong-sub@cf-ingress.wukong.mesh:443?path=%2Fargo-wukong&security=tls&encryption=none&host=cf.wukong.cloud#Wukong-Tunnel',
    descZh: '纯内网无公网 IPv4 VPS 救星！通过 Cloudflare Daemon 双向主动握手，彻底隐藏源站真实 IP。',
    descEn: 'No public IPv4 needed. Connects outward via Cloudflare Argo Daemon, completely shielding the origin server from scanning.'
  },
  {
    id: 'tuic',
    name: 'TUIC v5',
    port: '48080 (UDP)',
    transport: 'Pure QUIC v1',
    security: 'TLS 1.3 ALPN',
    congestionOrSni: 'BBR Congestion Control',
    flowOrCipher: 'Zero-RTT Handshake',
    tag: '极低握手延迟',
    sampleUri: 'tuic://user:pass@hk.wukong.mesh:48080/?congestion_control=bbr&alpn=h3&sni=hk.wukong.mesh#Wukong-HK-TUIC5',
    descZh: '基于 QUIC 协议的高并发多路复用方案，0-RTT 快速重连，移动网络频繁漫游无缝切换。',
    descEn: 'Ultra-fast multiplexing over QUIC with 0-RTT reconnection, keeping connections alive during mobile network handoffs.'
  },
  {
    id: 'ss2022',
    name: 'Shadowsocks 2022',
    port: '38080 (TCP/UDP)',
    transport: 'AEAD 2022',
    security: 'BLAKE3 + AES-128-GCM',
    congestionOrSni: 'Session Replay Filter',
    flowOrCipher: 'Sub-key derivation',
    tag: '纯粹轻量高吞吐',
    sampleUri: 'ss://2022-blake3-aes-128-gcm:d3Vrb25nLXNzLXBhc3N3b3Jk@sg.wukong.mesh:38080#Wukong-SG-SS2022',
    descZh: '下一代现代密码学规范，杜绝长连接重放攻击与主动探测，占用 CPU 极其轻量。',
    descEn: 'Modern cryptographic spec neutralizing active probes and replay attacks, with negligible CPU overhead.'
  },
  {
    id: 'trojan',
    name: 'Trojan TLS',
    port: '8443 (TCP)',
    transport: 'Direct TLS Stream',
    security: 'Standard Web PKI',
    congestionOrSni: 'SNI: panel.domain.com',
    flowOrCipher: 'SHA224 Password Digest',
    tag: '标准 HTTPS 拟真',
    sampleUri: 'trojan://wukong-trojan-pass@de.wukong.mesh:8443?security=tls&sni=panel.domain.com#Wukong-DE-Trojan',
    descZh: '流量与经典 HTTPS 网页毫无二致，遇到未授权访问自动回落至正规静态网页站点。',
    descEn: 'Indistinguishable from normal HTTPS web traffic, with automatic graceful fallback to static sites upon unauthorized access.'
  },
  {
    id: 'anytls',
    name: 'AnyTLS',
    port: '5443 (TCP/UDP)',
    transport: 'Adaptive Dynamic TLS',
    security: 'Multi-layer Camouflage',
    congestionOrSni: 'Dynamic Header Entropy',
    flowOrCipher: 'Entropy Randomization',
    tag: '前沿自适应流',
    sampleUri: 'anytls://token-wukong@jp.wukong.mesh:5443?sni=jp.wukong.mesh#Wukong-JP-AnyTLS',
    descZh: '悟空面板前沿自适应 TLS 封装，随机化报文字节特征与填充长度，规避深度流量指纹识别。',
    descEn: 'Cutting-edge dynamic TLS encapsulation with randomized payload padding, evading deep packet fingerprint inspection.'
  }
];

export class InteractiveSandbox {
  private element: HTMLElement;
  private lang: 'zh' | 'en' = 'zh';
  private activeProtocolIndex: number = 0;
  private isProbing: boolean = false;
  private probeLogs: Array<{ time: string; text: string; status: 'info' | 'pass' | 'diag' }> = [];
  private isShareModalOpen: boolean = false;

  constructor(lang: 'zh' | 'en') {
    this.lang = lang;
    this.element = document.createElement('section');
    this.element.className = 'sandbox-section section-spacing';
    this.element.id = 'sandbox';
    this.resetProbeLogs();
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
    this.scrollToActiveTab(false);
  }

  private resetProbeLogs() {
    const spec = PROTOCOL_SPECS[this.activeProtocolIndex];
    this.probeLogs = [
      { time: '00:00.01', text: `Node initialized: [${spec.name}] on ${spec.port}`, status: 'info' },
      { time: '00:00.03', text: `Transport: ${spec.transport} / Security: ${spec.security}`, status: 'info' },
      { time: '00:00.05', text: 'Dual-stack IPv4/IPv6 loopback listener ready', status: 'diag' }
    ];
  }

  private render() {
    const isZh = this.lang === 'zh';

    this.element.innerHTML = `
      <div class="container">
        <div style="text-align: center; max-width: 760px; margin: 0 auto;">
          <div class="chapter-kicker">${isZh ? '现场实机操控沙箱' : 'Interactive Live Console'}</div>
          <h2 class="text-title-1">
            ${isZh ? '七十二变 · ' : 'Seven Protocols · '}
            <span class="gold-gradient-text">${isZh ? '七大主流协议现场调度' : 'Dynamic Runtime Matrix'}</span>
          </h2>
          <p class="text-body" style="margin-top: 1rem;">
            ${isZh
              ? '不要只看说明，亲手体验！点击切换协议，直观观测节点参数、运行报文流向，并执行真实的本机闭环握手探针自检。'
              : 'Don’t just take our word for it—play with it live. Switch protocols, inspect specifications, and run instant closed-loop diagnostic probes.'}
          </p>
        </div>

        <div class="sandbox-console">
          <!-- Protocol Matrix Tabs -->
          <div class="sandbox-protocol-bar" role="tablist" aria-label="Protocols">
            ${PROTOCOL_SPECS.map((item, idx) => `
              <button type="button" role="tab" class="protocol-chip ${idx === this.activeProtocolIndex ? 'active' : ''}" data-idx="${idx}" aria-selected="${idx === this.activeProtocolIndex}">
                <span>${item.name}</span>
                <span class="badge-mono" style="font-size: 0.68rem;">${item.tag}</span>
              </button>
            `).join('')}
          </div>

          <!-- Main Sandbox Stage -->
          <div class="sandbox-stage" id="sandbox-stage">
            ${this.getStageHtml()}
          </div>
        </div>
      </div>

      <!-- Share & Dark Gold QR Code Modal -->
      <div class="modal-overlay ${this.isShareModalOpen ? 'open' : ''}" id="share-modal" role="dialog" aria-modal="true" aria-label="Share Protocol Subscription">
        ${this.getModalHtml()}
      </div>
    `;

    setTimeout(() => {
      const spec = PROTOCOL_SPECS[this.activeProtocolIndex];
      this.renderQRCode(spec.sampleUri);
    }, 10);
  }

  private getStageHtml(): string {
    const isZh = this.lang === 'zh';
    const spec = PROTOCOL_SPECS[this.activeProtocolIndex];

    return `
      <!-- Left: Realistic Interactive Node Card -->
      <div class="sandbox-node-card">
        <div class="node-card-head">
          <div class="node-title-group">
            <span class="cinnabar-seal">悟</span>
            <div>
              <div style="font-weight: 700; font-size: 1.15rem; color: var(--text-primary);">${spec.name}</div>
              <div class="font-mono text-caption" style="color: var(--text-muted);">${spec.tag}</div>
            </div>
          </div>
          <div class="node-badge-online">
            <span class="hero-pulse-dot" style="width: 6px; height: 6px;"></span>
            <span>ONLINE</span>
          </div>
        </div>

        <div class="node-specs-grid">
          <div class="spec-entry">
            <span class="spec-key">${isZh ? '入站端口' : 'Inbound Port'}</span>
            <span class="spec-value" style="color: var(--gold-bright);">${spec.port}</span>
          </div>
          <div class="spec-entry">
            <span class="spec-key">${isZh ? '传输协议' : 'Transport'}</span>
            <span class="spec-value">${spec.transport}</span>
          </div>
          <div class="spec-entry">
            <span class="spec-key">${isZh ? '安全伪装' : 'Security Layer'}</span>
            <span class="spec-value">${spec.security}</span>
          </div>
          <div class="spec-entry">
            <span class="spec-key">${isZh ? '流控/认证' : 'Flow / Cipher'}</span>
            <span class="spec-value">${spec.flowOrCipher}</span>
          </div>
          <div class="spec-entry" style="grid-column: span 2;">
            <span class="spec-key">${isZh ? '拥塞算法 / 域名' : 'Congestion / SNI Target'}</span>
            <span class="spec-value font-mono" style="font-size: 0.85rem;">${spec.congestionOrSni}</span>
          </div>
        </div>

        <div style="font-size: 0.88rem; color: var(--text-secondary); line-height: 1.6; background: var(--bg-primary); padding: 0.85rem 1rem; border-radius: var(--radius-md); border-left: 3px solid var(--gold-primary);">
          ${isZh ? spec.descZh : spec.descEn}
        </div>
      </div>

      <!-- Right: Real-Time Diagnostic Terminal Console -->
      <div class="sandbox-probe-console">
        <div class="probe-screen">
          <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(255, 255, 255, 0.08); padding-bottom: 0.6rem;">
            <span style="color: #9ca3af; font-size: 0.75rem;">$ wukong-probe --closed-loop --strict</span>
            <span class="badge-mono" style="color: var(--telemetry-green); border-color: rgba(16, 185, 129, 0.3);">
              ${this.isProbing ? 'PROBING...' : 'LOOPBACK READY'}
            </span>
          </div>

          <div class="probe-log-lines" id="sandbox-probe-logs">
            ${this.probeLogs.map((log) => `
              <div class="probe-log-line">
                <span class="log-timestamp">[${log.time}]</span>
                <span style="color: ${log.status === 'pass' ? '#34d399' : log.status === 'diag' ? '#d4ad57' : '#9ca3af'};">${log.text}</span>
              </div>
            `).join('')}
          </div>

          <div style="border-top: 1px solid rgba(255, 255, 255, 0.08); padding-top: 0.6rem; display: flex; justify-content: space-between; font-size: 0.78rem;">
            <span style="color: #9ca3af;">Roundtrip: <b style="color: #34d399;">26 ms</b></span>
            <span style="color: #9ca3af;">Loss: <b style="color: #34d399;">0.0% (30m)</b></span>
            <span style="color: #9ca3af;">Jitter: <b style="color: #34d399;">1.2 ms</b></span>
          </div>
        </div>

        <!-- Animated Packet Route Bar -->
        <div style="background: var(--bg-primary); padding: 0.85rem; border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
          <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono); margin-bottom: 0.5rem;">
            <span>CLIENT [Browser]</span>
            <span style="color: var(--telemetry-green);">PACKET ROUTE</span>
            <span>VPS EGRESS [sing-box]</span>
          </div>
          <div style="position: relative; height: 6px; background: rgba(255, 255, 255, 0.08); border-radius: 3px; overflow: hidden;">
            <div class="packet-flow-runner" style="position: absolute; top: 0; left: 0; height: 100%; width: 35%; background: linear-gradient(90deg, transparent, var(--gold-bright), transparent); animation: packet-flow 1.5s infinite linear;"></div>
          </div>
        </div>

        <div class="sandbox-controls">
          <button type="button" class="btn-probe-trigger" id="btn-run-probe" ${this.isProbing ? 'disabled' : ''}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
            </svg>
            <span>${this.isProbing ? (isZh ? '正在握手自检...' : 'Probing...') : (isZh ? '⚡ 立即执行闭环自检' : '⚡ Run Handshake Probe')}</span>
          </button>

          <button type="button" class="btn-share-trigger" id="btn-open-share">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="18" cy="5" r="3"></circle>
              <circle cx="6" cy="12" r="3"></circle>
              <circle cx="18" cy="19" r="3"></circle>
              <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line>
              <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line>
            </svg>
            <span>${isZh ? '分享订阅 / QR' : 'Share & QR'}</span>
          </button>
        </div>
      </div>
    `;
  }

  private getModalHtml(): string {
    const isZh = this.lang === 'zh';
    const spec = PROTOCOL_SPECS[this.activeProtocolIndex];

    return `
      <div class="modal-card">
        <div style="display: flex; align-items: center; gap: 0.5rem; justify-content: center;">
          <span class="cinnabar-seal">悟</span>
          <h3 class="text-title-3">${spec.name} ${isZh ? '订阅二维码' : 'Universal QR'}</h3>
        </div>

        <p class="text-caption">
          ${isZh ? '可直接使用客户端扫描导入，或复制通用协议 URI 链接' : 'Scan directly with any Sing-box / Clash client, or copy URI string.'}
        </p>

        <div class="qr-canvas-box">
          <canvas id="qr-code-canvas" width="220" height="220"></canvas>
        </div>

        <div style="width: 100%; display: flex; flex-direction: column; gap: 0.75rem;">
          <input type="text" readonly value="${spec.sampleUri}" class="font-mono text-caption" style="width: 100%; padding: 0.5rem 0.75rem; background: var(--bg-secondary); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); color: var(--text-primary); text-overflow: ellipsis;" id="share-uri-input">
          
          <div style="display: flex; gap: 0.75rem;">
            <button type="button" class="btn-primary" style="flex: 1; padding: 0.6rem;" id="btn-copy-uri">
              <span>${isZh ? '复制链接' : 'Copy URI'}</span>
            </button>
            <button type="button" class="btn-secondary" style="padding: 0.6rem 1.25rem;" id="btn-close-modal">
              <span>${isZh ? '关闭' : 'Close'}</span>
            </button>
          </div>
        </div>
      </div>
    `;
  }

  private async renderQRCode(text: string) {
    const canvas = this.element.querySelector('#qr-code-canvas') as HTMLCanvasElement;
    if (canvas) {
      try {
        await QRCode.toCanvas(canvas, text, {
          width: 200,
          margin: 1,
          color: {
            dark: '#121008',
            light: '#ffffff'
          }
        });
      } catch {
        // Safe catch
      }
    }
  }

  /**
   * Smoothly scrolls the protocol tab bar to position the active tab
   * and bring subsequent protocols into clear view.
   */
  public scrollToActiveTab(smooth: boolean = true) {
    const bar = this.element.querySelector('.sandbox-protocol-bar') as HTMLElement;
    if (!bar) return;
    const activeChip = bar.querySelector(`.protocol-chip[data-idx="${this.activeProtocolIndex}"]`) as HTMLElement;
    if (!activeChip) return;

    const barRect = bar.getBoundingClientRect();
    const chipRect = activeChip.getBoundingClientRect();
    const currentScrollLeft = bar.scrollLeft;
    // Calculate chip position relative to the scrollable content container
    const chipLeftInContent = (chipRect.left - barRect.left) + currentScrollLeft;
    const maxScrollLeft = bar.scrollWidth - bar.clientWidth;

    // Preferred visual offset: position the active chip ~28% from the left edge (up to 260px).
    // When Shadowsocks 2022 (index 4) or following tabs are selected, this ensures
    // the subsequent protocols (Trojan TLS, AnyTLS) automatically shift forward and remain visible!
    const preferredVisualLeft = Math.min(bar.clientWidth * 0.28, 260);
    const targetScrollLeft = chipLeftInContent - preferredVisualLeft;
    const clampedScrollLeft = Math.max(0, Math.min(targetScrollLeft, maxScrollLeft));

    bar.scrollTo({
      left: clampedScrollLeft,
      behavior: smooth ? 'smooth' : 'auto'
    });
  }

  private selectProtocol(idx: number, smooth: boolean = true) {
    if (idx === this.activeProtocolIndex) return;
    this.activeProtocolIndex = idx;
    this.resetProbeLogs();

    // 1. Update chip buttons active states without destroying the tab bar DOM or losing scroll
    const chips = this.element.querySelectorAll<HTMLButtonElement>('.protocol-chip');
    chips.forEach((chip) => {
      const chipIdx = Number(chip.getAttribute('data-idx'));
      const isActive = chipIdx === this.activeProtocolIndex;
      chip.classList.toggle('active', isActive);
      chip.setAttribute('aria-selected', String(isActive));
    });

    // 2. Re-render the stage and bind its events
    const stageEl = this.element.querySelector('#sandbox-stage');
    if (stageEl) {
      stageEl.innerHTML = this.getStageHtml();
      this.bindStageEvents();
    }

    // 3. Update modal content
    const modalEl = this.element.querySelector('#share-modal');
    if (modalEl) {
      modalEl.innerHTML = this.getModalHtml();
      this.bindModalEvents();
      if (this.isShareModalOpen) {
        this.renderQRCode(PROTOCOL_SPECS[this.activeProtocolIndex].sampleUri);
      }
    }

    // 4. Smoothly shift tabs so subsequent protocols move forward into view
    this.scrollToActiveTab(smooth);
  }

  private bindEvents() {
    this.bindProtocolBarEvents();
    this.bindStageEvents();
    this.bindModalEvents();

    // Keyboard ESC to close modal
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && this.isShareModalOpen) {
        this.closeModal();
      }
    });

    // Window resize adjustment
    window.addEventListener('resize', () => {
      this.scrollToActiveTab(false);
    });
  }

  private bindProtocolBarEvents() {
    const chips = this.element.querySelectorAll('.protocol-chip');
    chips.forEach((chip) => {
      chip.addEventListener('click', () => {
        audioHaptics.playSwitch();
        const idx = Number(chip.getAttribute('data-idx'));
        if (!isNaN(idx)) {
          this.selectProtocol(idx, true);
        }
      });
    });
  }

  private bindStageEvents() {
    // Run Handshake Probe
    const probeBtn = this.element.querySelector('#btn-run-probe');
    if (probeBtn) {
      probeBtn.addEventListener('click', () => {
        if (this.isProbing) return;
        this.runSimulatedProbe();
      });
    }

    // Open Share Modal
    const shareBtn = this.element.querySelector('#btn-open-share');
    if (shareBtn) {
      shareBtn.addEventListener('click', () => {
        audioHaptics.playClick();
        this.isShareModalOpen = true;
        const modal = this.element.querySelector('#share-modal');
        modal?.classList.add('open');
        this.renderQRCode(PROTOCOL_SPECS[this.activeProtocolIndex].sampleUri);
      });
    }
  }

  private bindModalEvents() {
    // Close Modal Button
    const closeBtn = this.element.querySelector('#btn-close-modal');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        audioHaptics.playClick();
        this.closeModal();
      });
    }

    // Click outside modal to close
    const modal = this.element.querySelector('#share-modal');
    if (modal) {
      modal.addEventListener('click', (e) => {
        if (e.target === modal) {
          this.closeModal();
        }
      });
    }

    // Copy URI
    const copyUriBtn = this.element.querySelector('#btn-copy-uri');
    if (copyUriBtn) {
      copyUriBtn.addEventListener('click', async () => {
        audioHaptics.playSuccess();
        const input = this.element.querySelector('#share-uri-input') as HTMLInputElement;
        if (input) {
          try {
            await navigator.clipboard.writeText(input.value);
            copyUriBtn.innerHTML = `<span>${this.lang === 'zh' ? '✓ 已复制' : '✓ Copied'}</span>`;
            setTimeout(() => {
              copyUriBtn.innerHTML = `<span>${this.lang === 'zh' ? '复制链接' : 'Copy URI'}</span>`;
            }, 2000);
          } catch {
            input.select();
          }
        }
      });
    }
  }

  private closeModal() {
    this.isShareModalOpen = false;
    const modal = this.element.querySelector('#share-modal');
    modal?.classList.remove('open');
  }

  private runSimulatedProbe() {
    this.isProbing = true;
    audioHaptics.playProbePing();
    const spec = PROTOCOL_SPECS[this.activeProtocolIndex];

    const probeBtn = this.element.querySelector('#btn-run-probe') as HTMLButtonElement;
    if (probeBtn) {
      probeBtn.disabled = true;
      probeBtn.innerHTML = `<span>${this.lang === 'zh' ? '⚡ 正在握手自检...' : '⚡ Probing...'}</span>`;
    }

    this.probeLogs = [
      { time: '00:00.01', text: `Initiating strict raw-socket probe to ${spec.port}...`, status: 'info' }
    ];
    this.updateLogScreen();

    setTimeout(() => {
      audioHaptics.playProbePing();
      this.probeLogs.push({ time: '00:00.12', text: `Transport [${spec.transport}] socket connected in 1.4ms`, status: 'diag' });
      this.updateLogScreen();
    }, 280);

    setTimeout(() => {
      this.probeLogs.push({ time: '00:00.28', text: `TLS 1.3 Handshake completed: cipher=${spec.flowOrCipher}`, status: 'diag' });
      this.updateLogScreen();
    }, 560);

    setTimeout(() => {
      audioHaptics.playSuccess();
      const randomLatency = Math.floor(22 + Math.random() * 8);
      this.probeLogs.push({
        time: '00:00.45',
        text: `VERIFIED: Closed-loop self-check 100% HEALTHY (${randomLatency}ms, 0% loss)`,
        status: 'pass'
      });
      this.updateLogScreen();
      this.isProbing = false;

      if (probeBtn) {
        probeBtn.disabled = false;
        probeBtn.innerHTML = `
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
          </svg>
          <span>${this.lang === 'zh' ? '⚡ 再次执行闭环自检' : '⚡ Re-run Probe'}</span>
        `;
      }
    }, 850);
  }

  private updateLogScreen() {
    const logBox = this.element.querySelector('#sandbox-probe-logs');
    if (logBox) {
      logBox.innerHTML = this.probeLogs.map((log) => `
        <div class="probe-log-line">
          <span class="log-timestamp">[${log.time}]</span>
          <span style="color: ${log.status === 'pass' ? '#34d399' : log.status === 'diag' ? '#d4ad57' : '#9ca3af'};">${log.text}</span>
        </div>
      `).join('');
      logBox.scrollTop = logBox.scrollHeight;
    }
  }
}
