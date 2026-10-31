/**
 * Wukong Official Site - Scrollytelling Epic Chapters
 * Five chapters dissecting Wukong Panel's architecture:
 * 1. 混沌归一 (Central Fleet Sovereignty)
 * 2. 七十二变 (Seven Protocols Matrix)
 * 3. 筋斗云径 (Zero-Loss Probing)
 * 4. 金刚不坏 (Host-Native Defense)
 * 5. 毫毛分身 (Fleet Device Mesh)
 * Supports native CSS scroll-driven animations with IntersectionObserver fallback.
 */

import { audioHaptics } from './AudioHaptics';

export class Scrollytelling {
  private element: HTMLElement;
  private lang: 'zh' | 'en' = 'zh';
  private observer: IntersectionObserver | null = null;

  constructor(lang: 'zh' | 'en') {
    this.lang = lang;
    this.element = document.createElement('section');
    this.element.className = 'scrolly-section section-spacing';
    this.element.id = 'stories';
    this.render();
    this.initObserverFallback();
    this.bindEvents();
  }

  public getElement(): HTMLElement {
    return this.element;
  }

  public setLang(lang: 'zh' | 'en') {
    this.lang = lang;
    this.render();
    this.initObserverFallback();
    this.bindEvents();
  }

  private render() {
    const isZh = this.lang === 'zh';

    this.element.innerHTML = `
      <div class="container">
        <!-- Section Header -->
        <div style="text-align: center; max-width: 780px; margin: 0 auto 5rem;">
          <div class="chapter-kicker">${isZh ? '五卷史诗叙事' : 'Five Epic Chapters'}</div>
          <h2 class="text-title-1">
            ${isZh ? '格物致知 · ' : 'Precision Engineering · '}
            <span class="gold-gradient-text">${isZh ? '解构现代 VPS 自治控制台' : 'Deconstructing the Modern Mesh'}</span>
          </h2>
          <p class="text-body" style="margin-top: 1rem;">
            ${isZh
              ? '从单机脚本的混沌泥潭，到十台远端主机的弹指调度。深度探索悟空面板的五大核心架构突破。'
              : 'From fragile ad-hoc shell scripts to seamless multi-host fleet sovereignty. Explore the five architectural breakthroughs of Wukong Panel.'}
          </p>
        </div>

        <!-- Chapter 1: 混沌归一 (Central Fleet Sovereignty) -->
        <article class="story-chapter" id="chapter-fleet">
          <div class="story-grid">
            <div class="scrolly-card">
              <div class="chapter-kicker">${isZh ? '卷一 · 混沌归一' : 'Chapter I · Fleet Sovereignty'}</div>
              <h3 class="text-title-2" style="margin-bottom: 1rem;">
                ${isZh ? '告别单机脚本地狱，执掌十方舰队' : 'Say Goodbye to Ad-hoc Scripts, Command 10 Nodes at Once'}
              </h3>
              <p class="text-body" style="margin-bottom: 1.5rem;">
                ${isZh
                  ? '以往每台 VPS 都要反复登录 SSH、手动装依赖、改 JSON，一台出事全家抓瞎。悟空面板在任意一台机器上秒级升级为主控，纳管 2–10 台远端 VPS，所有主机的节点生命周期、实时速率与账期流量一览无余。'
                  : 'Managing VPS via fragmented shell scripts is fragile and error-prone. With Wukong Panel, any host can be promoted to Central Master in seconds, unifying up to 10 remote nodes under a single glass pane with synchronized traffic quotas.'}
              </p>
              <div style="display: flex; gap: 0.75rem; flex-wrap: wrap;">
                <span class="badge-mono">⚡ ${isZh ? '秒级主控接入' : '10s Agent Pairing'}</span>
                <span class="badge-mono">🛡️ ${isZh ? '单凭据统一调度' : 'Unified Credentials'}</span>
                <span class="badge-mono">📊 ${isZh ? '跨机合并订阅' : 'Fleet Merged Subscriptions'}</span>
              </div>
            </div>

            <!-- Interactive Fleet Host Simulator -->
            <div class="scrolly-card" style="background: var(--bg-secondary);">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                <span class="font-mono" style="font-size: 0.8rem; color: var(--gold-bright);">${isZh ? '中央主控舰队拓扑' : 'Central Fleet Hosts'}</span>
                <span class="node-badge-online">10 / 10 ONLINE</span>
              </div>
              <div class="fleet-mesh-preview">
                <div class="fleet-host-row" data-host="local">
                  <div style="display: flex; align-items: center; gap: 0.6rem;">
                    <span class="cinnabar-seal" style="width: 22px; height: 22px; font-size: 12px;">主</span>
                    <div>
                      <div style="font-weight: 600; font-size: 0.9rem;">Tokyo Master (Local)</div>
                      <div class="font-mono text-caption" style="color: var(--text-muted);">Debian 12 · 45.12.8.*</div>
                    </div>
                  </div>
                  <div style="text-align: right;">
                    <div class="font-mono" style="color: var(--telemetry-green); font-size: 0.85rem; font-weight: 600;">18 ms</div>
                    <div class="font-mono text-caption" style="color: var(--gold-primary);">1.4 TB / 2.0 TB</div>
                  </div>
                </div>

                <div class="fleet-host-row" data-host="remote-1">
                  <div style="display: flex; align-items: center; gap: 0.6rem;">
                    <span class="badge-mono" style="font-size: 0.7rem;">SG</span>
                    <div>
                      <div style="font-weight: 600; font-size: 0.9rem;">Singapore Light Agent</div>
                      <div class="font-mono text-caption" style="color: var(--text-muted);">Alpine Linux · 104.28.1.*</div>
                    </div>
                  </div>
                  <div style="text-align: right;">
                    <div class="font-mono" style="color: var(--telemetry-green); font-size: 0.85rem; font-weight: 600;">32 ms</div>
                    <div class="font-mono text-caption">840 GB / 1.0 TB</div>
                  </div>
                </div>

                <div class="fleet-host-row" data-host="remote-2">
                  <div style="display: flex; align-items: center; gap: 0.6rem;">
                    <span class="badge-mono" style="font-size: 0.7rem;">US</span>
                    <div>
                      <div style="font-weight: 600; font-size: 0.9rem;">Los Angeles CN2 GIA</div>
                      <div class="font-mono text-caption" style="color: var(--text-muted);">Ubuntu 24.04 · 198.51.100.*</div>
                    </div>
                  </div>
                  <div style="text-align: right;">
                    <div class="font-mono" style="color: var(--telemetry-green); font-size: 0.85rem; font-weight: 600;">118 ms</div>
                    <div class="font-mono text-caption">2.8 TB / 5.0 TB</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </article>

        <!-- Chapter 2: 七十二变 (Seven Protocols Matrix) -->
        <article class="story-chapter" id="chapter-protocols">
          <div class="story-grid reversed">
            <div class="scrolly-card">
              <div class="chapter-kicker">${isZh ? '卷二 · 七十二变' : 'Chapter II · Seven Protocols'}</div>
              <h3 class="text-title-2" style="margin-bottom: 1rem;">
                ${isZh ? '无所不能的代理引擎全阵列' : 'The Complete Modern Protocol Matrix'}
              </h3>
              <p class="text-body" style="margin-bottom: 1.5rem;">
                ${isZh
                  ? '涵盖当今网络对抗最前沿技术栈：Hysteria 2 狂暴抗丢包、VLESS REALITY 偷天换日伪装、CF Tunnel 无公网端口暴露救星、TUIC v5 零延迟漫游、Shadowsocks 2022 轻量密码学、Trojan TLS 与 AnyTLS，全方位应对各类复杂网络。'
                  : 'Deep integration with leading modern proxy protocols: Hysteria 2 for high packet-loss tolerance, VLESS REALITY for seamless TLS camouflage, Cloudflare Tunnel for firewalled IPv4, TUIC v5, Shadowsocks 2022, Trojan TLS, and AnyTLS.'}
              </p>
              <div style="display: flex; gap: 0.75rem; flex-wrap: wrap;">
                <span class="badge-mono">🚀 QUIC / UDP / BBR</span>
                <span class="badge-mono">🔒 uTLS Fingerprint</span>
                <span class="badge-mono">🌐 Zero-Port Tunnel</span>
              </div>
            </div>

            <!-- Protocol Comparison Cards -->
            <div class="scrolly-card" style="background: var(--bg-secondary);">
              <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem;">
                <div style="background: var(--bg-primary); padding: 1rem; border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
                  <div style="font-weight: 700; color: var(--gold-bright);">Hysteria 2</div>
                  <div class="text-caption" style="margin: 0.35rem 0;">95%+ 弱网吞吐保障</div>
                  <div class="font-mono" style="font-size: 0.75rem; color: var(--telemetry-green);">Brutal UDP Congestion</div>
                </div>
                <div style="background: var(--bg-primary); padding: 1rem; border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
                  <div style="font-weight: 700; color: var(--gold-bright);">VLESS REALITY</div>
                  <div class="text-caption" style="margin: 0.35rem 0;">大厂合法证书伪装</div>
                  <div class="font-mono" style="font-size: 0.75rem; color: var(--telemetry-green);">uTLS Chrome Fingerprint</div>
                </div>
                <div style="background: var(--bg-primary); padding: 1rem; border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
                  <div style="font-weight: 700; color: var(--gold-bright);">CF Tunnel (Argo)</div>
                  <div class="text-caption" style="margin: 0.35rem 0;">零公网 IPv4 映射</div>
                  <div class="font-mono" style="font-size: 0.75rem; color: var(--telemetry-green);">gRPC Edge Multiplex</div>
                </div>
                <div style="background: var(--bg-primary); padding: 1rem; border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
                  <div style="font-weight: 700; color: var(--gold-bright);">TUIC v5</div>
                  <div class="text-caption" style="margin: 0.35rem 0;">0-RTT 移动漫游</div>
                  <div class="font-mono" style="font-size: 0.75rem; color: var(--telemetry-green);">Pure QUIC Stream</div>
                </div>
              </div>
            </div>
          </div>
        </article>

        <!-- Chapter 3: 筋斗云径 (Zero-Loss Probing) -->
        <article class="story-chapter" id="chapter-probing">
          <div class="story-grid">
            <div class="scrolly-card">
              <div class="chapter-kicker">${isZh ? '卷三 · 筋斗云径' : 'Chapter III · Zero-Loss Probing'}</div>
              <h3 class="text-title-2" style="margin-bottom: 1rem;">
                ${isZh ? '30分钟连续遥测，毫秒级网络质感' : '30-Minute Continuous Loss Telemetry Strip'}
              </h3>
              <p class="text-body" style="margin-bottom: 1.5rem;">
                ${isZh
                  ? '杜绝单次 Ping 的欺骗性假象。悟空面板独创 30 分钟连续 ICMP 质量条带采样，双栈 IPv4/IPv6 动态出口选择，仅在全区间加权丢包超阈值时告警，并自动智能切换备用目标。'
                  : 'Single ping spikes lie; continuous telemetry reveals the truth. Wukong Panel captures 30-minute rolling ICMP loss strips, weighted packet-loss alerts, and automatic IPv4/IPv6 egress route switching.'}
              </p>
              <div style="display: flex; gap: 0.75rem; flex-wrap: wrap;">
                <span class="badge-mono">📈 30-Min History</span>
                <span class="badge-mono">⚖️ Weighted Loss Alarm</span>
                <span class="badge-mono">🌐 Dual-Stack Auto-Route</span>
              </div>
            </div>

            <!-- Continuous Telemetry Bars Component -->
            <div class="scrolly-card" style="background: var(--bg-secondary);">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                <span class="font-mono" style="font-size: 0.8rem; color: var(--text-secondary);">${isZh ? '近 30 分钟质量条带' : '30-Min Loss Timeline'}</span>
                <span class="badge-mono" style="color: var(--telemetry-green);">0.0% LOSS</span>
              </div>
              <div style="display: flex; align-items: flex-end; gap: 4px; height: 60px; background: var(--bg-primary); padding: 0.75rem; border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
                ${Array.from({ length: 30 }).map((_, i) => {
                  const isRed = i === 18;
                  const height = isRed ? 25 : Math.floor(40 + Math.random() * 15);
                  return `
                    <div style="flex: 1; height: ${height}%; background: ${isRed ? 'var(--cinnabar)' : 'var(--telemetry-green)'}; border-radius: 2px; opacity: 0.85;" title="Sample #${i + 1}"></div>
                  `;
                }).join('')}
              </div>
              <div style="display: flex; justify-content: space-between; font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono); margin-top: 0.5rem;">
                <span>30 min ago</span>
                <span>15 min ago</span>
                <span style="color: var(--telemetry-green);">LIVE NOW</span>
              </div>
            </div>
          </div>
        </article>

        <!-- Chapter 4: 金刚不坏 (Host-Level Shield & Firewall) -->
        <article class="story-chapter" id="chapter-shield">
          <div class="story-grid reversed">
            <div class="scrolly-card">
              <div class="chapter-kicker">${isZh ? '卷四 · 金刚不坏' : 'Chapter IV · Host-Native Shield'}</div>
              <h3 class="text-title-2" style="margin-bottom: 1rem;">
                ${isZh ? '宿主级防火墙聚合与零公网暴露' : 'Host-Level Firewall Defense & Zero Inbound Exposure'}
              </h3>
              <p class="text-body" style="margin-bottom: 1.5rem;">
                ${isZh
                  ? '远端 Agent 绝不向公网开放监听端口，仅通过受信任的双向 HTTPS 主动向主控长轮询指令。宿主机 UFW、firewalld 与 nftables 端口自动聚合放行，搭配 Fail2ban 自动防御 SSH 暴力破解。'
                  : 'Remote Agents NEVER open listening ports to the public. They communicate solely via outbound HTTPS long-polling. Host firewall rules (UFW/nftables) auto-reconcile, backed by automated Fail2ban brute-force protection.'}
              </p>
              <div style="display: flex; gap: 0.75rem; flex-wrap: wrap;">
                <span class="badge-mono">🛡️ UFW / nftables Sync</span>
                <span class="badge-mono">🔒 Outbound Long-Polling</span>
                <span class="badge-mono">🚫 Fail2ban Defense</span>
              </div>
            </div>

            <!-- Firewall & Security Rules Mockup -->
            <div class="scrolly-card" style="background: var(--bg-secondary);">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                <span class="font-mono" style="font-size: 0.8rem; color: var(--gold-bright);">${isZh ? '防火墙聚合防护状态' : 'Firewall Reconciled State'}</span>
                <span class="badge-mono" style="color: var(--telemetry-green);">ENFORCED</span>
              </div>
              <div style="display: flex; flex-direction: column; gap: 0.5rem; font-family: var(--font-mono); font-size: 0.8rem;">
                <div style="display: flex; justify-content: space-between; background: var(--bg-primary); padding: 0.6rem 0.8rem; border-radius: var(--radius-sm); border-left: 3px solid var(--telemetry-green);">
                  <span>UDP 45080 (Hy2 Inbound)</span>
                  <span style="color: var(--telemetry-green);">ALLOWED</span>
                </div>
                <div style="display: flex; justify-content: space-between; background: var(--bg-primary); padding: 0.6rem 0.8rem; border-radius: var(--radius-sm); border-left: 3px solid var(--telemetry-green);">
                  <span>TCP 443 (REALITY Steal)</span>
                  <span style="color: var(--telemetry-green);">ALLOWED</span>
                </div>
                <div style="display: flex; justify-content: space-between; background: var(--bg-primary); padding: 0.6rem 0.8rem; border-radius: var(--radius-sm); border-left: 3px solid var(--cinnabar);">
                  <span>TCP 22 (SSH Brute Filter)</span>
                  <span style="color: var(--cinnabar);">FAIL2BAN ACTIVE (42 Banned)</span>
                </div>
              </div>
            </div>
          </div>
        </article>

        <!-- Chapter 5: 毫毛分身 (Fleet Device Mesh) -->
        <article class="story-chapter" id="chapter-device">
          <div class="story-grid">
            <div class="scrolly-card">
              <div class="chapter-kicker">${isZh ? '卷五 · 毫毛分身' : 'Chapter V · Fleet Device Mesh'}</div>
              <h3 class="text-title-2" style="margin-bottom: 1rem;">
                ${isZh ? '多设备专属入口与双落地出口' : 'Dedicated Per-Device Ports & Dual Egress Routing'}
              </h3>
              <p class="text-body" style="margin-bottom: 1.5rem;">
                ${isZh
                  ? '一个进程，管理几十台设备的专属通道！iPhone、Mac、电视盒子与软路由分配独立的专属端口与密码，互不干扰；支持双 VPS 落地 IP 出口与 fail-closed 故障隔离路由。'
                  : 'One sing-box process managing dozens of devices. Assign dedicated ports and credentials to iPhone, Mac, Apple TV, and routers without interference, plus dual-egress routing with fail-closed safeguards.'}
              </p>
              <div style="display: flex; gap: 0.75rem; flex-wrap: wrap;">
                <span class="badge-mono">📱 Per-Device Port</span>
                <span class="badge-mono">🔄 Dual VPS Egress</span>
                <span class="badge-mono">⚡ Zero Core Overhead</span>
              </div>
            </div>

            <!-- Device Mesh Diagram -->
            <div class="scrolly-card" style="background: var(--bg-secondary);">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                <span class="font-mono" style="font-size: 0.8rem; color: var(--gold-bright);">${isZh ? '设备分流矩阵' : 'Device Routing Mesh'}</span>
                <span class="badge-mono">4 DEVICES CONNECTED</span>
              </div>
              <div style="display: flex; flex-direction: column; gap: 0.6rem; font-family: var(--font-mono); font-size: 0.825rem;">
                <div style="background: var(--bg-primary); padding: 0.6rem 0.8rem; border-radius: var(--radius-sm); display: flex; justify-content: space-between; align-items: center;">
                  <span>📱 iPhone 16 Pro (Port 45081)</span>
                  <span class="badge-mono" style="color: var(--gold-bright);">-> Tokyo CN2</span>
                </div>
                <div style="background: var(--bg-primary); padding: 0.6rem 0.8rem; border-radius: var(--radius-sm); display: flex; justify-content: space-between; align-items: center;">
                  <span>💻 MacBook Pro M4 (Port 45082)</span>
                  <span class="badge-mono" style="color: var(--gold-bright);">-> Singapore Tier-1</span>
                </div>
                <div style="background: var(--bg-primary); padding: 0.6rem 0.8rem; border-radius: var(--radius-sm); display: flex; justify-content: space-between; align-items: center;">
                  <span>📺 Apple TV 4K (Port 45083)</span>
                  <span class="badge-mono" style="color: var(--gold-bright);">-> US Netflix Residential</span>
                </div>
              </div>
            </div>
          </div>
        </article>
      </div>
    `;
  }

  private initObserverFallback() {
    // Check if browser does NOT support native scroll-driven animations
    if (typeof window !== 'undefined' && !window.CSS?.supports?.('animation-timeline', 'view()')) {
      this.observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-revealed');
          }
        });
      }, {
        threshold: 0.15
      });

      const cards = this.element.querySelectorAll('.scrolly-card');
      cards.forEach((c) => this.observer?.observe(c));
    }
  }

  private bindEvents() {
    const fleetRows = this.element.querySelectorAll('.fleet-host-row');
    fleetRows.forEach((row) => {
      row.addEventListener('click', () => {
        audioHaptics.playClick();
        fleetRows.forEach((r) => r.classList.remove('active'));
        row.classList.add('active');
      });
    });
  }

  public destroy() {
    this.observer?.disconnect();
  }
}
