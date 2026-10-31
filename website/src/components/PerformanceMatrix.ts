/**
 * Wukong Official Site - Hardcore Performance Matrix Component
 * Architectural face-off comparing Wukong Panel's ultra-lean Go ELF binary
 * with heavy Python/Docker/Node alternatives.
 */

export class PerformanceMatrix {
  private element: HTMLElement;
  private lang: 'zh' | 'en' = 'zh';

  constructor(lang: 'zh' | 'en') {
    this.lang = lang;
    this.element = document.createElement('section');
    this.element.className = 'perf-section section-spacing';
    this.element.id = 'performance';
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
        <div style="text-align: center; max-width: 780px; margin: 0 auto 3.5rem;">
          <div class="chapter-kicker">${isZh ? '架构对决' : 'Architectural Showdown'}</div>
          <h2 class="text-title-1">
            ${isZh ? '硬核指标 · ' : 'Hardcore Metrics · '}
            <span class="gold-gradient-text">${isZh ? '工程设计与资源开销决胜' : 'Engineering & Zero Bloat'}</span>
          </h2>
          <p class="text-body" style="margin-top: 1rem;">
            ${isZh
              ? '不堆砌笨重的 Docker 与外部中间件，只用现代 Go 打造极致轻盈坚固的云上中枢。'
              : 'Zero bloated Docker layers, zero external runtime dependencies. Built strictly in modern Go for hyper-minimalist VPS management.'}
          </p>
        </div>

        <div class="perf-table-wrapper">
          <table class="perf-table" aria-label="Performance Comparison Table">
            <thead>
              <tr>
                <th scope="col">${isZh ? '维度 / 特性' : 'Dimension / Feature'}</th>
                <th scope="col" style="color: var(--gold-bright);">${isZh ? '悟空面板 (Wukong Panel)' : 'Wukong Panel (Ours)'}</th>
                <th scope="col">${isZh ? '传统 Python / Docker 面板' : 'Heavy Python / Docker Panels'}</th>
                <th scope="col">${isZh ? '传统单机 Shell 脚本' : 'Fragile Shell Scripts'}</th>
              </tr>
            </thead>
            <tbody>
              <tr class="highlight-wukong">
                <td>${isZh ? '运行时内存开销' : 'Idle RAM Footprint'}</td>
                <td><strong>&lt; 25 MB</strong> (Probe &lt; 8 MB)</td>
                <td>350 MB – 800 MB+ (Docker / Python)</td>
                <td>0 MB (无常驻监控与状态)</td>
              </tr>
              <tr>
                <td>${isZh ? '多主机舰队纳管' : 'Multi-Host Fleet Mesh'}</td>
                <td style="color: var(--telemetry-green); font-weight: 600;">✓ 2–10 台远端主控 (HTTPS长轮询)</td>
                <td>✗ 仅单机或需复杂外部集群</td>
                <td>✗ 纯单机，完全无协同</td>
              </tr>
              <tr>
                <td>${isZh ? '远端通信安全性' : 'Remote Agent Security'}</td>
                <td style="color: var(--telemetry-green); font-weight: 600;">✓ 零开放端口 (仅出站长轮询)</td>
                <td>✗ 需开公网端口或常驻 SSH</td>
                <td>✗ 频繁明文 SSH 登录</td>
              </tr>
              <tr>
                <td>${isZh ? '存储与事务保障' : 'Database & Transactions'}</td>
                <td style="color: var(--telemetry-green); font-weight: 600;">✓ SQLite 3 WAL (毫秒级零锁等待)</td>
                <td>✗ MySQL / Redis (额外依赖占用)</td>
                <td>✗ 脆弱的 JSON / 文本文件</td>
              </tr>
              <tr>
                <td>${isZh ? '配置热更与自动回滚' : 'Atomic Reload & Rollback'}</td>
                <td style="color: var(--telemetry-green); font-weight: 600;">✓ 秒级内核验证，失败自动恢复</td>
                <td>✗ 配置错误即服务崩溃失联</td>
                <td>✗ 无法原子回滚，极易失联</td>
              </tr>
              <tr>
                <td>${isZh ? '全链路 30 分钟丢包遥测' : '30-Min Continuous Telemetry'}</td>
                <td style="color: var(--telemetry-green); font-weight: 600;">✓ 原生滚动加权遥测条带</td>
                <td>✗ 仅有简单单次 Ping</td>
                <td>✗ 无</td>
              </tr>
              <tr>
                <td>${isZh ? '宿主防火墙自动放行' : 'Host Firewall Auto-Sync'}</td>
                <td style="color: var(--telemetry-green); font-weight: 600;">✓ UFW / firewalld / nftables 自动聚合</td>
                <td>✗ 仅提示用户手动开端口</td>
                <td>✗ 手动 iptables</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    `;
  }
}
