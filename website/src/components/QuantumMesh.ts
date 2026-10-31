/**
 * Wukong Official Site - Hero Interactive Quantum Node Mesh Canvas
 * Hyper-performance 60/120fps topology field simulating global VPS fleets,
 * orbital photon pulses, gravitational particle attraction, and theme-adaptive rendering.
 */

interface MeshNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  baseRadius: number;
  pulsePhase: number;
  label: string;
  isHub?: boolean;
}

interface Particle {
  sourceIndex: number;
  targetIndex: number;
  progress: number;
  speed: number;
  size: number;
  color: string;
}

export class QuantumMesh {
  private canvas: HTMLCanvasElement;
  private ctx: CanvasRenderingContext2D;
  private width: number = 0;
  private height: number = 0;
  private dpr: number = 1;

  private nodes: MeshNode[] = [];
  private particles: Particle[] = [];
  private mouse = { x: -1000, y: -1000, targetX: -1000, targetY: -1000 };

  private isRunning: boolean = false;
  private rafId: number | null = null;
  private isDark: boolean = true;
  private reducedMotion: boolean = false;

  constructor(container: HTMLElement) {
    this.canvas = document.createElement('canvas');
    this.canvas.className = 'quantum-mesh-canvas';
    this.canvas.style.display = 'block';
    this.canvas.style.width = '100%';
    this.canvas.style.height = '100%';
    container.appendChild(this.canvas);

    const context = this.canvas.getContext('2d', { alpha: true });
    if (!context) {
      throw new Error('Canvas 2D context not available');
    }
    this.ctx = context;

    this.checkPreferences();
    this.resize();
    this.initGraph();
    this.bindEvents();

    if (!this.reducedMotion) {
      this.start();
    } else {
      this.renderStatic();
    }
  }

  private checkPreferences() {
    this.reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const meta = document.querySelector('meta[name="color-scheme"]');
    const content = meta?.getAttribute('content') || '';
    if (content === 'light') {
      this.isDark = false;
    } else if (content === 'dark') {
      this.isDark = true;
    } else {
      this.isDark = !window.matchMedia('(prefers-color-scheme: light)').matches;
    }
  }

  public setTheme(isDark: boolean) {
    this.isDark = isDark;
    if (this.reducedMotion) {
      this.renderStatic();
    }
  }

  private resize() {
    const rect = this.canvas.getBoundingClientRect();
    this.width = rect.width;
    this.height = rect.height;
    this.dpr = Math.min(window.devicePixelRatio || 1, 2);

    this.canvas.width = Math.floor(this.width * this.dpr);
    this.canvas.height = Math.floor(this.height * this.dpr);
    this.ctx.scale(this.dpr, this.dpr);
  }

  private initGraph() {
    const hubNames = ['TOKYO', 'FRANKFURT', 'LOS ANGELES', 'SINGAPORE', 'HONG KONG', 'LONDON', 'SYDNEY', 'SAO PAULO'];
    this.nodes = [];
    this.particles = [];

    // Distribute nodes across viewport
    const count = Math.min(Math.max(Math.floor(this.width / 130), 8), 16);

    for (let i = 0; i < count; i++) {
      const isHub = i < hubNames.length;
      const margin = 80;
      const x = margin + Math.random() * (this.width - margin * 2);
      const y = margin + Math.random() * (this.height - margin * 2);

      this.nodes.push({
        x,
        y,
        vx: (Math.random() - 0.5) * 0.45,
        vy: (Math.random() - 0.5) * 0.45,
        baseRadius: isHub ? 4.5 : 2.5,
        pulsePhase: Math.random() * Math.PI * 2,
        label: isHub ? hubNames[i] : '',
        isHub
      });
    }

    // Initialize photon packets
    const particleCount = Math.floor(count * 1.8);
    for (let i = 0; i < particleCount; i++) {
      const sourceIndex = Math.floor(Math.random() * count);
      let targetIndex = Math.floor(Math.random() * count);
      while (targetIndex === sourceIndex) {
        targetIndex = Math.floor(Math.random() * count);
      }

      this.particles.push({
        sourceIndex,
        targetIndex,
        progress: Math.random(),
        speed: 0.003 + Math.random() * 0.005,
        size: 1.8 + Math.random() * 1.5,
        color: Math.random() > 0.4 ? '#d4ad57' : '#10b981'
      });
    }
  }

  private bindEvents() {
    window.addEventListener('resize', () => {
      this.resize();
      this.initGraph();
    }, { passive: true });

    window.addEventListener('mousemove', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      this.mouse.targetX = e.clientX - rect.left;
      this.mouse.targetY = e.clientY - rect.top;
    }, { passive: true });

    window.addEventListener('mouseleave', () => {
      this.mouse.targetX = -1000;
      this.mouse.targetY = -1000;
    });

    // Pause when page is hidden to save power
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        this.stop();
      } else if (!this.reducedMotion) {
        this.start();
      }
    });
  }

  public start() {
    if (this.isRunning) return;
    this.isRunning = true;
    let lastTime = performance.now();

    const loop = (now: number) => {
      if (!this.isRunning) return;
      const dt = Math.min((now - lastTime) / 1000, 0.1);
      lastTime = now;

      this.update(dt);
      this.render();

      this.rafId = requestAnimationFrame(loop);
    };

    this.rafId = requestAnimationFrame(loop);
  }

  public stop() {
    this.isRunning = false;
    if (this.rafId) {
      cancelAnimationFrame(this.rafId);
      this.rafId = null;
    }
  }

  private update(_dt: number) {
    // Smooth mouse coordinates
    this.mouse.x += (this.mouse.targetX - this.mouse.x) * 0.1;
    this.mouse.y += (this.mouse.targetY - this.mouse.y) * 0.1;

    // Update node positions with gentle floating and mouse gravitation
    for (let i = 0; i < this.nodes.length; i++) {
      const n = this.nodes[i];
      n.x += n.vx;
      n.y += n.vy;
      n.pulsePhase += 0.025;

      // Soft boundary rebound
      const pad = 50;
      if (n.x < pad) { n.x = pad; n.vx *= -1; }
      if (n.x > this.width - pad) { n.x = this.width - pad; n.vx *= -1; }
      if (n.y < pad) { n.y = pad; n.vy *= -1; }
      if (n.y > this.height - pad) { n.y = this.height - pad; n.vy *= -1; }

      // Mouse gravitational attraction & repulsion wave
      const dx = this.mouse.x - n.x;
      const dy = this.mouse.y - n.y;
      const dist = Math.hypot(dx, dy);
      if (dist < 220 && dist > 10) {
        const force = (1 - dist / 220) * 0.45;
        n.x -= (dx / dist) * force;
        n.y -= (dy / dist) * force;
      }
    }

    // Update particles along network paths
    for (let i = 0; i < this.particles.length; i++) {
      const p = this.particles[i];
      p.progress += p.speed;
      if (p.progress >= 1) {
        p.progress = 0;
        p.sourceIndex = p.targetIndex;
        let nextTarget = Math.floor(Math.random() * this.nodes.length);
        while (nextTarget === p.sourceIndex) {
          nextTarget = Math.floor(Math.random() * this.nodes.length);
        }
        p.targetIndex = nextTarget;
      }
    }
  }

  private render() {
    this.ctx.clearRect(0, 0, this.width, this.height);

    const goldColor = this.isDark ? '#d4ad57' : '#9e782f';
    const edgeBaseColor = this.isDark ? 'rgba(212, 173, 87,' : 'rgba(158, 120, 47,';
    const hubColor = this.isDark ? '#f5d77f' : '#b8860b';
    const labelColor = this.isDark ? 'rgba(243, 244, 246, 0.65)' : 'rgba(40, 36, 28, 0.75)';

    const maxDist = 240;

    // Draw connecting edges
    for (let i = 0; i < this.nodes.length; i++) {
      for (let j = i + 1; j < this.nodes.length; j++) {
        const n1 = this.nodes[i];
        const n2 = this.nodes[j];
        const dx = n2.x - n1.x;
        const dy = n2.y - n1.y;
        const dist = Math.hypot(dx, dy);

        if (dist < maxDist) {
          const alpha = (1 - dist / maxDist) * (this.isDark ? 0.22 : 0.16);
          this.ctx.beginPath();
          this.ctx.moveTo(n1.x, n1.y);
          this.ctx.lineTo(n2.x, n2.y);
          this.ctx.strokeStyle = `${edgeBaseColor} ${alpha})`;
          this.ctx.lineWidth = 1;
          this.ctx.stroke();
        }
      }
    }

    // Draw traveling photon particles
    for (let i = 0; i < this.particles.length; i++) {
      const p = this.particles[i];
      const s = this.nodes[p.sourceIndex];
      const t = this.nodes[p.targetIndex];
      if (!s || !t) continue;

      const px = s.x + (t.x - s.x) * p.progress;
      const py = s.y + (t.y - s.y) * p.progress;

      this.ctx.beginPath();
      this.ctx.arc(px, py, p.size, 0, Math.PI * 2);
      this.ctx.fillStyle = p.color;
      this.ctx.shadowColor = p.color;
      this.ctx.shadowBlur = 8;
      this.ctx.fill();
      this.ctx.shadowBlur = 0;
    }

    // Draw nodes
    this.ctx.font = '9px ui-monospace, "SF Mono", monospace';
    this.ctx.textAlign = 'center';

    for (let i = 0; i < this.nodes.length; i++) {
      const n = this.nodes[i];
      const pulse = Math.sin(n.pulsePhase) * 1.5;
      const radius = n.baseRadius + (n.isHub ? pulse * 0.8 : 0);

      // Orbital halo for hub nodes
      if (n.isHub) {
        this.ctx.beginPath();
        this.ctx.arc(n.x, n.y, radius + 7 + pulse * 2, 0, Math.PI * 2);
        this.ctx.strokeStyle = this.isDark ? 'rgba(212, 173, 87, 0.2)' : 'rgba(184, 134, 11, 0.25)';
        this.ctx.lineWidth = 1;
        this.ctx.stroke();
      }

      // Center core
      this.ctx.beginPath();
      this.ctx.arc(n.x, n.y, radius, 0, Math.PI * 2);
      this.ctx.fillStyle = n.isHub ? hubColor : goldColor;
      this.ctx.shadowColor = hubColor;
      this.ctx.shadowBlur = n.isHub ? 10 : 4;
      this.ctx.fill();
      this.ctx.shadowBlur = 0;

      // Label
      if (n.isHub && n.label) {
        this.ctx.fillStyle = labelColor;
        this.ctx.fillText(n.label, n.x, n.y + radius + 14);
      }
    }
  }

  private renderStatic() {
    this.render();
  }

  public destroy() {
    this.stop();
    this.canvas.remove();
  }
}
