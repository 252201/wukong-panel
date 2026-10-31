/**
 * Wukong Official Site - Magnetic Cursor & Spotlight Controller
 * Provides buttery smooth 120fps interpolated cursor trailing and magnetic snap
 * for interactive controls on desktop devices.
 */

export class MagneticCursor {
  private cursorRing: HTMLElement | null = null;
  private cursorDot: HTMLElement | null = null;
  private spotlight: HTMLElement | null = null;

  private mouseX: number = -100;
  private mouseY: number = -100;
  private currentX: number = -100;
  private currentY: number = -100;
  private dotX: number = -100;
  private dotY: number = -100;

  private rafId: number | null = null;
  private isHovered: boolean = false;
  private isEnabled: boolean = false;

  constructor() {
    // Only enable on desktop pointer devices
    if (typeof window !== 'undefined' && window.matchMedia('(hover: hover) and (pointer: fine)').matches) {
      this.isEnabled = true;
      this.initElements();
      this.bindEvents();
      this.startLoop();
    }
  }

  public getIsEnabled(): boolean {
    return this.isEnabled;
  }

  private initElements() {
    this.cursorRing = document.createElement('div');
    this.cursorRing.className = 'custom-cursor';
    this.cursorRing.setAttribute('aria-hidden', 'true');

    this.cursorDot = document.createElement('div');
    this.cursorDot.className = 'custom-cursor-dot';
    this.cursorDot.setAttribute('aria-hidden', 'true');

    document.body.appendChild(this.cursorRing);
    document.body.appendChild(this.cursorDot);

    this.spotlight = document.querySelector('.ambient-spotlight');
  }

  private bindEvents() {
    window.addEventListener('mousemove', (e) => {
      this.mouseX = e.clientX;
      this.mouseY = e.clientY;

      if (!this.cursorRing?.classList.contains('visible')) {
        this.cursorRing?.classList.add('visible');
        this.cursorDot?.classList.add('visible');
        if (this.spotlight) this.spotlight.style.opacity = '1';
      }

      if (this.currentX === -100) {
        this.currentX = this.mouseX;
        this.currentY = this.mouseY;
        this.dotX = this.mouseX;
        this.dotY = this.mouseY;
      }
    }, { passive: true });

    document.addEventListener('mouseleave', () => {
      this.cursorRing?.classList.remove('visible');
      this.cursorDot?.classList.remove('visible');
      if (this.spotlight) {
        this.spotlight.style.opacity = '0';
      }
    });

    document.addEventListener('mouseenter', () => {
      this.cursorRing?.classList.add('visible');
      this.cursorDot?.classList.add('visible');
      if (this.spotlight) {
        this.spotlight.style.opacity = '1';
      }
    });

    // Interactive target detection
    document.addEventListener('mouseover', (e) => {
      const target = (e.target as HTMLElement).closest('button, a, .protocol-chip, .fleet-host-row, .arch-btn, input');
      if (target) {
        this.isHovered = true;
        this.cursorRing?.classList.add('active');
      }
    });

    document.addEventListener('mouseout', (e) => {
      const target = (e.target as HTMLElement).closest('button, a, .protocol-chip, .fleet-host-row, .arch-btn, input');
      if (target) {
        this.isHovered = false;
        this.cursorRing?.classList.remove('active');
      }
    });
  }

  private startLoop() {
    const loop = () => {
      // Linear interpolation (LERP) for ring smoothness
      const ease = this.isHovered ? 0.22 : 0.16;
      this.currentX += (this.mouseX - this.currentX) * ease;
      this.currentY += (this.mouseY - this.currentY) * ease;

      // Faster response for center dot
      this.dotX += (this.mouseX - this.dotX) * 0.45;
      this.dotY += (this.mouseY - this.dotY) * 0.45;

      if (this.cursorRing) {
        this.cursorRing.style.transform = `translate3d(${this.currentX}px, ${this.currentY}px, 0)`;
      }

      if (this.cursorDot) {
        this.cursorDot.style.transform = `translate3d(${this.dotX}px, ${this.dotY}px, 0)`;
      }

      // Update ambient background spotlight
      if (this.spotlight) {
        this.spotlight.style.transform = `translate3d(${this.currentX}px, ${this.currentY}px, 0)`;
      }

      this.rafId = requestAnimationFrame(loop);
    };

    this.rafId = requestAnimationFrame(loop);
  }

  public destroy() {
    if (this.rafId) {
      cancelAnimationFrame(this.rafId);
    }
    this.cursorRing?.remove();
    this.cursorDot?.remove();
  }
}
