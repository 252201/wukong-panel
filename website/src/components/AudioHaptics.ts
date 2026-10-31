/**
 * Wukong Official Site - Audio Haptics Engine
 * Synthesizes crisp, tactile transistor micro-sounds using native Web Audio API.
 * Zero external audio files, zero network latency, ~1KB footprint.
 */

class AudioHapticsEngine {
  private ctx: AudioContext | null = null;
  private isMuted: boolean = true;
  private onStateChangeCallbacks: Array<(muted: boolean) => void> = [];

  constructor() {
    // Default to enabled (true) unless user explicitly muted ('false')
    const stored = typeof localStorage !== 'undefined' ? localStorage.getItem('wukong-sound-enabled') : null;
    this.isMuted = stored === 'false';

    // Hook first user interaction to unlock/resume AudioContext seamlessly on any browser
    if (typeof window !== 'undefined') {
      const unlockAudio = () => {
        if (!this.isMuted) {
          this.initContext();
        }
        window.removeEventListener('pointerdown', unlockAudio);
        window.removeEventListener('keydown', unlockAudio);
      };
      window.addEventListener('pointerdown', unlockAudio, { once: true, passive: true });
      window.addEventListener('keydown', unlockAudio, { once: true, passive: true });
    }
  }

  private initContext() {
    if (!this.ctx && typeof window !== 'undefined') {
      const AudioCtx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
      if (AudioCtx) {
        this.ctx = new AudioCtx();
      }
    }
    if (this.ctx && this.ctx.state === 'suspended') {
      this.ctx.resume().catch(() => {});
    }
  }

  public getMuted(): boolean {
    return this.isMuted;
  }

  public toggleMute(): boolean {
    this.isMuted = !this.isMuted;
    localStorage.setItem('wukong-sound-enabled', (!this.isMuted).toString());
    if (!this.isMuted) {
      this.initContext();
      this.playSuccess();
    }
    this.notifySubscribers();
    return this.isMuted;
  }

  public onStateChange(cb: (muted: boolean) => void) {
    this.onStateChangeCallbacks.push(cb);
  }

  private notifySubscribers() {
    for (const cb of this.onStateChangeCallbacks) {
      cb(this.isMuted);
    }
  }

  /**
   * Crisp transistor click for button and chip selections
   */
  public playClick() {
    if (this.isMuted) return;
    this.initContext();
    if (!this.ctx) return;

    try {
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      const now = this.ctx.currentTime;

      osc.type = 'triangle';
      osc.frequency.setValueAtTime(680, now);
      osc.frequency.exponentialRampToValueAtTime(140, now + 0.035);

      gain.gain.setValueAtTime(0.12, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.035);

      osc.connect(gain);
      gain.connect(this.ctx.destination);

      osc.start(now);
      osc.stop(now + 0.04);
    } catch {
      // Audio playback safety catch
    }
  }

  /**
   * Ascending golden harmonic chime for copy & probe completion
   */
  public playSuccess() {
    if (this.isMuted) return;
    this.initContext();
    if (!this.ctx) return;

    try {
      const now = this.ctx.currentTime;
      const notes = [587.33, 880.0]; // D5 -> A5 (Gold interval)

      notes.forEach((freq, idx) => {
        if (!this.ctx) return;
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        const startTime = now + idx * 0.06;

        osc.type = 'sine';
        osc.frequency.setValueAtTime(freq, startTime);

        gain.gain.setValueAtTime(0.08, startTime);
        gain.gain.exponentialRampToValueAtTime(0.0001, startTime + 0.16);

        osc.connect(gain);
        gain.connect(this.ctx.destination);

        osc.start(startTime);
        osc.stop(startTime + 0.17);
      });
    } catch {
      // Audio playback safety catch
    }
  }

  /**
   * Protocol switch frequency glide
   */
  public playSwitch() {
    if (this.isMuted) return;
    this.initContext();
    if (!this.ctx) return;

    try {
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      const now = this.ctx.currentTime;

      osc.type = 'sine';
      osc.frequency.setValueAtTime(320, now);
      osc.frequency.exponentialRampToValueAtTime(540, now + 0.05);

      gain.gain.setValueAtTime(0.1, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.05);

      osc.connect(gain);
      gain.connect(this.ctx.destination);

      osc.start(now);
      osc.stop(now + 0.06);
    } catch {
      // Audio playback safety catch
    }
  }

  /**
   * Sonar probe pulse for simulated network telemetry ping
   */
  public playProbePing() {
    if (this.isMuted) return;
    this.initContext();
    if (!this.ctx) return;

    try {
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      const filter = this.ctx.createBiquadFilter();
      const now = this.ctx.currentTime;

      filter.type = 'bandpass';
      filter.frequency.setValueAtTime(1200, now);
      filter.Q.setValueAtTime(4, now);

      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(880, now);

      gain.gain.setValueAtTime(0.12, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.12);

      osc.connect(filter);
      filter.connect(gain);
      gain.connect(this.ctx.destination);

      osc.start(now);
      osc.stop(now + 0.13);
    } catch {
      // Audio playback safety catch
    }
  }
}

export const audioHaptics = new AudioHapticsEngine();
