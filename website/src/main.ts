/**
 * Wukong Official Site - Main Application Entrypoint
 * Coordinates state, components, audio haptics, quantum mesh, and responsive navigation.
 */

import './styles/tokens.css';
import './styles/typography.css';
import './styles/scrollytelling.css';
import './styles/main.css';

import { audioHaptics } from './components/AudioHaptics';
import { MagneticCursor } from './components/MagneticCursor';
import { QuantumMesh } from './components/QuantumMesh';
import { Navbar, NavState } from './components/Navbar';
import { Hero } from './components/Hero';
import { InteractiveSandbox } from './components/InteractiveSandbox';
import { Scrollytelling } from './components/Scrollytelling';
import { PerformanceMatrix } from './components/PerformanceMatrix';
import { Footer } from './components/Footer';

function initApp() {
  const root = document.getElementById('app');
  if (!root) return;

  // Determine initial color scheme
  const meta = document.querySelector('meta[name="color-scheme"]');
  const urlParams = new URLSearchParams(window.location.search);
  const urlTheme = urlParams.get('theme') as 'dark' | 'light' | null;
  const storedTheme = (localStorage.getItem('color-scheme') as 'dark' | 'light' | null);
  const resolvedTheme: 'dark' | 'light' = urlTheme || storedTheme || (meta?.getAttribute('content') === 'light' ? 'light' : 'dark');

  if (urlTheme && meta) {
    meta.setAttribute('content', urlTheme);
  }
  document.documentElement.style.colorScheme = resolvedTheme;
  document.documentElement.setAttribute('data-theme', resolvedTheme);

  const initialState: NavState = {
    lang: 'zh',
    theme: resolvedTheme,
    isAudioMuted: audioHaptics.getMuted()
  };

  // 1. Create Core Component Instances
  const hero = new Hero(initialState.lang);
  const sandbox = new InteractiveSandbox(initialState.lang);
  const scrollytelling = new Scrollytelling(initialState.lang);
  const performanceMatrix = new PerformanceMatrix(initialState.lang);
  const footer = new Footer(initialState.lang);

  let quantumMesh: QuantumMesh | null = null;
  let currentLang = initialState.lang;
  let currentTheme = initialState.theme;

  // 2. Create Navbar with State Change Handler
  const navbar = new Navbar(initialState, (newState) => {
    // 1. Theme toggle
    if (newState.theme !== currentTheme) {
      currentTheme = newState.theme;
      if (quantumMesh) {
        quantumMesh.setTheme(currentTheme === 'dark');
      }
    }

    // 2. Language toggle (only re-render components if language actually changed)
    if (newState.lang !== currentLang) {
      currentLang = newState.lang;
      hero.setLang(currentLang);
      sandbox.setLang(currentLang);
      scrollytelling.setLang(currentLang);
      performanceMatrix.setLang(currentLang);
      footer.setLang(currentLang);

      // Update document title and lang
      document.documentElement.lang = currentLang;
      document.title = currentLang === 'zh'
        ? '悟空面板 (Wukong Panel) - 官方主页 · 万里云霄舰队归一'
        : 'Wukong Panel - Official Sovereign VPS Mesh & Fleet Console';
    }
  });

  // 3. Assemble DOM Hierarchy
  const siteWrapper = document.createElement('div');
  siteWrapper.className = 'site-wrapper';

  const onlySection = new URLSearchParams(window.location.search).get('only');

  siteWrapper.appendChild(navbar.getElement());
  if (!onlySection || onlySection === 'hero') siteWrapper.appendChild(hero.getElement());
  if (!onlySection || onlySection === 'sandbox') siteWrapper.appendChild(sandbox.getElement());
  if (!onlySection || onlySection === 'stories') siteWrapper.appendChild(scrollytelling.getElement());
  if (!onlySection || onlySection === 'performance') siteWrapper.appendChild(performanceMatrix.getElement());
  siteWrapper.appendChild(footer.getElement());

  root.appendChild(siteWrapper);

  // 4. Initialize Hero Quantum Mesh Canvas
  const canvasContainer = document.getElementById('hero-canvas-box');
  if (canvasContainer) {
    try {
      quantumMesh = new QuantumMesh(canvasContainer);
      quantumMesh.setTheme(initialState.theme === 'dark');
    } catch (err) {
      console.warn('Canvas QuantumMesh initialization fallback:', err);
    }
  }

  // 5. Initialize Magnetic Cursor & Spotlight on desktop
  new MagneticCursor();

  // 6. Modern Web Guidance Fallback: Scroll Progress Bar for browsers without CSS scroll-timeline
  if (!window.CSS?.supports?.('animation-timeline', 'scroll()')) {
    const progressBar = document.querySelector('#scroll-progress') as HTMLElement;
    if (progressBar) {
      window.addEventListener('scroll', () => {
        const scrollable = document.documentElement.scrollHeight - window.innerHeight;
        const scrolled = window.scrollY;
        const ratio = scrollable > 0 ? Math.min(Math.max(scrolled / scrollable, 0), 1) : 0;
        progressBar.style.transform = `scaleX(${ratio})`;
      }, { passive: true });
    }
  }

  // Sync with audio haptic engine state change
  audioHaptics.onStateChange((muted) => {
    navbar.updateState({ isAudioMuted: muted });
  });

  // Handle deep-link anchor hash or target query param on initial load
  const targetId = urlParams.get('target') || (window.location.hash ? window.location.hash.slice(1) : '');
  if (targetId) {
    const target = document.getElementById(targetId);
    if (target) {
      window.scrollTo(0, target.offsetTop);
    }
  } else if (urlParams.get('scrollY')) {
    window.scrollTo(0, parseInt(urlParams.get('scrollY')!, 10));
  }
}

// Bootstrap on DOMContentLoaded or immediately if ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initApp);
} else {
  initApp();
}
