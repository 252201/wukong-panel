import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const websiteDir = path.resolve(__dirname, '..');

test('Website HTML Structure and Accessibility Metadata', () => {
  const htmlPath = path.join(websiteDir, 'index.html');
  assert.ok(fs.existsSync(htmlPath), 'index.html must exist');

  const html = fs.readFileSync(htmlPath, 'utf8');

  // Modern Web Guidance: color-scheme & FOUC prevention
  assert.match(html, /<meta\s+name=["']color-scheme["']\s+content=["']light dark["']\s*\/?>/, 'Must declare meta color-scheme light dark');
  assert.match(html, /localStorage\.getItem\(["']color-scheme["']\)/, 'Must have inline FOUC prevention script');

  // Accessibility: decorative elements must have aria-hidden="true"
  assert.match(html, /<div\s+id=["']scroll-progress["']\s+aria-hidden=["']true["']>/, 'Scroll progress bar must have aria-hidden="true"');
  assert.match(html, /<div\s+class=["']ambient-spotlight["']\s+aria-hidden=["']true["']>/, 'Spotlight must have aria-hidden="true"');

  // SEO & Social Tags
  assert.match(html, /<title>.*悟空面板.*<\/title>/, 'Must include descriptive title');
  assert.match(html, /<meta\s+name=["']description["']/, 'Must include meta description');
  assert.match(html, /<meta\s+property=["']og:title["']/, 'Must include OpenGraph title');
  assert.match(html, /application\/ld\+json/, 'Must include JSON-LD structured data');
});

test('Modern Web Guidance: CSS Tokens and light-dark() compliance', () => {
  const tokensPath = path.join(websiteDir, 'src/styles/tokens.css');
  assert.ok(fs.existsSync(tokensPath), 'tokens.css must exist');

  const tokens = fs.readFileSync(tokensPath, 'utf8');

  assert.match(tokens, /color-scheme:\s*light dark/, 'tokens.css must declare color-scheme: light dark');
  assert.match(tokens, /light-dark\(/, 'tokens.css must use modern light-dark() CSS function');
  assert.match(tokens, /:root:has\(>\s*head\s*>\s*meta\[name="color-scheme"\]\[content="dark"\]\)/, 'Must map dark override from meta tag to CSS');
  assert.match(tokens, /:root:has\(>\s*head\s*>\s*meta\[name="color-scheme"\]\[content="light"\]\)/, 'Must map light override from meta tag to CSS');
});

test('Modern Web Guidance: Native Scroll-Driven Animations and Fallbacks', () => {
  const scrollyCssPath = path.join(websiteDir, 'src/styles/scrollytelling.css');
  assert.ok(fs.existsSync(scrollyCssPath), 'scrollytelling.css must exist');

  const scrollyCss = fs.readFileSync(scrollyCssPath, 'utf8');

  // Must include animation-range check in @supports to filter partial implementations
  assert.match(scrollyCss, /@supports\s*\(\(animation-timeline:\s*scroll\(\)\)\s*and\s*\(animation-range:\s*0%\s*100%\)\)/, 'Must include strict @supports scroll() and range check');
  assert.match(scrollyCss, /@supports\s*\(\(animation-timeline:\s*view\(\)\)\s*and\s*\(animation-range:\s*0%\s*100%\)\)/, 'Must include strict @supports view() and range check');

  // Must respect prefers-reduced-motion
  assert.match(scrollyCss, /@media\s*\(prefers-reduced-motion:\s*reduce\)/, 'Must support prefers-reduced-motion: reduce');

  // Scroll progress bar transform
  assert.match(scrollyCss, /transform-origin:\s*0\s*50%/, 'Scroll progress transform-origin must be 0 50%');
  assert.match(scrollyCss, /transform:\s*scaleX\(0\)/, 'Scroll progress must initialize with scaleX(0)');
});

test('Interactive Sandbox Protocols Matrix Completeness', async () => {
  const sandboxPath = path.join(websiteDir, 'src/components/InteractiveSandbox.ts');
  assert.ok(fs.existsSync(sandboxPath), 'InteractiveSandbox.ts must exist');

  const content = fs.readFileSync(sandboxPath, 'utf8');

  const requiredProtocols = [
    'Hysteria 2',
    'VLESS + REALITY',
    'CF Tunnel (Argo)',
    'TUIC v5',
    'Shadowsocks 2022',
    'Trojan TLS',
    'AnyTLS'
  ];

  for (const proto of requiredProtocols) {
    assert.ok(content.includes(proto), `Must define protocol "${proto}"`);
  }

  // Must have QR code rendering logic and probe simulation
  assert.match(content, /QRCode\.toCanvas/, 'Must use QRCode.toCanvas');
  assert.match(content, /runSimulatedProbe/, 'Must implement simulated probe execution');
});

test('Web Audio API Haptics Engine Definition', () => {
  const audioPath = path.join(websiteDir, 'src/components/AudioHaptics.ts');
  assert.ok(fs.existsSync(audioPath), 'AudioHaptics.ts must exist');

  const content = fs.readFileSync(audioPath, 'utf8');

  assert.match(content, /class AudioHapticsEngine/, 'AudioHapticsEngine must be defined');
  assert.match(content, /playClick/, 'Must implement playClick');
  assert.match(content, /playSuccess/, 'Must implement playSuccess');
  assert.match(content, /playSwitch/, 'Must implement playSwitch');
  assert.match(content, /playProbePing/, 'Must implement playProbePing');
  assert.match(content, /toggleMute/, 'Must implement toggleMute');
});

test('Five Epic Scrollytelling Chapters Structure', () => {
  const scrollyPath = path.join(websiteDir, 'src/components/Scrollytelling.ts');
  assert.ok(fs.existsSync(scrollyPath), 'Scrollytelling.ts must exist');

  const content = fs.readFileSync(scrollyPath, 'utf8');

  assert.match(content, /卷一 · 混沌归一/, 'Must include Chapter 1 混沌归一');
  assert.match(content, /卷二 · 七十二变/, 'Must include Chapter 2 七十二变');
  assert.match(content, /卷三 · 筋斗云径/, 'Must include Chapter 3 筋斗云径');
  assert.match(content, /卷四 · 金刚不坏/, 'Must include Chapter 4 金刚不坏');
  assert.match(content, /卷五 · 毫毛分身/, 'Must include Chapter 5 毫毛分身');
});

test('Performance Matrix Technical Comparison', () => {
  const perfPath = path.join(websiteDir, 'src/components/PerformanceMatrix.ts');
  assert.ok(fs.existsSync(perfPath), 'PerformanceMatrix.ts must exist');

  const content = fs.readFileSync(perfPath, 'utf8');

  assert.match(content, /(&lt;|<)\s*25\s*MB/, 'Must highlight <25MB RAM footprint');
  assert.match(content, /SQLite 3 WAL/, 'Must highlight SQLite WAL');
  assert.match(content, /350 MB – 800 MB\+/, 'Must compare against Python/Docker stacks');
});

test('Modern Web Guidance: Typography Layout & Legibility (text-wrap balance/pretty)', () => {
  const typoPath = path.join(websiteDir, 'src/styles/typography.css');
  assert.ok(fs.existsSync(typoPath), 'typography.css must exist');

  const content = fs.readFileSync(typoPath, 'utf8');

  // Must apply text-wrap: balance to headings
  assert.match(content, /text-wrap:\s*balance/, 'Headings must use text-wrap: balance');
  // Must apply text-wrap: pretty to paragraphs
  assert.match(content, /text-wrap:\s*pretty/, 'Body text must use text-wrap: pretty');
  // Gold gradient text must prevent single glyph orphans
  assert.match(content, /\.gold-gradient-text\s*\{[^}]*white-space:\s*nowrap/, 'Gold brand gradient text must not wrap orphans');
});

test('Navigation Anchors & Smooth Scroll Offset', () => {
  const mainCssPath = path.join(websiteDir, 'src/styles/main.css');
  assert.ok(fs.existsSync(mainCssPath), 'main.css must exist');

  const content = fs.readFileSync(mainCssPath, 'utf8');

  assert.match(content, /scroll-behavior:\s*smooth/, 'Must define html smooth scrolling');
  assert.match(content, /scroll-margin-top:\s*5rem/, 'Must declare section/article scroll-margin-top for navbar offset');
});

test('Custom Scrollbars and Mobile Responsive Resilience', () => {
  const mainCssPath = path.join(websiteDir, 'src/styles/main.css');
  const content = fs.readFileSync(mainCssPath, 'utf8');

  // Protocol tab scrollbar-width: none & webkit fallback
  assert.match(content, /scrollbar-width:\s*none/, 'Protocol chips bar must hide scrollbar via scrollbar-width: none');
  assert.match(content, /@supports\s+not\s+\(scrollbar-width:\s*none\)/, 'Must provide webkit-scrollbar fallback');

  // Mobile 640px queries for navbar compact action icons
  assert.match(content, /@media\s*\(max-width:\s*640px\)/, 'Must declare max-width: 640px mobile responsive rules');
  assert.match(content, /\.btn-icon-control\s*\{[^}]*width:\s*34px/, 'Action buttons must become compact 34px circles on mobile');
  assert.match(content, /\.perf-table\s*\{[^}]*min-width:\s*680px/, 'Performance matrix table must define min-width for mobile readability');
});

test('Magnetic Cursor 120fps LERP & Viewport Lifecycle', () => {
  const cursorCssPath = path.join(websiteDir, 'src/styles/main.css');
  const cursorCss = fs.readFileSync(cursorCssPath, 'utf8');

  // Must NOT include transform in transition to prevent fighting with rAF LERP
  assert.doesNotMatch(cursorCss, /\.custom-cursor\s*\{[^}]*transition:[^;]*transform/s, 'Custom cursor must not transition transform (fights with rAF LERP)');
  assert.match(cursorCss, /\.custom-cursor\.visible/, 'Must define .visible state for clean opacity fade-in');

  const cursorTsPath = path.join(websiteDir, 'src/components/MagneticCursor.ts');
  const cursorTs = fs.readFileSync(cursorTsPath, 'utf8');
  assert.match(cursorTs, /mouseleave/, 'Must handle mouseleave to hide cursor when pointer exits window');
  assert.match(cursorTs, /mouseenter/, 'Must handle mouseenter to restore cursor');
});

test('Hero Canvas Persistence and Navbar State Decoupling', () => {
  const heroTsPath = path.join(websiteDir, 'src/components/Hero.ts');
  const heroTs = fs.readFileSync(heroTsPath, 'utf8');
  assert.match(heroTs, /canvasBox/, 'Hero must manage a dedicated canvasBox instance variable');
  assert.match(heroTs, /contentBox/, 'Hero must manage a dedicated contentBox for dynamic content');
  assert.doesNotMatch(heroTs, /this\.element\.innerHTML\s*=/, 'Hero render must not overwrite this.element.innerHTML to preserve canvas');

  const mainTsPath = path.join(websiteDir, 'src/main.ts');
  const mainTs = fs.readFileSync(mainTsPath, 'utf8');
  assert.match(mainTs, /newState\.lang\s*!==\s*currentLang/, 'main.ts must guard language change before re-rendering components');
  assert.match(mainTs, /newState\.theme\s*!==\s*currentTheme/, 'main.ts must guard theme change before re-theming mesh');
});

test('Vite Production Build Artifacts Integrity', () => {
  const distDir = path.join(websiteDir, 'dist');
  if (!fs.existsSync(distDir)) {
    execSync('npm run build', { cwd: websiteDir, stdio: 'pipe' });
  }
  assert.ok(fs.existsSync(distDir), 'dist/ directory must exist after build');

  const htmlPath = path.join(distDir, 'index.html');
  assert.ok(fs.existsSync(htmlPath), 'dist/index.html must exist');

  const assetsDir = path.join(distDir, 'assets');
  assert.ok(fs.existsSync(assetsDir), 'dist/assets directory must exist');

  const assetFiles = fs.readdirSync(assetsDir);
  const jsFiles = assetFiles.filter((f) => f.endsWith('.js'));
  const cssFiles = assetFiles.filter((f) => f.endsWith('.css'));

  assert.ok(jsFiles.length >= 1, 'Must produce bundled JS');
  assert.ok(cssFiles.length >= 1, 'Must produce bundled CSS');

  // Verify bundle sizes within strict performance budgets
  for (const js of jsFiles) {
    const stat = fs.statSync(path.join(assetsDir, js));
    assert.ok(stat.size < 200 * 1024, `JS bundle (${stat.size} bytes) should be < 200KB`);
  }

  for (const css of cssFiles) {
    const stat = fs.statSync(path.join(assetsDir, css));
    assert.ok(stat.size < 50 * 1024, `CSS bundle (${stat.size} bytes) should be < 50KB`);
  }
});
