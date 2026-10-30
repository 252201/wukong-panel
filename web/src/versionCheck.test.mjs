import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  parseSemver,
  isNewerVersion,
  isAtLeastVersion,
  hostUpdateOnlineSupported,
  getProbeUpdateCommand,
  getPanelUpdateCommand,
  getSingBoxUpdateCommand,
  fetchLatestRelease
} from './versionCheck.ts';

test('parseSemver parses standard, prefixed, and prerelease versions', () => {
  assert.deepEqual(parseSemver('1.7.26'), { major: 1, minor: 7, patch: 26, prerelease: '' });
  assert.deepEqual(parseSemver('v1.7.26'), { major: 1, minor: 7, patch: 26, prerelease: '' });
  assert.deepEqual(parseSemver('V1.7.22'), { major: 1, minor: 7, patch: 22, prerelease: '' });
  assert.deepEqual(parseSemver('1.7.26-monitor.1'), { major: 1, minor: 7, patch: 26, prerelease: 'monitor.1' });
  assert.deepEqual(parseSemver('1.7.11-beta.2'), { major: 1, minor: 7, patch: 11, prerelease: 'beta.2' });
  assert.equal(parseSemver(''), null);
  assert.equal(parseSemver(null), null);
  assert.equal(parseSemver(undefined), null);
  assert.equal(parseSemver('invalid-version'), null);
  assert.equal(parseSemver('dev'), null);
});

test('isNewerVersion accurately determines if update is available', () => {
  // Probes with older versions should show update available
  assert.equal(isNewerVersion('1.7.22', '1.7.26'), true);
  assert.equal(isNewerVersion('1.7.11', '1.7.26'), true);
  assert.equal(isNewerVersion('v1.7.22', 'v1.7.26'), true);
  assert.equal(isNewerVersion('1.6.99', '1.7.26'), true);
  assert.equal(isNewerVersion('0.9.5', '1.7.26'), true);

  // Panel with pre-release/monitor build compared against official release
  assert.equal(isNewerVersion('1.7.26-monitor.1', '1.7.26'), true);
  assert.equal(isNewerVersion('1.7.26-rc.1', '1.7.26'), true);

  // When host is already on latest or newer
  assert.equal(isNewerVersion('1.7.26', '1.7.26'), false);
  assert.equal(isNewerVersion('v1.7.26', '1.7.26'), false);
  assert.equal(isNewerVersion('1.7.27', '1.7.26'), false);
  assert.equal(isNewerVersion('1.8.0', '1.7.26'), false);
  assert.equal(isNewerVersion('2.0.0', '1.7.26'), false);

  // Future release scenarios
  assert.equal(isNewerVersion('1.7.26', '1.7.27'), true);
  assert.equal(isNewerVersion('1.7.26', '1.8.0'), true);
  assert.equal(isNewerVersion('1.7.26', '2.0.0'), true);

  // Invalid inputs safely return false
  assert.equal(isNewerVersion(null, '1.7.26'), false);
  assert.equal(isNewerVersion('1.7.22', null), false);
  assert.equal(isNewerVersion('dev', '1.7.26'), false);
  assert.equal(isNewerVersion('', ''), false);
});

test('host fleet update detection matches actual probe and panel scenarios', () => {
  const isProbeHost = (host) => (host.capabilities || []).includes('probe');
  const hostVersion = (host) => isProbeHost(host) ? host.panelVersion : (host.panelVersion || host.snapshot?.overview?.panelVersion || '');
  const hasUpdate = (host, latest) => isNewerVersion(hostVersion(host), latest);

  const probeHK = { id: 'probe-hk', name: 'IPv4-HK', panelVersion: '1.7.11', capabilities: ['probe'] };
  const probeJP = { id: 'probe-jp', name: 'JP-三网直连', panelVersion: '1.7.22', capabilities: ['probe'] };
  const probeTW = { id: 'probe-tw', name: 'TW-HiNet-原生', panelVersion: '1.7.22', capabilities: ['probe'] };
  const panelLocal = { id: 'local', name: '本机', panelVersion: '1.7.26-monitor.1', singBoxVersion: '1.14.3', capabilities: ['overview'] };

  // When latest release is 1.7.26
  const latest26 = '1.7.26';
  assert.equal(hasUpdate(probeHK, latest26), true, 'Probe 1.7.11 should show update to 1.7.26');
  assert.equal(hasUpdate(probeJP, latest26), true, 'Probe 1.7.22 should show update to 1.7.26');
  assert.equal(hasUpdate(probeTW, latest26), true, 'Probe 1.7.22 should show update to 1.7.26');
  assert.equal(hasUpdate(panelLocal, latest26), true, 'Panel 1.7.26-monitor.1 should show update to stable 1.7.26');

  // When panel is running clean release 1.7.26
  const panelClean = { id: 'local', name: '本机', panelVersion: '1.7.26', singBoxVersion: '1.14.3' };
  assert.equal(hasUpdate(panelClean, latest26), false, 'Panel 1.7.26 has no update when latest is 1.7.26');

  // When next version 1.7.27 is released
  const latest27 = '1.7.27';
  assert.equal(hasUpdate(probeHK, latest27), true);
  assert.equal(hasUpdate(probeJP, latest27), true);
  assert.equal(hasUpdate(panelClean, latest27), true, 'Panel 1.7.26 should show update to 1.7.27');
});

test('official update commands return correct curl scripts', () => {
  const probeCmd = getProbeUpdateCommand();
  const panelCmd = getPanelUpdateCommand();
  const singBoxCmd = getSingBoxUpdateCommand();

  assert.match(probeCmd, /probe-install\.sh/);
  assert.match(probeCmd, /--update/);
  assert.match(panelCmd, /install\.sh/);
  assert.match(panelCmd, /--update/);
  assert.match(singBoxCmd, /install\.sh/);
  assert.match(singBoxCmd, /--update-sing-box/);
});

test('sing-box version comparison detects new sing-box releases', () => {
  // Current host runs 1.14.3, latest is 1.14.4
  assert.equal(isNewerVersion('1.14.3', '1.14.4'), true);
  assert.equal(isNewerVersion('v1.14.3', 'v1.14.4'), true);
  assert.equal(isNewerVersion('1.14.4', '1.14.4'), false);
  assert.equal(isNewerVersion('1.14.5', '1.14.4'), false);
});

test('fetchLatestRelease fetches and parses release response', async () => {
  const mockRelease = {
    ok: true,
    version: '1.7.26',
    tag: 'v1.7.26',
    name: 'v1.7.26',
    htmlUrl: 'https://github.com/252201/wukong-panel/releases/tag/v1.7.26',
    body: 'Release notes for 1.7.26'
  };

  const mockFetch = async (url, options) => {
    if (url.includes('api/v1/system/latest-release')) {
      assert.equal(options?.credentials, 'same-origin');
      return {
        ok: true,
        json: async () => mockRelease
      };
    }
    return { ok: false };
  };

  const release = await fetchLatestRelease(mockFetch);
  assert.ok(release);
  assert.equal(release.version, '1.7.26');
  assert.equal(release.tag, 'v1.7.26');
});

test('isAtLeastVersion compares versions correctly', () => {
  assert.equal(isAtLeastVersion('1.7.30', '1.7.30'), true);
  assert.equal(isAtLeastVersion('v1.7.30', '1.7.30'), true);
  assert.equal(isAtLeastVersion('V1.7.30', '1.7.30'), true);
  assert.equal(isAtLeastVersion('1.7.31', '1.7.30'), true);
  assert.equal(isAtLeastVersion('1.8.0', '1.7.30'), true);
  assert.equal(isAtLeastVersion('2.0.0', '1.7.30'), true);
  assert.equal(isAtLeastVersion('1.7.29', '1.7.30'), false);
  assert.equal(isAtLeastVersion('1.7.11', '1.7.30'), false);
  assert.equal(isAtLeastVersion('1.6.99', '1.7.30'), false);
  assert.equal(isAtLeastVersion('', '1.7.30'), false);
  assert.equal(isAtLeastVersion(null, '1.7.30'), false);
  assert.equal(isAtLeastVersion('invalid', '1.7.30'), false);
});

test('hostUpdateOnlineSupported accurately detects panel and probe online update support', () => {
  const localPanel = { id: 'local', name: '青蛙', capabilities: ['overview'] };
  const legacyProbe = { id: 'probe-1', name: 'JP-三网直连', panelVersion: '1.7.27', capabilities: ['overview', 'probe'] };
  const modernProbeExplicit = { id: 'probe-2', name: 'JP-三网直连-显式能力', capabilities: ['overview', 'probe', 'probe.update'] };
  const v30ProbeNoCap = { id: 'probe-3', name: 'JP-三网直连-v1.7.30', panelVersion: '1.7.30', capabilities: ['overview', 'probe'] };
  const v30ProbePrefix = { id: 'probe-4', name: 'JP-三网直连-v1.7.30带前缀', panelVersion: 'v1.7.30', capabilities: ['overview', 'probe'] };
  const v31ProbeSnapshot = {
    id: 'probe-5',
    name: 'JP-三网直连-快照版本',
    capabilities: ['overview', 'probe'],
    snapshot: { overview: { panelVersion: '1.7.31' } },
  };
  const remoteServerNoProbe = { id: 'remote-1', name: '远端控制机', capabilities: ['overview', 'command'] };
  const remotePanelWithCap = { id: 'remote-frog', name: '青蛙', capabilities: ['overview', 'nodes.write', 'panel.update'] };
  const remotePanelWithoutCap = { id: 'remote-legacy', name: '老面板', capabilities: ['overview', 'nodes.write'] };

  assert.equal(hostUpdateOnlineSupported(localPanel), true, 'Local panel always supports online update');
  assert.equal(hostUpdateOnlineSupported(legacyProbe), false, 'Legacy probe < 1.7.30 without probe.update requires terminal command');
  assert.equal(hostUpdateOnlineSupported(modernProbeExplicit), true, 'Probe with probe.update supports online update');
  assert.equal(hostUpdateOnlineSupported(v30ProbeNoCap), true, 'Probe running 1.7.30 supports online update even if capability was omitted');
  assert.equal(hostUpdateOnlineSupported(v30ProbePrefix), true, 'Probe running v1.7.30 supports online update with prefix');
  assert.equal(hostUpdateOnlineSupported(v31ProbeSnapshot), true, 'Probe running 1.7.31 in snapshot supports online update');
  assert.equal(hostUpdateOnlineSupported(remoteServerNoProbe), false, 'Non-probe remote host does not support probe update');
  assert.equal(hostUpdateOnlineSupported(remotePanelWithCap), true, 'Remote panel with panel.update supports online update');
  assert.equal(hostUpdateOnlineSupported(remotePanelWithoutCap), false, 'Remote panel without panel.update requires terminal command or local update');
});

test('mobile view removes the "可" character from update pill via responsive CSS', () => {
  const appVue = readFileSync(new URL('./App.vue', import.meta.url), 'utf-8');
  const stylesCss = readFileSync(new URL('./styles.css', import.meta.url), 'utf-8');

  // Verify App.vue encapsulates the "可" character in .fleet-update-lead
  assert.ok(
    appVue.includes('<span class="fleet-update-lead">可</span>更新 v{{ latestReleaseVersion }}'),
    'App.vue must wrap "可" in .fleet-update-lead for panel and probe updates'
  );
  assert.ok(
    appVue.includes('<span class="fleet-update-lead">可</span>更新 {{ latestSingBoxVersion }}'),
    'App.vue must wrap "可" in .fleet-update-lead for sing-box updates'
  );

  // Verify styles.css defines default inline display and hides on mobile (max-width: 700px)
  assert.match(
    stylesCss,
    /\.fleet-update-pill\s+\.fleet-update-lead\s*\{\s*display:\s*inline;\s*\}/,
    'styles.css must define default inline display for .fleet-update-lead'
  );
  assert.match(
    stylesCss,
    /@media\s*\(max-width:\s*700px\)[^{]*\{[\s\S]*?\.fleet-update-pill\s+\.fleet-update-lead\s*\{\s*display:\s*none;\s*\}/,
    'styles.css must hide .fleet-update-lead at <= 700px mobile breakpoint'
  );

  const inlineIdx = stylesCss.search(/\.fleet-update-pill\s+\.fleet-update-lead\s*\{\s*display:\s*inline;\s*\}/);
  const noneIdx = stylesCss.indexOf('.fleet-update-pill .fleet-update-lead { display: none; }');
  assert.ok(
    inlineIdx !== -1 && noneIdx !== -1 && inlineIdx < noneIdx,
    'Default display: inline must precede media query display: none in styles.css to ensure mobile override wins'
  );
});

test('system-glance (主机气脉) card version meta layout matches central fleet host card', () => {
  const appVue = readFileSync(new URL('./App.vue', import.meta.url), 'utf-8');
  const stylesCss = readFileSync(new URL('./styles.css', import.meta.url), 'utf-8');

  // Verify system-glance includes .fleet-host-version-meta with dot separator
  assert.ok(
    appVue.includes('<div class="version-strip"><div class="fleet-host-version-meta"><span class="fleet-host-version-text">Panel {{ overview?.panelVersion || \'—\' }}</span>'),
    'App.vue system-glance card must structure version meta with .fleet-host-version-meta and .fleet-host-version-text'
  );
  assert.ok(
    appVue.includes('<span class="fleet-version-dot">·</span><span class="fleet-host-version-text">sing-box {{ overview?.singBoxVersion || \'—\' }}</span>'),
    'App.vue system-glance card must include .fleet-version-dot separator between Panel and sing-box'
  );

  // Verify styles.css version-strip does not use justify-content: space-between
  assert.doesNotMatch(
    stylesCss,
    /\.version-strip\s*\{[^}]*justify-content:\s*space-between/,
    'styles.css .version-strip must not use space-between so versions remain together on the left'
  );

  // Verify styles.css .fleet-update-pill uses unified gold border and transparent background
  assert.match(
    stylesCss,
    /\.fleet-update-pill\s*\{[\s\S]*?border:\s*1px solid rgba\(211,\s*169,\s*77,\s*0\.22\);/,
    'styles.css .fleet-update-pill must use unified gold border rgba(211, 169, 77, 0.22)'
  );
});

test('light mode restores emerald green for panel/probe and indigo blue-purple for sing-box update pills', () => {
  const stylesCss = readFileSync(new URL('./styles.css', import.meta.url), 'utf-8');

  // Verify light mode .fleet-update-pill emerald green styles
  assert.match(
    stylesCss,
    /:root\[data-effective-theme="light"\]\s+\.fleet-update-pill\s*\{[\s\S]*?border-color:\s*rgba\(16,\s*185,\s*129,\s*0\.4\);[\s\S]*?color:\s*#047857;/,
    'styles.css must restore emerald green border and text for .fleet-update-pill in light mode'
  );

  // Verify light mode .singbox-update-pill indigo/blue-purple styles
  assert.match(
    stylesCss,
    /:root\[data-effective-theme="light"\]\s+\.singbox-update-pill\s*\{[\s\S]*?border-color:\s*rgba\(99,\s*102,\s*241,\s*0\.4\);[\s\S]*?color:\s*#4f46e5;/,
    'styles.css must restore indigo/blue-purple border and text for .singbox-update-pill in light mode'
  );
});

test('host update and sing-box update modals display success banner and completion actions', () => {
  const appVue = readFileSync(new URL('./App.vue', import.meta.url), 'utf-8');
  const stylesCss = readFileSync(new URL('./styles.css', import.meta.url), 'utf-8');

  // Verify host update modal has version-diff-card-success banner
  assert.ok(
    appVue.includes("hostUpdateJob?.status === 'success' && !hostReconnecting"),
    'App.vue host-update modal must check success state for completion banner'
  );
  assert.ok(
    appVue.includes("✓ 升级完成（关闭）"),
    'App.vue host-update modal must offer explicit completion button on success'
  );
  assert.ok(
    appVue.includes("hostUpdateJob?.status !== 'success' || hostReconnecting"),
    'App.vue must hide fallback terminal command section when host update succeeds'
  );

  // Verify sing-box update modal has success banner and completion button
  assert.ok(
    appVue.includes("singBoxUpdateJob?.status === 'success'"),
    'App.vue singbox-update modal must check success state'
  );

  // Verify styles.css contains .version-diff-card-success and .update-success-card
  assert.match(
    stylesCss,
    /\.version-diff-card-success\s*\{/,
    'styles.css must style .version-diff-card-success'
  );
  assert.match(
    stylesCss,
    /\.update-success-card\s*\{/,
    'styles.css must style .update-success-card'
  );
});

test('local panel update reconnect displays 2-second countdown prompt before automatic page reload', () => {
  const appVue = readFileSync(new URL('./App.vue', import.meta.url), 'utf-8');

  // Verify startPanelReconnect initializes countdown to 2 seconds and reloads
  assert.ok(
    appVue.includes('hostReloadCountdown'),
    'App.vue must track countdown for local panel reload'
  );
  assert.match(
    appVue,
    /hostReloadCountdown\.value\s*=\s*2/,
    'App.vue startPanelReconnect must initialize countdown to 2 seconds'
  );
  assert.match(
    appVue,
    /window\.location\.reload\(\)/,
    'App.vue must trigger window.location.reload() after countdown'
  );
});

test('sing-box migration preflight is embedded into singbox-update modal and removed from system page', () => {
  const appVue = readFileSync(new URL('./App.vue', import.meta.url), 'utf-8');
  const apiTs = readFileSync(new URL('./api.ts', import.meta.url), 'utf-8');
  const stylesCss = readFileSync(new URL('./styles.css', import.meta.url), 'utf-8');

  // Standalone card removed from system page
  assert.ok(
    !appVue.includes('class="panel-card migration-panel"'),
    'App.vue must remove standalone migration-panel from system page'
  );

  // Embedded into singbox-update modal
  assert.ok(
    appVue.includes('class="singbox-preflight-card"'),
    'App.vue must embed singbox-preflight-card inside singbox-update modal'
  );
  assert.ok(
    appVue.includes('loadSingBoxMigration'),
    'App.vue must trigger loadSingBoxMigration when opening sing-box update modal'
  );
  assert.ok(
    appVue.includes('singBoxMigrationPlan && !singBoxMigrationPlan.compatible'),
    'App.vue must check compatibility and guard upgrade when blocking issues exist'
  );

  // API supports hostId scoping
  assert.match(
    apiTs,
    /singBoxMigration:\s*async\s*\(target\s*=\s*latestSingBoxVersion,\s*hostId\?:?\s*string\)/,
    'api.ts singBoxMigration must accept optional hostId'
  );

  // Styles exist for preflight card and themes
  assert.match(
    stylesCss,
    /\.singbox-preflight-card\s*\{/,
    'styles.css must include .singbox-preflight-card'
  );
  assert.match(
    stylesCss,
    /:root\[data-effective-theme="light"\]\s+\.singbox-preflight-card\s*\{/,
    'styles.css must include light mode overrides for .singbox-preflight-card'
  );
});

test('host-update and singbox-update modals use wide layout with enhanced target host header', () => {
  const appVue = readFileSync(new URL('./App.vue', import.meta.url), 'utf-8');
  const stylesCss = readFileSync(new URL('./styles.css', import.meta.url), 'utf-8');

  // 1. Modals should not have compact class
  assert.match(appVue, /modal === 'host-update' && hostUpdateTarget" class="modal-card host-update-modal"/);
  assert.doesNotMatch(appVue, /modal === 'host-update' && hostUpdateTarget" class="modal-card compact host-update-modal"/);
  assert.match(appVue, /modal === 'singbox-update' && singBoxUpdateTarget" class="modal-card host-update-modal singbox-update-modal"/);
  assert.doesNotMatch(appVue, /modal === 'singbox-update' && singBoxUpdateTarget" class="modal-card compact host-update-modal/);

  // 2. Target host header has structured main and sub elements with flag support
  assert.ok(appVue.includes('<div class="target-host-main">'));
  assert.ok(appVue.includes('<div class="target-host-sub">'));

  // 3. styles.css sets wide dimensions for host-update-modal
  assert.match(stylesCss, /\.host-update-modal\s*\{[^}]*width:\s*min\(920px,\s*94vw\)/);
  assert.match(stylesCss, /\.host-update-modal\s*\{[^}]*max-width:\s*940px/);

  // 4. styles.css has flex alignment for target host banner
  assert.match(stylesCss, /\.host-update-modal \.fleet-host-action-target\s*\{[^}]*display:\s*flex/);
  assert.match(stylesCss, /\.host-update-modal \.target-host-main\s*\{[^}]*display:\s*flex/);

  // 5. Changelog notes body has increased comfortable max-height
  assert.match(stylesCss, /\.update-notes-body\s*\{[^}]*max-height:\s*220px/);

  // 6. Responsive styles for mobile
  assert.match(stylesCss, /\.host-update-modal\s*\{[^}]*width:\s*100%/);

  // 7. Merged version diff and online update card for single-row compact layout
  assert.match(appVue, /class="version-update-merged-card"/);
  assert.match(stylesCss, /\.version-update-merged-card\s*\{[^}]*display:\s*flex/);
  assert.match(stylesCss, /\.merged-diff-group\s*\{[^}]*display:\s*flex/);
  assert.match(stylesCss, /\.merged-action-group\s*\{[^}]*display:\s*flex/);
});




