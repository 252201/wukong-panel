import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseSemver,
  isNewerVersion,
  getProbeUpdateCommand,
  getPanelUpdateCommand,
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

  assert.match(probeCmd, /probe-install\.sh/);
  assert.match(probeCmd, /--update/);
  assert.match(panelCmd, /install\.sh/);
  assert.match(panelCmd, /--update/);
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

  const mockFetch = async (url) => {
    if (url.includes('/api/v1/system/latest-release')) {
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
