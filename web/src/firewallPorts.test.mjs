import assert from 'node:assert/strict'
import test from 'node:test'
import { nodeFirewallPorts } from './firewallPorts.ts'

test('public firewall openings follow the actual node listener transport', () => {
  const ports = protocol => nodeFirewallPorts({ protocol, listenPort: 8443 })
  assert.deepEqual(ports('hysteria2'), [{ port: 8443, protocol: 'udp' }])
  assert.deepEqual(ports('tuic'), ports('hysteria2'))
  assert.deepEqual(ports('shadowsocks'), [{ port: 8443, protocol: 'tcp' }, { port: 8443, protocol: 'udp' }])
  for (const protocol of ['vless', 'trojan', 'anytls']) assert.deepEqual(ports(protocol), [{ port: 8443, protocol: 'tcp' }])
})
test('loopback tunnel origins and unknown protocols never suggest a public opening', () => {
  for (const protocol of ['vless-ws-tunnel', 'unknown']) assert.deepEqual(nodeFirewallPorts({ protocol, listenPort: 34509 }), [])
  for (const listenPort of [0, -1, 65536, 80.5, NaN]) assert.deepEqual(nodeFirewallPorts({ protocol: 'vless', listenPort }), [])
})
