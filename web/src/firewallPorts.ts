import type { NodeItem } from './api'

// Tunnel origins stay on loopback. QUIC nodes only expose UDP on their listener;
// UDP relay in Trojan/AnyTLS runs inside their TCP connection.
export function nodeFirewallPorts(node: Pick<NodeItem, 'protocol' | 'listenPort'>): Array<{ port: number; protocol: 'tcp' | 'udp' }> {
  if (!Number.isInteger(node.listenPort) || node.listenPort < 1 || node.listenPort > 65535) return []
  switch (node.protocol) {
    case 'hysteria2': case 'tuic': return [{ port: node.listenPort, protocol: 'udp' }]
    case 'shadowsocks': return [{ port: node.listenPort, protocol: 'tcp' }, { port: node.listenPort, protocol: 'udp' }]
    case 'vless': case 'trojan': case 'anytls': return [{ port: node.listenPort, protocol: 'tcp' }]
    default: return []
  }
}
