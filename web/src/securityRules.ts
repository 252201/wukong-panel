export function parseSecurityPorts(value: string): number[] {
 if (!value.trim()) return []
 const ports = value.split(/[ ,]+/).map(part => Number(part))
 if (ports.some(port => !Number.isInteger(port) || port < 1 || port > 65535)) throw new Error('端口需为 1–65535')
 return [...new Set(ports)].sort((a, b) => a - b)
}
export function securityStateFresh(checkedAt: string, now = Date.now()): boolean {
 const checked = Date.parse(checkedAt)
 return Number.isFinite(checked) && now >= checked - 5000 && now - checked < 90_000
}
