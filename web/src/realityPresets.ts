export interface RealityPresetItem {
  domain: string
  title: string
  desc: string
}

export interface RealityPresetCategory {
  category: string
  items: RealityPresetItem[]
}

export const realityPresets: RealityPresetCategory[] = [
  {
    category: 'Apple 系',
    items: [
      { domain: 'swdist.apple.com', title: '苹果软件分发', desc: '苹果软件分发与测速节点，客户端日常后台请求极多，流量特征自然，全球路由极佳。' },
      { domain: 'itunes.apple.com', title: 'iTunes 资源', desc: '苹果媒体与应用资源节点，日常请求高频自然，全球 CDN 覆盖完善。' },
      { domain: 'mensura.cdn-apple.com', title: '测速与分发节点', desc: '苹果网络质量探测与测速分发，全球路由极佳，特征隐蔽。' },
    ],
  },
  {
    category: 'Microsoft 系',
    items: [
      { domain: 'learn.microsoft.com', title: '微软技术文档', desc: '微软官方技术文档站点，大流量访问自然，适合长期稳定连接。' },
    ],
  },
  {
    category: 'AWS / 亚马逊',
    items: [
      { domain: 's0.awsstatic.com', title: 'AWS 静态资源 0', desc: 'AWS 静态资源节点，若 VPS 在 AWS/Lightsail 或美亚机房，延迟极低。' },
      { domain: 'd1.awsstatic.com', title: 'AWS 静态资源 1', desc: 'CloudFront 边缘分发节点，适合近邻 AWS/美亚大型机房，延迟极低。' },
      { domain: 'aws.amazon.com', title: 'AWS 官网控制台', desc: '亚马逊云官网主控台，全球访问极其频繁，具备极高信誉与稳定性。' },
    ],
  },
  {
    category: 'Cloudflare',
    items: [
      { domain: 'www.cloudflare.com', title: 'Cloudflare 官网', desc: '默认使用已验证的 Cloudflare TLS 站点，全球 Anycast CDN 节点覆盖广泛。' },
    ],
  },
]

export interface FlattenedRealityPreset extends RealityPresetItem {
  category: string
}

export function flattenRealityPresets(presets: RealityPresetCategory[] = realityPresets): FlattenedRealityPreset[] {
  return presets.flatMap(cat => cat.items.map(item => ({ ...item, category: cat.category })))
}

export function findRealityPreset(domain: string, presets: RealityPresetCategory[] = realityPresets): FlattenedRealityPreset | undefined {
  const normalized = (domain || '').trim().toLowerCase()
  if (!normalized) return undefined
  return flattenRealityPresets(presets).find(p => p.domain.toLowerCase() === normalized)
}
