// Vite bundles these SVGs into the panel, so flags work without OS emoji fonts
// or a runtime connection to an image service.
const flagURLs = import.meta.glob('../node_modules/flag-icons/flags/4x3/[a-z][a-z].svg', {
  eager: true,
  query: '?url',
  import: 'default',
}) as Record<string, string>

const flagPath = (code: string) => `../node_modules/flag-icons/flags/4x3/${code}.svg`

export function countryFlagURL(code: string): string {
  const normalized = code.toLowerCase()
  const fallback = flagURLs[flagPath('xx')] || ''
  return /^[a-z]{2}$/.test(normalized) ? flagURLs[flagPath(normalized)] || fallback : fallback
}
