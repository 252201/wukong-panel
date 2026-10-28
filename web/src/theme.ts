export type ThemePreference = 'dark' | 'light' | 'system'
export type EffectiveTheme = 'dark' | 'light'

export const THEME_STORAGE_KEY = 'wukong-panel.theme'
const systemThemeQuery = '(prefers-color-scheme: light)'

function isThemePreference(value: string | null): value is ThemePreference {
  return value === 'dark' || value === 'light' || value === 'system'
}

export function readThemePreference(): ThemePreference {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY)
    return isThemePreference(stored) ? stored : 'dark'
  } catch {
    return 'dark'
  }
}

export function effectiveTheme(preference: ThemePreference): EffectiveTheme {
  if (preference !== 'system') return preference
  return window.matchMedia(systemThemeQuery).matches ? 'light' : 'dark'
}

export function nextToggledThemePreference(preference: ThemePreference): ThemePreference {
  const currentEffective = effectiveTheme(preference)
  const targetEffective: EffectiveTheme = currentEffective === 'dark' ? 'light' : 'dark'
  const systemEffective: EffectiveTheme = window.matchMedia(systemThemeQuery).matches ? 'light' : 'dark'
  return targetEffective === systemEffective ? 'system' : targetEffective
}

function syncThemeChrome(preference: ThemePreference) {
  const effective = effectiveTheme(preference)
  document.documentElement.dataset.theme = preference
  document.documentElement.dataset.effectiveTheme = effective
  document.documentElement.style.colorScheme = effective
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', effective === 'light' ? '#f7f8f8' : '#0b0d0b')
}

export function applyThemePreference(preference: ThemePreference, persist = true) {
  syncThemeChrome(preference)
  if (!persist) return
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, preference)
  } catch {
    // The visual preference still applies for this page when storage is blocked.
  }
}

export function observeSystemTheme(
  getPreference: () => ThemePreference,
  onChange?: (effective: EffectiveTheme) => void,
): () => void {
  const query = window.matchMedia(systemThemeQuery)
  const handleChange = () => {
    const pref = getPreference()
    if (pref === 'system') syncThemeChrome('system')
    onChange?.(effectiveTheme(pref))
  }
  query.addEventListener('change', handleChange)
  return () => query.removeEventListener('change', handleChange)
}
