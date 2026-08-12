(function () {
  var storageKey = 'wukong-panel.theme'
  var languageKey = 'wukong-panel.language'
  var preference = 'dark'
  var language = 'zh-CN'
  try {
    var stored = window.localStorage.getItem(storageKey)
    if (stored === 'dark' || stored === 'light' || stored === 'system') preference = stored
    if (window.localStorage.getItem(languageKey) === 'en-US') language = 'en-US'
  } catch (_) {
    // Storage can be unavailable in hardened/private browser contexts.
  }
  var effective = preference === 'system'
    ? (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark')
    : preference
  document.documentElement.dataset.theme = preference
  document.documentElement.dataset.effectiveTheme = effective
  document.documentElement.lang = language
  document.documentElement.style.colorScheme = effective
  var themeColor = document.querySelector('meta[name="theme-color"]')
  if (themeColor) themeColor.setAttribute('content', effective === 'light' ? '#f7f8f8' : '#0b0d0b')
})()
