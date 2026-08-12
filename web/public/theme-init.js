(function () {
  var storageKey = 'wukong-panel.theme'
  var preference = 'dark'
  try {
    var stored = window.localStorage.getItem(storageKey)
    if (stored === 'dark' || stored === 'light' || stored === 'system') preference = stored
  } catch (_) {
    // Storage can be unavailable in hardened/private browser contexts.
  }
  var effective = preference === 'system'
    ? (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark')
    : preference
  document.documentElement.dataset.theme = preference
  document.documentElement.dataset.effectiveTheme = effective
  document.documentElement.style.colorScheme = effective
  var themeColor = document.querySelector('meta[name="theme-color"]')
  if (themeColor) themeColor.setAttribute('content', effective === 'light' ? '#f7f8f8' : '#0b0d0b')
})()
