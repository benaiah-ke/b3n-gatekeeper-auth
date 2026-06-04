const AUTH_ENTRY_PATHS = new Set(['/login', '/signup'])
const REDIRECT_BASE = 'http://gatekeeper.local'

export function safeInternalRedirect(value: unknown) {
  const raw = Array.isArray(value) ? value[0] : value
  if (typeof raw !== 'string' || !raw.startsWith('/') || raw.startsWith('//')) {
    return ''
  }

  try {
    const parsed = new URL(raw, REDIRECT_BASE)
    if (parsed.origin !== REDIRECT_BASE || AUTH_ENTRY_PATHS.has(parsed.pathname)) {
      return ''
    }
    return `${parsed.pathname}${parsed.search}${parsed.hash}`
  } catch {
    return ''
  }
}
