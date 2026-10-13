export function origin(value) {
  const parsed = new URL(value);
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password ||
      parsed.pathname !== '/' || parsed.search || parsed.hash) throw new Error('Invalid configured origin');
  return parsed.origin;
}

export function networkPolicy(forumOrigin, hookOrigin = '') {
  const allowed = new Set([origin(forumOrigin)]);
  if (hookOrigin) allowed.add(origin(hookOrigin));
  return raw => {
    try {
      const url = new URL(raw);
      if (url.username || url.password) return false;
      if (url.protocol === 'ws:') url.protocol = 'http:';
      else if (url.protocol === 'wss:') url.protocol = 'https:';
      if (!['http:', 'https:'].includes(url.protocol)) return false;
      return allowed.has(url.origin);
    } catch { return false; }
  };
}

export async function protectContext(context, allows) {
  await context.route('**/*', route => allows(route.request().url()) ? route.continue() : route.abort());
  await context.routeWebSocket('**/*', socket => {
    if (allows(socket.url())) socket.connectToServer();
    else socket.close();
  });
}

export function runner(visit) {
  let active = false;
  return async () => {
    if (active) return false;
    active = true;
    try { await visit(); return true; }
    finally { active = false; }
  };
}
