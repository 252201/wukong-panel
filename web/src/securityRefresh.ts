// Give the firewall read a short head start on small hosts. A failed or stuck
// firewall must not prevent the independent SSH status from loading.
export async function afterFirewallRead<T>(firewall: Promise<unknown>, readSSH: () => Promise<T>, current: () => boolean, maxWait = 1500): Promise<T | undefined> {
 let timer: ReturnType<typeof setTimeout> | undefined
 try {
  await Promise.race([
   firewall.catch(() => {}),
   new Promise<void>(resolve => {timer = setTimeout(resolve, maxWait)}),
  ])
 } finally {clearTimeout(timer)}
 if (current()) return readSSH()
}
