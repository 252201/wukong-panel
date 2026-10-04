package hostsecurity

import (
	"context"
	"encoding/json"
	"strings"
)

// A reader belongs to one collection only. Preview, Apply and post-write
// verification each create a new reader; no sampled value survives a mutation.
type fail2banReader struct {
	c      *Controller
	values map[string]string
}

type fail2banReply struct {
	Args   []string `json:"args"`
	Output string   `json:"output"`
	OK     bool     `json:"ok"`
}

func newFail2banReader(c *Controller) *fail2banReader {
	return &fail2banReader{c: c, values: map[string]string{}}
}

func fail2banReadKey(args []string) string { return strings.Join(args, "\x00") }

// Keep the installed client's socket configuration and exact text formatting.
// Importing its Python modules once avoids launching a client for every field.
// Only status/get commands are accepted. Unsupported packages or failed replies
// fall back to the existing CLI, including its error handling.
const fail2banReadScript = `
import contextlib, io, json, re, sys
from fail2ban.client.fail2banclient import Fail2banClient
from fail2ban.client.csocket import CSocket
from fail2ban.client.beautifier import Beautifier
commands = json.load(sys.stdin)
keys = {'journalmatch','logpath','maxretry','findtime','bantime','ignoreip','actions','failregex','ignoreregex'}
def allowed(q):
    if not isinstance(q, list) or not all(isinstance(s, str) for s in q): return False
    if len(q) < 2 or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', q[1]): return False
    return (len(q) == 2 and q[0] == 'status') or (len(q) == 3 and q[0] == 'get' and q[2] in keys)
if not isinstance(commands, list) or len(commands) > 512 or not all(allowed(q) for q in commands):
    raise ValueError('invalid read commands')
replies = []
with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
    client = Fail2banClient()
    if client.initCmdLine(['fail2ban-client', 'status']) is False:
        raise RuntimeError('client configuration unavailable')
    sock = CSocket(client._conf['socket'], timeout=3)
    try:
        seen = set()
        for q in commands:
            if tuple(q) in seen: continue
            seen.add(tuple(q))
            try:
                reply = sock.send(q)
                ok = reply[0] == 0
                output = str(Beautifier(q).beautify(reply[1])).strip() if ok else ''
                replies.append({'args':q, 'output':output, 'ok':ok})
                if ok and len(q) == 3 and q[2] == 'actions':
                    action = next((a for a in ('iptables-multiport','nftables-multiport','firewallcmd-rich-rules') if a in output), None)
                    if action:
                        actions = [action] + [a for a in output.split() if re.fullmatch(r'wk-ssh-[0-9]{1,5}', a)]
                        for a in actions:
                            for field in ('actionstart','actionban'):
                                aq = ['get',q[1],'action',a,field]
                                ret = sock.send(aq)
                                success = ret[0] == 0
                                text = str(Beautifier(aq).beautify(ret[1])).strip() if success else ''
                                replies.append({'args':aq,'output':text,'ok':success})
            except Exception:
                replies.append({'args':q,'output':'','ok':False})
    finally:
        sock.close()
print(json.dumps(replies))
`

func (r *fail2banReader) prefetch(ctx context.Context, commands [][]string) {
	if len(commands) == 0 || len(commands) > 512 || !r.c.Lookup("python3") {
		return
	}
	input, _ := json.Marshal(commands)
	out, err := r.c.Run(ctx, "python3", []string{"-c", fail2banReadScript}, string(input))
	if err != nil {
		return
	}
	var replies []fail2banReply
	if json.Unmarshal([]byte(out), &replies) != nil {
		return
	}
	allowed := map[string]bool{}
	for _, q := range commands {
		allowed[fail2banReadKey(q)] = true
	}
	// Dynamic action fields are restricted to names read in this same batch.
	for _, reply := range replies {
		q := reply.Args
		if reply.OK && len(q) == 3 && q[0] == "get" && q[2] == "actions" && allowed[fail2banReadKey(q)] {
			for _, action := range fail2banActionNames(reply.Output) {
				for _, field := range []string{"actionstart", "actionban"} {
					allowed[fail2banReadKey([]string{"get", q[1], "action", action, field})] = true
				}
			}
		}
	}
	for _, reply := range replies {
		key := fail2banReadKey(reply.Args)
		if reply.OK && allowed[key] {
			r.values[key] = reply.Output
		}
	}
}

func (r *fail2banReader) exec(ctx context.Context, args ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	key := fail2banReadKey(args)
	if out, ok := r.values[key]; ok {
		return out, nil
	}
	out, err := r.c.exec(ctx, "fail2ban-client", args...)
	if err == nil {
		r.values[key] = out
	}
	return out, err
}

func fail2banJailReads(name string) [][]string {
	commands := [][]string{{"status", name}}
	for _, key := range []string{"journalmatch", "logpath", "maxretry", "findtime", "bantime", "ignoreip", "actions", "failregex", "ignoreregex"} {
		commands = append(commands, []string{"get", name, key})
	}
	return commands
}
