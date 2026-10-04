package hostsecurity

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/252201/wukong-panel/internal/model"
)

func manualBanAddress(ip string) (netip.Addr, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, errors.New("封禁需要有效单个 IP")
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return netip.Addr{}, errors.New("不能封禁本机、回环或特殊地址")
	}
	return a, nil
}

func localAddresses() ([]netip.Addr, error) {
	entries, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	result := []netip.Addr{}
	for _, entry := range entries {
		prefix, err := netip.ParsePrefix(entry.String())
		if err != nil {
			return nil, err
		}
		result = append(result, prefix.Addr().Unmap())
	}
	return result, nil
}

func (c *Controller) banSafety(ctx context.Context, ip, jail string) (netip.Addr, error) {
	a, err := manualBanAddress(ip)
	if err != nil {
		return a, err
	}
	addresses := c.LocalAddresses
	if addresses == nil {
		addresses = localAddresses
	}
	own, err := addresses()
	if err != nil {
		return a, errors.New("无法读取本机地址，已禁止手动封禁")
	}
	for _, addr := range own {
		if addr.Unmap() == a {
			return a, errors.New("不能封禁服务器自身地址")
		}
	}
	raw, err := c.exec(ctx, "fail2ban-client", "get", jail, "ignoreip")
	if err != nil {
		return a, err
	}
	// Runtime ignoreip may contain hostnames. Do not silently drop unknown
	// entries: a manual ban must never bypass a whitelist we cannot resolve.
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasSuffix(strings.TrimSpace(line), "ignored:") {
			continue
		}
		for _, token := range strings.Fields(line) {
			token = strings.Trim(token, "[],\"'`|- ")
			if token == "" {
				continue
			}
			if addr, e := netip.ParseAddr(token); e == nil {
				if addr.Unmap() == a {
					return a, errors.New("此 IP 在 SSH 防护白名单中，不能封禁")
				}
				continue
			}
			if prefix, e := netip.ParsePrefix(token); e == nil {
				if prefix.Contains(a) {
					return a, errors.New("此 IP 在 SSH 防护白名单中，不能封禁")
				}
				continue
			}
			return a, errors.New("白名单含无法识别的地址，已禁止手动封禁")
		}
	}
	return a, nil
}

func (c *Controller) manualBanTarget(ctx context.Context, f model.Fail2banState, req model.SecurityRequest) (netip.Addr, error) {
	if !f.Active || !f.Writable || req.Jail == "" || req.Jail != f.ManagedJail || !nameRE.MatchString(req.Jail) {
		return netip.Addr{}, errors.New("只能操作正在运行且由面板管理的 SSH 防护")
	}
	a, err := c.banSafety(ctx, req.IP, req.Jail)
	if err != nil {
		return a, err
	}
	if !f.FailureSourcesAvailable {
		return a, errors.New("失败来源暂不可用，请刷新后重试")
	}
	for _, jail := range f.Jails {
		if !jail.Managed || jail.ConfiguredOnly || jail.Name != req.Jail {
			continue
		}
		if contains(jail.Banned, a.String()) {
			return a, errors.New("此 IP 已被封禁，请刷新状态")
		}
		for _, source := range jail.Failures {
			if source.IP == a.String() {
				return a, nil
			}
		}
	}
	return a, errors.New("此 IP 不在当前 SSH 防护的最近失败来源中")
}

// Fail2ban may enqueue the action after accepting a ticket. Verify the actual
// SSH-only enforcement, allowing a short bounded time for the action to finish.
func (c *Controller) verifyManualBan(ctx context.Context, jail, ip string, banned bool) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var last error
	for {
		out, err := c.exec(ctx, "fail2ban-client", "status", jail)
		if err == nil {
			present := contains(parsedIPs(field(out, "Banned IP list")), ip)
			if present == banned {
				if !banned {
					return nil
				}
				ports, _ := c.ports(ctx)
				var err error
				if len(ports) > 0 {
					err = c.enforcement(ctx, jail, []string{ip}, ports)
				} else {
					err = errors.New("未识别到实际 SSH 端口")
				}
				if err == nil {
					return nil
				}
				last = err
			} else {
				last = errors.New("SSH 封禁列表尚未按操作更新")
			}
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return errors.Join(errors.New("无法确认 SSH 封禁操作实际生效"), last, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func banDuration(seconds int) string {
	if seconds == -1 {
		return "永久（不自动解除）"
	}
	return strconv.Itoa(seconds) + " 秒"
}
