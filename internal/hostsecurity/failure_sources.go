package hostsecurity

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/252201/wukong-panel/internal/model"
)

const failureLogLimit = 256 * 1024

// Accept only Fail2ban's own structured filter records, never raw SSH text.
var failureRecord = regexp.MustCompile(`^(?:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[,.]\d+\s+)?fail2ban\.(?:filter|filtersystemd)\s*\[\d+\]:\s*INFO\s+\[([A-Za-z0-9_.-]+)\]\s+(?:Found|Attempt)\s+(\S+)\s+-\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[,.]\d+)?)\s*$`)

type failureEntry struct {
	message  string
	recorded time.Time
}

func (c *Controller) failureSources(ctx context.Context, state *model.Fail2banState) {
	if !state.Active || len(state.Jails) == 0 {
		return
	}
	state.FailureSourcesSince = c.Now().Add(-24 * time.Hour)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	target, err := c.exec(ctx, "fail2ban-client", "get", "logtarget")
	if err != nil {
		state.FailureSourcesReason = "无法读取 Fail2ban 失败来源日志"
		return
	}
	lines := strings.Split(strings.TrimSpace(target), "\n")
	target = strings.Trim(strings.TrimSpace(lines[len(lines)-1]), "`|- \t")
	var entries []failureEntry
	if target == "/var/log/fail2ban.log" || target == "/var/log/fail2ban/fail2ban.log" {
		for _, path := range []string{target + ".1", target} {
			data, limited, readErr := c.failureLogTail(path)
			if readErr != nil {
				if path != target && errors.Is(readErr, os.ErrNotExist) {
					continue
				}
				state.FailureSourcesReason = "Fail2ban 失败来源日志不可读"
				return
			}
			state.FailureSourcesLimited = state.FailureSourcesLimited || limited
			for _, line := range strings.Split(string(data), "\n") {
				entries = append(entries, failureEntry{message: line})
			}
		}
	} else if target == "STDOUT" || target == "STDERR" || target == "SYSLOG" || target == "SYSTEMD-JOURNAL" {
		if !c.isSystemd() || !c.Lookup("journalctl") {
			state.FailureSourcesReason = "失败来源日志未写入可读取的文件或 journal"
			return
		}
		out, readErr := c.exec(ctx, "journalctl", "--no-pager", "--since", "-24 hours", "-n", "1500", "-o", "json", "_SYSTEMD_UNIT=fail2ban.service", "+", "SYSLOG_IDENTIFIER=fail2ban", "+", "_COMM=fail2ban-server")
		if readErr != nil {
			state.FailureSourcesReason = "Fail2ban journal 失败来源不可读"
			return
		}
		scanner := bufio.NewScanner(strings.NewReader(out))
		scanner.Buffer(make([]byte, 4096), failureLogLimit)
		for scanner.Scan() {
			var row struct {
				Message   string `json:"MESSAGE"`
				Timestamp string `json:"__REALTIME_TIMESTAMP"`
			}
			if json.Unmarshal(scanner.Bytes(), &row) != nil {
				state.FailureSourcesReason = "Fail2ban journal 记录格式无法识别"
				return
			}
			micros, e := strconv.ParseInt(row.Timestamp, 10, 64)
			if e != nil {
				continue
			}
			entries = append(entries, failureEntry{row.Message, time.UnixMicro(micros)})
		}
		if scanner.Err() != nil {
			state.FailureSourcesReason = "Fail2ban journal 记录超过读取限制"
			return
		}
		state.FailureSourcesLimited = len(entries) >= 1500
	} else {
		state.FailureSourcesReason = "当前 Fail2ban 日志位置暂不支持失败来源展示"
		return
	}
	state.FailureSourcesAvailable = true
	for i := range state.Jails {
		sources, limited := aggregateFailures(entries, state.Jails[i].Name, state.FailureSourcesSince, c.Now())
		state.Jails[i].Failures = sources
		state.FailureSourcesLimited = state.FailureSourcesLimited || limited
	}
}

func (c *Controller) failureLogTail(path string) ([]byte, bool, error) {
	path = c.path(path)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, errors.New("failure log must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return nil, false, errors.New("failure log changed while opening")
	}
	limited := opened.Size() > failureLogLimit
	if limited {
		if _, err = f.Seek(-failureLogLimit, io.SeekEnd); err != nil {
			return nil, false, err
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, failureLogLimit))
	if limited {
		if cut := strings.IndexByte(string(data), '\n'); cut >= 0 {
			data = data[cut+1:]
		} else {
			data = nil
		}
	}
	return data, limited, err
}

func aggregateFailures(entries []failureEntry, jail string, since, now time.Time) ([]model.SSHFailureSource, bool) {
	byIP := map[string]*model.SSHFailureSource{}
	seen := map[string]bool{}
	for _, entry := range entries {
		match := failureRecord.FindStringSubmatch(entry.message)
		if match == nil || match[1] != jail {
			continue
		}
		ip, err := netip.ParseAddr(match[2])
		if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		stamp, err := time.ParseInLocation("2006-01-02 15:04:05", strings.ReplaceAll(match[3], ",", "."), time.Local)
		if err != nil {
			continue
		}
		if !entry.recorded.IsZero() {
			stamp = entry.recorded
		}
		if stamp.Before(since) || stamp.After(now.Add(time.Minute)) {
			continue
		}
		key := entry.message
		if !entry.recorded.IsZero() {
			key += entry.recorded.String()
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		address := ip.Unmap().String()
		source := byIP[address]
		if source == nil {
			source = &model.SSHFailureSource{IP: address}
			byIP[address] = source
		}
		source.Count++
		if stamp.After(source.LastSeen) {
			source.LastSeen = stamp
		}
	}
	result := make([]model.SSHFailureSource, 0, len(byIP))
	for _, source := range byIP {
		result = append(result, *source)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].LastSeen.Equal(result[j].LastSeen) {
			return result[i].IP < result[j].IP
		}
		return result[i].LastSeen.After(result[j].LastSeen)
	})
	limited := len(result) > 50
	if limited {
		result = result[:50]
	}
	return result, limited
}
