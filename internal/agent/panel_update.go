package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var panelVersionPattern = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}$`)

type panelReleasePayload struct {
	TagName string `json:"tag_name"`
}

func (m *Manager) PanelUpdate(ctx context.Context, targetVersion string) error {
	m.mutation.Lock()
	defer m.mutation.Unlock()

	if m.cfg.Demo {
		return nil
	}

	cleanVer := strings.TrimPrefix(strings.TrimSpace(targetVersion), "v")
	client := &http.Client{
		Timeout: 5 * time.Minute,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 5 || r.URL.Scheme != "https" || r.URL.User != nil || r.URL.Port() != "" {
				return errors.New("untrusted redirect")
			}
			switch r.URL.Hostname() {
			case "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
				return nil
			}
			return errors.New("untrusted download host")
		},
	}

	if cleanVer == "" || cleanVer == "latest" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/252201/wukong-panel/releases/latest", nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "wukong-panel/panel-updater")
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("无法获取最新发布版本: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("GitHub release HTTP %d", resp.StatusCode)
		}
		var payload panelReleasePayload
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil || payload.TagName == "" {
			return errors.New("解析 GitHub 发布版本失败")
		}
		cleanVer = strings.TrimPrefix(payload.TagName, "v")
	}

	if !panelVersionPattern.MatchString(cleanVer) {
		return fmt.Errorf("无效的目标版本号: %s", cleanVer)
	}

	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return fmt.Errorf("不支持的系统架构: %s", arch)
	}
	assetName := fmt.Sprintf("wukong-panel-linux-%s", arch)

	baseURL := fmt.Sprintf("https://github.com/252201/wukong-panel/releases/download/v%s", cleanVer)
	if override := os.Getenv("WUKONG_TEST_PANEL_DOWNLOAD_URL"); override != "" {
		baseURL = override
	}

	// 1. Download and parse SHA256SUMS
	sumsURL := baseURL + "/SHA256SUMS"
	sumsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, sumsURL, nil)
	if err != nil {
		return err
	}
	sumsReq.Header.Set("User-Agent", "wukong-panel/panel-updater")
	sumsResp, err := client.Do(sumsReq)
	if err != nil {
		return fmt.Errorf("下载校验清单失败: %w", err)
	}
	defer sumsResp.Body.Close()
	if sumsResp.StatusCode != http.StatusOK {
		return fmt.Errorf("校验清单下载 HTTP %d", sumsResp.StatusCode)
	}

	expectedSHA := ""
	scanner := bufio.NewScanner(io.LimitReader(sumsResp.Body, 1<<20))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) >= 2 && filepath.Base(fields[1]) == assetName {
			expectedSHA = strings.ToLower(fields[0])
			break
		}
	}
	if len(expectedSHA) != 64 {
		return fmt.Errorf("校验清单中未找到 %s 的有效 SHA-256", assetName)
	}

	// 2. Download binary to temp file and stream sha256
	stageDir := filepath.Join(m.cfg.DataDir, "tmp")
	_ = os.MkdirAll(stageDir, 0700)
	tmpFile, err := os.CreateTemp(stageDir, ".panel-stage-*")
	if err != nil {
		tmpFile, err = os.CreateTemp("", ".panel-stage-*")
		if err != nil {
			return fmt.Errorf("创建临时更新文件失败: %w", err)
		}
	}
	stagePath := tmpFile.Name()
	defer os.Remove(stagePath)

	binURL := baseURL + "/" + assetName
	binReq, err := http.NewRequestWithContext(ctx, http.MethodGet, binURL, nil)
	if err != nil {
		tmpFile.Close()
		return err
	}
	binReq.Header.Set("User-Agent", "wukong-panel/panel-updater")
	binResp, err := client.Do(binReq)
	if err != nil {
		tmpFile.Close()
		return fmt.Errorf("下载面板程序失败: %w", err)
	}
	defer binResp.Body.Close()
	if binResp.StatusCode != http.StatusOK {
		tmpFile.Close()
		return fmt.Errorf("面板程序下载 HTTP %d", binResp.StatusCode)
	}

	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmpFile, hasher), io.LimitReader(binResp.Body, 128<<20))
	if err != nil {
		tmpFile.Close()
		return fmt.Errorf("保存面板程序失败: %w", err)
	}
	if written <= 0 {
		tmpFile.Close()
		return errors.New("下载的文件为空")
	}

	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if actualSHA != expectedSHA {
		tmpFile.Close()
		return fmt.Errorf("SHA-256 校验不匹配 (期望: %s, 实际: %s)", expectedSHA, actualSHA)
	}

	if err = tmpFile.Chmod(0755); err != nil {
		tmpFile.Close()
		return err
	}
	if err = tmpFile.Sync(); err != nil {
		tmpFile.Close()
		return err
	}
	if err = tmpFile.Close(); err != nil {
		return err
	}

	// 3. Test execution
	testCmd := exec.CommandContext(ctx, stagePath, "version")
	if out, err := testCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("新版二进制测试执行失败 (%s): %w", strings.TrimSpace(string(out)), err)
	}

	// 4. Backup current version
	destBin := "/usr/local/bin/wukong-panel"
	if override := os.Getenv("WUKONG_TEST_PANEL_BIN"); override != "" {
		destBin = override
	} else if ex, err := os.Executable(); err == nil {
		if realEx, err := filepath.EvalSymlinks(ex); err == nil && filepath.Base(realEx) == "wukong-panel" {
			destBin = realEx
		}
	}

	backupDir := filepath.Join(m.cfg.DataDir, "backups", "update-"+time.Now().Format("20060102-150405"))
	_ = os.MkdirAll(backupDir, 0700)

	if destInfo, err := os.Stat(destBin); err == nil && destInfo.Mode().IsRegular() {
		_ = copyFile(destBin, filepath.Join(backupDir, "wukong-panel"), 0755)
	}
	// Backup database
	dbPattern := filepath.Join(m.cfg.DataDir, "wukong.db*")
	if matches, err := filepath.Glob(dbPattern); err == nil {
		for _, dbFile := range matches {
			_ = copyFile(dbFile, filepath.Join(backupDir, filepath.Base(dbFile)), 0600)
		}
	}
	// Backup env
	envFile := "/etc/wukong-panel/env"
	if envInfo, err := os.Stat(envFile); err == nil && envInfo.Mode().IsRegular() {
		_ = copyFile(envFile, filepath.Join(backupDir, "env"), 0600)
	}

	// 5. Replace binary
	if err := os.MkdirAll(filepath.Dir(destBin), 0755); err != nil {
		return err
	}
	if err := replaceExecutable(stagePath, destBin, 0755); err != nil {
		return fmt.Errorf("替换可执行文件失败: %w", err)
	}

	ctlSymlink := "/usr/local/bin/wukongctl"
	if destBin == "/usr/local/bin/wukong-panel" {
		_ = os.Remove(ctlSymlink)
		_ = os.Symlink(destBin, ctlSymlink)
	}

	_ = m.store.Audit("agent", "panel.update", "local", cleanVer)

	// 6. Asynchronous service restart
	if os.Getenv("WUKONG_TEST_NO_RESTART") != "1" {
		go func() {
			time.Sleep(1500 * time.Millisecond)
			if _, err := os.Stat("/run/systemd/system"); err == nil {
				_ = exec.Command("systemctl", "restart", "wukong-agent.service", "wukong-web.service").Run()
			} else if _, err := os.Stat("/sbin/openrc-run"); err == nil {
				_ = exec.Command("sh", "-c", "rc-service wukong-agent restart && rc-service wukong-web restart").Run()
			}
		}()
	}

	return nil
}

func replaceExecutable(src, dst string, mode os.FileMode) error {
	if realDst, err := filepath.EvalSymlinks(dst); err == nil && realDst != "" {
		dst = realDst
	}
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(dst)+".new-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	tmpName = ""

	if dirF, err := os.Open(dir); err == nil {
		_ = dirF.Sync()
		_ = dirF.Close()
	}

	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
