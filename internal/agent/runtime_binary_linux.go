//go:build linux

package agent

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// runtimeProcessHasArg and runtimeProcessMapsBinary recognize binaries started
// through a Linux ELF interpreter. In that case /proc/PID/exe points at the
// loader, while cmdline and maps still identify the configured executable.
func runtimeProcessHasArg(procDir, expected string) bool {
	args, err := os.ReadFile(filepath.Join(procDir, "cmdline"))
	if err != nil {
		return false
	}
	for _, arg := range strings.Split(string(args), "\x00") {
		if arg == expected {
			return true
		}
	}
	return false
}

func runtimeProcessMapsBinary(procDir, binary string, target os.FileInfo) (mapped, sameFile bool) {
	identity, ok := target.Sys().(*syscall.Stat_t)
	if !ok {
		return false, false
	}
	f, err := os.Open(filepath.Join(procDir, "maps"))
	if err != nil {
		return false, false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024), 64*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 || strings.TrimSuffix(strings.Join(fields[5:], " "), " (deleted)") != binary {
			continue
		}
		mapped = true
		device := strings.SplitN(fields[3], ":", 2)
		if len(device) != 2 {
			continue
		}
		major, majorErr := strconv.ParseUint(device[0], 16, 32)
		minor, minorErr := strconv.ParseUint(device[1], 16, 32)
		inode, inodeErr := strconv.ParseUint(fields[4], 10, 64)
		if majorErr != nil || minorErr != nil || inodeErr != nil {
			continue
		}
		if linuxDeviceNumber(major, minor) == uint64(identity.Dev) && inode == identity.Ino {
			return true, true
		}
	}
	return mapped, false
}

func linuxDeviceNumber(major, minor uint64) uint64 {
	return (minor & 0xff) |
		((major & 0xfff) << 8) |
		((minor & 0xffffff00) << 12) |
		((major & 0xfffff000) << 32)
}
