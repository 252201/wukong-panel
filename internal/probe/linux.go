package probe

import (
	"net"
	"os"
	"strconv"
	"strings"
)

func defaultInterface() string {
	data, _ := os.ReadFile("/proc/net/route")
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 2 && fields[1] == "00000000" && fields[0] != "Iface" {
			return fields[0]
		}
	}
	interfaces, _ := net.Interfaces()
	for _, item := range interfaces {
		if item.Flags&net.FlagLoopback == 0 && item.Flags&net.FlagUp != 0 {
			return item.Name
		}
	}
	return "unknown"
}
func networkBytes(iface string) (int64, int64) {
	data, _ := os.ReadFile("/proc/net/dev")
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) != iface {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) >= 9 {
			rx, _ := strconv.ParseInt(fields[0], 10, 64)
			tx, _ := strconv.ParseInt(fields[8], 10, 64)
			return rx, tx
		}
	}
	return 0, 0
}
func readCPU() (uint64, uint64) {
	data, _ := os.ReadFile("/proc/stat")
	line := strings.SplitN(string(data), "\n", 2)[0]
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, 0
	}
	var total, idle uint64
	for i, value := range fields[1:] {
		n, _ := strconv.ParseUint(value, 10, 64)
		total += n
		if i == 3 || i == 4 {
			idle += n
		}
	}
	return total, idle
}
func memoryUsage() (int64, int64) {
	data, _ := os.ReadFile("/proc/meminfo")
	values := map[string]int64{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		n, _ := strconv.ParseInt(fields[1], 10, 64)
		values[strings.TrimSuffix(fields[0], ":")] = n * 1024
	}
	total := values["MemTotal"]
	used := total - values["MemAvailable"]
	if used < 0 {
		used = 0
	}
	return used, total
}
func firstFloat(path string) float64 {
	data, _ := os.ReadFile(path)
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	value, _ := strconv.ParseFloat(fields[0], 64)
	return value
}
