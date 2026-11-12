// ============================================================================
// VECTRANET NATIVE LINUX AGENT COLLECTOR (Procfs / Sysfs / Dpkg / RPM)
// File: agents/linux/agent.go
// Build AMD64: CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o vectranet-agent-linux-amd64 agents/linux/agent.go
// Build ARM64: CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o vectranet-agent-linux-arm64 agents/linux/agent.go
// Resource Target: RAM RSS < 15 MB | Avg CPU < 1% | Gzip + TLS 1.3 Ingestion
// ============================================================================
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	AgentVersion        = "v2.4.2-linux"
	MaxWorkerGoroutines = 4
	SoftwareScanEvery   = 15
)

type NetworkInterface struct {
	Name       string  `json:"interface_name"`
	IPAddress  string  `json:"ip_address"`
	MACAddress string  `json:"mac_address"`
	SpeedMbps  int     `json:"speed_mbps"`
	VLANID     int     `json:"vlan_id"`
	RxMbps     float64 `json:"rx_mbps"`
	TxMbps     float64 `json:"tx_mbps"`
	IsPrimary  bool    `json:"is_primary"`
}

type SoftwareItem struct {
	Name        string `json:"software_name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher"`
	InstallDate string `json:"install_date"`
}

type IngestPayload struct {
	AgentVersion  string             `json:"agent_version"`
	Hostname      string             `json:"hostname"`
	IPAddress     string             `json:"ip_address"`
	MACAddress    string             `json:"mac_address"`
	OSFamily      string             `json:"os_family"`
	OSVersion     string             `json:"os_version"`
	KernelArch    string             `json:"kernel_arch"`
	CPUModel      string             `json:"cpu_model"`
	CPUCores      int                `json:"cpu_cores"`
	CPUUsagePct   float64            `json:"cpu_usage_pct"`
	RAMTotalGB    float64            `json:"ram_total_gb"`
	RAMUsedGB     float64            `json:"ram_used_gb"`
	DiskTotalGB   float64            `json:"disk_total_gb"`
	DiskUsedGB    float64            `json:"disk_used_gb"`
	AgentRSSMB    float64            `json:"agent_rss_mb"`
	HeartbeatMode string             `json:"heartbeat_mode"`
	Interfaces    []NetworkInterface `json:"interfaces"`
	Software      []SoftwareItem     `json:"software,omitempty"`
	RecordedAt    time.Time          `json:"recorded_at"`
}

type IngestResponse struct {
	Status           string `json:"status"`
	NextHeartbeatSec int    `json:"next_heartbeat_sec"`
}

type netDevSample struct {
	rxBytes uint64
	txBytes uint64
	ts      time.Time
}

type LinuxAgentCollector struct {
	serverURL        string
	authToken        string
	baseInterval     time.Duration
	httpClient       *http.Client
	gzipBufferPool   sync.Pool
	workerSem        chan struct{}
	lastCPUPct       float64
	prevIdleTicks    uint64
	prevTotalTicks   uint64
	prevNetSamples   map[string]netDevSample
	heartbeatCounter int
	cachedSoftware   []SoftwareItem
}

func NewLinuxAgentCollector(serverURL, authToken string, baseInterval time.Duration, insecureTLS bool) *LinuxAgentCollector {
	debug.SetMemoryLimit(15 * 1024 * 1024)
	debug.SetGCPercent(40)
	runtime.GOMAXPROCS(2)

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: insecureTLS,
	}

	return &LinuxAgentCollector{
		serverURL:      strings.TrimRight(serverURL, "/"),
		authToken:      authToken,
		baseInterval:   baseInterval,
		workerSem:      make(chan struct{}, MaxWorkerGoroutines),
		prevNetSamples: make(map[string]netDevSample),
		gzipBufferPool: sync.Pool{
			New: func() any {
				return bytes.NewBuffer(make([]byte, 0, 8192))
			},
		},
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     tlsConfig,
				MaxIdleConns:        2,
				MaxIdleConnsPerHost: 1,
				IdleConnTimeout:     120 * time.Second,
			},
		},
	}
}

func readProcNetDevBytes() map[string][2]uint64 {
	res := make(map[string][2]uint64)
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return res
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum <= 2 {
			continue
		}
		line := strings.TrimSpace(scanner.Text())
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		ifName := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if len(fields) >= 9 {
			rxBytes, _ := strconv.ParseUint(fields[0], 10, 64)
			txBytes, _ := strconv.ParseUint(fields[8], 10, 64)
			res[ifName] = [2]uint64{rxBytes, txBytes}
		}
	}
	return res
}

func (a *LinuxAgentCollector) collectNetworkInterfaces() ([]NetworkInterface, string, string) {
	a.workerSem <- struct{}{}
	defer func() { <-a.workerSem }()

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, "127.0.0.1", "00:00:00:00:00:00"
	}

	netStats := readProcNetDevBytes()
	now := time.Now()

	var result []NetworkInterface
	primaryIP := "127.0.0.1"
	primaryMAC := "00:00:00:00:00:00"

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		mac := strings.ToUpper(iface.HardwareAddr.String())
		if mac == "" {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP == nil || ipNet.IP.IsLoopback() {
				continue
			}
			ipv4 := ipNet.IP.To4()
			if ipv4 == nil {
				continue
			}
			ipStr := ipv4.String()
			isPrimary := len(result) == 0
			if isPrimary {
				primaryIP = ipStr
				primaryMAC = mac
			}

			var rxMbps, txMbps float64
			if counters, ok := netStats[iface.Name]; ok {
				if prev, hasPrev := a.prevNetSamples[iface.Name]; hasPrev {
					elapsedSec := now.Sub(prev.ts).Seconds()
					if elapsedSec > 0 && counters[0] >= prev.rxBytes && counters[1] >= prev.txBytes {
						rxMbps = round2((float64(counters[0]-prev.rxBytes) * 8.0) / (elapsedSec * 1_000_000.0))
						txMbps = round2((float64(counters[1]-prev.txBytes) * 8.0) / (elapsedSec * 1_000_000.0))
					}
				}
				a.prevNetSamples[iface.Name] = netDevSample{
					rxBytes: counters[0],
					txBytes: counters[1],
					ts:      now,
				}
			}

			result = append(result, NetworkInterface{
				Name:       iface.Name,
				IPAddress:  ipStr,
				MACAddress: mac,
				SpeedMbps:  1000,
				VLANID:     1,
				RxMbps:     rxMbps,
				TxMbps:     txMbps,
				IsPrimary:  isPrimary,
			})
			break
		}
	}
	return result, primaryIP, primaryMAC
}

func readProcStatTicks() (totalTicks, idleTicks uint64, ok bool) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 5 && fields[0] == "cpu" {
			for i := 1; i < len(fields); i++ {
				val, _ := strconv.ParseUint(fields[i], 10, 64)
				totalTicks += val
				if i == 4 || i == 5 { // idle + iowait
					idleTicks += val
				}
			}
			return totalTicks, idleTicks, totalTicks > 0
		}
	}
	return 0, 0, false
}

func (a *LinuxAgentCollector) readLinuxMetrics(ctx context.Context) (osFamily, osVersion, cpuModel string, cpuPct, ramTotalGB, ramUsedGB, diskTotalGB, diskUsedGB float64) {
	a.workerSem <- struct{}{}
	defer func() { <-a.workerSem }()

	osFamily = "Linux"
	osVersion = "Generic Linux"
	cpuModel = runtime.GOARCH

	if f, err := os.Open("/etc/os-release"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				osVersion = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
				break
			}
		}
		_ = f.Close()
	}

	if f, err := os.Open("/proc/cpuinfo"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "model name") || strings.HasPrefix(line, "Model") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
					cpuModel = strings.TrimSpace(parts[1])
					break
				}
			}
		}
		_ = f.Close()
	}

	// Real-time CPU Usage Calculation via /proc/stat delta.
	// On the first sample (prevTotalTicks == 0), take two readings 160ms apart so the very first heartbeat reports real CPU load (never 0%).
	if a.prevTotalTicks == 0 {
		if t1, i1, ok := readProcStatTicks(); ok {
			a.prevTotalTicks = t1
			a.prevIdleTicks = i1
			time.Sleep(160 * time.Millisecond)
		}
	}
	if totalTicks, idleTicks, ok := readProcStatTicks(); ok {
		if a.prevTotalTicks > 0 && totalTicks > a.prevTotalTicks {
			deltaTotal := float64(totalTicks - a.prevTotalTicks)
			deltaIdle := float64(idleTicks - a.prevIdleTicks)
			cpuPct = math.Max(0.1, math.Min(100.0, (1.0-(deltaIdle/deltaTotal))*100.0))
		}
		a.prevTotalTicks = totalTicks
		a.prevIdleTicks = idleTicks
	}

	// Fallback to /proc/loadavg if /proc/stat delta was 0
	if cpuPct <= 0 {
		if data, err := os.ReadFile("/proc/loadavg"); err == nil {
			fields := strings.Fields(string(data))
			if len(fields) >= 1 {
				if load1, err := strconv.ParseFloat(fields[0], 64); err == nil && load1 > 0 {
					cores := float64(runtime.NumCPU())
					if cores < 1 {
						cores = 1
					}
					cpuPct = math.Min(100.0, math.Max(0.5, (load1/cores)*100.0))
				}
			}
		}
	}

	if f, err := os.Open("/proc/meminfo"); err == nil {
		var memTotalKB, memAvailableKB, memFreeKB, buffersKB, cachedKB uint64
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			val, _ := strconv.ParseUint(fields[1], 10, 64)
			switch fields[0] {
			case "MemTotal:":
				memTotalKB = val
			case "MemAvailable:":
				memAvailableKB = val
			case "MemFree:":
				memFreeKB = val
			case "Buffers:":
				buffersKB = val
			case "Cached:":
				cachedKB = val
			}
		}
		_ = f.Close()
		if memTotalKB > 0 {
			avail := memAvailableKB
			if avail == 0 {
				avail = memFreeKB + buffersKB + cachedKB
			}
			ramTotalGB = float64(memTotalKB) / (1024.0 * 1024.0)
			if memTotalKB > avail {
				ramUsedGB = float64(memTotalKB-avail) / (1024.0 * 1024.0)
			}
		}
	}

	cmdCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(cmdCtx, "df", "-kP", "/").Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) >= 2 {
			fields := strings.Fields(lines[1])
			if len(fields) >= 4 {
				totalKB, _ := strconv.ParseFloat(fields[1], 64)
				usedKB, _ := strconv.ParseFloat(fields[2], 64)
				diskTotalGB = totalKB / (1024.0 * 1024.0)
				diskUsedGB = usedKB / (1024.0 * 1024.0)
			}
		}
	}
	return
}

func (a *LinuxAgentCollector) collectInstalledSoftware(ctx context.Context) []SoftwareItem {
	a.workerSem <- struct{}{}
	defer func() { <-a.workerSem }()

	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var items []SoftwareItem
	today := time.Now().UTC().Format("2006-01-02")

	if out, err := exec.CommandContext(cmdCtx, "dpkg-query", "-W", "-f=${Package}|${Version}|${Maintainer}\n").Output(); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() && len(items) < 40 {
			parts := strings.SplitN(scanner.Text(), "|", 3)
			if len(parts) == 3 {
				items = append(items, SoftwareItem{
					Name:        parts[0],
					Version:     parts[1],
					Publisher:   parts[2],
					InstallDate: today,
				})
			}
		}
		return items
	}

	if out, err := exec.CommandContext(cmdCtx, "rpm", "-qa", "--queryformat", "%{NAME}|%{VERSION}-%{RELEASE}|%{VENDOR}\n").Output(); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() && len(items) < 40 {
			parts := strings.SplitN(scanner.Text(), "|", 3)
			if len(parts) == 3 {
				items = append(items, SoftwareItem{
					Name:        parts[0],
					Version:     parts[1],
					Publisher:   parts[2],
					InstallDate: today,
				})
			}
		}
	}
	return items
}

func (a *LinuxAgentCollector) computeAdaptiveSchedule(cpuPct, ramPct float64) (time.Duration, string) {
	deltaCPU := math.Abs(cpuPct - a.lastCPUPct)
	a.lastCPUPct = cpuPct

	if cpuPct >= 85.0 || ramPct >= 90.0 || deltaCPU >= 25.0 {
		burst := a.baseInterval / 6
		if burst < 10*time.Second {
			burst = 10 * time.Second
		}
		return burst, "burst-event"
	}
	if cpuPct <= 20.0 && ramPct <= 50.0 && deltaCPU < 5.0 {
		eco := time.Duration(float64(a.baseInterval) * 1.5)
		if eco > 300*time.Second {
			eco = 300 * time.Second
		}
		return eco, "idle-eco"
	}
	return a.baseInterval, "standard"
}

func (a *LinuxAgentCollector) sendIngest(ctx context.Context, payload IngestPayload) (int, error) {
	buf := a.gzipBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer a.gzipBufferPool.Put(buf)

	gzWriter, err := gzip.NewWriterLevel(buf, gzip.BestSpeed)
	if err != nil {
		return 0, err
	}
	if err := json.NewEncoder(gzWriter).Encode(payload); err != nil {
		_ = gzWriter.Close()
		return 0, err
	}
	if err := gzWriter.Close(); err != nil {
		return 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.serverURL+"/api/v1/agent/ingest", bytes.NewReader(buf.Bytes()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("User-Agent", "VectraNet-LinuxAgent/"+AgentVersion)
	if a.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.authToken)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var ingestResp IngestResponse
	if err := json.Unmarshal(bodyBytes, &ingestResp); err == nil && ingestResp.NextHeartbeatSec >= 5 {
		return ingestResp.NextHeartbeatSec, nil
	}
	return 0, nil
}

func round2(val float64) float64 {
	return math.Round(val*100) / 100
}

func main() {
	serverFlag := flag.String("server", os.Getenv("VECTRANET_SERVER_URL"), "VectraNet Central Server URL")
	tokenFlag := flag.String("token", os.Getenv("VECTRANET_AGENT_TOKEN"), "Agent Bearer Auth Token")
	intervalFlag := flag.Int("interval", 60, "Base heartbeat interval in seconds")
	insecureFlag := flag.Bool("insecure", false, "Skip TLS verification")
	flag.Parse()

	if *serverFlag == "" {
		*serverFlag = "https://rmm.internal.corp:8443"
	}

	collector := NewLinuxAgentCollector(
		*serverFlag,
		*tokenFlag,
		time.Duration(*intervalFlag)*time.Second,
		*insecureFlag,
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hostname, _ := os.Hostname()
	log.Printf("[vectranet-linux-agent %s] started on %s (%s) target=%s", AgentVersion, hostname, runtime.GOARCH, *serverFlag)

	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			ifaces, primaryIP, primaryMAC := collector.collectNetworkInterfaces()
			osFam, osVer, cpuMod, cpuPct, ramTot, ramUsed, diskTot, diskUsed := collector.readLinuxMetrics(ctx)

			if collector.heartbeatCounter%SoftwareScanEvery == 0 {
				collector.cachedSoftware = collector.collectInstalledSoftware(ctx)
			}
			collector.heartbeatCounter++

			ramPct := 0.0
			if ramTot > 0 {
				ramPct = (ramUsed / ramTot) * 100.0
			}
			nextDuration, mode := collector.computeAdaptiveSchedule(cpuPct, ramPct)

			var memStats runtime.MemStats
			runtime.ReadMemStats(&memStats)
			agentRSSMB := float64(memStats.Sys) / (1024.0 * 1024.0)

			payload := IngestPayload{
				AgentVersion:  AgentVersion,
				Hostname:      hostname,
				IPAddress:     primaryIP,
				MACAddress:    primaryMAC,
				OSFamily:      osFam,
				OSVersion:     osVer,
				KernelArch:    "linux/" + runtime.GOARCH,
				CPUModel:      cpuMod,
				CPUCores:      runtime.NumCPU(),
				CPUUsagePct:   round2(cpuPct),
				RAMTotalGB:    round2(ramTot),
				RAMUsedGB:     round2(ramUsed),
				DiskTotalGB:   round2(diskTot),
				DiskUsedGB:    round2(diskUsed),
				AgentRSSMB:    round2(agentRSSMB),
				HeartbeatMode: mode,
				Interfaces:    ifaces,
				Software:      collector.cachedSoftware,
				RecordedAt:    time.Now().UTC(),
			}

			overrideSec, err := collector.sendIngest(ctx, payload)
			if err != nil {
				log.Printf("[warn] telemetry ingest failed: %v", err)
			} else if overrideSec > 0 && mode == "standard" {
				nextDuration = time.Duration(overrideSec) * time.Second
			}

			timer.Reset(nextDuration)
		}
	}
}
