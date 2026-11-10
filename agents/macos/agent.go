// ============================================================================
// VECTRANET NATIVE macOS AGENT COLLECTOR (Apple Silicon M1/M2/M3 & Intel)
// File: agents/macos/agent.go
// Build Apple Silicon: CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o vectranet-agent-darwin-arm64 agents/macos/agent.go
// Build Intel Mac:     CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o vectranet-agent-darwin-amd64 agents/macos/agent.go
// Resource Target:     RAM RSS < 15 MB | Avg CPU < 1% | Gzip + TLS 1.3 Ingestion
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
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	AgentVersion        = "v2.4.2-darwin"
	MaxWorkerGoroutines = 4
	AppScanCycleMod     = 15 // Pindai direktori /Applications setiap 15 siklus heartbeat agar CPU < 1%
)

// NetworkInterface merepresentasikan skema tabel network_interfaces
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

// SoftwareItem merepresentasikan bundel aplikasi macOS (.app) di /Applications
type SoftwareItem struct {
	Name        string `json:"software_name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher"`
	InstallDate string `json:"install_date"`
}

// MacHardwareMetadata menyimpan atribut spesifik Apple dari SPHardwareDataType
type MacHardwareMetadata struct {
	ModelName      string `json:"model_name"`
	ModelID        string `json:"model_identifier"`
	ChipType       string `json:"chip_type"`
	SerialNumber   string `json:"serial_number"`
	HardwareUUID   string `json:"hardware_uuid"`
	ProvisionUDID  string `json:"provisioning_udid,omitempty"`
	ActivationLock string `json:"activation_lock_status,omitempty"`
}

// IngestPayload adalah payload JSON terkompresi Gzip untuk endpoint /api/v1/agent/ingest
type IngestPayload struct {
	AgentVersion     string              `json:"agent_version"`
	Hostname         string              `json:"hostname"`
	IPAddress        string              `json:"ip_address"`
	MACAddress       string              `json:"mac_address"`
	OSFamily         string              `json:"os_family"`
	OSVersion        string              `json:"os_version"`
	KernelArch       string              `json:"kernel_arch"`
	CPUModel         string              `json:"cpu_model"`
	CPUCores         int                 `json:"cpu_cores"`
	CPUUsagePct      float64             `json:"cpu_usage_pct"`
	RAMTotalGB       float64             `json:"ram_total_gb"`
	RAMUsedGB        float64             `json:"ram_used_gb"`
	DiskTotalGB      float64             `json:"disk_total_gb"`
	DiskUsedGB       float64             `json:"disk_used_gb"`
	AgentRSSMB       float64             `json:"agent_rss_mb"`
	HeartbeatMode    string              `json:"heartbeat_mode"`
	HardwareMetadata MacHardwareMetadata `json:"hardware_metadata"`
	Interfaces       []NetworkInterface  `json:"interfaces"`
	Software         []SoftwareItem      `json:"software,omitempty"`
	RecordedAt       time.Time           `json:"recorded_at"`
}

type IngestResponse struct {
	Status           string `json:"status"`
	NextHeartbeatSec int    `json:"next_heartbeat_sec"`
}

// spHardwareJSON memetakan output `system_profiler SPHardwareDataType -json`
type spHardwareJSON struct {
	SPHardwareDataType []struct {
		MachineName      string `json:"machine_name"`
		MachineModel     string `json:"machine_model"`
		ChipType         string `json:"chip_type"`
		CPUType          string `json:"cpu_type"`
		PhysicalMemory   string `json:"physical_memory"`
		SerialNumber     string `json:"serial_number"`
		PlatformUUID     string `json:"platform_UUID"`
		ProvisioningUDID string `json:"provisioning_UDID"`
		ActivationLock   string `json:"activation_lock_status"`
	} `json:"SPHardwareDataType"`
}

type MacAgentCollector struct {
	serverURL      string
	authToken      string
	baseInterval   time.Duration
	httpClient     *http.Client
	gzipBufPool    sync.Pool
	workerSem      chan struct{}
	lastCPUPct     float64
	cycleCount     int
	cachedHardware MacHardwareMetadata
	cachedOSVer    string
	cachedApps     []SoftwareItem
}

func NewMacAgentCollector(serverURL, authToken string, baseInterval time.Duration, insecureTLS bool) *MacAgentCollector {
	// Batasi agresif penggunaan memori runtime Go agar RSS di bawah 15 MB
	debug.SetMemoryLimit(15 * 1024 * 1024)
	debug.SetGCPercent(40)
	runtime.GOMAXPROCS(2)

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: insecureTLS,
	}

	return &MacAgentCollector{
		serverURL:    strings.TrimRight(serverURL, "/"),
		authToken:    authToken,
		baseInterval: baseInterval,
		workerSem:    make(chan struct{}, MaxWorkerGoroutines),
		gzipBufPool: sync.Pool{
			New: func() any {
				return bytes.NewBuffer(make([]byte, 0, 8192))
			},
		},
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     tlsCfg,
				MaxIdleConns:        2,
				MaxIdleConnsPerHost: 1,
				IdleConnTimeout:     120 * time.Second,
			},
		},
	}
}

// collectMacHardwareProfile mengeksekusi `system_profiler SPHardwareDataType -json` & `sw_vers`
func (m *MacAgentCollector) collectMacHardwareProfile(ctx context.Context) (MacHardwareMetadata, string) {
	m.workerSem <- struct{}{}
	defer func() { <-m.workerSem }()

	meta := MacHardwareMetadata{
		ModelName:    "Mac",
		ModelID:      "Mac",
		ChipType:     "Apple Silicon / Intel",
		SerialNumber: "UNKNOWN",
		HardwareUUID: "00000000-0000-0000-0000-000000000000",
	}

	// 1. Ambil versi macOS via sw_vers
	osVersion := "macOS"
	swCtx, swCancel := context.WithTimeout(ctx, 3*time.Second)
	defer swCancel()
	if out, err := exec.CommandContext(swCtx, "/usr/bin/sw_vers").Output(); err == nil {
		var prodName, prodVer, buildVer string
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "ProductName:") {
				prodName = strings.TrimSpace(strings.TrimPrefix(line, "ProductName:"))
			} else if strings.HasPrefix(line, "ProductVersion:") {
				prodVer = strings.TrimSpace(strings.TrimPrefix(line, "ProductVersion:"))
			} else if strings.HasPrefix(line, "BuildVersion:") {
				buildVer = strings.TrimSpace(strings.TrimPrefix(line, "BuildVersion:"))
			}
		}
		if prodVer != "" {
			osVersion = fmt.Sprintf("%s %s (%s)", prodName, prodVer, buildVer)
		}
	}

	// 2. Ambil Serial Number, Hardware UUID, dan Chip via system_profiler SPHardwareDataType -json
	spCtx, spCancel := context.WithTimeout(ctx, 5*time.Second)
	defer spCancel()
	if out, err := exec.CommandContext(spCtx, "/usr/sbin/system_profiler", "SPHardwareDataType", "-json").Output(); err == nil {
		var parsed spHardwareJSON
		if err := json.Unmarshal(out, &parsed); err == nil && len(parsed.SPHardwareDataType) > 0 {
			hw := parsed.SPHardwareDataType[0]
			if hw.MachineName != "" {
				meta.ModelName = hw.MachineName
			}
			if hw.MachineModel != "" {
				meta.ModelID = hw.MachineModel
			}
			if hw.ChipType != "" {
				meta.ChipType = hw.ChipType
			} else if hw.CPUType != "" {
				meta.ChipType = hw.CPUType
			}
			if hw.SerialNumber != "" {
				meta.SerialNumber = hw.SerialNumber
			}
			if hw.PlatformUUID != "" {
				meta.HardwareUUID = hw.PlatformUUID
			}
			meta.ProvisionUDID = hw.ProvisioningUDID
			meta.ActivationLock = hw.ActivationLock
		}
	}

	// Fallback model chip jika system_profiler tidak mengembalikan chip_type
	if meta.ChipType == "Apple Silicon / Intel" {
		if out, err := exec.CommandContext(ctx, "/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string").Output(); err == nil {
			brand := strings.TrimSpace(string(out))
			if brand != "" {
				meta.ChipType = brand
			}
		}
	}

	return meta, osVersion
}

// collectDarwinTelemetry membaca utilisasi CPU, RAM (sysctl + vm_stat), dan Disk APFS ("/")
func (m *MacAgentCollector) collectDarwinTelemetry(ctx context.Context) (cpuPct, ramTotalGB, ramUsedGB, diskTotalGB, diskUsedGB float64) {
	m.workerSem <- struct{}{}
	defer func() { <-m.workerSem }()

	// 1. Total RAM fisik via sysctl hw.memsize (dalam byte)
	if out, err := exec.CommandContext(ctx, "/usr/sbin/sysctl", "-n", "hw.memsize").Output(); err == nil {
		if memBytes, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64); err == nil && memBytes > 0 {
			ramTotalGB = memBytes / (1024.0 * 1024.0 * 1024.0)
		}
	}

	// 2. RAM terpakai via vm_stat (pages active + wired + compressed)
	if out, err := exec.CommandContext(ctx, "/usr/bin/vm_stat").Output(); err == nil {
		pageSize := 4096.0
		if runtime.GOARCH == "arm64" {
			pageSize = 16384.0 // Apple Silicon menggunakan page size 16 KB
		}
		var activePages, wiredPages, compressedPages float64
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "page size of") {
				fields := strings.Fields(line)
				for i, f := range fields {
					if f == "of" && i+1 < len(fields) {
						if ps, err := strconv.ParseFloat(fields[i+1], 64); err == nil && ps > 0 {
							pageSize = ps
						}
					}
				}
			} else if strings.HasPrefix(line, "Pages active:") {
				activePages = parseVMStatValue(line)
			} else if strings.HasPrefix(line, "Pages wired down:") {
				wiredPages = parseVMStatValue(line)
			} else if strings.HasPrefix(line, "Pages occupied by compressor:") {
				compressedPages = parseVMStatValue(line)
			}
		}
		usedBytes := (activePages + wiredPages + compressedPages) * pageSize
		if usedBytes > 0 {
			ramUsedGB = usedBytes / (1024.0 * 1024.0 * 1024.0)
			if ramTotalGB > 0 && ramUsedGB > ramTotalGB {
				ramUsedGB = ramTotalGB * 0.92
			}
		}
	}

	// 3. Rata-rata utilisasi CPU dari ps -A -o %cpu
	if out, err := exec.CommandContext(ctx, "/bin/ps", "-A", "-o", "%cpu").Output(); err == nil {
		var sumCPU float64
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			txt := strings.TrimSpace(scanner.Text())
			if txt == "%CPU" || txt == "" {
				continue
			}
			if val, err := strconv.ParseFloat(txt, 64); err == nil {
				sumCPU += val
			}
		}
		cores := float64(runtime.NumCPU())
		if cores < 1 {
			cores = 1
		}
		cpuPct = math.Min(100.0, math.Max(0.5, sumCPU/cores))
	}

	// 4. Kapasitas dan penggunaan Disk APFS "/" via df -kP /
	if out, err := exec.CommandContext(ctx, "/bin/df", "-kP", "/").Output(); err == nil {
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

func parseVMStatValue(line string) float64 {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return 0
	}
	clean := strings.TrimSuffix(strings.TrimSpace(parts[1]), ".")
	val, _ := strconv.ParseFloat(clean, 64)
	return val
}

// collectApplications memindai bundel .app di /Applications dan membaca CFBundleShortVersionString
func (m *MacAgentCollector) collectApplications(ctx context.Context) []SoftwareItem {
	m.workerSem <- struct{}{}
	defer func() { <-m.workerSem }()

	entries, err := os.ReadDir("/Applications")
	if err != nil {
		return nil
	}

	var apps []SoftwareItem
	for _, entry := range entries {
		if len(apps) >= 50 {
			break
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".app") {
			continue
		}

		appPath := filepath.Join("/Applications", name)
		infoPlist := filepath.Join(appPath, "Contents", "Info")
		appTitle := strings.TrimSuffix(name, ".app")
		version := "1.0"
		publisher := "Apple / macOS Developer"
		installDate := time.Now().UTC().Format("2006-01-02")

		if info, err := entry.Info(); err == nil {
			installDate = info.ModTime().UTC().Format("2006-01-02")
		}

		// Baca versi dari Info.plist menggunakan `defaults read` dengan batas waktu ketat
		cmdCtx, cancel := context.WithTimeout(ctx, 600*time.Millisecond)
		if out, err := exec.CommandContext(cmdCtx, "/usr/bin/defaults", "read", infoPlist, "CFBundleShortVersionString").Output(); err == nil {
			v := strings.TrimSpace(string(out))
			if v != "" {
				version = v
			}
		}
		cancel()

		idCtx, idCancel := context.WithTimeout(ctx, 600*time.Millisecond)
		if out, err := exec.CommandContext(idCtx, "/usr/bin/defaults", "read", infoPlist, "CFBundleIdentifier").Output(); err == nil {
			bundleID := strings.TrimSpace(string(out))
			if bundleID != "" {
				publisher = bundleID
			}
		}
		idCancel()

		apps = append(apps, SoftwareItem{
			Name:        appTitle,
			Version:     version,
			Publisher:   publisher,
			InstallDate: installDate,
		})
	}

	return apps
}

func (m *MacAgentCollector) collectInterfaces() ([]NetworkInterface, string, string) {
	m.workerSem <- struct{}{}
	defer func() { <-m.workerSem }()

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, "127.0.0.1", "00:00:00:00:00:00"
	}

	var out []NetworkInterface
	primaryIP := "127.0.0.1"
	primaryMAC := "00:00:00:00:00:00"

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		// Abaikan interface virtual awdl0 / llw0 / utun pada macOS jika bukan interface utama
		if strings.HasPrefix(iface.Name, "awdl") || strings.HasPrefix(iface.Name, "llw") {
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
			isPrimary := len(out) == 0
			if isPrimary {
				primaryIP = ipStr
				primaryMAC = mac
			}

			out = append(out, NetworkInterface{
				Name:       iface.Name,
				IPAddress:  ipStr,
				MACAddress: mac,
				SpeedMbps:  1000,
				VLANID:     1,
				RxMbps:     0.0,
				TxMbps:     0.0,
				IsPrimary:  isPrimary,
			})
			break
		}
	}

	return out, primaryIP, primaryMAC
}

func (m *MacAgentCollector) computeAdaptiveSchedule(cpuPct, ramPct float64) (time.Duration, string) {
	deltaCPU := math.Abs(cpuPct - m.lastCPUPct)
	m.lastCPUPct = cpuPct

	if cpuPct >= 85.0 || ramPct >= 90.0 || deltaCPU >= 25.0 {
		burst := m.baseInterval / 6
		if burst < 10*time.Second {
			burst = 10 * time.Second
		}
		return burst, "burst-event"
	}

	if cpuPct <= 20.0 && ramPct <= 50.0 && deltaCPU < 5.0 {
		eco := time.Duration(float64(m.baseInterval) * 1.5)
		if eco > 300*time.Second {
			eco = 300 * time.Second
		}
		return eco, "idle-eco"
	}

	return m.baseInterval, "standard"
}

func (m *MacAgentCollector) sendCompressedIngest(ctx context.Context, payload IngestPayload) (int, error) {
	buf := m.gzipBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer m.gzipBufPool.Put(buf)

	gz, err := gzip.NewWriterLevel(buf, gzip.BestSpeed)
	if err != nil {
		return 0, err
	}
	if err := json.NewEncoder(gz).Encode(payload); err != nil {
		_ = gz.Close()
		return 0, err
	}
	if err := gz.Close(); err != nil {
		return 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.serverURL+"/api/v1/agent/ingest", bytes.NewReader(buf.Bytes()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("User-Agent", "VectraNet-MacAgent/"+AgentVersion)
	if m.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+m.authToken)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var parsed IngestResponse
	if err := json.Unmarshal(body, &parsed); err == nil && parsed.NextHeartbeatSec >= 5 {
		return parsed.NextHeartbeatSec, nil
	}
	return 0, nil
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

func main() {
	serverFlag := flag.String("server", os.Getenv("VECTRANET_SERVER_URL"), "VectraNet Server URL")
	tokenFlag := flag.String("token", os.Getenv("VECTRANET_AGENT_TOKEN"), "Agent Bearer Token")
	intervalFlag := flag.Int("interval", 60, "Base heartbeat interval (seconds)")
	insecureFlag := flag.Bool("insecure", false, "Skip TLS verification")
	flag.Parse()

	if *serverFlag == "" {
		*serverFlag = "https://rmm.internal.corp:8443"
	}

	agent := NewMacAgentCollector(
		*serverFlag,
		*tokenFlag,
		time.Duration(*intervalFlag)*time.Second,
		*insecureFlag,
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "mac-endpoint"
	}

	// Inisialisasi profil hardware macOS saat startup
	agent.cachedHardware, agent.cachedOSVer = agent.collectMacHardwareProfile(ctx)
	log.Printf("[vectranet-macos-agent %s] started on %s (%s | Serial: %s | UUID: %s)",
		AgentVersion, hostname, agent.cachedHardware.ChipType, agent.cachedHardware.SerialNumber, agent.cachedHardware.HardwareUUID)

	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[vectranet-macos-agent] shutting down cleanly")
			return
		case <-timer.C:
			ifaces, primaryIP, primaryMAC := agent.collectInterfaces()
			cpuPct, ramTot, ramUsed, diskTot, diskUsed := agent.collectDarwinTelemetry(ctx)

			if agent.cycleCount%AppScanCycleMod == 0 {
				agent.cachedApps = agent.collectApplications(ctx)
			}
			agent.cycleCount++

			ramPct := 0.0
			if ramTot > 0 {
				ramPct = (ramUsed / ramTot) * 100.0
			}
			nextInterval, mode := agent.computeAdaptiveSchedule(cpuPct, ramPct)

			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			rssMB := float64(ms.Sys) / (1024.0 * 1024.0)

			payload := IngestPayload{
				AgentVersion:     AgentVersion,
				Hostname:         hostname,
				IPAddress:        primaryIP,
				MACAddress:       primaryMAC,
				OSFamily:         "macOS",
				OSVersion:        agent.cachedOSVer,
				KernelArch:       "darwin/" + runtime.GOARCH,
				CPUModel:         agent.cachedHardware.ChipType,
				CPUCores:         runtime.NumCPU(),
				CPUUsagePct:      round2(cpuPct),
				RAMTotalGB:       round2(ramTot),
				RAMUsedGB:        round2(ramUsed),
				DiskTotalGB:      round2(diskTot),
				DiskUsedGB:       round2(diskUsed),
				AgentRSSMB:       round2(rssMB),
				HeartbeatMode:    mode,
				HardwareMetadata: agent.cachedHardware,
				Interfaces:       ifaces,
				Software:         agent.cachedApps,
				RecordedAt:       time.Now().UTC(),
			}

			overrideSec, err := agent.sendCompressedIngest(ctx, payload)
			if err != nil {
				log.Printf("[warn] macOS telemetry ingest failed: %v (retry in %v)", err, nextInterval)
			} else if overrideSec > 0 && mode == "standard" {
				nextInterval = time.Duration(overrideSec) * time.Second
			}

			timer.Reset(nextInterval)
		}
	}
}
