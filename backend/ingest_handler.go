// ============================================================================
// VECTRANET BACKEND INGESTION & INSTALLER DISTRIBUTION SERVER
// File: backend/ingest_handler.go
// Run:  go get github.com/jackc/pgx/v5/pgxpool && go run backend/ingest_handler.go
// ============================================================================
package main

import (
	"compress/gzip"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type NetworkInterfaceDTO struct {
	Name       string  `json:"interface_name"`
	IPAddress  string  `json:"ip_address"`
	MACAddress string  `json:"mac_address"`
	SpeedMbps  int     `json:"speed_mbps"`
	VLANID     int     `json:"vlan_id"`
	RxMbps     float64 `json:"rx_mbps"`
	TxMbps     float64 `json:"tx_mbps"`
	IsPrimary  bool    `json:"is_primary"`
}

type SoftwareItemDTO struct {
	Name        string `json:"software_name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher"`
	InstallDate string `json:"install_date"`
}

type AgentIngestRequest struct {
	AgentVersion     string                `json:"agent_version"`
	Hostname         string                `json:"hostname"`
	IPAddress        string                `json:"ip_address"`
	MACAddress       string                `json:"mac_address"`
	OSFamily         string                `json:"os_family"`
	OSVersion        string                `json:"os_version"`
	KernelArch       string                `json:"kernel_arch"`
	CPUModel         string                `json:"cpu_model"`
	CPUCores         int                   `json:"cpu_cores"`
	CPUUsagePct      float64               `json:"cpu_usage_pct"`
	RAMTotalGB       float64               `json:"ram_total_gb"`
	RAMUsedGB        float64               `json:"ram_used_gb"`
	DiskTotalGB      float64               `json:"disk_total_gb"`
	DiskUsedGB       float64               `json:"disk_used_gb"`
	AgentRSSMB       float64               `json:"agent_rss_mb"`
	HeartbeatMode    string                `json:"heartbeat_mode"`
	HardwareMetadata map[string]any        `json:"hardware_metadata,omitempty"`
	Interfaces       []NetworkInterfaceDTO `json:"interfaces"`
	Software         []SoftwareItemDTO     `json:"software"`
	RecordedAt       time.Time             `json:"recorded_at"`
}

type IngestHandler struct {
	dbPool        *pgxpool.Pool
	expectedToken string
}

func NewIngestHandler(dbPool *pgxpool.Pool, expectedToken string) *IngestHandler {
	return &IngestHandler{
		dbPool:        dbPool,
		expectedToken: expectedToken,
	}
}

func (h *IngestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	if h.expectedToken != "" {
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(h.expectedToken)) != 1 {
			http.Error(w, `{"error":"unauthorized agent token"}`, http.StatusUnauthorized)
			return
		}
	}

	var bodyReader io.Reader = io.LimitReader(r.Body, 2*1024*1024)
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		gzReader, err := gzip.NewReader(bodyReader)
		if err != nil {
			http.Error(w, `{"error":"invalid gzip stream"}`, http.StatusBadRequest)
			return
		}
		defer gzReader.Close()
		bodyReader = gzReader
	}

	var payload AgentIngestRequest
	if err := json.NewDecoder(bodyReader).Decode(&payload); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid json payload: %v"}`, err), http.StatusBadRequest)
		return
	}

	if payload.MACAddress == "" || payload.Hostname == "" {
		http.Error(w, `{"error":"hostname and mac_address are required"}`, http.StatusUnprocessableEntity)
		return
	}
	if payload.RecordedAt.IsZero() {
		payload.RecordedAt = time.Now().UTC()
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	deviceID, err := h.persistTelemetryTransaction(ctx, payload)
	if err != nil {
		log.Printf("[error] database persistence failed for host=%s: %v", payload.Hostname, err)
		http.Error(w, `{"error":"internal database error"}`, http.StatusInternalServerError)
		return
	}

	nextHeartbeat := 60
	if payload.CPUUsagePct >= 85.0 || (payload.RAMTotalGB > 0 && (payload.RAMUsedGB/payload.RAMTotalGB)*100.0 >= 90.0) {
		nextHeartbeat = 10
	} else if payload.CPUUsagePct <= 20.0 {
		nextHeartbeat = 90
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":             "ingested",
		"device_id":          deviceID,
		"next_heartbeat_sec": nextHeartbeat,
	})
}

func (h *IngestHandler) persistTelemetryTransaction(ctx context.Context, p AgentIngestRequest) (string, error) {
	tx, err := h.dbPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	deviceStatus := "online"
	ramPct := 0.0
	if p.RAMTotalGB > 0 {
		ramPct = (p.RAMUsedGB / p.RAMTotalGB) * 100.0
	}
	if p.CPUUsagePct >= 85.0 || ramPct >= 90.0 {
		deviceStatus = "warning"
	}

	hwMetaJSON := []byte(`{}`)
	if len(p.HardwareMetadata) > 0 {
		if b, err := json.Marshal(p.HardwareMetadata); err == nil {
			hwMetaJSON = b
		}
	}

	var deviceID string
	upsertDeviceSQL := `
		INSERT INTO devices (
			hostname, ip_address, mac_address, os_family, os_version, kernel_arch,
			device_role, status, agent_state, agent_version, agent_memory_mb,
			cpu_model, cpu_cores, ram_total_gb, disk_total_gb, hardware_metadata, last_seen, updated_at
		) VALUES (
			$1, $2::inet, $3::macaddr, $4, $5, $6,
			'server', $7, 'active', $8, $9,
			$10, $11, $12, $13, $14::jsonb, NOW(), NOW()
		)
		ON CONFLICT (mac_address) DO UPDATE SET
			hostname          = EXCLUDED.hostname,
			ip_address        = EXCLUDED.ip_address,
			os_family         = EXCLUDED.os_family,
			os_version        = EXCLUDED.os_version,
			kernel_arch       = EXCLUDED.kernel_arch,
			status            = EXCLUDED.status,
			agent_state       = 'active',
			agent_version     = EXCLUDED.agent_version,
			agent_memory_mb   = EXCLUDED.agent_memory_mb,
			cpu_model         = EXCLUDED.cpu_model,
			cpu_cores         = EXCLUDED.cpu_cores,
			ram_total_gb      = EXCLUDED.ram_total_gb,
			disk_total_gb     = EXCLUDED.disk_total_gb,
			hardware_metadata = EXCLUDED.hardware_metadata,
			last_seen         = NOW(),
			updated_at        = NOW()
		RETURNING id;
	`
	err = tx.QueryRow(
		ctx,
		upsertDeviceSQL,
		p.Hostname,
		p.IPAddress,
		p.MACAddress,
		p.OSFamily,
		p.OSVersion,
		p.KernelArch,
		deviceStatus,
		p.AgentVersion,
		p.AgentRSSMB,
		p.CPUModel,
		p.CPUCores,
		p.RAMTotalGB,
		p.DiskTotalGB,
		string(hwMetaJSON),
	).Scan(&deviceID)
	if err != nil {
		return "", fmt.Errorf("upsert devices failed: %w", err)
	}

	var totalRxMbps, totalTxMbps float64
	upsertIfaceSQL := `
		INSERT INTO network_interfaces (
			device_id, interface_name, ip_address, mac_address,
			speed_mbps, vlan_id, rx_mbps, tx_mbps, is_primary, updated_at
		) VALUES (
			$1, $2, $3::inet, $4::macaddr,
			$5, $6, $7, $8, $9, NOW()
		)
		ON CONFLICT (device_id, interface_name) DO UPDATE SET
			ip_address = EXCLUDED.ip_address,
			mac_address = EXCLUDED.mac_address,
			speed_mbps = EXCLUDED.speed_mbps,
			vlan_id    = EXCLUDED.vlan_id,
			rx_mbps    = EXCLUDED.rx_mbps,
			tx_mbps    = EXCLUDED.tx_mbps,
			is_primary = EXCLUDED.is_primary,
			updated_at = NOW();
	`
	for _, iface := range p.Interfaces {
		totalRxMbps += iface.RxMbps
		totalTxMbps += iface.TxMbps
		if _, err := tx.Exec(
			ctx,
			upsertIfaceSQL,
			deviceID,
			iface.Name,
			iface.IPAddress,
			iface.MACAddress,
			iface.SpeedMbps,
			iface.VLANID,
			iface.RxMbps,
			iface.TxMbps,
			iface.IsPrimary,
		); err != nil {
			return "", fmt.Errorf("upsert network_interface %s failed: %w", iface.Name, err)
		}
	}

	if len(p.Software) > 0 {
		upsertSoftwareSQL := `
			INSERT INTO installed_software (
				device_id, software_name, version, publisher, install_date, detected_at
			) VALUES (
				$1, $2, $3, $4, NULLIF($5, '')::date, NOW()
			)
			ON CONFLICT (device_id, software_name, version) DO UPDATE SET
				publisher   = EXCLUDED.publisher,
				detected_at = NOW();
		`
		for _, sw := range p.Software {
			if sw.Name == "" || sw.Version == "" {
				continue
			}
			if _, err := tx.Exec(
				ctx,
				upsertSoftwareSQL,
				deviceID,
				sw.Name,
				sw.Version,
				sw.Publisher,
				sw.InstallDate,
			); err != nil {
				return "", fmt.Errorf("upsert software %s failed: %w", sw.Name, err)
			}
		}
	}

	insertTelemetrySQL := `
		INSERT INTO telemetry_logs (
			recorded_at, device_id, cpu_usage_pct, ram_used_gb, disk_used_gb,
			net_rx_mbps, net_tx_mbps, agent_rss_mb, heartbeat_mode
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		);
	`
	_, err = tx.Exec(
		ctx,
		insertTelemetrySQL,
		p.RecordedAt,
		deviceID,
		math.Round(p.CPUUsagePct*100)/100,
		math.Round(p.RAMUsedGB*100)/100,
		math.Round(p.DiskUsedGB*100)/100,
		math.Round(totalRxMbps*100)/100,
		math.Round(totalTxMbps*100)/100,
		math.Round(p.AgentRSSMB*100)/100,
		p.HeartbeatMode,
	)
	if err != nil {
		return "", fmt.Errorf("insert telemetry_logs failed: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return deviceID, nil
}

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://vectranet_admin:secret@127.0.0.1:5432/vectranet_cmdb?sslmode=disable"
	}
	agentToken := os.Getenv("VECTRANET_AGENT_TOKEN")
	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8443"
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	poolCfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		log.Fatalf("[fatal] invalid DATABASE_URL: %v", err)
	}
	poolCfg.MaxConns = 32
	poolCfg.MinConns = 4
	poolCfg.MaxConnIdleTime = 5 * time.Minute

	dbPool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		log.Fatalf("[fatal] failed to connect to PostgreSQL pool: %v", err)
	}
	defer dbPool.Close()

	mux := http.NewServeMux()
	// 1. Endpoint Ingest Telemetri Agen (Windows / Linux / macOS)
	mux.Handle("/api/v1/agent/ingest", NewIngestHandler(dbPool, agentToken))

	// 2. Endpoint Distribusi Skrip Installer (/agents/{windows,linux,macos}/install.{ps1,sh})
	mux.Handle("/agents/", http.StripPrefix("/agents/", http.FileServer(http.Dir("./agents"))))

	// 3. Endpoint Distribusi Biner Agen Hasil Build (/downloads/{windows,linux,macos}/*)
	mux.Handle("/downloads/", http.StripPrefix("/downloads/", http.FileServer(http.Dir("./downloads"))))

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("[vectranet-backend] listening on %s", listenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[fatal] server error: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
