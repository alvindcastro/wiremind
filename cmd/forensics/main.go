package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"wiremind/config"
	"wiremind/internal/api"
	"wiremind/internal/enrichment"
	"wiremind/internal/input"
	"wiremind/internal/output"
	"wiremind/internal/parser"
	"wiremind/internal/store"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "forensics",
	Short: "Network forensics pipeline — parse PCAPs, detect threats, map to MITRE ATT&CK",
}

var parseCmd = &cobra.Command{
	Use:   "parse",
	Short: "Parse a packet source and emit structured JSON",
	RunE:  runParse,
}

var (
	flagInput     string
	flagFile      string
	flagInterface string
	flagOutput    string
	flagConfig    string
	flagServe     bool
)

func init() {
	parseCmd.Flags().StringVar(&flagInput, "input", "file", "Input source type: file|pcapng|live|pipe")
	parseCmd.Flags().StringVar(&flagFile, "file", "", "Path to .pcap or .pcapng file (for --input file|pcapng)")
	parseCmd.Flags().StringVar(&flagInterface, "interface", "", "Network interface name (for --input live)")
	parseCmd.Flags().StringVar(&flagOutput, "output", "./output", "Directory to write JSON output files")
	parseCmd.Flags().StringVar(&flagConfig, "config", "config/config.yaml", "Path to config file")
	parseCmd.Flags().BoolVar(&flagServe, "serve", false, "Start the HTTP API server after parsing")

	rootCmd.AddCommand(parseCmd)
}

func runParse(cmd *cobra.Command, args []string) error {
	// --- logger ------------------------------------------------------------
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// --- config ------------------------------------------------------------
	cfg, err := config.Load(flagConfig)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// honour --output flag over config value
	if flagOutput != "" {
		cfg.OutputDir = flagOutput
	}

	slog.Info("parse started",
		"input", flagInput,
		"output", cfg.OutputDir,
	)

	// --- source ------------------------------------------------------------
	src, err := input.NewPacketSource(input.SourceType(flagInput), input.SourceConfig{
		FilePath:  flagFile,
		Interface: flagInterface,
	})
	if err != nil {
		return fmt.Errorf("create source: %w", err)
	}

	if err := src.Open(); err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer src.Close()

	// --- parse -------------------------------------------------------------
	result := parser.Parse(src, cfg)

	// --- enrichment --------------------------------------------------------
	ep, err := enrichment.NewPipeline(cfg)
	if err != nil {
		return fmt.Errorf("init enrichment pipeline: %w", err)
	}
	defer ep.Close()

	enriched := ep.Enrich(result)

	// --- persistence -------------------------------------------------------
	var db *store.PostgresStore
	if cfg.Postgres.Enabled {
		db, err = store.NewPostgresStore(cfg.Postgres)
		if err != nil {
			slog.Warn("failed to connect to postgres, skipping DB persistence", "err", err)
		} else {
			defer db.Close()
		}
	}

	// --- write -------------------------------------------------------------
	if err := output.WriteJSON(result, cfg.OutputDir); err != nil {
		return fmt.Errorf("write raw output: %w", err)
	}

	// Write enriched results to filesystem
	if err := output.WriteEnrichedJSON(enriched, filepath.Join(cfg.OutputDir, "enriched")); err != nil {
		slog.Warn("failed to write enriched results", "err", err)
	}

	// Persist to Postgres if enabled
	if db != nil {
		if err := output.WriteToPostgres(enriched, db); err != nil {
			slog.Warn("failed to persist to postgres", "err", err)
		}
	}

	slog.Info("done",
		"packets", result.Stats.TotalPackets,
		"flows", len(result.Flows),
		"output", cfg.OutputDir,
	)

	if flagServe {
		srv := api.NewServer(cfg, ep, db)
		srv.UpdateResults(enriched)
		return srv.Start()
	}

	return nil
}
