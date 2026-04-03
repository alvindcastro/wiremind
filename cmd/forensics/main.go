package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"wiremind/config"
	"wiremind/internal/api"
	"wiremind/internal/enrichment"
	"wiremind/internal/input"
	"wiremind/internal/output"
	"wiremind/internal/parser"
	"wiremind/internal/queue"
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

var workerCmd = &cobra.Command{
	Use:   "worker",
	Short: "Start a background worker to process PCAPs from Redis",
	RunE:  runWorker,
}

var (
	flagInput     string
	flagFile      string
	flagInterface string
	flagOutput    string
	flagConfig    string
	flagServe     bool
	flagAsync     bool
)

func init() {
	parseCmd.Flags().StringVar(&flagInput, "input", "file", "Input source type: file|pcapng|live|pipe")
	parseCmd.Flags().StringVar(&flagFile, "file", "", "Path to .pcap or .pcapng file (for --input file|pcapng)")
	parseCmd.Flags().StringVar(&flagInterface, "interface", "", "Network interface name (for --input live)")
	parseCmd.Flags().StringVar(&flagOutput, "output", "./output", "Directory to write JSON output files")
	parseCmd.Flags().StringVar(&flagConfig, "config", "config/config.yaml", "Path to config file")
	parseCmd.Flags().BoolVar(&flagServe, "serve", false, "Start the HTTP API server after parsing")
	parseCmd.Flags().BoolVar(&flagAsync, "async", false, "Push job to Redis instead of processing immediately")

	workerCmd.Flags().StringVar(&flagConfig, "config", "config/config.yaml", "Path to config file")

	rootCmd.AddCommand(parseCmd)
	rootCmd.AddCommand(workerCmd)
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

	// --- redis ------------------------------------------------------------
	if flagAsync {
		if !cfg.Redis.Enabled {
			return fmt.Errorf("redis must be enabled in config for --async mode")
		}

		q, err := queue.NewRedisQueue(cfg.Redis)
		if err != nil {
			return fmt.Errorf("connect to redis: %w", err)
		}
		defer q.Close()

		job := queue.Job{
			ID:         uuid.New().String(),
			InputPath:  flagFile,
			OutputPath: cfg.OutputDir,
			CreatedAt:  time.Now(),
		}

		if err := q.PublishJob(context.Background(), job); err != nil {
			return fmt.Errorf("publish job: %w", err)
		}

		slog.Info("job published to redis", "job_id", job.ID, "file", flagFile)
		return nil
	}

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

func runWorker(cmd *cobra.Command, args []string) error {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg, err := config.Load(flagConfig)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if !cfg.Redis.Enabled {
		return fmt.Errorf("redis must be enabled for worker mode")
	}

	q, err := queue.NewRedisQueue(cfg.Redis)
	if err != nil {
		return fmt.Errorf("connect to redis: %w", err)
	}
	defer q.Close()

	ep, err := enrichment.NewPipeline(cfg)
	if err != nil {
		return fmt.Errorf("init enrichment pipeline: %w", err)
	}
	defer ep.Close()

	var db *store.PostgresStore
	if cfg.Postgres.Enabled {
		db, err = store.NewPostgresStore(cfg.Postgres)
		if err != nil {
			slog.Warn("failed to connect to postgres, skipping DB persistence", "err", err)
		} else {
			defer db.Close()
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("worker started, waiting for jobs...")

	for {
		select {
		case <-ctx.Done():
			slog.Info("worker shutting down")
			return nil
		default:
			job, err := q.ConsumeJob(ctx)
			if err != nil {
				if err == context.Canceled {
					return nil
				}
				slog.Error("failed to consume job", "err", err)
				time.Sleep(2 * time.Second)
				continue
			}

			slog.Info("processing job", "job_id", job.ID, "file", job.InputPath)

			// Process job (simplified version of runParse logic)
			src, err := input.NewPacketSource(input.SourceFile, input.SourceConfig{
				FilePath: job.InputPath,
			})
			if err != nil {
				slog.Error("failed to create source", "err", err, "job_id", job.ID)
				continue
			}

			if err := src.Open(); err != nil {
				slog.Error("failed to open source", "err", err, "job_id", job.ID)
				continue
			}

			result := parser.Parse(src, cfg)
			src.Close()

			enriched := ep.Enrich(result)

			// Write output
			outDir := job.OutputPath
			if outDir == "" {
				outDir = cfg.OutputDir
			}

			if err := output.WriteJSON(result, outDir); err != nil {
				slog.Error("failed to write raw output", "err", err, "job_id", job.ID)
			}
			if err := output.WriteEnrichedJSON(enriched, filepath.Join(outDir, "enriched")); err != nil {
				slog.Error("failed to write enriched output", "err", err, "job_id", job.ID)
			}
			if db != nil {
				if err := output.WriteToPostgres(enriched, db); err != nil {
					slog.Error("failed to persist to postgres", "err", err, "job_id", job.ID)
				}
			}

			slog.Info("job completed", "job_id", job.ID, "packets", result.Stats.TotalPackets)
		}
	}
}
