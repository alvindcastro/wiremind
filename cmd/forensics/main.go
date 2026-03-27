package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
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
)

func init() {
	parseCmd.Flags().StringVar(&flagInput, "input", "file", "Input source type: file|live|pipe|pcapng|ssh|afpacket|zeek|s3|vpc|kafka")
	parseCmd.Flags().StringVar(&flagFile, "file", "", "Path to .pcap or .pcapng file (for --input file|pcapng)")
	parseCmd.Flags().StringVar(&flagInterface, "interface", "", "Network interface (for --input live|afpacket)")
	parseCmd.Flags().StringVar(&flagOutput, "output", "./output", "Directory to write JSON output files")
	parseCmd.Flags().StringVar(&flagConfig, "config", "config/config.yaml", "Path to config file")

	rootCmd.AddCommand(parseCmd)
}

func runParse(cmd *cobra.Command, args []string) error {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	slog.Info("parse started", "input", flagInput, "output", flagOutput)

	// TODO: Step 5 — NewPacketSource → Parse → WriteJSON
	fmt.Println("parse: not yet implemented")
	return nil
}
