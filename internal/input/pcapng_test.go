package input

import (
	"path/filepath"
	"runtime"
	"testing"
)

func fixturePath(name string) string {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	return filepath.Join(root, "scripts", "sample_pcaps", name)
}

func TestPCAPNGSource_RequiresFilePath(t *testing.T) {
	_, err := newPCAPNGSource(SourceConfig{})
	if err == nil {
		t.Error("expected error for empty file path, got nil")
	}
}

func TestPCAPNGSource_NonExistentFile(t *testing.T) {
	src, err := newPCAPNGSource(SourceConfig{FilePath: "nonexistent.pcapng"})
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}
	if err := src.Open(); err == nil {
		t.Error("expected error opening nonexistent file, got nil")
		src.Close()
	}
}

func TestPCAPNGSource_ReadsPackets(t *testing.T) {
	// Skip for now as we don't have a sample pcapng file in repo
	t.Skip("skipping pcapng test, no sample pcapng file available")

	src, err := newPCAPNGSource(SourceConfig{FilePath: fixturePath("sample.pcapng")})
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	if err := src.Open(); err != nil {
		t.Fatalf("open source: %v", err)
	}
	defer src.Close()

	if src.Meta().Type != SourcePCAPNG {
		t.Errorf("Meta.Type = %q, want %q", src.Meta().Type, SourcePCAPNG)
	}

	count := 0
	for range src.Packets() {
		count++
	}
	if count == 0 {
		t.Error("received 0 packets, want > 0")
	}
}
