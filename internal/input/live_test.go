package input

import (
	"testing"
)

func TestLiveSource_RequiresInterface(t *testing.T) {
	_, err := newLiveSource(SourceConfig{})
	if err == nil {
		t.Error("expected error for empty interface, got nil")
	}
}

func TestLiveSource_InvalidInterface(t *testing.T) {
	src, err := newLiveSource(SourceConfig{Interface: "nonexistent99"})
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}
	// Open() should fail because the interface doesn't exist
	if err := src.Open(); err == nil {
		t.Error("expected error opening nonexistent interface, got nil")
		src.Close()
	}
}

func TestLiveSource_Meta(t *testing.T) {
	src, err := newLiveSource(SourceConfig{Interface: "eth0"})
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	// Don't call Open() — just check the type is correct after construction
	ls := src.(*LiveSource)
	if ls.cfg.Interface != "eth0" {
		t.Errorf("Interface = %q, want eth0", ls.cfg.Interface)
	}
}
