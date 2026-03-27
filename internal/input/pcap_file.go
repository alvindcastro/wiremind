package input

import "errors"

// newPCAPFileSource is implemented in Step 4.
func newPCAPFileSource(_ SourceConfig) (PacketSource, error) {
	return nil, errors.New("input: pcap file source not yet implemented")
}
