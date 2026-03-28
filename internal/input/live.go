package input

import "errors"

// newLiveSource is implemented in Step 9b.
func newLiveSource(_ SourceConfig) (PacketSource, error) {
	return nil, errors.New("input: live capture not yet implemented")
}
