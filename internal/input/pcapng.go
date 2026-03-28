package input

import "errors"

// newPCAPNGSource is implemented in Step 9a.
func newPCAPNGSource(_ SourceConfig) (PacketSource, error) {
	return nil, errors.New("input: pcapng source not yet implemented")
}
