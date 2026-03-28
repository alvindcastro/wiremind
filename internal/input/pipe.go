package input

import "errors"

// newPipeSource is implemented in Step 9c.
func newPipeSource(_ SourceConfig) (PacketSource, error) {
	return nil, errors.New("input: stdin/pipe source not yet implemented")
}
