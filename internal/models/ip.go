package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"net"
)

// IPAddr wraps net.IP with database Scan/Value support.
// Postgres inet columns are returned as strings by the pgx driver,
// so we implement sql.Scanner to parse them back into net.IP.
type IPAddr net.IP

func (ip IPAddr) String() string {
	return net.IP(ip).String()
}

func (ip *IPAddr) Scan(value interface{}) error {
	if value == nil {
		*ip = nil
		return nil
	}
	switch v := value.(type) {
	case string:
		*ip = IPAddr(net.ParseIP(v))
	case []byte:
		*ip = IPAddr(net.ParseIP(string(v)))
	default:
		return fmt.Errorf("IPAddr: unsupported type %T", value)
	}
	return nil
}

func (ip IPAddr) Value() (driver.Value, error) {
	if net.IP(ip) == nil {
		return nil, nil
	}
	return net.IP(ip).String(), nil
}

func (ip IPAddr) MarshalJSON() ([]byte, error) {
	if net.IP(ip) == nil {
		return []byte("null"), nil
	}
	return json.Marshal(net.IP(ip).String())
}

func (ip *IPAddr) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*ip = IPAddr(net.ParseIP(s))
	return nil
}
