package enrichment

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/oschwald/geoip2-golang"

	"wiremind/internal/models"
)

// GeoIPEnricher performs geographic and ASN lookups for IP addresses using
// MaxMind GeoLite2 databases. Both databases are optional — if a path is
// empty the corresponding fields in GeoInfo are left zero-valued.
//
// City DB  (GeoLite2-City.mmdb)  → CountryCode, CountryName, City, Lat/Lon
// ASN DB   (GeoLite2-ASN.mmdb)   → ASN, ASNOrg
//
// Private, loopback, and link-local addresses are returned immediately
// with only the IP field set — MaxMind databases have no data for these ranges.
type GeoIPEnricher struct {
	city *geoip2.Reader // nil if CityDBPath was empty
	asn  *geoip2.Reader // nil if ASNDBPath was empty
}

// NewGeoIPEnricher opens the configured MaxMind database files.
// At least one of cityDBPath or asnDBPath must be non-empty.
func NewGeoIPEnricher(cityDBPath, asnDBPath string) (*GeoIPEnricher, error) {
	if cityDBPath == "" && asnDBPath == "" {
		return nil, fmt.Errorf("geoip: at least one database path must be provided")
	}

	e := &GeoIPEnricher{}

	if cityDBPath != "" {
		r, err := geoip2.Open(cityDBPath)
		if err != nil {
			return nil, fmt.Errorf("geoip: open city db %s: %w", cityDBPath, err)
		}
		e.city = r
		slog.Info("geoip city db opened", "path", cityDBPath)
	}

	if asnDBPath != "" {
		r, err := geoip2.Open(asnDBPath)
		if err != nil {
			return nil, fmt.Errorf("geoip: open asn db %s: %w", asnDBPath, err)
		}
		e.asn = r
		slog.Info("geoip asn db opened", "path", asnDBPath)
	}

	return e, nil
}

// Lookup returns GeoInfo for ip. The result always has IP set.
// Fields that require a database that was not loaded are left zero-valued.
// Errors from individual lookups are logged at debug level and do not
// propagate — callers receive a partial result rather than a failure.
func (e *GeoIPEnricher) Lookup(ip net.IP) *models.GeoInfo {
	info := &models.GeoInfo{IP: ip.String()}

	if isPrivateIP(ip) {
		return info
	}

	if e.city != nil {
		rec, err := e.city.City(ip)
		if err != nil {
			slog.Debug("geoip city lookup failed", "ip", ip, "err", err)
		} else {
			info.CountryCode = rec.Country.IsoCode
			info.CountryName = rec.Country.Names["en"]
			info.City = rec.City.Names["en"]
			info.Latitude = rec.Location.Latitude
			info.Longitude = rec.Location.Longitude
		}
	}

	if e.asn != nil {
		rec, err := e.asn.ASN(ip)
		if err != nil {
			slog.Debug("geoip asn lookup failed", "ip", ip, "err", err)
		} else {
			info.ASN = uint(rec.AutonomousSystemNumber)
			info.ASNOrg = rec.AutonomousSystemOrganization
		}
	}

	return info
}

// Close releases the database file handles.
func (e *GeoIPEnricher) Close() {
	if e.city != nil {
		e.city.Close()
	}
	if e.asn != nil {
		e.asn.Close()
	}
}

// isPrivateIP reports whether ip is in a range that MaxMind databases
// have no data for: loopback, RFC1918, link-local, and the unspecified address.
func isPrivateIP(ip net.IP) bool {
	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fe80::/10",
		"169.254.0.0/16",
	}
	for _, cidr := range private {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return ip.IsUnspecified()
}
