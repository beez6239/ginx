package core

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/kgretzky/evilginx2/log"
)

type BlockIP struct {
	ipv4 net.IP
	mask *net.IPNet
}

type Blacklist struct {
	ips        map[string]*BlockIP
	masks      []*BlockIP
	whitelist  map[string]bool
	whitelistCIDR []*net.IPNet
	configPath string
	verbose    bool
	mu         sync.RWMutex
	
	// Country whitelist
	allowedCountries map[string]bool
	countryMode     bool
}

func NewBlacklist(path string) (*Blacklist, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bl := &Blacklist{
		ips:              make(map[string]*BlockIP),
		whitelist:        make(map[string]bool),
		whitelistCIDR:    make([]*net.IPNet, 0),
		configPath:       path,
		verbose:          true,
		allowedCountries: make(map[string]bool),
		countryMode:      false,
	}

	// Load blacklist from file
	fs := bufio.NewScanner(f)
	fs.Split(bufio.ScanLines)

	for fs.Scan() {
		l := fs.Text()
		// remove comments
		if n := strings.Index(l, ";"); n > -1 {
			l = l[:n]
		}
		l = strings.Trim(l, " ")

		if len(l) > 0 {
			if strings.Contains(l, "/") {
				ipv4, mask, err := net.ParseCIDR(l)
				if err == nil {
					bl.masks = append(bl.masks, &BlockIP{ipv4: ipv4, mask: mask})
				} else {
					log.Error("blacklist: invalid ip/mask address: %s", l)
				}
			} else {
				ipv4 := net.ParseIP(l)
				if ipv4 != nil {
					bl.ips[ipv4.String()] = &BlockIP{ipv4: ipv4, mask: nil}
				} else {
					log.Error("blacklist: invalid ip address: %s", l)
				}
			}
		}
	}

	// Load whitelist from file
	whitelistPath := getWhitelistPath(path)
	bl.loadWhitelist(whitelistPath)

	// Load country whitelist from file
	countryPath := getCountryConfigPath(path)
	bl.loadCountryConfig(countryPath)

	log.Info("blacklist: loaded %d ip addresses, %d ip masks", len(bl.ips), len(bl.masks))
	log.Info("whitelist: loaded %d ip addresses and %d CIDR ranges", len(bl.whitelist), len(bl.whitelistCIDR))
	if bl.countryMode {
		log.Info("country whitelist: loaded %d countries", len(bl.allowedCountries))
	}
	
	return bl, nil
}

func getWhitelistPath(blacklistPath string) string {
	dir := filepath.Dir(blacklistPath)
	return filepath.Join(dir, "whitelist.txt")
}

func getCountryConfigPath(blacklistPath string) string {
	dir := filepath.Dir(blacklistPath)
	return filepath.Join(dir, "countries.txt")
}

func (bl *Blacklist) loadWhitelist(path string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		log.Warning("whitelist: could not open file: %v", err)
		bl.whitelist["127.0.0.1"] = true
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Check for CIDR notation
		if strings.Contains(line, "/") {
			_, ipnet, err := net.ParseCIDR(line)
			if err == nil {
				bl.whitelistCIDR = append(bl.whitelistCIDR, ipnet)
				log.Debug("whitelist: added CIDR %s", line)
				continue
			}
			log.Warning("whitelist: invalid CIDR: %s", line)
			continue
		}
		
		// Single IP
		ip := net.ParseIP(line)
		if ip != nil {
			bl.whitelist[ip.String()] = true
		} else {
			log.Warning("whitelist: invalid IP: %s", line)
		}
	}
	
	// Always ensure localhost is whitelisted
	bl.whitelist["127.0.0.1"] = true
}

func (bl *Blacklist) loadCountryConfig(path string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		log.Debug("country whitelist: no config file found at %s", path)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Country code format: US, GB, DE, etc.
		code := strings.ToUpper(strings.TrimSpace(line))
		if len(code) == 2 && isAlpha(code) {
			bl.allowedCountries[code] = true
			bl.countryMode = true
		} else {
			log.Warning("country whitelist: invalid country code: %s", line)
		}
	}
	
	if bl.countryMode {
		log.Info("country whitelist: enabled for: %v", bl.allowedCountries)
	}
}

func isAlpha(s string) bool {
	for _, r := range s {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
			return false
		}
	}
	return true
}

func (bl *Blacklist) GetStats() (int, int, int, int) {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	return len(bl.ips), len(bl.masks), len(bl.whitelist), len(bl.whitelistCIDR)
}

func (bl *Blacklist) AddIP(ip string) error {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	
	if bl.IsBlacklisted(ip) {
		return nil
	}

	ipv4 := net.ParseIP(ip)
	if ipv4 != nil {
		bl.ips[ipv4.String()] = &BlockIP{ipv4: ipv4, mask: nil}
	} else {
		return fmt.Errorf("invalid ip address: %s", ip)
	}

	// write to file
	f, err := os.OpenFile(bl.configPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(ipv4.String() + "\n")
	return err
}

func (bl *Blacklist) IsBlacklisted(ip string) bool {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	
	ipv4 := net.ParseIP(ip)
	if ipv4 == nil {
		return false
	}

	// Check whitelist (exact IP)
	if _, ok := bl.whitelist[ip]; ok {
		if bl.verbose {
			log.Debug("whitelist: %s is whitelisted (exact match)", ip)
		}
		return false
	}
	
	// Check CIDR whitelist
	for _, cidr := range bl.whitelistCIDR {
		if cidr.Contains(ipv4) {
			if bl.verbose {
				log.Debug("whitelist: %s is whitelisted (CIDR match)", ip)
			}
			return false
		}
	}
	
	// Check country whitelist (using MaxMind GeoIP)
	if bl.countryMode && bl.isCountryAllowed(ipv4) {
		if bl.verbose {
			log.Debug("whitelist: %s is whitelisted (country match)", ip)
		}
		return false
	}

	// Check blacklist
	if _, ok := bl.ips[ip]; ok {
		if bl.verbose {
			log.Debug("blacklist: %s is blacklisted (exact match)", ip)
		}
		return true
	}
	for _, m := range bl.masks {
		if m.mask != nil && m.mask.Contains(ipv4) {
			if bl.verbose {
				log.Debug("blacklist: %s is blacklisted (CIDR match)", ip)
			}
			return true
		}
	}
	return false
}

func (bl *Blacklist) isCountryAllowed(ip net.IP) bool {
	// This is a placeholder for GeoIP lookup
	// To fully enable country whitelist, you need to:
	// 1. Install GeoIP database: apt-get install geoipupdate && geoipupdate
	// 2. Import: go get github.com/oschwald/geoip2-golang
	// 3. Uncomment the code below
	
	
	// Initialize GeoIP reader if not already done
	if bl.geoDB == nil {
		geoPaths := []string{
			"/usr/share/GeoIP/GeoLite2-Country.mmdb",
			"/var/lib/GeoIP/GeoLite2-Country.mmdb",
		}
		for _, path := range geoPaths {
			if _, err := os.Stat(path); err == nil {
				bl.geoDB, err = geoip2.Open(path)
				if err == nil {
					break
				}
			}
		}
	}
	
	if bl.geoDB != nil {
		record, err := bl.geoDB.Country(ip)
		if err == nil {
			return bl.allowedCountries[record.Country.IsoCode]
		}
	}
	
	
	// Without GeoIP, country whitelist doesn't work
	// Return false to block everything unless explicitly whitelisted
	return false
}

func (bl *Blacklist) SetVerbose(verbose bool) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	bl.verbose = verbose
}

func (bl *Blacklist) IsVerbose() bool {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	return bl.verbose
}

func (bl *Blacklist) IsWhitelisted(ip string) bool {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	
	ipv4 := net.ParseIP(ip)
	if ipv4 == nil {
		return false
	}
	
	// Check exact match
	if _, ok := bl.whitelist[ip]; ok {
		return true
	}
	
	// Check CIDR match
	for _, cidr := range bl.whitelistCIDR {
		if cidr.Contains(ipv4) {
			return true
		}
	}
	
	// Check country match
	if bl.countryMode && bl.isCountryAllowed(ipv4) {
		return true
	}
	
	return false
}