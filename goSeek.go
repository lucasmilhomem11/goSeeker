package main

import (
    "context"
    "crypto/tls"
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "net"
    "os"
    "os/signal"
    "sort"
    "strconv"
    "strings"
    "sync"
    "syscall"
    "time"
    
    "github.com/zs5460/art"
    "github.com/fatih/color"
)

// Constants for the application
const (
    maxRetries    = 2
    defaultWorkers = 1500
    bannerSize    = 1024
)

// PortInfo stores information about a scanned port
type PortInfo struct {
    Port     int       `json:"port"`
    State    string    `json:"state"`
    Service  string    `json:"service"`
    Banner   string    `json:"banner,omitempty"`
    SSLInfo  *SSLInfo  `json:"ssl_info,omitempty"`
}

// SSLInfo stores SSL/TLS information for a port
type SSLInfo struct {
    Version     string    `json:"version"`
    Cipher      string    `json:"cipher"`
    CertExpires string    `json:"cert_expires,omitempty"`
}

// ScanResult stores the complete scan results for a host
type ScanResult struct {
    IP            string               `json:"ip"`
    Timestamp     string              `json:"timestamp"`
    OpenPorts     map[int]*PortInfo   `json:"ports"`
    ScanDuration  string              `json:"scan_duration"`
    PortsScanned  int                 `json:"ports_scanned"`
}

// Scanner represents the port scanner configuration
type Scanner struct {
    target    string
    ports     []int
    timeout   time.Duration
    workers   int
    output    string
    verbose   bool
    ctx       context.Context
    cancel    context.CancelFunc
}

// NewScanner creates a new Scanner instance
func NewScanner(target string, ports []int, timeout time.Duration, workers int, output string, verbose bool) *Scanner {
    ctx, cancel := context.WithCancel(context.Background())
    return &Scanner{
        target:    target,
        ports:     ports,
        timeout:   timeout,
        workers:   workers,
        output:    output,
        verbose:   verbose,
        ctx:       ctx,
        cancel:    cancel,
    }
}

// scanPort attempts to connect to a single port
func (s *Scanner) scanPort(ip string, port int) *PortInfo {
    target := fmt.Sprintf("%s:%d", ip, port)
    d := net.Dialer{Timeout: s.timeout}
    
    conn, err := d.DialContext(s.ctx, "tcp", target)
    if err != nil {
        return nil
    }
    defer conn.Close()

    info := &PortInfo{
        Port:    port,
        State:   "open",
        Service: getServiceName(port),
    }

    // Try SSL/TLS detection
    if isTLSPort(port) {
        tlsConn := tls.Client(conn, &tls.Config{
            InsecureSkipVerify: true,
            ServerName:         ip,
        })
        
        // Set deadline for TLS handshake
        tlsConn.SetDeadline(time.Now().Add(s.timeout))
        
        if err := tlsConn.Handshake(); err == nil {
            state := tlsConn.ConnectionState()
            info.SSLInfo = &SSLInfo{
                Version: tlsVersionToString(state.Version),
                Cipher:  tls.CipherSuiteName(state.CipherSuite),
            }
            
            // Get certificate expiration if available
            if len(state.PeerCertificates) > 0 {
                info.SSLInfo.CertExpires = state.PeerCertificates[0].NotAfter.Format(time.RFC3339)
            }
        }
        tlsConn.Close()
    }

    // Try banner grabbing
    if err := conn.SetDeadline(time.Now().Add(s.timeout)); err == nil {
        // Try HTTP first
        httpBanner := tryHTTPBanner(conn)
        if httpBanner != "" {
            info.Banner = httpBanner
        } else {
            // Try raw banner grab
            banner := make([]byte, bannerSize)
            if n, err := conn.Read(banner); err == nil {
                info.Banner = string(banner[:n])
            }
        }
    }

    return info
}

// tryHTTPBanner attempts to get an HTTP banner
func tryHTTPBanner(conn net.Conn) string {
    _, err := conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
    if err != nil {
        return ""
    }

    banner := make([]byte, bannerSize)
    n, err := conn.Read(banner)
    if err != nil {
        return ""
    }

    return string(banner[:n])
}

// worker processes ports from the queue
func (s *Scanner) worker(ports <-chan int, results chan<- *PortInfo, wg *sync.WaitGroup) {
    defer wg.Done()

    for port := range ports {
        select {
        case <-s.ctx.Done():
            return
        default:
            if info := s.scanPort(s.target, port); info != nil {
                results <- info
            }
        }
    }
}

// Scan performs the port scanning
func (s *Scanner) Scan() (*ScanResult, error) {
    startTime := time.Now()
    
    // Setup result
    result := &ScanResult{
        IP:        s.target,
        Timestamp: startTime.Format(time.RFC3339),
        OpenPorts: make(map[int]*PortInfo),
    }

    // Create buffered channels
    portsChan := make(chan int, len(s.ports))
    resultsChan := make(chan *PortInfo, len(s.ports))
    
    // Start workers
    var wg sync.WaitGroup
    for i := 0; i < s.workers; i++ {
        wg.Add(1)
        go s.worker(portsChan, resultsChan, &wg)
    }

    // Feed ports to workers
    go func() {
        for _, port := range s.ports {
            portsChan <- port
        }
        close(portsChan)
    }()

    // Wait for workers in a goroutine
    go func() {
        wg.Wait()
        close(resultsChan)
    }()

    // Collect results
    for info := range resultsChan {
        result.OpenPorts[info.Port] = info
    }

    // Set final statistics
    result.ScanDuration = time.Since(startTime).String()
    result.PortsScanned = len(s.ports)

    return result, nil
}

// PrintResults displays the scan results
func (s *Scanner) PrintResults(result *ScanResult) {
    // Sort ports for display
    var ports []int
    for port := range result.OpenPorts {
        ports = append(ports, port)
    }
    sort.Ints(ports)

    // Create colored output
    titleColor := color.New(color.FgHiCyan, color.Bold)
    portColor := color.New(color.FgGreen)
    infoColor := color.New(color.FgYellow)

    titleColor.Printf("\nScan Results for %s\n", result.IP)
    fmt.Printf("Scan duration: %s\n", result.ScanDuration)
    fmt.Printf("Ports scanned: %d\n", result.PortsScanned)
    portColor.Printf("Open ports found: %d\n\n", len(result.OpenPorts))

    for _, port := range ports {
        info := result.OpenPorts[port]
        portColor.Printf("Port %d:\n", port)
        infoColor.Printf("  Service: %s\n", info.Service)
        
        if info.SSLInfo != nil {
            infoColor.Printf("  SSL Version: %s\n", info.SSLInfo.Version)
            infoColor.Printf("  SSL Cipher: %s\n", info.SSLInfo.Cipher)
            if info.SSLInfo.CertExpires != "" {
                infoColor.Printf("  Cert Expires: %s\n", info.SSLInfo.CertExpires)
            }
        }
        
        if info.Banner != "" {
            infoColor.Printf("  Banner: %s\n", strings.TrimSpace(info.Banner))
        }
        fmt.Println()
    }
}

// SaveResults saves the scan results to a file
func (s *Scanner) SaveResults(result *ScanResult) error {
    if s.output == "" {
        return nil
    }

    data, err := json.MarshalIndent(result, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal results: %v", err)
    }

    if err := os.WriteFile(s.output, data, 0644); err != nil {
        return fmt.Errorf("failed to write results: %v", err)
    }

    fmt.Printf("Results saved to: %s\n", s.output)
    return nil
}

// getServiceName returns the service name for a port
func getServiceName(port int) string {
    services := map[int]string{
        20:    "FTP-DATA",           // File Transfer Protocol (Data)
        21:    "FTP",                 // File Transfer Protocol (Control)
        22:    "SSH",                 // Secure Shell
        23:    "TELNET",              // Telnet Protocol
        25:    "SMTP",                // Simple Mail Transfer Protocol
        53:    "DNS",                 // Domain Name System
        67:    "DHCP",                // Dynamic Host Configuration Protocol (Server)
        68:    "DHCP-Client",         // Dynamic Host Configuration Protocol (Client)
        80:    "HTTP",                // Hypertext Transfer Protocol
        110:   "POP3",                // Post Office Protocol v3
        111:   "RPCBIND",            // Remote Procedure Call (RPC)
        135:   "MSRPC",               // Microsoft RPC
        137:   "NETBIOS-NAME",        // NetBIOS Name Service
        138:   "NETBIOS-DATAGRAM",    // NetBIOS Datagram Service
        139:   "NETBIOS-SESSION",      // NetBIOS Session Service
        143:   "IMAP",                // Internet Message Access Protocol
        161:   "SNMP",                // Simple Network Management Protocol
        162:   "SNMP-TRAP",           // SNMP Trap
        443:   "HTTPS",               // Hypertext Transfer Protocol Secure
        445:   "SMB",                 // Server Message Block
        465:   "SMTP-SSL",            // SMTP over SSL
        587:   "SMTP-Submission",      // SMTP (Submission)
        636:   "LDAPS",               // LDAP over SSL
        993:   "IMAPS",               // IMAP over SSL
        995:   "POP3S",               // POP3 over SSL
        1720:  "H.323",               // H.323 Call Signaling
        1723:  "PPTP",                // Point-to-Point Tunneling Protocol
        3306:  "MYSQL",               // MySQL Database
        3389:  "RDP",                 // Remote Desktop Protocol
        5060:  "SIP",                 // Session Initiation Protocol
        5061:  "SIP-TLS",             // SIP over TLS
        5900:  "VNC",                 // Virtual Network Computing
        6379:  "REDIS",               // Redis Database
        8080:  "HTTP-PROXY",          // HTTP Proxy
        8443:  "HTTPS-ALT",           // Alternative HTTPS
        9000:  "PHP-Server",          // PHP Built-in Web Server
        9200:  "ELASTICSEARCH",        // Elasticsearch
        9300:  "ELASTICSEARCH-TRANSPORT", // Elasticsearch Transport
        27017: "MONGODB",             // MongoDB
    }
    
    if service, ok := services[port]; ok {
        return service
    }
    return "unknown"
}

// isTLSPort checks if the port commonly uses SSL/TLS
func isTLSPort(port int) bool {
    tlsPorts := map[int]bool{
        443:   true,
        465:   true,
        636:   true,
        993:   true,
        995:   true,
        8443:  true,
        9443:  true,
    }
    return tlsPorts[port]
}

// tlsVersionToString converts TLS version to string
func tlsVersionToString(version uint16) string {
    versions := map[uint16]string{
        tls.VersionTLS10: "TLS 1.0",
        tls.VersionTLS11: "TLS 1.1",
        tls.VersionTLS12: "TLS 1.2",
        tls.VersionTLS13: "TLS 1.3",
    }
    if v, ok := versions[version]; ok {
        return v
    }
    return "unknown"
}

// parsePorts parses the port specification string
func parsePorts(portsFlag string) ([]int, error) {
    var ports []int
    ranges := strings.Split(portsFlag, ",")
    
    for _, r := range ranges {
        r = strings.TrimSpace(r)
        if strings.Contains(r, "-") {
            parts := strings.Split(r, "-")
            if len(parts) != 2 {
                return nil, fmt.Errorf("invalid port range: %s", r)
            }
            
            start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
            if err != nil {
                return nil, fmt.Errorf("invalid start port: %s", parts[0])
            }
            
            end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
            if err != nil {
                return nil, fmt.Errorf("invalid end port: %s", parts[1])
            }
            
            if start > end {
                return nil, fmt.Errorf("invalid port range: %d-%d", start, end)
            }
            
            for port := start; port <= end; port++ {
                ports = append(ports, port)
            }
        } else {
            port, err := strconv.Atoi(r)
            if err != nil {
                return nil, fmt.Errorf("invalid port: %s", r)
            }
            ports = append(ports, port)
        }
    }
    
    return ports, nil
}

func main() {
    // Parse command line flags
    target := flag.String("target", "", "Target IP address")
    portsFlag := flag.String("ports", "1-1024", "Port range to scan (e.g., 80,443 or 1-1024)")
    timeout := flag.Duration("timeout", time.Second, "Timeout for each port scan")
    workers := flag.Int("workers", defaultWorkers, "Number of concurrent workers")
    output := flag.String("output", "", "Output file for results (JSON)")
    verbose := flag.Bool("verbose", false, "Enable verbose output")
    flag.Parse()

    // Colors defined for ascii
    lightGreen := color.New(color.FgHiGreen).Add(color.Bold)
    blue := color.New(color.FgBlue).Add(color.Bold)

    blue.Print(art.String("goSeeker"))
    lightGreen.Print("By Lucas Milhomem - CypherSentry\n\n\n")

    // Validate target
    if *target == "" {
        log.Fatal("Please specify a target IP address")
    }

    // Parse ports
    ports, err := parsePorts(*portsFlag)
    if err != nil {
        log.Fatalf("Invalid port specification: %v", err)
    }

    // Create scanner
    scanner := NewScanner(*target, ports, *timeout, *workers, *output, *verbose)

    // Setup signal handling
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        <-sigChan
        fmt.Println("\nScan interrupted, cleaning up...")
        scanner.cancel()
    }()

    // Start scan
    fmt.Printf("Starting scan of %s (%d ports)\n", *target, len(ports))
    result, err := scanner.Scan()
    if err != nil {
        log.Fatalf("Scan failed: %v", err)
    }

    // Print and save results
    scanner.PrintResults(result)
    if err := scanner.SaveResults(result); err != nil {
        log.Printf("Failed to save results: %v", err)
    }
}