//go:build quickjs && cgo

package main

import (
	"bufio"
	contextpkg "context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/metacubex/mihomo/component/quickjs"
)

func main() {
	network := flag.Bool("network", false, "run DNS, TCP loopback, and TLS certificate checks")
	flag.Parse()

	if err := run(*network); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(network bool) (retErr error) {
	runtime, err := quickjs.NewRuntime(quickjs.RuntimeOptions{})
	if err != nil {
		return fmt.Errorf("create QuickJS Runtime: %w", err)
	}
	defer func() {
		if err := runtime.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close QuickJS Runtime: %w", err))
		}
	}()

	context, err := runtime.NewContext()
	if err != nil {
		return fmt.Errorf("create QuickJS Context: %w", err)
	}
	defer func() {
		if err := context.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close QuickJS Context: %w", err))
		}
	}()

	result, err := context.Eval("1 + 2")
	if err != nil {
		return fmt.Errorf("evaluate QuickJS expression: %w", err)
	}
	if result != "3" {
		return fmt.Errorf("QuickJS Eval returned %q, want %q", result, "3")
	}
	fmt.Println("QuickJS Eval: PASS (1 + 2 = 3)")

	if network {
		if err := checkDNS(); err != nil {
			return err
		}
		if err := checkTCPLoopback(); err != nil {
			return err
		}
		if err := checkTLSCertificateLookup(); err != nil {
			return err
		}
	}
	return nil
}

func checkDNS() error {
	ctx, cancel := contextpkg.WithTimeout(contextpkg.Background(), 10*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupHost(ctx, "example.com")
	if err != nil {
		return fmt.Errorf("DNS lookup example.com: %w", err)
	}
	if len(addresses) == 0 {
		return errors.New("DNS lookup example.com returned no addresses")
	}
	fmt.Printf("DNS lookup: PASS (%d address(es))\n", len(addresses))
	return nil
}

func checkTCPLoopback() error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen on TCP loopback: %w", err)
	}
	defer listener.Close()

	serverResult := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverResult <- fmt.Errorf("accept TCP loopback connection: %w", err)
			return
		}
		defer connection.Close()
		_, err = io.Copy(connection, connection)
		serverResult <- err
	}()

	connection, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial TCP loopback: %w", err)
	}
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(connection, "mitmhomo-quickjs-smoke\n"); err != nil {
		_ = connection.Close()
		return fmt.Errorf("write to TCP loopback: %w", err)
	}
	response, err := bufio.NewReader(connection).ReadString('\n')
	_ = connection.Close()
	if err != nil {
		return fmt.Errorf("read from TCP loopback: %w", err)
	}
	if response != "mitmhomo-quickjs-smoke\n" {
		return fmt.Errorf("TCP loopback returned %q", response)
	}
	if err := <-serverResult; err != nil {
		return fmt.Errorf("TCP loopback server: %w", err)
	}
	fmt.Println("TCP loopback: PASS")
	return nil
}

func checkTLSCertificateLookup() error {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return fmt.Errorf("read system certificate pool: %w", err)
	}
	if roots == nil || len(roots.Subjects()) == 0 {
		return errors.New("system certificate pool is empty")
	}

	client := http.Client{Timeout: 15 * time.Second}
	response, err := client.Get("https://example.com/")
	if err != nil {
		return fmt.Errorf("HTTPS certificate validation: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("HTTPS request returned status %s", response.Status)
	}
	fmt.Printf("TLS certificate lookup: PASS (%d system root(s), HTTP %s)\n", len(roots.Subjects()), response.Status)
	return nil
}
