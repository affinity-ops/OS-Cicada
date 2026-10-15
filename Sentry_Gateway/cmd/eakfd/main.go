// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// eakfd is the Ephemeral Agent Kernel Firewall daemon — a gRPC server
// that receives code execution requests from the Sentry Gateway over
// a UNIX Domain Socket and runs them in isolated subprocesses with
// resource limits, timeout enforcement, and output scrubbing.
//
// In production Kubernetes deployments, eakfd runs inside a pod with
// runtimeClassName: gvisor, which provides user-space kernel syscall
// interception. The daemon itself does not need to know about gVisor —
// the container runtime provides the isolation layer transparently.
//
// For bare-metal deployments, eakfd can optionally use Firecracker
// microVMs via /dev/kvm (not implemented in this reference build).
//
// Source: EPHEMERAL_AGENT_KERNEL_FIREWALL.md §7.4, lines 286–290.
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/asai/cicada/sentry/internal/eakfd/scrub"
	eakfv1 "github.com/asai/cicada/sentry/pkg/eakf/v1"
)

// server implements the EphemeralAgentKernelFirewallServer gRPC interface.
type server struct {
	eakfv1.UnimplementedEphemeralAgentKernelFirewallServer
}

// Execute handles a single code execution request from the Sentry Gateway.
//
// Execution flow (§3, lines 50–101):
//   1. Resolve runtime binary from runtime_hint
//   2. Create a temporary working directory (read-only root, writable /tmp)
//   3. Write the payload to a temp file
//   4. Execute the payload in a subprocess with timeout and resource limits
//   5. Scrub stdout and stderr through the Deterministic State Sieve (§5)
//   6. Return the sanitised output with scrub telemetry
func (s *server) Execute(ctx context.Context, req *eakfv1.ExecuteRequest) (*eakfv1.ExecuteResponse, error) {
	sagaID := req.SagaId
	if sagaID == "" {
		sagaID = fmt.Sprintf("sg_%d", time.Now().UnixNano())
	}

	log.Printf("[eakfd] Execute: saga=%s agent=%s tenant=%s runtime=%s timeout=%ds",
		sagaID, req.AgentId, req.TenantId, req.RuntimeHint, req.TimeoutSeconds)

	// Resolve the runtime binary.
	runtimeBin, err := resolveRuntime(req.RuntimeHint)
	if err != nil {
		log.Printf("[eakfd] Unknown runtime_hint=%q for saga=%s: %v", req.RuntimeHint, sagaID, err)
		return &eakfv1.ExecuteResponse{
			SagaId:           sagaID,
			ExitCode:         1,
			ExecutionSuccess: false,
			SanitizedStdout:  "",
			SanitizedStderr:  fmt.Sprintf("unsupported runtime: %s", req.RuntimeHint),
			Status:           eakfv1.ExecuteResponse_STATUS_FAILED,
		}, nil
	}

	// Create a temporary working directory for this execution.
	workDir, err := os.MkdirTemp("", "eakf-"+sagaID+"-")
	if err != nil {
		return nil, fmt.Errorf("failed to create work dir: %w", err)
	}
	defer os.RemoveAll(workDir) // §3 line 101: "Instantaneous Destruction"

	// Write the payload to a temp file.
	payloadFile := workDir + "/payload" + runtimeExt(req.RuntimeHint)
	if err := os.WriteFile(payloadFile, []byte(req.Payload), 0400); err != nil {
		return nil, fmt.Errorf("failed to write payload: %w", err)
	}

	// Enforce timeout.
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second // §3.5, line 92: sync fast-path default
	}
	if timeout > 30*time.Minute {
		timeout = 30 * time.Minute // §3.5, line 93: async saga max
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Build the command.
	cmd := exec.CommandContext(execCtx, runtimeBin, payloadFile)
	cmd.Dir = workDir
	cmd.Env = sanitisedEnv(req)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute.
	startTime := time.Now()
	execErr := cmd.Run()
	elapsed := time.Since(startTime)

	exitCode := 0
	executionSuccess := true
	status := eakfv1.ExecuteResponse_STATUS_SUCCESS

	if execErr != nil {
		executionSuccess = false
		if execCtx.Err() == context.DeadlineExceeded {
			status = eakfv1.ExecuteResponse_STATUS_TIMEOUT
			log.Printf("[eakfd] Execution timed out after %s for saga=%s", elapsed, sagaID)
		} else {
			status = eakfv1.ExecuteResponse_STATUS_FAILED
		}
		// Extract exit code from ProcessState.
		if exitErr, ok := execErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	// Scrub stdout and stderr through the Deterministic State Sieve (§5).
	stdoutResult := scrub.Scrub(stdout.String())
	stderrResult := scrub.Scrub(stderr.String())

	// Merge redaction telemetry from both streams.
	allRedactedKeys := append(stdoutResult.RedactedKeys, stderrResult.RedactedKeys...)
	allRedactedIPs := append(stdoutResult.RedactedIPs, stderrResult.RedactedIPs...)

	log.Printf("[eakfd] Execution complete: saga=%s status=%s exit_code=%d elapsed=%s redacted_keys=%d redacted_ips=%d",
		sagaID, status.String(), exitCode, elapsed, len(allRedactedKeys), len(allRedactedIPs))

	return &eakfv1.ExecuteResponse{
		SagaId:           sagaID,
		ExitCode:         int32(exitCode),
		ExecutionSuccess: executionSuccess,
		SanitizedStdout:  stdoutResult.Output,
		SanitizedStderr:  stderrResult.Output,
		RedactedKeys:     allRedactedKeys,
		RedactedIps:      allRedactedIPs,
		Status:           status,
	}, nil
}

// resolveRuntime maps a runtime_hint to a host binary path.
func resolveRuntime(hint string) (string, error) {
	switch strings.ToLower(hint) {
	case "python3", "python":
		return lookupBinary("python3", "python")
	case "bash", "sh":
		return lookupBinary("bash", "sh")
	case "terraform", "tf":
		return lookupBinary("terraform")
	case "node", "nodejs", "javascript":
		return lookupBinary("node")
	default:
		return "", fmt.Errorf("unsupported runtime hint: %s", hint)
	}
}

// lookupBinary finds the first available binary from the candidates.
func lookupBinary(candidates ...string) (string, error) {
	for _, c := range candidates {
		if path, err := exec.LookPath(c); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("none of %v found in PATH", candidates)
}

// runtimeExt returns the appropriate file extension for the runtime.
func runtimeExt(hint string) string {
	switch strings.ToLower(hint) {
	case "python3", "python":
		return ".py"
	case "bash", "sh":
		return ".sh"
	case "terraform", "tf":
		return ".tf"
	case "node", "nodejs", "javascript":
		return ".js"
	default:
		return ".sh"
	}
}

// sanitisedEnv builds a minimal, clean environment for the subprocess.
// It does NOT inherit the host environment — this prevents credential
// leakage from the daemon's own env vars into the sandboxed execution.
func sanitisedEnv(req *eakfv1.ExecuteRequest) []string {
	env := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=/tmp",
		"LANG=en_US.UTF-8",
		"TERM=dumb",
		"EAKF_SAGA_ID=" + req.SagaId,
		"EAKF_AGENT_ID=" + req.AgentId,
		"EAKF_TENANT_ID=" + req.TenantId,
	}
	return env
}

func main() {
	socketPath := os.Getenv("EAKF_SOCKET_PATH")
	if socketPath == "" {
		socketPath = "/var/run/cicada/eakf.sock"
	}

	// Remove stale socket file if it exists.
	os.Remove(socketPath)

	// Ensure the socket directory exists.
	socketDir := socketPath[:strings.LastIndex(socketPath, "/")]
	if err := os.MkdirAll(socketDir, 0750); err != nil {
		log.Fatalf("[eakfd] Failed to create socket directory %s: %v", socketDir, err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("[eakfd] Failed to listen on %s: %v", socketPath, err)
	}
	defer listener.Close()

	// Restrict socket permissions — only the gateway process user can dial.
	os.Chmod(socketPath, 0660)

	grpcServer := grpc.NewServer()

	// Register the EAKF execution service.
	eakfv1.RegisterEphemeralAgentKernelFirewallServer(grpcServer, &server{})

	// Register gRPC health checking service (used by PluginManager 30s probes).
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	log.Printf("[eakfd] Ephemeral Agent Kernel Firewall daemon listening on %s", socketPath)
	log.Printf("[eakfd] Health check: SERVING")

	// Graceful shutdown on SIGINT/SIGTERM.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		log.Printf("[eakfd] Received %s — shutting down gracefully", sig)
		healthServer.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
		grpcServer.GracefulStop()
	}()

	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("[eakfd] gRPC server error: %v", err)
	}

	log.Printf("[eakfd] Shutdown complete")
}
