//go:build !linux

package kubeletshim

import (
	"context"
	"os"
	"os/exec"
)

// isolatedCmd falls back to a plain command off Linux (namespaces are a Linux
// feature; the shim only runs in a Linux container in production).
func (sh *Shim) isolatedCmd(ctx context.Context, args []string, sandbox execSandbox, _ string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = sandbox.env
	sandbox.applyOverride(cmd, args[0])
	return cmd
}

// RunExecInit is unreachable off Linux (the --exec-init re-exec path is only
// taken under execIsolation, which only builds those commands on Linux).
func RunExecInit([]string) { os.Exit(1) }
