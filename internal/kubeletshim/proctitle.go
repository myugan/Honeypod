package kubeletshim

// writeTitle overwrites buf with title: zero the whole region first (so no
// tail of the old, longer content survives), then copy title in, truncated to
// what fits. Pure and side-effect-free on its input so the argv-rewriting in
// MaskProcessTitle (platform-specific, hard to unit test) is exercised here.
func writeTitle(buf []byte, title string) {
	for i := range buf {
		buf[i] = 0
	}
	copy(buf, title)
}

// procTitle is the benign process title the shim masks itself with. An exec
// session runs a real process in the kubelet-shim container, whose PID 1 is
// this binary; without masking, `ps` / `cat /proc/1/cmdline` inside a decoy
// would print "/kubelet-shim --seed=/etc/kubernetes/seed/seed.json ...", which
// names the honeypot outright. "/pause" is the innocuous sandbox process every
// real pod already has.
const procTitle = "/pause"
