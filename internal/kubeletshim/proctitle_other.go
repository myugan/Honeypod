//go:build !linux

package kubeletshim

// MaskProcessTitle is a no-op off Linux (the shim only ever runs in a Linux
// container in production; this keeps the package building on other OSes).
func MaskProcessTitle() {}
