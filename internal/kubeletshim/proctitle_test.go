package kubeletshim

import "testing"

// TestWriteTitle covers the byte-level rewrite MaskProcessTitle applies to the
// argv region: the new title lands at the front, and no tail of the old,
// longer content survives (a leftover "--seed=..." would still unmask it).
func TestWriteTitle(t *testing.T) {
	// The real argv region is longer than "/pause", the common case.
	buf := []byte("/kubelet-shim --seed=/etc/kubernetes/seed/seed.json --client-token-file=x")
	writeTitle(buf, procTitle)

	if string(buf[:len(procTitle)]) != procTitle {
		t.Fatalf("title not written at the front: %q", string(buf[:len(procTitle)]))
	}
	for i := len(procTitle); i < len(buf); i++ {
		if buf[i] != 0 {
			t.Fatalf("byte %d not zeroed, old content leaks: %q", i, string(buf))
		}
	}
	// Sanity: none of the giveaway substrings survive anywhere.
	for _, bad := range []string{"kubelet-shim", "seed", "token"} {
		if containsSub(buf, bad) {
			t.Fatalf("masked argv still contains %q", bad)
		}
	}
}

func TestWriteTitle_TruncatesWhenRegionSmaller(t *testing.T) {
	buf := []byte("abc") // smaller than procTitle "/pause"
	writeTitle(buf, procTitle)
	if string(buf) != procTitle[:3] {
		t.Fatalf("expected truncation to region size, got %q", string(buf))
	}
}

func containsSub(b []byte, sub string) bool {
	s, n := string(b), len(sub)
	for i := 0; i+n <= len(s); i++ {
		if s[i:i+n] == sub {
			return true
		}
	}
	return false
}
