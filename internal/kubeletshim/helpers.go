package kubeletshim

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/fnv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"honeypod.io/honeypod/internal/seed"
)

// hexBlob returns the first n bytes of a stable digest of seed, hex encoded.
// Everything in this package that needs a believable-but-deterministic
// identifier -- container IDs, image IDs, UIDs, machine identity, replica
// suffixes -- is derived from this one primitive rather than hashing inline,
// so they cannot drift apart in shape.
func hexBlob(seed string, n int) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:n])
}

// uuidFrom formats a stable digest of seed as a dashed UUID.
func uuidFrom(seed string) string {
	h := hexBlob(seed, 16)
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

// hash32 is a stable non-cryptographic hash of s, for values that must look
// arbitrary but stay identical across restarts and heartbeats: pod IPs,
// restart counts, the synthesized resource usage in stats.go.
func hash32(s string) uint32 {
	f := fnv.New32a()
	_, _ = f.Write([]byte(s))
	return f.Sum32()
}

// replicaSuffix derives the suffix for the Nth replica of a FakePod. It is
// a hash, not a random value, so re-seeding the same spec always produces
// the same pod names and upserts stay idempotent.
func replicaSuffix(base string, n int32) string {
	return hexBlob(fmt.Sprintf("%s-%d", base, n), 5)
}

// fakeContainerID builds a believable containerd container ID for a fake
// container. Real running containers have a "containerd://<64 hex>" ID;
// an empty one gives a fake pod away under `kubectl describe`. Derived from
// the pod and container names so it is stable across re-seeds, the way a
// real container ID is stable until the container restarts.
func fakeContainerID(podName, containerName string) string {
	return "containerd://" + hexBlob("containerid/"+podName+"/"+containerName, 32)
}

// fakeImageID builds a believable image ID for a fake container's image.
// Real ones look like "<image>@sha256:<64 hex>"; an empty one is another
// describe-level tell. Deterministic from the image reference.
func fakeImageID(image string) string {
	return image + "@sha256:" + hexBlob("imageid/"+image, 32)
}

// resolveOwnerRefs converts the seed's minimal owner refs into API owner
// references, marking them as controller + blockOwnerDeletion like a real
// controller-created object. The UID is the one the apiserver actually
// assigned the owner object (recorded in objectUIDs while seeding it), so a
// pod's ownerReference matches its owner's real UID; a not-yet-seen owner
// falls back to a stable derived UID.
func (sh *Shim) resolveOwnerRefs(refs []seed.OwnerRef) []metav1.OwnerReference {
	if len(refs) == 0 {
		return nil
	}
	ctrlTrue := true
	out := make([]metav1.OwnerReference, 0, len(refs))
	for _, r := range refs {
		uid, ok := sh.objectUIDs[r.Kind+"/"+r.Name]
		if !ok {
			uid = fakeUID(r.Kind + "/" + r.Name)
		}
		out = append(out, metav1.OwnerReference{
			APIVersion:         r.APIVersion,
			Kind:               r.Kind,
			Name:               r.Name,
			UID:                uid,
			Controller:         &ctrlTrue,
			BlockOwnerDeletion: &ctrlTrue,
		})
	}
	return out
}

// fakeUID derives a stable, believable UID from a seed key, so an owner
// reference (and the owning object it points at) carry a consistent UID
// across re-seeds -- a real object's UID never changes.
func fakeUID(key string) types.UID {
	return types.UID(uuidFrom("uid/" + key))
}
