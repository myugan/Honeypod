package notifier

import (
	"context"
	"encoding/json"
	"strconv"
	"time"
)

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

type lokiPushRequest struct {
	Streams []lokiStream `json:"streams"`
}

// sendLoki pushes lines as one stream to a Loki push-API address
// (typically ending in /loki/api/v1/push). Loki requires strictly
// increasing per-stream timestamps, so lines are spread a nanosecond apart.
func (d *Dispatcher) sendLoki(ctx context.Context, address string, labels map[string]string, lines []string) error {
	now := time.Now()
	values := make([][2]string, len(lines))
	for i, line := range lines {
		ts := now.Add(time.Duration(i) * time.Nanosecond).UnixNano()
		values[i] = [2]string{strconv.FormatInt(ts, 10), line}
	}
	body, err := json.Marshal(lokiPushRequest{Streams: []lokiStream{{Stream: labels, Values: values}}})
	if err != nil {
		return err
	}
	return d.postJSON(ctx, address, body)
}
