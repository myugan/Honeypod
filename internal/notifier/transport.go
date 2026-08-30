package notifier

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
)

func (d *Dispatcher) httpClient() *http.Client {
	if d.HTTPClient != nil {
		return d.HTTPClient
	}
	return http.DefaultClient
}

// postJSON POSTs body to address and treats any non-2xx response as an error.
func (d *Dispatcher) postJSON(ctx context.Context, address string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("%s returned %d: %s", address, resp.StatusCode, b)
	}
	return nil
}
