package observability

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestAuditLog(t *testing.T) {
	var output bytes.Buffer
	audit := AuditLog{Logger: slog.New(slog.NewJSONHandler(&output, nil))}
	audit.Record(context.Background(), "login", map[string]string{"outcome": "success", "issuer_id": "default"})
	logged := output.String()
	if !strings.Contains(logged, `"event":"login"`) || !strings.Contains(logged, `"outcome":"success"`) {
		t.Fatalf("log %s", logged)
	}
}
