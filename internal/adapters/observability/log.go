package observability

import (
	"context"
	"log/slog"
)

type AuditLog struct{ Logger *slog.Logger }

func (a AuditLog) Record(ctx context.Context, event string, fields map[string]string) {
	arguments := make([]any, 0, len(fields)*2+2)
	arguments = append(arguments, "event", event)
	for key, value := range fields {
		arguments = append(arguments, key, value)
	}
	a.Logger.InfoContext(ctx, "audit", arguments...)
}
