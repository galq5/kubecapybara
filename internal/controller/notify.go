package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Notification is sent when a finding fires or resolves.
type Notification struct {
	Event     string    `json:"event"` // firing or resolved
	Cluster   string    `json:"cluster,omitempty"`
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	Rule      string    `json:"rule"`
	Severity  string    `json:"severity"`
	Category  string    `json:"category"`
	Title     string    `json:"title"`
	Details   []string  `json:"details,omitempty"`
	Hint      string    `json:"hint,omitempty"`
	Time      time.Time `json:"time"`
}

// Notifier delivers notifications.
type Notifier interface {
	Notify(ctx context.Context, n Notification) error
}

// Multi sends to several notifiers.
type Multi []Notifier

// Notify implements Notifier.
func (m Multi) Notify(ctx context.Context, n Notification) error {
	var errs []error
	for _, x := range m {
		errs = append(errs, x.Notify(ctx, n))
	}
	return errors.Join(errs...)
}

// Webhook POSTs notifications as JSON, or as a Slack message when Slack is
// set (Slack incoming webhooks; also works with Mattermost).
type Webhook struct {
	URL    string
	Slack  bool
	Client *http.Client
}

// SlackText formats a notification for chat.
func SlackText(n Notification) string {
	icon := map[string]string{"CRIT": ":red_circle:", "WARN": ":large_orange_circle:", "INFO": ":large_blue_circle:"}[n.Severity]
	var b strings.Builder
	if n.Event == "resolved" {
		icon = ":white_check_mark:"
		fmt.Fprintf(&b, "%s *resolved* %s", icon, n.Title)
	} else {
		fmt.Fprintf(&b, "%s *%s* %s", icon, n.Severity, n.Title)
	}
	if n.Cluster != "" {
		fmt.Fprintf(&b, " _(%s)_", n.Cluster)
	}
	if n.Event != "resolved" {
		for i, d := range n.Details {
			if i == 5 {
				fmt.Fprintf(&b, "\n• … %d more", len(n.Details)-5)
				break
			}
			fmt.Fprintf(&b, "\n• %s", d)
		}
		if n.Hint != "" {
			fmt.Fprintf(&b, "\n→ %s", n.Hint)
		}
	}
	fmt.Fprintf(&b, "\n`kubectl get capyfinding -n %s %s -o yaml`", n.Namespace, n.Name)
	return b.String()
}

// Notify implements Notifier.
func (w *Webhook) Notify(ctx context.Context, n Notification) error {
	var body any = n
	if w.Slack {
		body = map[string]string{"text": SlackText(n)}
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := w.Client
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook answered %s", resp.Status)
	}
	return nil
}
