// Copyright 2026 Patrick Matthews and Affinity Ops Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"testing"
)

func TestDefaultPolicy_ScopeVocabulary(t *testing.T) {
	eng, err := NewEngine(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	in := func(scopes []string, action, status string) map[string]interface{} {
		s := make([]interface{}, len(scopes))
		for i, v := range scopes {
			s[i] = v
		}
		return map[string]interface{}{
			"evar_scopes": s, "action_scope": action, "agent_status": status,
			"action_cost": 0, "current_spend": 0, "spend_limit": 999999,
		}
	}
	cases := []struct {
		name   string
		scopes []string
		action string
		status string
		want   bool
	}{
		{"read scope allows read", []string{"proxy:read"}, "proxy:read", "certified", true},
		{"read scope does not allow write", []string{"proxy:read"}, "proxy:write", "certified", false},
		{"write scope allows write", []string{"proxy:read", "proxy:write"}, "proxy:write", "pending_review", true},
		{"write scope does not allow delete", []string{"proxy:write"}, "proxy:delete", "certified", false},
		{"proxy:call umbrella allows delete", []string{"proxy:call"}, "proxy:delete", "certified", true},
		{"proxy:call does not cover non-proxy actions", []string{"proxy:call"}, "db:drop", "certified", false},
		{"revoked agent denied even with scope", []string{"proxy:call"}, "proxy:read", "revoked", false},
		{"no scopes denied", []string{}, "proxy:read", "certified", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := eng.Evaluate(context.Background(), in(tc.scopes, tc.action, tc.status))
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("allow = %v, want %v", got, tc.want)
			}
		})
	}
}
