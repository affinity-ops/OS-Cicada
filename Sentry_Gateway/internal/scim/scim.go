// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package scim implements SCIM 2.0 provisioning endpoints (S6.4).
//
// SCIM (System for Cross-domain Identity Management, RFC 7644) enables
// enterprise IdPs (Okta, Azure AD, Google Workspace) to automatically
// provision and deprovision operator accounts in Cicada.
//
// Supported operations:
//   - GET    /scim/v2/Users          — List/filter operators
//   - GET    /scim/v2/Users/{id}     — Get operator by ID
//   - POST   /scim/v2/Users          — Create operator
//   - PUT    /scim/v2/Users/{id}     — Replace operator
//   - PATCH  /scim/v2/Users/{id}     — Partial update (active status)
//   - DELETE /scim/v2/Users/{id}     — Deactivate operator
//
// Authentication: SCIM endpoints require a bearer token matching
// CICADA_SCIM_TOKEN (per-tenant in production).
package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ── SCIM Resource Types (RFC 7643) ───────────────────────────────────────────

// User is the SCIM User resource representation.
type User struct {
	Schemas    []string `json:"schemas"`
	ID         string   `json:"id"`
	ExternalID string   `json:"externalId,omitempty"`
	UserName   string   `json:"userName"`
	Name       *Name    `json:"name,omitempty"`
	Emails     []Email  `json:"emails,omitempty"`
	Active     bool     `json:"active"`
	DisplayName string  `json:"displayName,omitempty"`
	Role       string   `json:"roles,omitempty"` // Cicada extension
	Meta       *Meta    `json:"meta,omitempty"`
}

// Name represents the SCIM name attribute.
type Name struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	Formatted  string `json:"formatted,omitempty"`
}

// Email represents a SCIM email entry.
type Email struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// Meta is the SCIM resource metadata.
type Meta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
}

// ListResponse is the SCIM list response envelope.
type ListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []User   `json:"Resources"`
}

// PatchOp is a SCIM PATCH operation.
type PatchOp struct {
	Schemas    []string    `json:"schemas"`
	Operations []PatchItem `json:"Operations"`
}

// PatchItem is a single SCIM PATCH operation entry.
type PatchItem struct {
	Op    string      `json:"op"`
	Path  string      `json:"path,omitempty"`
	Value interface{} `json:"value"`
}

// ErrorResponse is the SCIM error format.
type ErrorResponse struct {
	Schemas  []string `json:"schemas"`
	Detail   string   `json:"detail"`
	Status   string   `json:"status"`
}

const (
	schemaCore  = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaList  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaPatch = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	schemaError = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// ── Handler Registration ─────────────────────────────────────────────────────

// RegisterRoutes mounts the SCIM 2.0 endpoints on the given router.
func RegisterRoutes(r chi.Router, db *pgxpool.Pool) {
	h := &handler{db: db}

	r.Route("/scim/v2", func(r chi.Router) {
		r.Use(h.authMiddleware)
		r.Get("/Users", h.listUsers)
		r.Post("/Users", h.createUser)
		r.Get("/Users/{id}", h.getUser)
		r.Put("/Users/{id}", h.replaceUser)
		r.Patch("/Users/{id}", h.patchUser)
		r.Delete("/Users/{id}", h.deleteUser)
	})
}

type handler struct {
	db *pgxpool.Pool
}

// ── Auth Middleware ───────────────────────────────────────────────────────────

func (h *handler) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := os.Getenv("CICADA_SCIM_TOKEN")
		if token == "" {
			scimError(w, "SCIM endpoint not configured", http.StatusServiceUnavailable)
			return
		}

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || strings.TrimPrefix(auth, "Bearer ") != token {
			scimError(w, "Invalid or missing bearer token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ── List Users ───────────────────────────────────────────────────────────────

func (h *handler) listUsers(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Cicada-Tenant-ID")
	filter := r.URL.Query().Get("filter")

	var rows interface{ Close() }
	var users []User
	var err error

	if filter != "" && strings.Contains(filter, "userName eq") {
		// Parse: userName eq "user@example.com"
		username := extractFilterValue(filter)
		row := h.db.QueryRow(r.Context(), `
			SELECT id, COALESCE(external_id,''), username, email,
			       COALESCE(display_name,''), COALESCE(given_name,''), COALESCE(family_name,''),
			       role, active, created_at, updated_at
			FROM operators WHERE tenant_id = $1::UUID AND username = $2 AND active = true
		`, tenantID, username)

		u, scanErr := scanUser(row)
		if scanErr == nil {
			users = append(users, u)
		}
		_ = rows // unused for single query
	} else {
		dbRows, qErr := h.db.Query(r.Context(), `
			SELECT id, COALESCE(external_id,''), username, email,
			       COALESCE(display_name,''), COALESCE(given_name,''), COALESCE(family_name,''),
			       role, active, created_at, updated_at
			FROM operators WHERE tenant_id = $1::UUID
			ORDER BY created_at DESC LIMIT 100
		`, tenantID)
		if qErr != nil {
			scimError(w, qErr.Error(), http.StatusInternalServerError)
			return
		}
		defer dbRows.Close()

		for dbRows.Next() {
			var u User
			var extID, username, email, displayName, givenName, familyName, role string
			var active bool
			var createdAt, updatedAt time.Time

			if err = dbRows.Scan(&u.ID, &extID, &username, &email,
				&displayName, &givenName, &familyName,
				&role, &active, &createdAt, &updatedAt); err != nil {
				continue
			}

			u = buildUser(u.ID, extID, username, email, displayName, givenName, familyName, role, active, createdAt, updatedAt)
			users = append(users, u)
		}
	}

	resp := ListResponse{
		Schemas:      []string{schemaList},
		TotalResults: len(users),
		StartIndex:   1,
		ItemsPerPage: len(users),
		Resources:    users,
	}

	w.Header().Set("Content-Type", "application/scim+json")
	json.NewEncoder(w).Encode(resp)
}

// ── Get User ─────────────────────────────────────────────────────────────────

func (h *handler) getUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	row := h.db.QueryRow(r.Context(), `
		SELECT id, COALESCE(external_id,''), username, email,
		       COALESCE(display_name,''), COALESCE(given_name,''), COALESCE(family_name,''),
		       role, active, created_at, updated_at
		FROM operators WHERE id = $1::UUID
	`, id)

	u, err := scanUser(row)
	if err != nil {
		scimError(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/scim+json")
	json.NewEncoder(w).Encode(u)
}

// ── Create User ──────────────────────────────────────────────────────────────

func (h *handler) createUser(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Cicada-Tenant-ID")
	var req User
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		scimError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	email := req.UserName
	if len(req.Emails) > 0 {
		email = req.Emails[0].Value
	}

	givenName, familyName := "", ""
	if req.Name != nil {
		givenName = req.Name.GivenName
		familyName = req.Name.FamilyName
	}

	role := "viewer"
	if req.Role != "" {
		role = req.Role
	}

	var id string
	err := h.db.QueryRow(r.Context(), `
		INSERT INTO operators (tenant_id, external_id, username, email, display_name,
		                       given_name, family_name, role, active)
		VALUES ($1::UUID, NULLIF($2,''), $3, $4, $5, $6, $7, $8, $9)
		RETURNING id
	`, tenantID, req.ExternalID, req.UserName, email, req.DisplayName,
		givenName, familyName, role, true,
	).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			scimError(w, "User already exists", http.StatusConflict)
		} else {
			scimError(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	h.auditLog(r.Context(), tenantID, id, "create", "scim/idp", nil)
	log.Printf("[SCIM] Created operator %s (%s) for tenant %s", req.UserName, id, tenantID)

	// Return the created user
	u := buildUser(id, req.ExternalID, req.UserName, email, req.DisplayName,
		givenName, familyName, role, true, time.Now(), time.Now())

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(u)
}

// ── Replace User (PUT) ──────────────────────────────────────────────────────

func (h *handler) replaceUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tenantID := r.Header.Get("X-Cicada-Tenant-ID")

	var req User
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		scimError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	email := req.UserName
	if len(req.Emails) > 0 {
		email = req.Emails[0].Value
	}
	givenName, familyName := "", ""
	if req.Name != nil {
		givenName = req.Name.GivenName
		familyName = req.Name.FamilyName
	}

	tag, err := h.db.Exec(r.Context(), `
		UPDATE operators SET
			external_id = NULLIF($2, ''), username = $3, email = $4,
			display_name = $5, given_name = $6, family_name = $7,
			active = $8, updated_at = NOW()
		WHERE id = $1::UUID
	`, id, req.ExternalID, req.UserName, email, req.DisplayName,
		givenName, familyName, req.Active)
	if err != nil || tag.RowsAffected() == 0 {
		scimError(w, "User not found", http.StatusNotFound)
		return
	}

	h.auditLog(r.Context(), tenantID, id, "update", "scim/idp", nil)

	u := buildUser(id, req.ExternalID, req.UserName, email, req.DisplayName,
		givenName, familyName, req.Role, req.Active, time.Now(), time.Now())

	w.Header().Set("Content-Type", "application/scim+json")
	json.NewEncoder(w).Encode(u)
}

// ── Patch User ───────────────────────────────────────────────────────────────

func (h *handler) patchUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tenantID := r.Header.Get("X-Cicada-Tenant-ID")

	var patch PatchOp
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		scimError(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	for _, op := range patch.Operations {
		switch strings.ToLower(op.Op) {
		case "replace":
			if strings.EqualFold(op.Path, "active") || op.Path == "" {
				active := false
				switch v := op.Value.(type) {
				case bool:
					active = v
				case map[string]interface{}:
					if a, ok := v["active"]; ok {
						active, _ = a.(bool)
					}
				}

				eventType := "deactivate"
				if active {
					eventType = "reactivate"
				}

				_, err := h.db.Exec(r.Context(), `
					UPDATE operators SET active = $2, updated_at = NOW(),
					       deprovisioned_at = CASE WHEN $2 = false THEN NOW() ELSE NULL END
					WHERE id = $1::UUID
				`, id, active)
				if err != nil {
					scimError(w, err.Error(), http.StatusInternalServerError)
					return
				}

				h.auditLog(r.Context(), tenantID, id, eventType, "scim/idp",
					map[string]interface{}{"active": active})
				log.Printf("[SCIM] %s operator %s (tenant %s)", eventType, id, tenantID)
			}
		}
	}

	// Return the updated user
	h.getUser(w, r)
}

// ── Delete User ──────────────────────────────────────────────────────────────

func (h *handler) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	tenantID := r.Header.Get("X-Cicada-Tenant-ID")

	// Soft-delete: deactivate rather than remove
	_, err := h.db.Exec(r.Context(), `
		UPDATE operators SET active = false, deprovisioned_at = NOW(), updated_at = NOW()
		WHERE id = $1::UUID
	`, id)
	if err != nil {
		scimError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r.Context(), tenantID, id, "deactivate", "scim/idp", nil)
	log.Printf("[SCIM] Deactivated operator %s (tenant %s)", id, tenantID)

	w.WriteHeader(http.StatusNoContent)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func scanUser(row interface{ Scan(dest ...any) error }) (User, error) {
	var id, extID, username, email, displayName, givenName, familyName, role string
	var active bool
	var createdAt, updatedAt time.Time

	err := row.Scan(&id, &extID, &username, &email,
		&displayName, &givenName, &familyName,
		&role, &active, &createdAt, &updatedAt)
	if err != nil {
		return User{}, err
	}

	return buildUser(id, extID, username, email, displayName, givenName, familyName, role, active, createdAt, updatedAt), nil
}

func buildUser(id, extID, username, email, displayName, givenName, familyName, role string, active bool, created, updated time.Time) User {
	u := User{
		Schemas:     []string{schemaCore},
		ID:          id,
		ExternalID:  extID,
		UserName:    username,
		DisplayName: displayName,
		Active:      active,
		Role:        role,
		Meta: &Meta{
			ResourceType: "User",
			Created:      created.Format(time.RFC3339),
			LastModified: updated.Format(time.RFC3339),
		},
	}
	if email != "" {
		u.Emails = []Email{{Value: email, Type: "work", Primary: true}}
	}
	if givenName != "" || familyName != "" {
		u.Name = &Name{
			GivenName:  givenName,
			FamilyName: familyName,
			Formatted:  strings.TrimSpace(givenName + " " + familyName),
		}
	}
	return u
}

func extractFilterValue(filter string) string {
	// Parse: userName eq "user@example.com"
	parts := strings.SplitN(filter, "\"", 3)
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

func scimError(w http.ResponseWriter, detail string, status int) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{
		Schemas: []string{schemaError},
		Detail:  detail,
		Status:  fmt.Sprintf("%d", status),
	})
}

func (h *handler) auditLog(ctx context.Context, tenantID, operatorID, eventType, initiatedBy string, changed map[string]interface{}) {
	changedJSON, _ := json.Marshal(changed)
	_, err := h.db.Exec(ctx, `
		INSERT INTO scim_audit_log (tenant_id, operator_id, event_type, changed_fields, initiated_by)
		VALUES ($1::UUID, NULLIF($2,'')::UUID, $3, $4::JSONB, $5)
	`, tenantID, operatorID, eventType, string(changedJSON), initiatedBy)
	if err != nil {
		log.Printf("[SCIM] Audit log error: %v", err)
	}
}
