// Package controller reconciles immutable publication receipts only after fencing.
package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
)

// PublicationExchange supplies only immutable Exchange observations. A missing
// saved record is not evidence of nonpublication.
type PublicationExchange interface {
	GetReference(context.Context, string, string) (map[string]any, error)
	GetRecord(context.Context, string, string) (map[string]any, error)
	GetAcquisition(context.Context, string, string) (map[string]any, error)
}

// PublicationStateReader reads a confirmed-stopped execution's private state.
// Implementations must confine access to the exact execution identity and reject
// symlink, hard-link, ownership and mount replacement. The observer independently
// bounds every relative name and response before interpreting JSON.
type PublicationStateReader interface {
	ReadState(context.Context, executor.ExecutionIdentity, string, int64) ([]byte, error)
}

type PublicationStateReaderFunc func(context.Context, executor.ExecutionIdentity, string, int64) ([]byte, error)

func (f PublicationStateReaderFunc) ReadState(ctx context.Context, id executor.ExecutionIdentity, name string, maxBytes int64) ([]byte, error) {
	return f(ctx, id, name, maxBytes)
}

// AuthoritativePublicationObserver compares fenced durable intents with the
// exact server record, creator, attachment hashes and current publication chain.
type AuthoritativePublicationObserver struct {
	DB                  *store.DB
	Exchange            PublicationExchange
	StateReader         PublicationStateReader
	ExternalStateReader PublicationStateReader
	Principal           func(jobID, componentID, participantID string) string
	MaxAncestry         int
}

type publicationComponent struct {
	id, role, participant string
	external              bool
}

type publicationBarrier struct {
	epoch    int64
	started  map[string]bool
	revoke   string
	stops    map[string]string
	external []publicationComponent
}

type publicationEvidenceError struct{ reason string }

func (e *publicationEvidenceError) Error() string { return e.reason }
func publicationFailure(reason string) error      { return &publicationEvidenceError{reason: reason} }

func publicationUnknown(err error) PublicationObservation {
	reason := "publication_evidence_unavailable"
	var evidence *publicationEvidenceError
	if errors.As(err, &evidence) {
		reason = evidence.reason
	}
	return PublicationObservation{Known: false, Status: "unknown", Evidence: map[string]any{"reason": reason}}
}

func publicationMap(v any) map[string]any {
	if x, ok := v.(map[string]any); ok && x != nil {
		return x
	}
	return map[string]any{}
}
func publicationString(v any) string { x, _ := v.(string); return x }
func publicationBool(v any) bool     { x, ok := v.(bool); return ok && x }
func publicationInteger(v any) (int64, bool) {
	switch x := v.(type) {
	case json.Number:
		n, e := x.Int64()
		return n, e == nil
	case int64:
		return x, true
	case int:
		return int64(x), true
	case int32:
		return int64(x), true
	case uint:
		if uint64(x) <= uint64(1<<63-1) {
			return int64(x), true
		}
	case uint64:
		if x <= uint64(1<<63-1) {
			return int64(x), true
		}
	}
	return 0, false
}
func publicationHash(b []byte) string {
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}
func publicationSpec(job map[string]any) (domain.JobSpec, error) {
	b, err := domain.CanonicalJSON(job["spec_json"])
	if err != nil {
		return domain.JobSpec{}, publicationFailure("invalid_job_specification")
	}
	spec, err := domain.DecodeJobSpec(b)
	if err != nil {
		return domain.JobSpec{}, publicationFailure("invalid_job_specification")
	}
	return spec, nil
}

// PublicationIntentFingerprint is the exact Python worker-compatible intent
// fingerprint. Initialization omits mutable result/error/phase fields; client
// fingerprints include the complete durable intent.
func PublicationIntentFingerprint(role string, doc map[string]any) (string, error) {
	var fields []string
	value := doc
	switch role {
	case "init":
		fields = []string{"binding", "manifest_sha256", "checkpoint_files_sha256"}
	case "owner":
		fields = []string{"revision", "source_round", "publication_intent"}
	case "client":
		fields = []string{"repo_id", "participant", "base_revision", "submission_revision", "submitted_at", "checkpoint_files_sha256"}
	default:
		return "", publicationFailure("invalid_publication_role")
	}
	for _, field := range fields {
		if _, ok := doc[field]; !ok {
			return "", publicationFailure("incomplete_publication_intent")
		}
	}
	if role == "owner" && len(publicationMap(doc["publication_intent"])) == 0 {
		return "", publicationFailure("incomplete_publication_intent")
	}
	if role != "client" {
		value = make(map[string]any, len(fields))
		for _, field := range fields {
			value[field] = doc[field]
		}
	}
	b, err := domain.CanonicalJSON(value)
	if err != nil || len(b) > 1024*1024 {
		return "", publicationFailure("invalid_publication_intent")
	}
	return publicationHash(b), nil
}

type publicationBoundedState struct {
	reader       PublicationStateReader
	identity     executor.ExecutionIdentity
	reads, total int64
}

func (s *publicationBoundedState) read(ctx context.Context, name string) ([]byte, error) {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || utf8.RuneCountInString(name) > 4096 || !utf8.ValidString(name) {
		return nil, publicationFailure("unsafe_publication_state_path")
	}
	for _, c := range name {
		if c < 32 || c == 127 {
			return nil, publicationFailure("unsafe_publication_state_path")
		}
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return nil, publicationFailure("unsafe_publication_state_path")
		}
	}
	s.reads++
	if s.reads > 32 {
		return nil, publicationFailure("publication_read_limit")
	}
	if s.reader == nil {
		return nil, publicationFailure("publication_state_reader_unavailable")
	}
	data, err := s.reader.ReadState(ctx, s.identity, name, 1024*1024)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, publicationFailure("publication_state_unavailable")
	}
	if len(data) > 1024*1024 {
		return nil, publicationFailure("publication_state_oversized")
	}
	s.total += int64(len(data))
	if s.total > 16*1024*1024 {
		return nil, publicationFailure("publication_total_read_limit")
	}
	return data, nil
}
func publicationDecode(data []byte) (map[string]any, error) {
	if !utf8.Valid(data) {
		return nil, publicationFailure("invalid_publication_json")
	}
	value, err := domain.DecodeJSON(data)
	if err != nil {
		return nil, publicationFailure("invalid_publication_json")
	}
	result, valid := value.(map[string]any)
	if !valid || result == nil {
		return nil, publicationFailure("invalid_publication_json")
	}
	return result, nil
}

func (s *publicationBoundedState) json(ctx context.Context, name string) (map[string]any, error) {
	data, err := s.read(ctx, name)
	if err != nil || data == nil {
		return nil, err
	}
	return publicationDecode(data)
}

func (o *AuthoritativePublicationObserver) barrier(ctx context.Context, jobID, attemptID string) (result publicationBarrier, err error) {
	result.started = map[string]bool{}
	result.stops = map[string]string{}
	err = o.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		attempt, err := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id = ?", attemptID)
		if err != nil {
			return err
		}
		if attempt == nil || publicationString(attempt["job_id"]) != jobID || !publicationBool(attempt["revocation_confirmed"]) {
			return publicationFailure("grant_revocation_unconfirmed")
		}
		epoch, valid := publicationInteger(attempt["epoch"])
		if !valid || epoch < 1 {
			return publicationFailure("invalid_attempt_epoch")
		}
		result.epoch = epoch
		allocations, err := tx.All(ctx, "SELECT * FROM jm_allocations WHERE attempt_id = ?", attemptID)
		if err != nil {
			return err
		}
		for _, allocation := range allocations {
			if !publicationBool(allocation["termination_confirmed"]) {
				return publicationFailure("execution_termination_unconfirmed")
			}
		}
		operations, err := tx.All(ctx, "SELECT * FROM jm_provisioning_operations WHERE attempt_id = ? ORDER BY id", attemptID)
		if err != nil {
			return err
		}
		for _, operation := range operations {
			component := publicationString(operation["component_id"])
			state := publicationString(operation["state"])
			switch publicationString(operation["operation"]) {
			case "start":
				if state != "refused" {
					result.started[component] = true
				}
			case "revoke":
				if result.revoke == "" && (state == "confirmed" || state == "ready" || state == "done") {
					result.revoke = publicationString(operation["id"])
				}
			case "stop":
				if state == "confirmed" || state == "ready" || state == "done" {
					result.stops[component] = publicationString(operation["id"])
				}
			}
		}
		job, err := tx.One(ctx, "SELECT * FROM jm_jobs WHERE id = ?", jobID)
		if err != nil {
			return err
		}
		if job == nil {
			return publicationFailure("publication_job_missing")
		}
		spec, err := publicationSpec(job)
		if err != nil {
			return err
		}
		executions, err := tx.All(ctx, "SELECT * FROM jm_provisioning_resources WHERE job_id = ? AND attempt_id = ? AND kind = ? AND state != ?", jobID, attemptID, "external_execution", "deleted")
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, execution := range executions {
			details := publicationMap(execution["details_json"])
			owner := publicationMap(execution["ownership_json"])
			participantID := publicationString(details["participant_id"])
			var participant *domain.ParticipantSpec
			for index := range spec.Participants {
				if spec.Participants[index].ParticipantID == participantID {
					participant = &spec.Participants[index]
					break
				}
			}
			encoded, err := domain.CanonicalJSON([]any{participantID})
			if err != nil {
				return err
			}
			expected := "participant-" + publicationHash(encoded)[:40]
			component := publicationString(execution["component_id"])
			executionEpoch, valid := publicationInteger(details["epoch"])
			if participant == nil || participant.Mode != "external" || component != expected || seen[component] ||
				publicationString(details["dataset_binding"]) != participant.DatasetBinding || !valid || executionEpoch != epoch ||
				publicationString(details["spec_digest"]) != publicationString(job["spec_hash"]) ||
				publicationString(owner["job_id"]) != jobID || publicationString(owner["attempt_id"]) != attemptID ||
				publicationString(owner["component_id"]) != component {
				return publicationFailure("external_publication_identity_mismatch")
			}
			seen[component] = true
			stopID := publicationString(details["termination_operation_id"])
			if !publicationBool(details["termination_confirmed"]) || stopID == "" {
				return publicationFailure("external_termination_unconfirmed")
			}
			receipt := map[string]any{}
			if raw, exists := details["stop_receipt"]; exists {
				var valid bool
				receipt, valid = raw.(map[string]any)
				if !valid || receipt == nil {
					return publicationFailure("invalid_external_stop_receipt")
				}
			}
			if publicationBool(receipt["never_started"]) {
				receiptEpoch, valid := publicationInteger(receipt["epoch"])
				if publicationString(receipt["job_id"]) != jobID || publicationString(receipt["attempt_id"]) != attemptID ||
					publicationString(receipt["component_id"]) != component || !valid || receiptEpoch != epoch ||
					publicationString(receipt["termination_operation_id"]) != stopID {
					return publicationFailure("external_absence_receipt_mismatch")
				}
			} else {
				result.started[component] = true
				result.stops[component] = stopID
				result.external = append(result.external, publicationComponent{id: component, role: "participant", participant: participantID, external: true})
			}
		}
		return nil
	})
	return
}

func publicationInline(record map[string]any, name string) (map[string]any, error) {
	metadata, ok := record["metadata"].(map[string]any)
	if !ok {
		if _, exists := record["metadata"]; !exists {
			metadata = map[string]any{}
		} else {
			return nil, publicationFailure("invalid_publication_metadata")
		}
	}
	files := publicationMap(metadata["hf2l_files"])
	value, exists := files[name]
	if !exists {
		return map[string]any{}, nil
	}
	doc, ok := value.(map[string]any)
	if !ok || doc == nil {
		return nil, publicationFailure("invalid_inline_publication")
	}
	return doc, nil
}
func (o *AuthoritativePublicationObserver) main(ctx context.Context, space string) (map[string]any, int64, error) {
	ref, err := o.Exchange.GetReference(ctx, space, "main")
	if err != nil {
		var d *domain.Error
		if errors.As(err, &d) && d.Code == "reference_not_found" {
			return nil, 0, nil
		}
		return nil, 0, publicationFailure("main_reference_unavailable")
	}
	recordID := publicationString(ref["record_id"])
	if recordID == "" {
		return nil, 0, publicationFailure("invalid_main_reference")
	}
	record, err := o.Exchange.GetRecord(ctx, space, recordID)
	if err != nil {
		return nil, 0, publicationFailure("main_record_unavailable")
	}
	doc, err := publicationInline(record, "fedavg_round.json")
	if err != nil {
		return nil, 0, err
	}
	round, valid := publicationInteger(doc["round"])
	if !valid || round < 0 || publicationString(record["kind"]) != "model.global" || publicationString(record["state"]) != "published" {
		return nil, 0, publicationFailure("invalid_main_publication")
	}
	return record, round, nil
}
func (o *AuthoritativePublicationObserver) inChain(ctx context.Context, space, recordID string, main map[string]any) (bool, error) {
	limit := o.MaxAncestry
	if limit == 0 {
		limit = 1024
	}
	if limit < 1 {
		return false, publicationFailure("invalid_publication_ancestry_bound")
	}
	current := main
	for count := 0; count < limit; count++ {
		if current == nil {
			return false, nil
		}
		if publicationString(current["id"]) == recordID {
			return true, nil
		}
		metadata := publicationMap(current["metadata"])
		parent := publicationString(metadata["base_record_id"])
		currentDoc, err := publicationInline(current, "fedavg_round.json")
		if err != nil {
			return false, err
		}
		if parent == "" {
			parent = publicationString(currentDoc["base_revision"])
		}
		if parent == "" {
			return false, nil
		}
		previous, err := o.Exchange.GetRecord(ctx, space, parent)
		if err != nil {
			return false, publicationFailure("publication_ancestry_unavailable")
		}
		if publicationString(previous["kind"]) != "model.global" || publicationString(previous["state"]) != "published" {
			return false, publicationFailure("invalid_publication_ancestry")
		}
		priorDoc, err := publicationInline(previous, "fedavg_round.json")
		if err != nil {
			return false, err
		}
		priorRound, valid1 := publicationInteger(priorDoc["round"])
		currentRound, valid2 := publicationInteger(currentDoc["round"])
		if !valid1 || !valid2 || priorRound != currentRound-1 {
			return false, publicationFailure("publication_ancestry_round_mismatch")
		}
		current = previous
	}
	return false, publicationFailure("publication_ancestry_bound_exceeded")
}

func (o *AuthoritativePublicationObserver) recordProof(ctx context.Context, jobID, space string, component publicationComponent, intent, upload map[string]any, role string, main, manifest map[string]any, manifestSHA string) (string, string, error) {
	recordID := publicationString(upload["record_id"])
	if recordID == "" {
		return "", "", publicationFailure("publication_creation_receipt_missing")
	}
	record, err := o.Exchange.GetRecord(ctx, space, recordID)
	if err != nil || record == nil {
		return "", "", publicationFailure("saved_publication_unavailable")
	}
	if publicationString(record["space_id"]) != space || publicationString(record["creator"]) != o.Principal(jobID, component.id, component.participant) {
		return "", "", publicationFailure("publication_creator_mismatch")
	}
	expectedKind := "model.global"
	if role == "client" {
		expectedKind = "training.update"
	}
	if publicationString(record["kind"]) != expectedKind {
		return "", "", publicationFailure("publication_kind_mismatch")
	}
	hashesValue, exists := intent["checkpoint_files_sha256"]
	if role == "owner" {
		hashesValue, exists = manifest["checkpoint_files_sha256"]
	}
	if !exists {
		hashesValue = map[string]any{}
	}
	expectedHashes, ok := hashesValue.(map[string]any)
	if !ok {
		return "", "", publicationFailure("invalid_publication_checkpoint_hashes")
	}
	attachments := map[string]any{}
	switch rows := record["attachments"].(type) {
	case []any:
		for _, item := range rows {
			row, ok := item.(map[string]any)
			if !ok {
				return "", "", publicationFailure("invalid_publication_attachment")
			}
			attachments[publicationString(row["path"])] = row["sha256"]
		}
	case []map[string]any:
		for _, row := range rows {
			attachments[publicationString(row["path"])] = row["sha256"]
		}
	case nil:
		if _, exists := record["attachments"]; exists {
			return "", "", publicationFailure("invalid_publication_attachment")
		}
	default:
		return "", "", publicationFailure("invalid_publication_attachment")
	}
	for name, digest := range expectedHashes {
		expected, valid := digest.(string)
		if !valid || publicationString(attachments[name]) != expected {
			return "", "", publicationFailure("publication_checkpoint_hash_mismatch")
		}
	}
	var expectedManifest any
	if role == "init" {
		expectedManifest = intent["manifest_sha256"]
	}
	if role == "owner" {
		expectedManifest = publicationMap(intent["publication_intent"])["manifest_sha256"]
	}
	if expectedManifest != nil && expectedManifest != "" && expectedManifest != manifestSHA {
		return "", "", publicationFailure("publication_manifest_hash_mismatch")
	}
	inlineName := "fedavg_round.json"
	if role == "client" {
		inlineName = "fedavg_submission.json"
	}
	published, err := publicationInline(record, inlineName)
	if err != nil {
		return "", "", err
	}
	if publicationString(published["complete_manifest"]) == "fedavg_round-full.json" {
		if publicationString(attachments["fedavg_round-full.json"]) != manifestSHA {
			return "", "", publicationFailure("publication_full_manifest_hash_mismatch")
		}
	} else {
		publishedBytes, err1 := domain.CanonicalJSON(published)
		manifestBytes, err2 := domain.CanonicalJSON(manifest)
		if err1 != nil || err2 != nil || !bytes.Equal(publishedBytes, manifestBytes) {
			return "", "", publicationFailure("publication_inline_manifest_mismatch")
		}
	}
	if role == "owner" {
		target, valid1 := publicationInteger(publicationMap(intent["publication_intent"])["target_round"])
		actual, valid2 := publicationInteger(published["round"])
		if !valid1 || !valid2 || target != actual {
			return "", "", publicationFailure("publication_target_round_mismatch")
		}
	}
	if role == "client" {
		if publicationString(publicationMap(record["creator_bindings"])["participant"]) != component.participant {
			return "", "", publicationFailure("publication_participant_mismatch")
		}
		if publicationString(publicationMap(record["metadata"])["base_record_id"]) != publicationString(intent["base_revision"]) {
			return "", "", publicationFailure("publication_base_mismatch")
		}
	}
	switch publicationString(record["state"]) {
	case "published":
		if role != "client" {
			found, err := o.inChain(ctx, space, recordID, main)
			if err != nil {
				return "", "", err
			}
			if !found {
				if role == "init" && main != nil {
					return "", "", publicationFailure("initial_publication_conflicts_with_main")
				}
				return "absent", recordID, nil
			}
		}
		return "confirmed", recordID, nil
	case "cancelled", "failed", "withdrawn", "expired", "draft":
		return "absent", recordID, nil
	}
	return "", "", publicationFailure("publication_server_state_unknown")
}

type publicationPending struct {
	role                     string
	intent                   map[string]any
	uploadPath, manifestPath string
}
type publicationExplicitProof struct {
	ids        map[string]bool
	outcome    string
	references map[string]bool
}

func publicationPendingIntents(ctx context.Context, reader *publicationBoundedState, jobID string, component publicationComponent) ([]publicationPending, error) {
	progress, err := reader.json(ctx, "progress.json")
	if err != nil {
		return nil, err
	}
	if progress == nil || publicationString(progress["job_id"]) != jobID || publicationString(progress["component_id"]) != component.id {
		return nil, publicationFailure("publication_worker_identity_mismatch")
	}
	var initial map[string]any
	if component.role == "owner" {
		initial, err = reader.json(ctx, "initialization.json")
		if err != nil {
			return nil, err
		}
	}
	listener, err := reader.json(ctx, "listener/state.json")
	if err != nil {
		return nil, err
	}
	pending := []publicationPending{}
	if initial != nil {
		if phase, exists := initial["phase"]; exists {
			if _, valid := phase.(string); !valid {
				return nil, publicationFailure("invalid_initial_publication_phase")
			}
		}
	}
	if initial != nil && (publicationString(initial["phase"]) == "publishing" || publicationString(initial["phase"]) == "uncertain") {
		pending = append(pending, publicationPending{"init", initial, "initial-model.exchange-upload.json", "initial-model/fedavg_round.json"})
	}
	if listener != nil {
		key := publicationString(listener["active"])
		if raw, exists := listener["active"]; exists && raw != nil {
			if _, valid := raw.(string); !valid {
				return nil, publicationFailure("invalid_publication_listener_active")
			}
		}
		active := map[string]any{}
		if key != "" {
			jobs := map[string]any{}
			if raw, exists := listener["jobs"]; exists {
				var valid bool
				jobs, valid = raw.(map[string]any)
				if !valid || jobs == nil {
					return nil, publicationFailure("invalid_publication_listener_jobs")
				}
			}
			if raw, exists := jobs[key]; exists && raw != nil {
				var valid bool
				active, valid = raw.(map[string]any)
				if !valid || active == nil {
					return nil, publicationFailure("invalid_publication_listener_job")
				}
			}
		}
		if raw, exists := active["status"]; exists && raw != nil {
			if _, valid := raw.(string); !valid {
				return nil, publicationFailure("invalid_publication_listener_status")
			}
		}
		status := publicationString(active["status"])
		if key != "" && (status == "publishing" || status == "uncertain") {
			revision, ok := active["revision"].(string)
			if !ok {
				return nil, publicationFailure("invalid_publication_listener_revision")
			}
			directory := "listener/jobs/" + publicationHash([]byte(revision))
			if component.role == "owner" {
				aggregate := publicationString(publicationMap(active["publication_intent"])["aggregate_dir"])
				if !strings.HasPrefix(aggregate, "/job/state/") {
					return nil, publicationFailure("unsafe_owner_publication_path")
				}
				relative := strings.TrimPrefix(aggregate, "/job/state/")
				// Validate before path operations can normalize traversal components.
				if err := publicationRelativeName(relative); err != nil {
					return nil, err
				}
				uploadPath := path.Join(path.Dir(relative), path.Base(relative)+".exchange-upload.json")
				pending = append(pending, publicationPending{"owner", active, uploadPath, relative + "/fedavg_round.json"})
			} else {
				intent, err := reader.json(ctx, directory+"/work/client-publication-intent.json")
				if err != nil {
					return nil, err
				}
				if intent == nil {
					return nil, publicationFailure("client_publication_intent_missing")
				}
				pending = append(pending, publicationPending{"client", intent, directory + "/work/trained_model.exchange-upload.json", directory + "/work/trained_model/fedavg_submission.json"})
			}
		}
	} else if publicationString(progress["phase"]) != "completed" && initial == nil {
		return nil, publicationFailure("publication_worker_state_incomplete")
	}
	return pending, nil
}
func publicationRelativeName(name string) error {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || utf8.RuneCountInString(name) > 4096 || !utf8.ValidString(name) {
		return publicationFailure("unsafe_publication_state_path")
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return publicationFailure("unsafe_publication_state_path")
		}
	}
	for _, c := range name {
		if c < 32 || c == 127 {
			return publicationFailure("unsafe_publication_state_path")
		}
	}
	return nil
}
func publicationDirective(role, action, fingerprint, attemptID string, epoch int64, revoke, stop, record, acquisition string) (map[string]any, error) {
	for _, id := range []string{attemptID, revoke, stop, record} {
		if err := domain.ValidateIdentifier(id); err != nil {
			return nil, publicationFailure("invalid_publication_fencing_receipt")
		}
	}
	if acquisition != "" {
		if err := domain.ValidateIdentifier(acquisition); err != nil {
			return nil, publicationFailure("invalid_publication_acquisition")
		}
	}
	var acquisitionValue any
	if acquisition != "" {
		acquisitionValue = acquisition
	}
	return map[string]any{"role": role, "action": action, "intent_sha256": fingerprint,
		"old_attempt_id": attemptID, "old_epoch": epoch, "revocation_operation_id": revoke,
		"termination_operation_id": stop, "grants_revoked": true, "termination_confirmed": true,
		"record_id": record, "acquisition_id": acquisitionValue}, nil
}

// Observe always returns an unknown observation for incomplete, conflicting or
// unavailable evidence. It never treats a timeout, 404 or attained current round
// as proof that a pending write did not publish.
func (o *AuthoritativePublicationObserver) Observe(ctx context.Context, job, attempt map[string]any, space string) (PublicationObservation, error) {
	unknown := func(err error) (PublicationObservation, error) { return publicationUnknown(err), nil }
	if o.DB == nil || o.Exchange == nil || o.Principal == nil || (o.StateReader == nil && o.ExternalStateReader == nil) {
		return unknown(publicationFailure("publication_observer_not_configured"))
	}
	jobID, attemptID := publicationString(job["id"]), publicationString(attempt["id"])
	if domain.ValidateIdentifier(jobID) != nil || domain.ValidateIdentifier(attemptID) != nil {
		return unknown(publicationFailure("invalid_publication_execution_identity"))
	}
	barrier, err := o.barrier(ctx, jobID, attemptID)
	if err != nil {
		return unknown(err)
	}
	if len(barrier.started) == 0 {
		round := int64(0)
		if space != "" {
			_, round, err = o.main(ctx, space)
			if err != nil {
				return unknown(err)
			}
		}
		return PublicationObservation{Known: true, Status: "absent", CurrentRound: &round, Evidence: map[string]any{"source": "durable_never_started_operations"}}, nil
	}
	if space == "" {
		return unknown(publicationFailure("started_execution_space_missing"))
	}
	main, currentRound, err := o.main(ctx, space)
	if err != nil {
		return unknown(err)
	}
	spec, err := publicationSpec(job)
	if err != nil {
		return unknown(err)
	}
	storedAttempt, err := o.DB.One(ctx, "SELECT * FROM jm_attempts WHERE id = ?", attemptID)
	if err != nil || storedAttempt == nil {
		return unknown(publicationFailure("publication_attempt_unavailable"))
	}
	attemptDetails, validDetails := storedAttempt["details_json"].(map[string]any)
	if !validDetails || attemptDetails == nil {
		return unknown(publicationFailure("invalid_publication_attempt_details"))
	}
	requested := map[string]any{}
	if raw, exists := attemptDetails["reconciliation_evidence"]; exists && raw != nil {
		var valid bool
		requested, valid = raw.(map[string]any)
		if !valid || requested == nil {
			return unknown(publicationFailure("invalid_requested_publication_evidence"))
		}
	}
	components := append([]publicationComponent{}, barrier.external...)
	for _, item := range spec.Components {
		participant := ""
		if item.ParticipantID != nil {
			participant = *item.ParticipantID
		}
		components = append(components, publicationComponent{id: item.ComponentID, role: item.Role, participant: participant})
	}
	directives := map[string]any{}
	recordIDs := []string{}
	proofs := []publicationExplicitProof{}
	for _, component := range components {
		if !barrier.started[component.id] || component.role == "build" {
			continue
		}
		if domain.ValidateIdentifier(component.id) != nil {
			return unknown(publicationFailure("invalid_publication_component"))
		}
		reader := o.StateReader
		if component.external {
			reader = o.ExternalStateReader
		}
		if reader == nil {
			return unknown(publicationFailure("publication_state_reader_unavailable"))
		}
		bounded := &publicationBoundedState{reader: reader, identity: executor.ExecutionIdentity{JobID: jobID, AttemptID: attemptID, ComponentID: component.id, Epoch: barrier.epoch}}
		pending, err := publicationPendingIntents(ctx, bounded, jobID, component)
		if err != nil {
			return unknown(err)
		}
		resolutions := []any{}
		for _, item := range pending {
			upload, err := bounded.json(ctx, item.uploadPath)
			if err != nil {
				return unknown(err)
			}
			manifestBytes, err := bounded.read(ctx, item.manifestPath)
			if err != nil {
				return unknown(err)
			}
			if manifestBytes == nil {
				return unknown(publicationFailure("publication_manifest_missing"))
			}
			manifest, err := publicationDecode(manifestBytes)
			if err != nil {
				return unknown(err)
			}
			manifestSHA := publicationHash(manifestBytes)
			action, recordID, err := o.recordProof(ctx, jobID, space, component, item.intent, upload, item.role, main, manifest, manifestSHA)
			if err != nil {
				return unknown(err)
			}
			stop := barrier.stops[component.id]
			if barrier.revoke == "" || stop == "" {
				return unknown(publicationFailure("publication_fencing_receipt_missing"))
			}
			acquisition := ""
			if item.role == "owner" {
				revision := publicationString(item.intent["revision"])
				directory := "listener/jobs/" + publicationHash([]byte(revision))
				claim, err := bounded.json(ctx, directory+"/claim-state.json")
				if err != nil {
					return unknown(err)
				}
				acquisition = publicationString(claim["claim_id"])
				if acquisition != "" {
					row, err := o.Exchange.GetAcquisition(ctx, space, acquisition)
					if err != nil {
						return unknown(publicationFailure("publication_acquisition_unavailable"))
					}
					if action == "confirmed" && (publicationString(row["state"]) != "completed" || publicationString(row["result_record_id"]) != recordID) {
						return unknown(publicationFailure("publication_acquisition_mismatch"))
					}
					if action == "absent" && publicationString(row["state"]) == "completed" {
						return unknown(publicationFailure("completed_acquisition_not_absence"))
					}
				}
			}
			fingerprint, err := PublicationIntentFingerprint(item.role, item.intent)
			if err != nil {
				return unknown(err)
			}
			directive, err := publicationDirective(item.role, action, fingerprint, attemptID, barrier.epoch, barrier.revoke, stop, recordID, acquisition)
			if err != nil {
				return unknown(err)
			}
			resolutions = append(resolutions, directive)
			recordIDs = append(recordIDs, recordID)
			outcome := "not_published"
			if action == "confirmed" {
				outcome = "published"
			}
			ids := map[string]bool{recordID: true, fingerprint: true}
			if key := publicationString(upload["key"]); key != "" {
				ids[key] = true
			}
			proofs = append(proofs, publicationExplicitProof{ids: ids, outcome: outcome, references: map[string]bool{recordID: true, "exchange:" + space + ":" + recordID: true, "sha256:" + fingerprint: true}})
		}
		if len(resolutions) > 0 {
			directives[component.id] = resolutions
		}
	}
	if len(requested) > 0 {
		found := false
		for _, proof := range proofs {
			if proof.ids[publicationString(requested["publication_id"])] && proof.outcome == publicationString(requested["outcome"]) && proof.references[publicationString(requested["evidence_ref"])] {
				found = true
				break
			}
		}
		if !found {
			return unknown(publicationFailure("requested_publication_evidence_mismatch"))
		}
	}
	err = o.DB.WithTx(ctx, true, func(tx *store.Tx) error {
		row, err := tx.One(ctx, "SELECT * FROM jm_attempts WHERE id = ?"+tx.ForUpdate(), attemptID)
		if err != nil {
			return err
		}
		if row == nil || publicationString(row["job_id"]) != jobID || !publicationBool(row["revocation_confirmed"]) {
			return publicationFailure("publication_fence_changed")
		}
		epoch, ok := publicationInteger(row["epoch"])
		if !ok || epoch != barrier.epoch {
			return publicationFailure("publication_epoch_changed")
		}
		details := publicationMap(row["details_json"])
		details["reconciliation_directives"] = directives
		return tx.Update(ctx, "jm_attempts", map[string]any{"id": attemptID}, map[string]any{"details_json": details})
	})
	if err != nil {
		return unknown(err)
	}
	status := "absent"
	if main != nil {
		status = "confirmed"
	}
	return PublicationObservation{Known: true, Status: status, CurrentRound: &currentRound, Evidence: map[string]any{"source": "exchange_records_and_fenced_durable_intents", "record_ids": recordIDs, "directives": directives}}, nil
}
