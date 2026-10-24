// Package secrets delivers explicitly scoped, file-backed plugin option secrets.
// It never resolves URLs, reads environment fallbacks, or evaluates source code.
package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/resources"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/store"
	"golang.org/x/sys/unix"
)

const MaxSecretBytes = 8192
const MaxManifestBytes = 64 * 1024

var ErrReferenceRefused = errors.New("secret_reference_refused")
var reserved = map[string]bool{"repo_id": true, "space_id": true, "dataset_npz": true, "eval_npz": true, "data_path": true, "dataset_path": true, "source_dir": true, "state_dir": true, "command": true, "mounts": true, "resources": true, "target_round": true, "max_duration_seconds": true, "participant": true, "participant_id": true, "minimum_participants": true}
var forbidden = regexp.MustCompile(`(?i)(^|_)(git|github|hf|huggingface|s3|aws|azure|gcp|database|db|postgres|oidc|human|signing|jwt|docker|container|runtime|ssh|host|proxy|manager|deployment)($|_)`)
var normalize = regexp.MustCompile(`[^a-z0-9]+`)

const directoryFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

func validID(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || (i > 0 && (c == '_' || c == '.' || c == '-'))) {
			return false
		}
	}
	return true
}
func validPath(path string) bool {
	if !filepath.IsAbs(path) || path == "/" || strings.ContainsRune(path, 0) {
		return false
	}
	for _, p := range strings.Split(path, "/")[1:] {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	return true
}
func privateStat(st *unix.Stat_t, limit int64) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Nlink == 1 && (st.Uid == 0 || st.Uid == uint32(os.Geteuid())) && st.Mode&0077 == 0 && st.Size >= 0 && st.Size <= limit
}
func parentFD(path string) (int, string, error) {
	if !validPath(path) {
		return -1, "", ErrReferenceRefused
	}
	parts := strings.Split(path, "/")[1:]
	fd, err := unix.Open("/", directoryFlags, 0)
	if err != nil {
		return -1, "", ErrReferenceRefused
	}
	for _, p := range parts[:len(parts)-1] {
		child, e := unix.Openat(fd, p, directoryFlags, 0)
		unix.Close(fd)
		if e != nil {
			return -1, "", ErrReferenceRefused
		}
		fd = child
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || st.Mode&0077 != 0 {
		unix.Close(fd)
		return -1, "", ErrReferenceRefused
	}
	return fd, parts[len(parts)-1], nil
}

// ReadPrivateFile reads one pinned regular, private, single-link inode. Its errors
// contain neither the configured source path nor secret material.
func ReadPrivateFile(path string, limit int64) ([]byte, error) {
	if limit < 1 || limit > 1024*1024 {
		return nil, ErrReferenceRefused
	}
	parent, name, err := parentFD(path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrReferenceRefused
	}
	f := os.NewFile(uintptr(fd), "private-secret")
	defer f.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || !privateStat(&before, limit) {
		return nil, ErrReferenceRefused
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, ErrReferenceRefused
	}
	if unix.Fstat(fd, &after) != nil || !privateStat(&after, limit) || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || int64(len(data)) != after.Size {
		return nil, ErrReferenceRefused
	}
	return data, nil
}
func secretText(data []byte) (string, error) {
	if !utf8.Valid(data) {
		return "", ErrReferenceRefused
	}
	value := string(data)
	if strings.HasSuffix(value, "\n") {
		value = strings.TrimSuffix(value, "\n")
		value = strings.TrimSuffix(value, "\r")
	}
	if value == "" || strings.ContainsRune(value, 0) || len(value) > MaxSecretBytes {
		return "", ErrReferenceRefused
	}
	return value, nil
}

type Approval struct {
	ID           string   `json:"id"`
	ProjectID    string   `json:"project_id"`
	Path         string   `json:"-"`
	Purpose      string   `json:"purpose"`
	Roles        []string `json:"roles"`
	OptionNames  []string `json:"option_names"`
	ComponentIDs []string `json:"component_ids"`
}

func (a Approval) validate() error {
	if !validID(a.ID) || !validID(a.ProjectID) || !validPath(a.Path) || len(a.Roles) == 0 || len(a.OptionNames) == 0 || len(a.OptionNames) > 64 || (a.Purpose != "" && a.Purpose != "plugin_option") {
		return ErrReferenceRefused
	}
	for _, r := range a.Roles {
		if r != "owner" && r != "participant" {
			return ErrReferenceRefused
		}
	}
	for _, name := range a.OptionNames {
		normal := normalize.ReplaceAllString(strings.ToLower(name), "_")
		if !validID(name) || reserved[normal] || forbidden.MatchString(normal) {
			return ErrReferenceRefused
		}
	}
	for _, id := range a.ComponentIDs {
		if !validID(id) {
			return ErrReferenceRefused
		}
	}
	return nil
}

type Binding struct {
	JobID       string `json:"job_id"`
	AttemptID   string `json:"attempt_id"`
	ComponentID string `json:"component_id"`
	Epoch       int64  `json:"epoch"`
}

func (b Binding) validate() error {
	if !validID(b.JobID) || !validID(b.AttemptID) || !validID(b.ComponentID) || b.Epoch < 1 {
		return ErrReferenceRefused
	}
	return nil
}

type Resolved struct {
	Binding
	PrivatePath     string   `json:"-"`
	RedactionValues []string `json:"-"`
	OptionNames     []string `json:"option_names"`
}
type Manifest struct {
	SchemaVersion int64 `json:"schema_version"`
	Binding
	Role       string            `json:"role"`
	Options    map[string]string `json:"options"`
	References map[string]string `json:"references"`
}

func ReadManifest(path string, binding Binding) (Manifest, error) {
	if binding.validate() != nil {
		return Manifest{}, ErrReferenceRefused
	}
	data, err := ReadPrivateFile(path, MaxManifestBytes)
	if err != nil {
		return Manifest{}, err
	}
	var raw map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(data))
	if decoder.Decode(&raw) != nil {
		return Manifest{}, ErrReferenceRefused
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return Manifest{}, ErrReferenceRefused
	}
	for _, key := range []string{"schema_version", "epoch"} {
		var n json.Number
		if json.Unmarshal(raw[key], &n) != nil {
			return Manifest{}, ErrReferenceRefused
		}
		if _, err = n.Int64(); err != nil {
			return Manifest{}, ErrReferenceRefused
		}
	}
	var result Manifest
	if json.Unmarshal(data, &result) != nil || result.SchemaVersion != 1 || result.Binding != binding || (result.Role != "owner" && result.Role != "participant") || len(result.Options) == 0 || len(result.Options) > 64 || len(result.Options) != len(result.References) {
		return Manifest{}, ErrReferenceRefused
	}
	for key, value := range result.Options {
		if !validID(key) || !validID(result.References[key]) || value == "" || !utf8.ValidString(value) || len(value) > MaxSecretBytes || strings.ContainsRune(value, 0) {
			return Manifest{}, ErrReferenceRefused
		}
	}
	return result, nil
}

type Resolver struct {
	DB        *store.DB
	Root      string
	Approvals map[string]Approval
}

func NewResolver(db *store.DB, root string, approvals map[string]Approval) (*Resolver, error) {
	if !validPath(root) || len(approvals) > 10000 {
		return nil, ErrReferenceRefused
	}
	result := &Resolver{DB: db, Root: root, Approvals: map[string]Approval{}}
	for id, approval := range approvals {
		if id != approval.ID || approval.validate() != nil {
			return nil, ErrReferenceRefused
		}
		if approval.Purpose == "" {
			approval.Purpose = "plugin_option"
		}
		approval.Roles = append([]string{}, approval.Roles...)
		approval.OptionNames = append([]string{}, approval.OptionNames...)
		approval.ComponentIDs = append([]string{}, approval.ComponentIDs...)
		result.Approvals[id] = approval
	}
	return result, nil
}
func contains(values []string, s string) bool {
	for _, value := range values {
		if value == s {
			return true
		}
	}
	return false
}
func (r *Resolver) current(ctx context.Context, spec domain.JobSpec) (map[string]Approval, error) {
	result := map[string]Approval{}
	if len(spec.SecretRefs) == 0 {
		return result, nil
	}
	if r.DB == nil {
		return nil, ErrReferenceRefused
	}
	err := r.DB.WithTx(ctx, false, func(tx *store.Tx) error {
		for option, reference := range spec.SecretRefs {
			approval, ok := r.Approvals[reference]
			if !ok {
				return ErrReferenceRefused
			}
			row, err := tx.One(ctx, "SELECT * FROM jm_secret_references WHERE id=?", reference)
			if err != nil {
				return err
			}
			if row == nil || row["enabled"] != true || approval.ProjectID != spec.ProjectID || row["project_id"] != spec.ProjectID || row["reference"] != approval.Path || !contains(approval.OptionNames, option) {
				return ErrReferenceRefused
			}
			if _, exists := spec.Options[option]; exists {
				return ErrReferenceRefused
			}
			result[option] = approval
		}
		return nil
	})
	if err != nil {
		return nil, ErrReferenceRefused
	}
	return result, nil
}
func components(spec domain.JobSpec) ([]domain.ComponentSpec, error) {
	values := append([]domain.ComponentSpec{}, spec.Components...)
	seen := map[string]bool{}
	for _, component := range values {
		seen[component.ComponentID] = true
	}
	for _, participant := range spec.Participants {
		if participant.Mode == "external" {
			id := "participant-" + resources.StableKey(participant.ParticipantID)[:40]
			if seen[id] {
				return nil, ErrReferenceRefused
			}
			seen[id] = true
			pid := participant.ParticipantID
			values = append(values, domain.ComponentSpec{ComponentID: id, Role: "participant", ParticipantID: &pid})
		}
	}
	return values, nil
}
func (r *Resolver) ValidateSpec(ctx context.Context, spec domain.JobSpec) error {
	if spec.Validate() != nil {
		return ErrReferenceRefused
	}
	current, err := r.current(ctx, spec)
	if err != nil {
		return err
	}
	assigned, err := components(spec)
	if err != nil {
		return err
	}
	for _, approval := range current {
		found := false
		for _, component := range assigned {
			if contains(approval.Roles, component.Role) && (len(approval.ComponentIDs) == 0 || contains(approval.ComponentIDs, component.ComponentID)) {
				found = true
				break
			}
		}
		if !found {
			return ErrReferenceRefused
		}
	}
	return nil
}
func stringValue(v any) string { s, _ := v.(string); return s }
func intValue(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case json.Number:
		x, err := n.Int64()
		return x, err == nil
	}
	return 0, false
}
func (r *Resolver) selection(ctx context.Context, job, attempt map[string]any, component domain.ComponentSpec) (Binding, domain.ComponentSpec, map[string]Approval, error) {
	encoded, err := domain.CanonicalJSON(job["spec_json"])
	if err != nil {
		return Binding{}, component, nil, ErrReferenceRefused
	}
	spec, err := domain.DecodeJobSpec(encoded)
	if err != nil {
		return Binding{}, component, nil, ErrReferenceRefused
	}
	digest, err := spec.Digest()
	if err != nil {
		return Binding{}, component, nil, ErrReferenceRefused
	}
	jid := stringValue(job["id"])
	epoch, ok := intValue(attempt["epoch"])
	jobEpoch, hasEpoch := intValue(job["epoch"])
	if !hasEpoch {
		jobEpoch = epoch
	}
	state := stringValue(job["state"])
	if state == "" {
		state = "PROVISIONING"
	}
	if job["project_id"] != spec.ProjectID || attempt["job_id"] != jid || (job["spec_hash"] != nil && job["spec_hash"] != digest) || !ok || epoch < 1 || jobEpoch != epoch || (state != "PROVISIONING" && state != "STARTING" && state != "RUNNING") {
		return Binding{}, component, nil, ErrReferenceRefused
	}
	if r.ValidateSpec(ctx, spec) != nil {
		return Binding{}, component, nil, ErrReferenceRefused
	}
	assigned, err := components(spec)
	if err != nil {
		return Binding{}, component, nil, err
	}
	found := false
	var target domain.ComponentSpec
	for _, candidate := range assigned {
		if candidate.ComponentID == component.ComponentID {
			target = candidate
			found = true
			break
		}
	}
	sameParticipant := (target.ParticipantID == nil && component.ParticipantID == nil) || (target.ParticipantID != nil && component.ParticipantID != nil && *target.ParticipantID == *component.ParticipantID)
	if !found || target.Role != component.Role || !sameParticipant {
		return Binding{}, component, nil, ErrReferenceRefused
	}
	binding := Binding{jid, stringValue(attempt["id"]), target.ComponentID, epoch}
	if binding.validate() != nil {
		return binding, target, nil, ErrReferenceRefused
	}
	current, err := r.current(ctx, spec)
	if err != nil {
		return binding, target, nil, err
	}
	selected := map[string]Approval{}
	if target.Role != "build" {
		for key, approval := range current {
			if contains(approval.Roles, target.Role) && (len(approval.ComponentIDs) == 0 || contains(approval.ComponentIDs, target.ComponentID)) {
				selected[key] = approval
			}
		}
	}
	return binding, target, selected, nil
}
func (r *Resolver) path(binding Binding) string {
	return filepath.Join(r.Root, binding.JobID, binding.AttemptID, binding.ComponentID, strconv.FormatInt(binding.Epoch, 10), "secrets.json")
}
func (r *Resolver) Planned(ctx context.Context, job, attempt map[string]any, component domain.ComponentSpec) (Resolved, error) {
	binding, _, selected, err := r.selection(ctx, job, attempt, component)
	if err != nil {
		return Resolved{}, err
	}
	result := Resolved{Binding: binding, OptionNames: []string{}, RedactionValues: []string{}}
	if len(selected) > 0 {
		result.PrivatePath = r.path(binding)
		for key := range selected {
			result.OptionNames = append(result.OptionNames, key)
		}
		sort.Strings(result.OptionNames)
	}
	return result, nil
}

func (r *Resolver) directory(binding Binding, create bool) (int, error) {
	if binding.validate() != nil {
		return -1, ErrReferenceRefused
	}
	roots := strings.Split(r.Root, "/")[1:]
	parts := append(append([]string{}, roots...), binding.JobID, binding.AttemptID, binding.ComponentID, strconv.FormatInt(binding.Epoch, 10))
	fd, err := unix.Open("/", directoryFlags, 0)
	if err != nil {
		return -1, ErrReferenceRefused
	}
	for index, p := range parts {
		if create {
			if e := unix.Mkdirat(fd, p, 0700); e != nil && e != unix.EEXIST {
				unix.Close(fd)
				return -1, ErrReferenceRefused
			}
		}
		child, e := unix.Openat(fd, p, directoryFlags, 0)
		unix.Close(fd)
		if e != nil {
			if e == unix.ENOENT && !create {
				return -1, os.ErrNotExist
			}
			return -1, ErrReferenceRefused
		}
		fd = child
		if index >= len(roots)-1 {
			var st unix.Stat_t
			if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
				unix.Close(fd)
				return -1, ErrReferenceRefused
			}
		}
	}
	return fd, nil
}
func lockDirectory(fd int) (int, error) {
	lock, err := unix.Openat(fd, ".secret-lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return -1, ErrReferenceRefused
	}
	var st unix.Stat_t
	if unix.Fstat(lock, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		unix.Close(lock)
		return -1, ErrReferenceRefused
	}
	if unix.Flock(lock, unix.LOCK_EX) != nil {
		unix.Close(lock)
		return -1, ErrReferenceRefused
	}
	return lock, nil
}
func sameDirectory(a, b int) bool {
	var x, y unix.Stat_t
	return unix.Fstat(a, &x) == nil && unix.Fstat(b, &y) == nil && x.Dev == y.Dev && x.Ino == y.Ino
}
func (r *Resolver) Resolve(ctx context.Context, job, attempt map[string]any, component domain.ComponentSpec) (Resolved, error) {
	binding, target, selected, err := r.selection(ctx, job, attempt, component)
	if err != nil {
		return Resolved{}, err
	}
	return r.materialize(binding, target.Role, selected)
}

func (r *Resolver) materialize(binding Binding, role string, selected map[string]Approval) (Resolved, error) {
	result := Resolved{Binding: binding, OptionNames: []string{}, RedactionValues: []string{}}
	if len(selected) == 0 {
		return result, nil
	}
	fd, err := r.directory(binding, true)
	if err != nil {
		return result, err
	}
	defer unix.Close(fd)
	lock, err := lockDirectory(fd)
	if err != nil {
		return result, err
	}
	defer unix.Close(lock)
	references := map[string]string{}
	for key, approval := range selected {
		references[key] = approval.ID
	}
	path := r.path(binding)
	var st unix.Stat_t
	exists := unix.Fstatat(fd, "secrets.json", &st, unix.AT_SYMLINK_NOFOLLOW)
	var manifest Manifest
	if exists == nil {
		manifest, err = ReadManifest(path, binding)
		if err != nil {
			return result, err
		}
		if manifest.Role != role || len(manifest.References) != len(references) {
			return result, ErrReferenceRefused
		}
		for key, ref := range references {
			if manifest.References[key] != ref {
				return result, ErrReferenceRefused
			}
		}
	} else if exists == unix.ENOENT {
		values := map[string]string{}
		for key, approval := range selected {
			content, e := ReadPrivateFile(approval.Path, MaxSecretBytes)
			if e != nil {
				return result, e
			}
			value, e := secretText(content)
			for i := range content {
				content[i] = 0
			}
			if e != nil {
				return result, e
			}
			values[key] = value
		}
		manifest = Manifest{SchemaVersion: 1, Binding: binding, Role: role, Options: values, References: references}
		// The explicit map preserves the existing Python wire document exactly.
		data, e := domain.CanonicalJSON(map[string]any{"schema_version": 1, "job_id": binding.JobID, "attempt_id": binding.AttemptID, "component_id": binding.ComponentID, "epoch": binding.Epoch, "role": role, "options": values, "references": references})
		if e != nil || len(data) > MaxManifestBytes {
			return result, ErrReferenceRefused
		}
		temp := ".secret-tmp-" + domain.NewID()
		out, e := unix.Openat(fd, temp, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0400)
		if e != nil {
			return result, ErrReferenceRefused
		}
		defer unix.Unlinkat(fd, temp, 0)
		f := os.NewFile(uintptr(out), "private-secret-manifest")
		if _, e = f.Write(data); e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		for i := range data {
			data[i] = 0
		}
		if e != nil || closeErr != nil {
			return result, ErrReferenceRefused
		}
		if unix.Renameat(fd, temp, fd, "secrets.json") != nil || unix.Fsync(fd) != nil {
			return result, ErrReferenceRefused
		}
	} else {
		return result, ErrReferenceRefused
	}
	current, e := r.directory(binding, false)
	if e != nil {
		return result, ErrReferenceRefused
	}
	same := sameDirectory(fd, current)
	unix.Close(current)
	if !same {
		return result, ErrReferenceRefused
	}
	result.PrivatePath = path
	unique := map[string]bool{}
	for key, value := range manifest.Options {
		result.OptionNames = append(result.OptionNames, key)
		unique[value] = true
	}
	for value := range unique {
		result.RedactionValues = append(result.RedactionValues, value)
	}
	sort.Strings(result.OptionNames)
	sort.Slice(result.RedactionValues, func(i, j int) bool {
		x, y := result.RedactionValues[i], result.RedactionValues[j]
		if utf8.RuneCountInString(x) != utf8.RuneCountInString(y) {
			return utf8.RuneCountInString(x) > utf8.RuneCountInString(y)
		}
		return x < y
	})
	return result, nil
}

// Cleanup keeps the nonsecret lock inode for cross-process exclusion and removes
// no manifest until the caller has proved authoritative runtime termination.
func (r *Resolver) Cleanup(ctx context.Context, binding Binding, terminationConfirmed bool) (bool, error) {
	if !terminationConfirmed || binding.validate() != nil {
		return false, ErrReferenceRefused
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	fd, err := r.directory(binding, false)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	lock, err := lockDirectory(fd)
	if err != nil {
		return false, err
	}
	defer unix.Close(lock)
	var st unix.Stat_t
	if e := unix.Fstatat(fd, "secrets.json", &st, unix.AT_SYMLINK_NOFOLLOW); e == unix.ENOENT {
		return true, nil
	} else if e != nil {
		return false, ErrReferenceRefused
	}
	if _, err = ReadManifest(r.path(binding), binding); err != nil {
		return false, err
	}
	current, e := r.directory(binding, false)
	if e != nil {
		return false, ErrReferenceRefused
	}
	same := sameDirectory(fd, current)
	unix.Close(current)
	if !same {
		return false, ErrReferenceRefused
	}
	if unix.Unlinkat(fd, "secrets.json", 0) != nil || unix.Fsync(fd) != nil {
		return false, ErrReferenceRefused
	}
	return true, nil
}
