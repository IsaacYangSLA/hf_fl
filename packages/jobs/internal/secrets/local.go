package secrets

import (
	"context"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
)

// LocalResolver implements node-local plugin-option approval. It deliberately
// has no database connection, manager authentication, or control-plane keys.
type LocalResolver struct{ resolver *Resolver }

func NewLocalResolver(root string, approvals map[string]Approval) (*LocalResolver, error) {
	resolver, err := NewResolver(nil, root, approvals)
	if err != nil {
		return nil, err
	}
	return &LocalResolver{resolver: resolver}, nil
}
func (l *LocalResolver) selected(binding Binding, spec domain.JobSpec, component domain.ComponentSpec) (map[string]Approval, error) {
	if l == nil || l.resolver == nil || binding.validate() != nil || spec.Validate() != nil || binding.ComponentID != component.ComponentID {
		return nil, ErrReferenceRefused
	}
	assigned, err := components(spec)
	if err != nil {
		return nil, err
	}
	found := false
	for _, candidate := range assigned {
		if candidate.ComponentID != component.ComponentID || candidate.Role != component.Role {
			continue
		}
		if (candidate.ParticipantID == nil) != (component.ParticipantID == nil) {
			continue
		}
		if candidate.ParticipantID != nil && *candidate.ParticipantID != *component.ParticipantID {
			continue
		}
		found = true
		break
	}
	if !found {
		return nil, ErrReferenceRefused
	}
	selected := map[string]Approval{}
	for option, reference := range spec.SecretRefs {
		approval, local := l.resolver.Approvals[reference]
		// Different organizations maintain independent catalogs. An unknown
		// reference is never fetched from a manager or another organization.
		if !local {
			continue
		}
		if approval.ProjectID != spec.ProjectID || !contains(approval.OptionNames, option) {
			return nil, ErrReferenceRefused
		}
		if _, inline := spec.Options[option]; inline {
			return nil, ErrReferenceRefused
		}
		if contains(approval.Roles, component.Role) && (len(approval.ComponentIDs) == 0 || contains(approval.ComponentIDs, component.ComponentID)) {
			selected[option] = approval
		}
	}
	return selected, nil
}
func (l *LocalResolver) PlannedAssignment(ctx context.Context, binding Binding, spec domain.JobSpec, component domain.ComponentSpec) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	selected, err := l.selected(binding, spec, component)
	if err != nil {
		return "", err
	}
	if len(selected) == 0 {
		return "", nil
	}
	return l.resolver.path(binding), nil
}
func optionSet(value any) (map[string]bool, error) {
	result := map[string]bool{}
	var values []string
	switch v := value.(type) {
	case []string:
		values = v
	case []any:
		for _, item := range v {
			name, ok := item.(string)
			if !ok {
				return nil, ErrReferenceRefused
			}
			values = append(values, name)
		}
	default:
		return nil, ErrReferenceRefused
	}
	if len(values) > 64 {
		return nil, ErrReferenceRefused
	}
	for _, name := range values {
		if !validID(name) {
			return nil, ErrReferenceRefused
		}
		result[name] = true
	}
	return result, nil
}
func (l *LocalResolver) MaterializeAssignment(ctx context.Context, binding Binding, spec domain.JobSpec, component domain.ComponentSpec, configuration map[string]any, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	selected, err := l.selected(binding, spec, component)
	if err != nil {
		return err
	}
	configured, err := optionSet(configuration["secret_option_names"])
	if err != nil {
		return err
	}
	if len(configured) != len(selected) {
		return ErrReferenceRefused
	}
	for key := range selected {
		if !configured[key] {
			return ErrReferenceRefused
		}
	}
	planned := ""
	if len(selected) > 0 {
		planned = l.resolver.path(binding)
	}
	if path != planned {
		return ErrReferenceRefused
	}
	if len(selected) == 0 {
		return nil
	}
	_, err = l.resolver.materialize(binding, component.Role, selected)
	return err
}
func (l *LocalResolver) Cleanup(ctx context.Context, binding Binding, confirmed bool) (bool, error) {
	if l == nil || l.resolver == nil {
		return false, ErrReferenceRefused
	}
	return l.resolver.Cleanup(ctx, binding, confirmed)
}
