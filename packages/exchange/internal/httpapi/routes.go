package httpapi

import (
	"context"
	"strconv"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
)

type routeSpec struct{ method, path, action, etag string }

var routeSpecs = []routeSpec{
	{"POST", "/v2/spaces", "create_space", ""},
	{"PUT", "/v2/spaces/{space}/managed", "enable_managed_space", ""},
	{"GET", "/v2/spaces/{space}/managed", "get_managed_space", ""},
	{"POST", "/v2/spaces/{space}/managed/retire", "retire_managed_space", ""},
	{"POST", "/v2/spaces/{space}/workload-grants", "create_workload_grant", ""},
	{"POST", "/v2/spaces/{space}/workload-grants/revoke", "revoke_workload_grants", ""},
	{"POST", "/v2/spaces/{space}/workload-grants/verify", "verify_workload_grant", ""},
	{"GET", "/v2/spaces/{space}/workload-grants/{grant}", "get_workload_grant", ""},
	{"GET", "/v2/spaces/{space}", "get_space", ""},
	{"PATCH", "/v2/spaces/{space}", "update_space_limits", ""},
	{"GET", "/v2/spaces/{space}/membership", "membership", ""},
	{"GET", "/v2/spaces/{space}/members", "members", ""},
	{"PUT", "/v2/spaces/{space}/members/{member}", "put_member", ""},
	{"GET", "/v2/spaces/{space}/types", "types", ""},
	{"POST", "/v2/spaces/{space}/types/{kind}/revisions", "register_type", ""},
	{"GET", "/v2/spaces/{space}/types/{kind}/revisions/{revision}", "get_type", ""},
	{"PUT", "/v2/spaces/{space}/policies/{kind}", "put_policy", ""},
	{"POST", "/v2/spaces/{space}/records", "create_record", ""},
	{"GET", "/v2/spaces/{space}/records", "records", ""},
	{"GET", "/v2/spaces/{space}/records/{record}", "get_record", "version"},
	{"PATCH", "/v2/spaces/{space}/records/{record}", "patch_record", "version"},
	{"DELETE", "/v2/spaces/{space}/records/{record}", "withdraw_record", ""},
	{"POST", "/v2/spaces/{space}/records/{record}/purge", "purge_record", ""},
	{"POST", "/v2/spaces/{space}/records/{record}/publish", "publish_record", ""},
	{"GET", "/v2/spaces/{space}/refs/{name}", "get_reference", "token"},
	{"PUT", "/v2/spaces/{space}/refs/{name}", "put_reference", "token"},
	{"POST", "/v2/spaces/{space}/acquisitions", "acquire", ""},
	{"GET", "/v2/spaces/{space}/acquisitions/{acquisition}", "acquisition", ""},
	{"POST", "/v2/spaces/{space}/acquisitions/{acquisition}/renew", "renew", ""},
	{"POST", "/v2/spaces/{space}/acquisitions/{acquisition}/abandon", "abandon", ""},
	{"POST", "/v2/spaces/{space}/acquisitions/{acquisition}/complete", "complete", ""},
	{"GET", "/v2/spaces/{space}/events", "events", ""},
	{"POST", "/v2/spaces/{space}/records/{record}/attachments/{attachment}/upload", "initiate", ""},
	{"GET", "/v2/spaces/{space}/records/{record}/attachments/{attachment}/parts", "parts", ""},
	{"POST", "/v2/spaces/{space}/records/{record}/attachments/{attachment}/grants", "grants", ""},
	{"POST", "/v2/spaces/{space}/records/{record}/attachments/{attachment}/complete", "finish_upload", ""},
	{"GET", "/v2/spaces/{space}/records/{record}/attachments/{attachment}/download", "download", ""},
}

// Route describes an actual public API route; health and optional docs are not
// part of the versioned OpenAPI contract.
type Route struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

func RouteInventory() []Route {
	out := make([]Route, len(routeSpecs))
	for i, r := range routeSpecs {
		out[i] = Route{r.method, r.path}
	}
	return out
}

type callData struct {
	vars                                  map[string]string
	body                                  object
	key, precondition, kind, after, state string
	limit, eventAfter, revision           int64
}

func (s *server) invoke(ctx context.Context, p domain.Principal, spec routeSpec, d callData) (object, error) {
	space, record, attachment := d.vars["space"], d.vars["record"], d.vars["attachment"]
	switch spec.action {
	case "create_space":
		return s.core.CreateSpace(ctx, p, d.body, d.key)
	case "enable_managed_space":
		return s.core.EnableManagedSpace(ctx, p, space, d.body, d.key)
	case "get_managed_space":
		return s.core.GetManagedSpace(ctx, p, space)
	case "retire_managed_space":
		return s.core.RetireManagedSpace(ctx, p, space, d.body, d.key)
	case "create_workload_grant":
		return s.core.CreateWorkloadGrant(ctx, p, space, d.body, d.key)
	case "revoke_workload_grants":
		return s.core.RevokeWorkloadGrants(ctx, p, space, d.body, d.key)
	case "verify_workload_grant":
		return s.core.VerifyWorkloadGrant(ctx, p, space)
	case "get_workload_grant":
		return s.core.GetWorkloadGrant(ctx, p, space, d.vars["grant"])
	case "get_space":
		return s.core.GetSpace(ctx, p, space)
	case "update_space_limits":
		return s.core.UpdateSpaceLimits(ctx, p, space, d.body)
	case "membership":
		return s.core.GetMembership(ctx, p, space)
	case "members":
		return s.core.ListMembers(ctx, p, space)
	case "put_member":
		return s.core.PutMember(ctx, p, space, d.vars["member"], d.body)
	case "types":
		return s.core.ListTypes(ctx, p, space)
	case "register_type":
		return s.core.RegisterType(ctx, p, space, d.vars["kind"], d.body, d.key)
	case "get_type":
		return s.core.GetType(ctx, p, space, d.vars["kind"], d.revision)
	case "put_policy":
		return s.core.PutPolicy(ctx, p, space, d.vars["kind"], d.body)
	case "create_record":
		return s.core.CreateRecord(ctx, p, space, d.body, d.key)
	case "records":
		return s.core.ListRecords(ctx, p, space, d.kind, d.after, d.limit, d.state)
	case "get_record":
		return s.core.GetRecord(ctx, p, space, record)
	case "patch_record":
		return s.core.PatchRecord(ctx, p, space, record, d.body, d.precondition)
	case "withdraw_record":
		return s.core.WithdrawRecord(ctx, p, space, record)
	case "purge_record":
		return s.core.PurgeRecord(ctx, p, space, record)
	case "publish_record":
		return s.core.PublishRecord(ctx, p, space, record, d.key)
	case "get_reference":
		return s.core.GetReference(ctx, p, space, d.vars["name"])
	case "put_reference":
		return s.core.PutReference(ctx, p, space, d.vars["name"], d.body, d.precondition, d.key)
	case "acquire":
		return s.core.Acquire(ctx, p, space, d.body, d.key)
	case "acquisition":
		return s.core.GetAcquisition(ctx, p, space, d.vars["acquisition"])
	case "renew":
		return s.core.Renew(ctx, p, space, d.vars["acquisition"], fenceValue(d.body["fence"]))
	case "abandon":
		return s.core.Abandon(ctx, p, space, d.vars["acquisition"], fenceValue(d.body["fence"]))
	case "complete":
		return s.core.Complete(ctx, p, space, d.vars["acquisition"], d.body, d.key)
	case "events":
		return s.core.Events(ctx, p, space, d.eventAfter, d.limit)
	case "initiate":
		return s.managed.Initiate(ctx, space, record, attachment, p)
	case "parts":
		return s.managed.Parts(ctx, space, record, attachment, p)
	case "grants":
		values := anySlice(d.body["numbers"])
		numbers := make([]int, len(values))
		for i, v := range values {
			n, ok := domain.Int64(v)
			if !ok || int64(int(n)) != n {
				return nil, domain.Err(422, "invalid_part_numbers")
			}
			numbers[i] = int(n)
		}
		return s.managed.Grants(ctx, space, record, attachment, p, numbers)
	case "finish_upload":
		return s.managed.Complete(ctx, space, record, attachment, p)
	case "download":
		return s.managed.Download(ctx, space, record, attachment, p)
	}
	return nil, domain.Err(500, "internal_error")
}

// A wire fence is a positive arbitrary-precision Python integer. Persisted
// fences are positive int64. Overflow therefore cannot match; zero deliberately
// reaches the service's normal membership/lookup/fence checks without wrapping.
func fenceValue(v any) int64 {
	n, ok := domain.Int64(v)
	if !ok {
		return 0
	}
	return n
}
func statusFor(c *compiledContract, spec routeSpec) int {
	op := c.operations[spec.method+" "+spec.path]
	responses, _ := op["responses"].(map[string]any)
	for _, code := range []string{"200", "201", "202", "204"} {
		if _, ok := responses[code]; ok {
			v, _ := strconv.Atoi(code)
			return v
		}
	}
	return 200
}
