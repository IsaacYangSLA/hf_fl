package app

import (
	"context"
	"encoding/json"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/artifacts"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/executor"
)

func composeLogReader(s *Services) artifacts.LogReader {
	return func(ctx context.Context, id artifacts.LogIdentity, offset, maximum int64) (artifacts.LogReceipt, error) {
		reader, ok := s.Node.(executionLogs)
		if !ok {
			return artifacts.LogReceipt{}, domain.Err(503, "log_reader_unavailable")
		}
		raw, e := reader.ReadLogs(ctx, executor.ExecutionIdentity{JobID: id.JobID, AttemptID: id.AttemptID, ComponentID: id.ComponentID, Epoch: id.Epoch}, offset, maximum)
		if e != nil {
			return artifacts.LogReceipt{}, e
		}
		b, e := json.Marshal(raw)
		if e != nil {
			return artifacts.LogReceipt{}, e
		}
		var receipt artifacts.LogReceipt
		if e = json.Unmarshal(b, &receipt); e != nil {
			return artifacts.LogReceipt{}, domain.Err(422, "invalid_log_receipt")
		}
		if e = receipt.Validate(id, offset); e != nil {
			return artifacts.LogReceipt{}, e
		}
		return receipt, nil
	}
}
func brokerRemoteRoute(s *Services) func(context.Context, artifacts.LogIdentity) (string, error) {
	return func(ctx context.Context, id artifacts.LogIdentity) (string, error) {
		execution := executor.ExecutionIdentity{JobID: id.JobID, AttemptID: id.AttemptID, ComponentID: id.ComponentID, Epoch: id.Epoch}
		remote, e := isRemote(ctx, s, execution)
		if e != nil {
			return "", e
		}
		if !remote {
			return "", nil
		}
		rows, e := s.DB.All(ctx, "SELECT * FROM jm_allocations WHERE job_id = ? AND attempt_id = ? AND component_id = ? AND epoch = ?", id.JobID, id.AttemptID, id.ComponentID, id.Epoch)
		if e != nil {
			return "", e
		}
		if len(rows) != 1 {
			return "", domain.Err(404, "artifact_unavailable")
		}
		if node := strValue(objMap(rows[0]["details_json"])["node_id"]); node != "" {
			return node, nil
		}
		if rows[0]["released_at"] != nil {
			return "", domain.Err(404, "artifact_unavailable")
		}
		pool, e := s.DB.One(ctx, "SELECT * FROM jm_pools WHERE id = ?", rows[0]["pool_id"])
		if e != nil {
			return "", e
		}
		if pool == nil || strValue(pool["node_id"]) == "" {
			return "", domain.Err(404, "artifact_unavailable")
		}
		return strValue(pool["node_id"]), nil
	}
}
func brokerRemoteRead(s *Services) func(context.Context, artifacts.LogIdentity, string, int64) ([]byte, error) {
	return func(ctx context.Context, id artifacts.LogIdentity, path string, maximum int64) ([]byte, error) {
		reader, ok := s.Node.(executionArtifacts)
		if !ok {
			return nil, config.Invalid()
		}
		return reader.ReadArtifact(ctx, executor.ExecutionIdentity{JobID: id.JobID, AttemptID: id.AttemptID, ComponentID: id.ComponentID, Epoch: id.Epoch}, path, maximum)
	}
}
