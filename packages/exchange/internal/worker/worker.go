// Package worker runs separately bounded verification and reclamation pools.
package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/config"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/store"
	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/transfers"
)

var outcomes = []string{"verified", "failed", "recovered", "cleaned", "retry", "skipped", "invalid_parts", "expired"}

type engine interface {
	Expire(context.Context, int) (int, error)
	Work(context.Context, int) ([]string, []string, error)
	Process(context.Context, string, bool) (string, error)
}

// Tick expires drafts, processes due transfers in independent pools, and prunes
// discardable history. Selection is only a snapshot: Process must recheck the
// selected pool category while acquiring the current durable attempt.
func Tick(ctx context.Context, svc *transfers.Service, batch int) (map[string]int, error) {
	if svc == nil || svc.DB == nil {
		return nil, errors.New("worker_service_unavailable")
	}
	return tick(ctx, svc, svc.Settings.Worker, batch, func(ctx context.Context, batch int) error {
		return Prune(ctx, svc, batch)
	})
}

func tick(ctx context.Context, svc engine, settings config.WorkerSettings, batch int, prune func(context.Context, int) error) (map[string]int, error) {
	if batch == 0 {
		batch = settings.BatchSize
	}
	if batch < 1 || settings.VerifyConcurrency < 1 || settings.CleanupConcurrency < 1 {
		return nil, errors.New("invalid_worker_settings")
	}
	counts := make(map[string]int, len(outcomes))
	for _, name := range outcomes {
		counts[name] = 0
	}
	expired, err := svc.Expire(ctx, batch)
	if err != nil {
		return counts, err
	}
	if expired < 0 {
		return counts, errors.New("invalid_worker_outcome")
	}
	counts["expired"] = expired
	verification, cleanup, err := svc.Work(ctx, batch)
	if err != nil {
		return counts, err
	}

	results := make(chan string, len(verification)+len(cleanup))
	var workers sync.WaitGroup
	start := func(ids []string, cleanup bool, concurrency int) {
		jobs := make(chan string, len(ids))
		for _, id := range ids {
			jobs <- id
		}
		close(jobs)
		if concurrency > len(ids) {
			concurrency = len(ids)
		}
		for n := 0; n < concurrency; n++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for id := range jobs {
					if ctx.Err() != nil {
						results <- "skipped"
						continue
					}
					results <- guarded(ctx, svc, id, cleanup)
				}
			}()
		}
	}
	// Starting either pool never waits for the other pool's provider calls.
	start(verification, false, settings.VerifyConcurrency)
	start(cleanup, true, settings.CleanupConcurrency)
	workers.Wait()
	close(results)
	invalidOutcome := false
	for result := range results {
		if _, ok := counts[result]; !ok {
			invalidOutcome = true
			continue
		}
		counts[result]++
	}
	if ctx.Err() != nil {
		return counts, ctx.Err()
	}
	if invalidOutcome {
		return counts, errors.New("invalid_worker_outcome")
	}
	if err := prune(ctx, batch); err != nil {
		return counts, err
	}
	return counts, nil
}

func guarded(ctx context.Context, svc engine, id string, cleanup bool) (result string) {
	result = "retry"
	defer func() {
		if recover() != nil {
			// Never log provider exceptions: they may contain origin credentials.
			slog.ErrorContext(ctx, "worker operation panicked", "attempt", id)
			result = "retry"
		}
	}()
	value, err := svc.Process(ctx, id, cleanup)
	if err != nil {
		slog.ErrorContext(ctx, "worker operation failed", "attempt", id, "error_class", fmt.Sprintf("%T", err))
		return "retry"
	}
	return value
}

// Prune removes only retained operations, fully cleaned attempt history with no
// outstanding mutation markers, and expired events. Active provider ownership is
// never inferred from elapsed lease time.
func Prune(ctx context.Context, svc *transfers.Service, batch int) error {
	if svc == nil || svc.DB == nil {
		return errors.New("worker_service_unavailable")
	}
	if batch == 0 {
		batch = svc.Settings.Worker.BatchSize
	}
	return prune(ctx, svc.DB, svc.Settings.Worker, batch)
}

func prune(ctx context.Context, db *store.DB, settings config.WorkerSettings, batch int) error {
	if batch < 1 || settings.OperationRetentionSeconds < 1 || settings.EventRetentionSeconds < 1 {
		return errors.New("invalid_worker_settings")
	}
	var events []domain.Object
	var eventCutoff float64
	err := db.WithTx(ctx, true, func(tx *store.Tx) error {
		now, err := tx.Now(ctx)
		if err != nil {
			return err
		}
		operationCutoff := now - float64(settings.OperationRetentionSeconds)
		operations, err := tx.All(ctx, "SELECT space_id,principal_id,scope,key FROM v2_operations WHERE created_at<? ORDER BY created_at,space_id,principal_id,scope,key LIMIT ?", operationCutoff, batch)
		if err != nil {
			return err
		}
		for _, operation := range operations {
			// The age predicate also protects a replacement inserted after a
			// concurrent deletion of the selected compound identity.
			_, err := tx.Exec(ctx, "DELETE FROM v2_operations WHERE space_id=? AND principal_id=? AND scope=? AND key=? AND created_at<?",
				operation["space_id"], operation["principal_id"], operation["scope"], operation["key"], operationCutoff)
			if err != nil {
				return err
			}
		}
		attempts, err := tx.All(ctx, "SELECT id,mutation_tokens FROM v2_transfer_attempts WHERE state='cleaned' AND updated_at<? ORDER BY updated_at,id LIMIT ?"+tx.ForUpdate(), operationCutoff, batch)
		if err != nil {
			return err
		}
		for _, attempt := range attempts {
			tokens, valid := domain.MutationTokens(attempt["mutation_tokens"])
			if !valid || len(tokens) != 0 {
				continue
			}
			if _, err := tx.Exec(ctx, "DELETE FROM v2_transfer_attempts WHERE id=? AND state='cleaned' AND updated_at<?", attempt["id"], operationCutoff); err != nil {
				return err
			}
		}
		eventCutoff = now - float64(settings.EventRetentionSeconds)
		events, err = tx.All(ctx, "SELECT id,space_id FROM v2_events WHERE created_at<? ORDER BY id LIMIT ?", eventCutoff, batch)
		return err
	})
	if err != nil {
		return err
	}

	bySpace := make(map[string][]int64)
	for _, event := range events {
		spaceID, ok := event["space_id"].(string)
		id, valid := domain.Int64(event["id"])
		if !ok || !valid {
			return errors.New("invalid_retained_event")
		}
		bySpace[spaceID] = append(bySpace[spaceID], id)
	}
	spaceIDs := make([]string, 0, len(bySpace))
	for spaceID := range bySpace {
		spaceIDs = append(spaceIDs, spaceID)
	}
	sort.Strings(spaceIDs)
	for _, spaceID := range spaceIDs {
		if err := db.WithTx(ctx, true, func(tx *store.Tx) error {
			space, err := tx.One(ctx, "SELECT id,event_floor FROM v2_spaces WHERE id=?"+tx.ForUpdate(), spaceID)
			if err != nil {
				return err
			}
			if space == nil {
				return errors.New("retained_event_space_missing")
			}
			floor, ok := domain.Int64(space["event_floor"])
			if !ok {
				return errors.New("invalid_event_floor")
			}
			for _, id := range bySpace[spaceID] {
				if _, err := tx.Exec(ctx, "DELETE FROM v2_events WHERE space_id=? AND id=? AND created_at<?", spaceID, id, eventCutoff); err != nil {
					return err
				}
				if id > floor {
					floor = id
				}
			}
			return tx.Update(ctx, "v2_spaces", domain.Object{"id": spaceID}, domain.Object{"event_floor": floor})
		}); err != nil {
			return err
		}
	}
	return nil
}
