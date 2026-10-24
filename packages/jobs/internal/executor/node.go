package executor

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

type NodeOption func(*nodeOptions) error
type nodeOptions struct {
	clock     func() float64
	wallClock func() float64
	bootID    string
	watchdog  time.Duration
}

func WithNodeClocks(clock, wallClock func() float64) NodeOption {
	return func(o *nodeOptions) error {
		if clock == nil || wallClock == nil {
			return refused("invalid_clock")
		}
		o.clock = clock
		o.wallClock = wallClock
		return nil
	}
}
func WithNodeBootID(id string) NodeOption {
	return func(o *nodeOptions) error {
		if id == "" || len(id) > 256 || strings.ContainsAny(id, "\n\r\x00") {
			return refused("invalid_boot_id")
		}
		o.bootID = id
		return nil
	}
}
func WithWatchdogInterval(interval time.Duration) NodeOption {
	return func(o *nodeOptions) error {
		if interval < 100*time.Millisecond || interval > 60*time.Second {
			return refused("invalid_watchdog_interval")
		}
		o.watchdog = interval
		return nil
	}
}
func nodeMonotonic() float64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return math.Inf(1)
	}
	return float64(ts.Sec) + float64(ts.Nsec)/1e9
}

type NodeAgent struct {
	Backend    Backend
	NodeID     string
	PoolID     string
	Capacity   ResourceLimits
	db         *sql.DB
	ledgerPath string
	guardRoot  string
	clock      func() float64
	wallClock  func() float64
	bootID     string
	mu         sync.Mutex
	guards     sync.Map
	cancel     context.CancelFunc
	done       chan struct{}
	closeOnce  sync.Once
	closeErr   error
}
type nodeRecord struct {
	Key                                 string
	Identity                            ExecutionIdentity
	Spec                                string
	State                               string
	CPUMillis, MemoryBytes, DiskBytes   int64
	LeaseUntil                          float64
	Deadline                            sql.NullFloat64
	BootID                              string
	Stopped, DiskReleased               bool
	RetainedOutputBytes, AuxiliaryBytes int64
	ExecutorAbsent                      bool
}
type nodeScanner interface{ Scan(...any) error }

const nodeColumns = "execution_key,job_id,attempt_id,component_id,epoch,spec,state,cpu_millis,memory_bytes,disk_bytes,lease_until,deadline,boot_id,stopped,disk_released,retained_output_bytes,auxiliary_bytes,executor_absent"

func scanNodeRecord(row nodeScanner) (nodeRecord, error) {
	var r nodeRecord
	err := row.Scan(&r.Key, &r.Identity.JobID, &r.Identity.AttemptID, &r.Identity.ComponentID, &r.Identity.Epoch, &r.Spec, &r.State, &r.CPUMillis, &r.MemoryBytes, &r.DiskBytes, &r.LeaseUntil, &r.Deadline, &r.BootID, &r.Stopped, &r.DiskReleased, &r.RetainedOutputBytes, &r.AuxiliaryBytes, &r.ExecutorAbsent)
	if err != nil {
		return r, err
	}
	if r.Identity.Validate() != nil || r.Key != r.Identity.Key() || r.CPUMillis < 1 || r.MemoryBytes < 1 || r.DiskBytes < 1 || r.RetainedOutputBytes < 0 || r.AuxiliaryBytes < 0 || math.IsNaN(r.LeaseUntil) || math.IsInf(r.LeaseUntil, 0) {
		return r, uncertain(errors.New("invalid node ledger"))
	}
	return r, nil
}
func NewNodeAgent(backend Backend, ledgerPath, nodeID, poolID string, capacity ResourceLimits, options ...NodeOption) (*NodeAgent, error) {
	if backend == nil || !safeID.MatchString(nodeID) || !safeID.MatchString(poolID) {
		return nil, refused("invalid_identity")
	}
	capacity = capacity.Defaults()
	if err := capacity.Validate(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(ledgerPath) || filepath.Clean(ledgerPath) != ledgerPath {
		return nil, refused("unsafe_root")
	}
	opts := nodeOptions{clock: nodeMonotonic, wallClock: func() float64 { return float64(time.Now().UnixNano()) / 1e9 }, watchdog: time.Second}
	for _, option := range options {
		if err := option(&opts); err != nil {
			return nil, err
		}
	}
	if opts.bootID == "" {
		raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
		if err != nil {
			return nil, refused("boot_identity_unavailable")
		}
		opts.bootID = strings.TrimSpace(string(raw))
	}
	if !nodeFinite(opts.clock()) || !nodeFinite(opts.wallClock()) || opts.bootID == "" {
		return nil, refused("invalid_clock")
	}
	if err := nodePrivateDirectory(filepath.Dir(ledgerPath)); err != nil {
		return nil, err
	}
	fd, err := unix.Open(ledgerPath, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, refused("unsafe_root")
	}
	var st unix.Stat_t
	err = unix.Fstat(fd, &st)
	if err == nil && (st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Getuid()) || st.Mode&0077 != 0) {
		err = errors.New("unsafe ledger")
	}
	unix.Close(fd)
	if err != nil {
		return nil, refused("unsafe_root")
	}
	u := url.URL{Scheme: "file", Path: ledgerPath}
	query := u.Query()
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "journal_mode(WAL)")
	query.Add("_pragma", "synchronous(FULL)")
	query.Set("_txlock", "immediate")
	u.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	agent := &NodeAgent{Backend: backend, NodeID: nodeID, PoolID: poolID, Capacity: capacity, db: db, ledgerPath: ledgerPath, guardRoot: ledgerPath + ".guards", clock: opts.clock, wallClock: opts.wallClock, bootID: opts.bootID, done: make(chan struct{})}
	if err = agent.initialize(); err != nil {
		db.Close()
		return nil, err
	}
	if b, ok := backend.(interface {
		SetLeaseGuard(func(ExecutionIdentity) bool)
	}); ok {
		b.SetLeaseGuard(agent.allowLaunch)
	}
	ctx, cancel := context.WithCancel(context.Background())
	agent.cancel = cancel
	go func() {
		defer close(agent.done)
		ticker := time.NewTicker(opts.watchdog)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// A failed stop is quarantined and remains charged. Other leases keep being enforced.
				_, _ = agent.WatchdogOnce(ctx)
			}
		}
	}()
	return agent, nil
}
func (a *NodeAgent) initialize() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ddl := []string{
		`CREATE TABLE IF NOT EXISTS executions(execution_key TEXT PRIMARY KEY,job_id TEXT NOT NULL,attempt_id TEXT NOT NULL,component_id TEXT NOT NULL,epoch INTEGER NOT NULL,spec TEXT NOT NULL,state TEXT NOT NULL,cpu_millis INTEGER NOT NULL,memory_bytes INTEGER NOT NULL,disk_bytes INTEGER NOT NULL,lease_until REAL NOT NULL,deadline REAL,boot_id TEXT NOT NULL,stopped INTEGER NOT NULL DEFAULT 0)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS active_component ON executions(job_id,component_id) WHERE state!='RELEASED'`,
		`CREATE TABLE IF NOT EXISTS fences(job_id TEXT NOT NULL,component_id TEXT NOT NULL,epoch INTEGER NOT NULL,PRIMARY KEY(job_id,component_id))`,
		`CREATE TABLE IF NOT EXISTS shared_auxiliary(job_id TEXT NOT NULL,component_id TEXT NOT NULL,reserved_bytes INTEGER NOT NULL,PRIMARY KEY(job_id,component_id))`,
	}
	for _, query := range ddl {
		if _, err = tx.ExecContext(ctx, query); err != nil {
			return err
		}
	}
	rows, err := tx.QueryContext(ctx, "PRAGMA table_info(executions)")
	if err != nil {
		return err
	}
	columns := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt any
		if err = rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		columns[name] = true
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, column := range []string{"disk_released", "retained_output_bytes", "auxiliary_bytes", "executor_absent"} {
		if !columns[column] {
			if _, err = tx.ExecContext(ctx, "ALTER TABLE executions ADD COLUMN "+column+" INTEGER NOT NULL DEFAULT 0"); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}
func (a *NodeAgent) Close() error {
	a.closeOnce.Do(func() {
		a.cancel()
		select {
		case <-a.done:
			a.closeErr = a.db.Close()
		case <-time.After(65 * time.Second):
			a.closeErr = uncertain(errors.New("local watchdog did not stop"))
		}
	})
	return a.closeErr
}
func nodeFinite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
func nodePrivateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return refused("unsafe_root")
	}
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err = os.Mkdir(current, 0700); err != nil && !os.IsExist(err) {
				return refused("unsafe_root")
			}
			info, err = os.Lstat(current)
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return refused("unsafe_root")
		}
	}
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Getuid()) || st.Mode&0077 != 0 {
		return refused("unsafe_root")
	}
	return nil
}
func nodeComponentKey(id ExecutionIdentity) string {
	// Validated identifiers are ASCII, so this encoding matches Python compact ASCII JSON.
	b, _ := json.Marshal([]string{id.JobID, id.ComponentID})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])[:32]
}
func (a *NodeAgent) guard(ctx context.Context, kind, key string) (func(), error) {
	guardID := kind + "-" + key
	if tokens, ok := ctx.Value(nodeGuardContextKey{}).(map[string]*nodeGuardToken); ok {
		if token := tokens[guardID]; token != nil && token.agent == a && token.active.Load() {
			return func() {}, nil
		}
	}
	value, _ := a.guards.LoadOrStore(guardID, make(chan struct{}, 1))
	gate := value.(chan struct{})
	select {
	case gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	releaseGate := func() { <-gate }
	if err := nodePrivateDirectory(a.guardRoot); err != nil {
		releaseGate()
		return nil, err
	}
	fd, err := unix.Open(filepath.Join(a.guardRoot, guardID+".lock"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		releaseGate()
		return nil, refused("unsafe_root")
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Getuid()) || st.Mode&0077 != 0 {
		unix.Close(fd)
		releaseGate()
		return nil, refused("unsafe_root")
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
			unix.Close(fd)
			releaseGate()
			return nil, err
		}
		select {
		case <-ctx.Done():
			unix.Close(fd)
			releaseGate()
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = unix.Close(fd); releaseGate() }, nil
}
func (a *NodeAgent) withOperation(ctx context.Context, id ExecutionIdentity, fn func() error) error {
	if err := id.Validate(); err != nil {
		return err
	}
	release, err := a.guard(ctx, "execution", id.Key())
	if err != nil {
		return err
	}
	defer release()
	return fn()
}
func (a *NodeAgent) withComponent(ctx context.Context, id ExecutionIdentity, fn func() error) error {
	if err := id.Validate(); err != nil {
		return err
	}
	release, err := a.guard(ctx, "component", nodeComponentKey(id))
	if err != nil {
		return err
	}
	defer release()
	return fn()
}

type nodeGuardContextKey struct{}
type nodeGuardToken struct {
	agent  *NodeAgent
	active atomic.Bool
}

// WithComponentGuardContext holds the component fence over staging or physical
// cleanup. Pass the callback context to nested NodeAgent calls. Its unexported
// token is valid only for this agent, this component, and the callback lifetime.
func (a *NodeAgent) WithComponentGuardContext(ctx context.Context, id ExecutionIdentity, purge bool, fn func(context.Context) error) error {
	if err := id.Validate(); err != nil {
		return err
	}
	if fn == nil {
		return refused("invalid_guard_callback")
	}
	key := "component-" + nodeComponentKey(id)
	release, err := a.guard(ctx, "component", nodeComponentKey(id))
	if err != nil {
		return err
	}
	token := &nodeGuardToken{agent: a}
	token.active.Store(true)
	defer func() { token.active.Store(false); release() }()
	held := map[string]*nodeGuardToken{}
	if prior, ok := ctx.Value(nodeGuardContextKey{}).(map[string]*nodeGuardToken); ok {
		for k, v := range prior {
			held[k] = v
		}
	}
	held[key] = token
	nested := context.WithValue(ctx, nodeGuardContextKey{}, held)
	if purge {
		allowed, err := a.ComponentPurgeAllowed(nested, id)
		if err != nil {
			return err
		}
		if !allowed {
			return refused("runtime_active")
		}
	}
	return fn(nested)
}

// WithComponentResourceGuard serializes local staging and purge. The callback must not reserve the same component.
func (a *NodeAgent) WithComponentResourceGuard(ctx context.Context, id ExecutionIdentity, fn func() error) error {
	return a.withComponent(ctx, id, fn)
}
func (a *NodeAgent) WithComponentPurgeGuard(ctx context.Context, id ExecutionIdentity, fn func() error) error {
	return a.withComponent(ctx, id, func() error {
		allowed, err := a.ComponentPurgeAllowed(ctx, id)
		if err != nil {
			return err
		}
		if !allowed {
			return refused("runtime_active")
		}
		return fn()
	})
}

type nodeQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (a *NodeAgent) row(ctx context.Context, q nodeQuerier, id ExecutionIdentity, allowStale bool) (nodeRecord, error) {
	if err := id.Validate(); err != nil {
		return nodeRecord{}, err
	}
	record, err := scanNodeRecord(q.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM executions WHERE execution_key=?", id.Key()))
	if errors.Is(err, sql.ErrNoRows) {
		return record, refused("missing_reservation")
	}
	if err != nil {
		return record, err
	}
	if record.Identity != id {
		return record, refused("identity_mismatch")
	}
	if !allowStale {
		var epoch int64
		if err = q.QueryRowContext(ctx, "SELECT epoch FROM fences WHERE job_id=? AND component_id=?", id.JobID, id.ComponentID).Scan(&epoch); err != nil || epoch != id.Epoch {
			return record, refused("stale_epoch")
		}
	}
	return record, nil
}
func (a *NodeAgent) leaseValid(row nodeRecord) bool {
	now, wall := a.clock(), a.wallClock()
	return nodeFinite(now) && nodeFinite(wall) && row.BootID == a.bootID && now < row.LeaseUntil && (!row.Deadline.Valid || wall < row.Deadline.Float64)
}
func (a *NodeAgent) allowLaunch(id ExecutionIdentity) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	row, err := a.row(context.Background(), a.db, id, false)
	return err == nil && a.leaseValid(row) && row.State != "STOPPED" && row.State != "QUARANTINED" && row.State != "RELEASED"
}
func (a *NodeAgent) transaction(ctx context.Context, fn func(*sql.Tx) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
func nodeStorageUsage(ctx context.Context, q nodeQuerier) (int64, error) {
	var local, shared int64
	err := q.QueryRowContext(ctx, "SELECT COALESCE(SUM(CASE WHEN disk_released=1 THEN 0 ELSE disk_bytes*2+? END+auxiliary_bytes),0) FROM executions", StorageHeadroomBytes).Scan(&local)
	if err != nil {
		return 0, err
	}
	if err = q.QueryRowContext(ctx, "SELECT COALESCE(SUM(reserved_bytes),0) FROM shared_auxiliary").Scan(&shared); err != nil {
		return 0, err
	}
	if local < 0 || shared < 0 || local > math.MaxInt64-shared {
		return 0, refused("invalid_resources")
	}
	return local + shared, nil
}
func (a *NodeAgent) StorageUsageBytes(ctx context.Context) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return nodeStorageUsage(ctx, a.db)
}
func (a *NodeAgent) quarantine(ctx context.Context, id ExecutionIdentity, cause error) error {
	// A caller may already have cancelled its request. Persist quarantine independently.
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a.mu.Lock()
	defer a.mu.Unlock()
	_, err := a.db.ExecContext(cleanup, "UPDATE executions SET state='QUARANTINED' WHERE execution_key=? AND state!='RELEASED'", id.Key())
	if err != nil {
		return uncertain(errors.Join(cause, err))
	}
	return cause
}
func (a *NodeAgent) Reserve(ctx context.Context, spec ExecutionSpec) (result Reservation, err error) {
	if err = spec.Validate(); err != nil {
		return result, err
	}
	if spec.NodeID != "" && spec.NodeID != a.NodeID {
		return result, refused("node_mismatch")
	}
	if spec.PoolID != "" && spec.PoolID != a.PoolID {
		return result, refused("pool_mismatch")
	}
	if spec.Deadline != nil && a.wallClock() >= *spec.Deadline {
		return result, refused("job_deadline_expired")
	}
	serialized, e := spec.Canonical()
	if e != nil {
		return result, e
	}
	err = a.withComponent(ctx, spec.Identity, func() error {
		return a.withOperation(ctx, spec.Identity, func() error {
			if qualified, ok := a.Backend.(interface{ QualifyHealth(context.Context) error }); ok {
				if e := qualified.QualifyHealth(ctx); e != nil {
					return e
				}
			}
			pending := false
			err := a.transaction(ctx, func(tx *sql.Tx) error {
				prior, readErr := a.row(ctx, tx, spec.Identity, false)
				if readErr == nil {
					if !nodeSpecMatches(prior.Spec, serialized) {
						return refused("reservation_conflict")
					}
					if prior.State == "QUARANTINED" {
						return refused("node_quarantined")
					}
					if prior.State != "RESERVING" {
						result = Reservation{Identity: spec.Identity, Acknowledged: true, NodeID: a.NodeID, State: prior.State}
						return nil
					}
					if !a.leaseValid(prior) {
						return refused("lease_expired")
					}
					pending = true
					return nil
				}
				if ErrorCode(readErr) != "missing_reservation" {
					return readErr
				}
				var fence int64
				e := tx.QueryRowContext(ctx, "SELECT epoch FROM fences WHERE job_id=? AND component_id=?", spec.Identity.JobID, spec.Identity.ComponentID).Scan(&fence)
				if e != nil && !errors.Is(e, sql.ErrNoRows) {
					return e
				}
				if e == nil && spec.Identity.Epoch <= fence {
					return refused("stale_epoch")
				}
				var existing int64
				if e = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM executions WHERE job_id=? AND component_id=? AND state!='RELEASED'", spec.Identity.JobID, spec.Identity.ComponentID).Scan(&existing); e != nil {
					return e
				}
				if existing != 0 {
					return refused("node_quarantined")
				}
				var cpu, memory int64
				if e = tx.QueryRowContext(ctx, "SELECT COALESCE(SUM(CASE WHEN state!='RELEASED' THEN cpu_millis ELSE 0 END),0),COALESCE(SUM(CASE WHEN state!='RELEASED' THEN memory_bytes ELSE 0 END),0) FROM executions").Scan(&cpu, &memory); e != nil {
					return e
				}
				used, e := nodeStorageUsage(ctx, tx)
				if e != nil {
					return e
				}
				budget, e := ExecutionStorageBudget(spec.Resources.DiskBytes)
				if e != nil {
					return e
				}
				if cpu < 0 || memory < 0 || cpu > a.Capacity.CPUMillis || memory > a.Capacity.MemoryBytes || used > a.Capacity.DiskBytes || spec.Resources.CPUMillis > a.Capacity.CPUMillis-cpu || spec.Resources.MemoryBytes > a.Capacity.MemoryBytes-memory || budget > a.Capacity.DiskBytes-used {
					return refused("capacity")
				}
				if _, e = tx.ExecContext(ctx, "INSERT INTO fences(job_id,component_id,epoch) VALUES(?,?,?) ON CONFLICT(job_id,component_id) DO UPDATE SET epoch=excluded.epoch", spec.Identity.JobID, spec.Identity.ComponentID, spec.Identity.Epoch); e != nil {
					return e
				}
				var deadline any
				if spec.Deadline != nil {
					deadline = *spec.Deadline
				}
				_, e = tx.ExecContext(ctx, "INSERT INTO executions(execution_key,job_id,attempt_id,component_id,epoch,spec,state,cpu_millis,memory_bytes,disk_bytes,lease_until,deadline,boot_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", spec.Identity.Key(), spec.Identity.JobID, spec.Identity.AttemptID, spec.Identity.ComponentID, spec.Identity.Epoch, string(serialized), "RESERVING", spec.Resources.CPUMillis, spec.Resources.MemoryBytes, spec.Resources.DiskBytes, a.clock()+spec.LeaseSeconds, deadline, a.bootID)
				if e == nil {
					pending = true
				}
				return e
			})
			if err != nil || !pending {
				return err
			}
			// Durable intent and the capacity/fence charge committed before the external effect.
			reservation, e := a.Backend.Reserve(ctx, spec)
			if e == nil && (!reservation.Acknowledged || reservation.Identity != spec.Identity || (reservation.NodeID != "" && reservation.NodeID != a.NodeID)) {
				e = uncertain(errors.New("unacknowledged or foreign reservation"))
			}
			if e != nil {
				return a.quarantine(ctx, spec.Identity, e)
			}
			e = a.transaction(ctx, func(tx *sql.Tx) error {
				row, e := a.row(ctx, tx, spec.Identity, false)
				if e != nil {
					return e
				}
				if row.State != "RESERVING" || !a.leaseValid(row) {
					return refused("lease_expired")
				}
				_, e = tx.ExecContext(ctx, "UPDATE executions SET state='RESERVED' WHERE execution_key=?", spec.Identity.Key())
				return e
			})
			if e != nil {
				return a.quarantine(ctx, spec.Identity, e)
			}
			result = Reservation{Identity: spec.Identity, Acknowledged: true, NodeID: a.NodeID, State: "RESERVED"}
			return nil
		})
	})
	return result, err
}
func (a *NodeAgent) Renew(ctx context.Context, id ExecutionIdentity) error {
	return a.RenewLease(ctx, id, 120)
}
func (a *NodeAgent) RenewLease(ctx context.Context, id ExecutionIdentity, seconds float64) error {
	if !nodeFinite(seconds) || seconds <= 0 || seconds > 300 {
		return refused("invalid_lease")
	}
	return a.transaction(ctx, func(tx *sql.Tx) error {
		row, err := a.row(ctx, tx, id, false)
		if err != nil {
			return err
		}
		if row.State == "QUARANTINED" || row.State == "STOPPED" || row.State == "STOPPING" || row.State == "RELEASED" || !a.leaseValid(row) {
			return refused("lease_expired")
		}
		_, err = tx.ExecContext(ctx, "UPDATE executions SET lease_until=? WHERE execution_key=?", a.clock()+seconds, id.Key())
		return err
	})
}
func (a *NodeAgent) Start(ctx context.Context, id ExecutionIdentity) (result RuntimeObservation, err error) {
	err = a.withOperation(ctx, id, func() error {
		err := a.transaction(ctx, func(tx *sql.Tx) error {
			row, e := a.row(ctx, tx, id, false)
			if e != nil {
				return e
			}
			if !a.leaseValid(row) {
				return refused("lease_expired")
			}
			if row.State != "RESERVED" && row.State != "RUNNING" && row.State != "STARTING" {
				return refused("invalid_execution_state")
			}
			_, e = tx.ExecContext(ctx, "UPDATE executions SET state='STARTING' WHERE execution_key=?", id.Key())
			return e
		})
		if err != nil {
			return err
		}
		result, err = a.Backend.Start(ctx, id)
		if err != nil {
			return a.quarantine(ctx, id, err)
		}
		valid := false
		err = a.transaction(ctx, func(tx *sql.Tx) error {
			row, e := a.row(ctx, tx, id, false)
			if e != nil {
				return e
			}
			valid = a.leaseValid(row)
			_, e = tx.ExecContext(ctx, "UPDATE executions SET state=? WHERE execution_key=?", result.State, id.Key())
			return e
		})
		if err != nil {
			return a.quarantine(ctx, id, uncertain(err))
		}
		if !valid {
			_, stopErr := a.stop(ctx, id, 0)
			if stopErr != nil {
				return a.quarantine(ctx, id, stopErr)
			}
			return refused("lease_expired")
		}
		return nil
	})
	return result, err
}
func (a *NodeAgent) inspect(ctx context.Context, id ExecutionIdentity) (RuntimeObservation, error) {
	a.mu.Lock()
	row, err := a.row(ctx, a.db, id, false)
	a.mu.Unlock()
	if err != nil {
		return RuntimeObservation{}, err
	}
	if row.ExecutorAbsent {
		return RuntimeObservation{Identity: id, State: row.State, TerminationConfirmed: true, Details: map[string]any{"never_reserved": true}}, nil
	}
	result, err := a.Backend.Inspect(ctx, id)
	if ErrorCode(err) == "missing_reservation" && row.State == "RESERVING" {
		return RuntimeObservation{Identity: id, State: "RESERVING"}, nil
	}
	if IsUncertain(err) {
		return result, a.quarantine(ctx, id, err)
	}
	return result, err
}
func (a *NodeAgent) Inspect(ctx context.Context, id ExecutionIdentity) (RuntimeObservation, error) {
	return a.inspect(ctx, id)
}
func (a *NodeAgent) stop(ctx context.Context, id ExecutionIdentity, grace int) (RuntimeObservation, error) {
	a.mu.Lock()
	row, err := a.row(ctx, a.db, id, false)
	a.mu.Unlock()
	if err != nil {
		return RuntimeObservation{}, err
	}
	if row.State == "RELEASED" || row.ExecutorAbsent {
		return a.inspect(ctx, id)
	}
	if err = a.transaction(ctx, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, "UPDATE executions SET state='STOPPING' WHERE execution_key=?", id.Key())
		return e
	}); err != nil {
		return RuntimeObservation{}, err
	}
	observed, err := a.Backend.Stop(ctx, id, grace)
	absent := false
	if ErrorCode(err) == "missing_reservation" {
		if proof, ok := a.Backend.(interface {
			ConfirmAbsent(context.Context, ExecutionIdentity) (bool, error)
		}); ok {
			confirmed, proofErr := proof.ConfirmAbsent(ctx, id)
			if proofErr == nil && confirmed {
				absent = true
				observed = RuntimeObservation{Identity: id, State: "STOPPED", TerminationConfirmed: true, Details: map[string]any{"never_reserved": true}}
				err = nil
			}
		}
	}
	if err == nil && !observed.TerminationConfirmed {
		err = uncertain(errors.New("termination not confirmed"))
	}
	if err != nil {
		return observed, a.quarantine(ctx, id, err)
	}
	err = a.transaction(ctx, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, "UPDATE executions SET state='STOPPED',stopped=1,executor_absent=? WHERE execution_key=?", absent, id.Key())
		return e
	})
	if err != nil {
		return observed, a.quarantine(ctx, id, uncertain(err))
	}
	return observed, nil
}
func (a *NodeAgent) Stop(ctx context.Context, id ExecutionIdentity, grace int) (result RuntimeObservation, err error) {
	err = a.withOperation(ctx, id, func() error { var e error; result, e = a.stop(ctx, id, grace); return e })
	return result, err
}
func (a *NodeAgent) collect(ctx context.Context, id ExecutionIdentity) ([]CollectedArtifact, error) {
	a.mu.Lock()
	row, err := a.row(ctx, a.db, id, true)
	if err == nil && row.State != "RELEASED" {
		row, err = a.row(ctx, a.db, id, false)
	}
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if row.DiskReleased || row.ExecutorAbsent {
		return []CollectedArtifact{}, nil
	}
	if !row.Stopped {
		observed, e := a.inspect(ctx, id)
		if e != nil {
			return nil, e
		}
		if !observed.TerminationConfirmed {
			return nil, refused("runtime_active")
		}
	}
	files, err := a.Backend.Collect(ctx, id)
	if err != nil {
		return nil, err
	}
	var actual int64
	for _, file := range files {
		if file.SizeBytes < 0 || file.SizeBytes > math.MaxInt64-actual {
			return nil, refused("retention_capacity")
		}
		actual += file.SizeBytes
	}
	if row.DiskBytes > math.MaxInt64-StorageHeadroomBytes || actual > row.DiskBytes+StorageHeadroomBytes {
		return nil, refused("retention_capacity")
	}
	err = a.transaction(ctx, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, "UPDATE executions SET retained_output_bytes=? WHERE execution_key=?", actual, id.Key())
		return e
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}
func (a *NodeAgent) Collect(ctx context.Context, id ExecutionIdentity) (result []CollectedArtifact, err error) {
	err = a.withOperation(ctx, id, func() error { var e error; result, e = a.collect(ctx, id); return e })
	return result, err
}
func (a *NodeAgent) RetainedManifest(ctx context.Context, id ExecutionIdentity) ([]CollectedArtifact, error) {
	return a.Collect(ctx, id)
}
func (a *NodeAgent) Release(ctx context.Context, id ExecutionIdentity) (confirmed bool, err error) {
	err = a.withOperation(ctx, id, func() error {
		a.mu.Lock()
		row, e := a.row(ctx, a.db, id, false)
		a.mu.Unlock()
		if e != nil {
			return e
		}
		if row.State == "RELEASED" {
			confirmed = true
			return nil
		}
		observed, e := a.inspect(ctx, id)
		if e != nil {
			return e
		}
		if !observed.TerminationConfirmed {
			return uncertain(errors.New("active or unknown execution"))
		}
		if observed.State != "RESERVED" && observed.State != "PREPARING" {
			if _, e = a.collect(ctx, id); e != nil {
				return e
			}
		}
		if !row.ExecutorAbsent {
			ok, e := a.Backend.Release(ctx, id)
			if e != nil {
				return e
			}
			if !ok {
				return uncertain(errors.New("release not confirmed"))
			}
		}
		if e = a.transaction(ctx, func(tx *sql.Tx) error {
			_, e := tx.ExecContext(ctx, "UPDATE executions SET state='RELEASED',stopped=1 WHERE execution_key=?", id.Key())
			return e
		}); e != nil {
			return uncertain(e)
		}
		confirmed = true
		return nil
	})
	return confirmed, err
}
func (a *NodeAgent) Purge(ctx context.Context, id ExecutionIdentity) (bool, error) {
	return a.PurgeWithAuxiliary(ctx, id, false)
}
func (a *NodeAgent) PurgeWithAuxiliary(ctx context.Context, id ExecutionIdentity, auxiliaryDeleted bool) (confirmed bool, err error) {
	err = a.withComponent(ctx, id, func() error {
		return a.withOperation(ctx, id, func() error {
			a.mu.Lock()
			row, e := a.row(ctx, a.db, id, true)
			var shared int64
			if e == nil {
				e = a.db.QueryRowContext(ctx, "SELECT COALESCE((SELECT reserved_bytes FROM shared_auxiliary WHERE job_id=? AND component_id=?),0)", id.JobID, id.ComponentID).Scan(&shared)
			}
			a.mu.Unlock()
			if e != nil {
				return e
			}
			if row.State != "RELEASED" {
				return refused("runtime_active")
			}
			if row.DiskReleased && shared == 0 {
				confirmed = true
				return nil
			}
			if (row.AuxiliaryBytes > 0 || shared > 0) && !auxiliaryDeleted {
				return refused("auxiliary_storage_retained")
			}
			if auxiliaryDeleted {
				ok, e := a.ComponentPurgeAllowed(ctx, id)
				if e != nil {
					return e
				}
				if !ok {
					return refused("runtime_active")
				}
			}
			if !row.ExecutorAbsent {
				ok, e := a.Backend.Purge(ctx, id)
				if e != nil {
					return e
				}
				if !ok {
					return uncertain(errors.New("retained deletion not confirmed"))
				}
			}
			e = a.transaction(ctx, func(tx *sql.Tx) error {
				if _, e := tx.ExecContext(ctx, "UPDATE executions SET disk_released=1,auxiliary_bytes=0 WHERE execution_key=?", id.Key()); e != nil {
					return e
				}
				if auxiliaryDeleted {
					_, e := tx.ExecContext(ctx, "UPDATE shared_auxiliary SET reserved_bytes=0 WHERE job_id=? AND component_id=?", id.JobID, id.ComponentID)
					return e
				}
				return nil
			})
			if e != nil {
				return uncertain(e)
			}
			confirmed = true
			return nil
		})
	})
	return confirmed, err
}
func (a *NodeAgent) AssignmentResources(ctx context.Context, id ExecutionIdentity, allowStale bool) (map[string]int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	row, err := a.row(ctx, a.db, id, allowStale)
	if err != nil {
		return nil, err
	}
	return map[string]int64{"cpu_millicores": row.CPUMillis, "memory_bytes": row.MemoryBytes, "disk_bytes": row.DiskBytes}, nil
}
func (a *NodeAgent) ComponentPurgeAllowed(ctx context.Context, id ExecutionIdentity) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.row(ctx, a.db, id, true); err != nil {
		return false, err
	}
	var count, active int64
	err := a.db.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(CASE WHEN state!='RELEASED' THEN 1 ELSE 0 END),0) FROM executions WHERE job_id=? AND component_id=?", id.JobID, id.ComponentID).Scan(&count, &active)
	return count > 0 && active == 0, err
}
func (a *NodeAgent) ConfirmAbsent(ctx context.Context, id ExecutionIdentity) (confirmed bool, err error) {
	err = a.withComponent(ctx, id, func() error {
		return a.withOperation(ctx, id, func() error {
			a.mu.Lock()
			var count int64
			e := a.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM executions WHERE execution_key=? OR(job_id=? AND component_id=? AND state!='RELEASED')", id.Key(), id.JobID, id.ComponentID).Scan(&count)
			a.mu.Unlock()
			if e != nil {
				return e
			}
			if count != 0 {
				return nil
			}
			proof, ok := a.Backend.(interface {
				ConfirmAbsent(context.Context, ExecutionIdentity) (bool, error)
			})
			if !ok {
				return nil
			}
			confirmed, e = proof.ConfirmAbsent(ctx, id)
			if e != nil {
				confirmed = false
				return nil
			}
			return nil
		})
	})
	return confirmed, err
}
func (a *NodeAgent) chargeAuxiliary(ctx context.Context, id ExecutionIdentity, total int64, shared bool) (bool, error) {
	if total < 0 {
		return false, refused("invalid_resources")
	}
	err := a.transaction(ctx, func(tx *sql.Tx) error {
		row, e := a.row(ctx, tx, id, false)
		if e != nil {
			return e
		}
		if row.State == "RELEASED" || row.State == "STOPPED" || row.State == "QUARANTINED" || row.DiskReleased {
			return refused("invalid_execution_state")
		}
		previous := row.AuxiliaryBytes
		if shared {
			if e = tx.QueryRowContext(ctx, "SELECT COALESCE((SELECT reserved_bytes FROM shared_auxiliary WHERE job_id=? AND component_id=?),0)", id.JobID, id.ComponentID).Scan(&previous); e != nil {
				return e
			}
		}
		if previous < 0 {
			return refused("invalid_resources")
		}
		if total <= previous {
			return nil
		}
		used, e := nodeStorageUsage(ctx, tx)
		if e != nil {
			return e
		}
		if used > a.Capacity.DiskBytes || total-previous > a.Capacity.DiskBytes-used {
			return refused("capacity")
		}
		if shared {
			_, e = tx.ExecContext(ctx, "INSERT INTO shared_auxiliary(job_id,component_id,reserved_bytes)VALUES(?,?,?) ON CONFLICT(job_id,component_id) DO UPDATE SET reserved_bytes=excluded.reserved_bytes", id.JobID, id.ComponentID, total)
		} else {
			_, e = tx.ExecContext(ctx, "UPDATE executions SET auxiliary_bytes=? WHERE execution_key=?", total, id.Key())
		}
		return e
	})
	return err == nil, err
}
func (a *NodeAgent) ChargeAuxiliaryBytes(ctx context.Context, id ExecutionIdentity, total int64) (bool, error) {
	return a.chargeAuxiliary(ctx, id, total, false)
}
func (a *NodeAgent) ChargeSharedAuxiliaryBytes(ctx context.Context, id ExecutionIdentity, total int64) (bool, error) {
	return a.chargeAuxiliary(ctx, id, total, true)
}
func (a *NodeAgent) ReadLogs(ctx context.Context, id ExecutionIdentity, offset, maxBytes int64) (result map[string]any, err error) {
	if offset < 0 || maxBytes < 1 || maxBytes > 65536 {
		return nil, refused("invalid_log_range")
	}
	err = a.withOperation(ctx, id, func() error {
		a.mu.Lock()
		row, e := a.row(ctx, a.db, id, true)
		if e == nil && row.State != "RELEASED" {
			row, e = a.row(ctx, a.db, id, false)
		}
		a.mu.Unlock()
		if e != nil {
			return e
		}
		if row.DiskReleased {
			return refused("artifact_unavailable")
		}
		if row.ExecutorAbsent {
			if offset != 0 {
				return refused("log_cursor_conflict")
			}
			result = map[string]any{"identity": id, "source_id": id.Key(), "offset": int64(0), "next_offset": int64(0), "content": "", "complete": true, "truncated": false}
			return nil
		}
		reader, ok := a.Backend.(interface {
			ReadLogs(context.Context, ExecutionIdentity, int64, int64) (map[string]any, error)
		})
		if !ok {
			return refused("logs_unavailable")
		}
		result, e = reader.ReadLogs(ctx, id, offset, maxBytes)
		return e
	})
	return result, err
}
func (a *NodeAgent) ReadArtifact(ctx context.Context, id ExecutionIdentity, path string, maxBytes int64) (result []byte, err error) {
	if maxBytes < 1 || maxBytes > 256*1024*1024 {
		return nil, refused("unsafe_output")
	}
	err = a.withOperation(ctx, id, func() error {
		a.mu.Lock()
		row, e := a.row(ctx, a.db, id, true)
		if e == nil && row.State != "RELEASED" {
			row, e = a.row(ctx, a.db, id, false)
		}
		a.mu.Unlock()
		if e != nil {
			return e
		}
		if row.DiskReleased {
			return refused("artifact_unavailable")
		}
		if _, e = a.collect(ctx, id); e != nil {
			return e
		}
		reader, ok := a.Backend.(interface {
			ReadArtifact(context.Context, ExecutionIdentity, string, int64) ([]byte, error)
		})
		if !ok {
			return refused("artifact_unavailable")
		}
		result, e = reader.ReadArtifact(ctx, id, path, maxBytes)
		return e
	})
	return result, err
}
func (a *NodeAgent) ReconciliationRoot(ctx context.Context, id ExecutionIdentity) (string, error) {
	a.mu.Lock()
	_, err := a.row(ctx, a.db, id, false)
	a.mu.Unlock()
	if err != nil {
		return "", err
	}
	reader, ok := a.Backend.(interface {
		ReconciliationRoot(context.Context, ExecutionIdentity) (string, error)
	})
	if !ok {
		return "", refused("missing_resource")
	}
	return reader.ReconciliationRoot(ctx, id)
}
func (a *NodeAgent) WatchdogOnce(ctx context.Context) ([]ExecutionIdentity, error) {
	a.mu.Lock()
	rows, err := a.db.QueryContext(ctx, "SELECT "+nodeColumns+" FROM executions WHERE state NOT IN('RELEASED','STOPPED')")
	if err != nil {
		a.mu.Unlock()
		return nil, err
	}
	records := []nodeRecord{}
	for rows.Next() {
		record, e := scanNodeRecord(rows)
		if e != nil {
			rows.Close()
			a.mu.Unlock()
			return nil, e
		}
		records = append(records, record)
	}
	err = rows.Err()
	rows.Close()
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	expired := []ExecutionIdentity{}
	for _, record := range records {
		if a.leaseValid(record) {
			continue
		}
		stopCtx, cancel := context.WithTimeout(ctx, 65*time.Second)
		claimed := false
		err := a.withOperation(stopCtx, record.Identity, func() error {
			// Re-read under the write transaction: a renewal can commit after the initial
			// inventory snapshot. Mark STOPPING before the side effect to exclude revival.
			err := a.transaction(stopCtx, func(tx *sql.Tx) error {
				current, e := a.row(stopCtx, tx, record.Identity, false)
				if e != nil {
					return e
				}
				if current.State == "RELEASED" || current.State == "STOPPED" || a.leaseValid(current) {
					return nil
				}
				if _, e = tx.ExecContext(stopCtx, "UPDATE executions SET state='STOPPING' WHERE execution_key=?", record.Identity.Key()); e != nil {
					return e
				}
				claimed = true
				return nil
			})
			if err != nil || !claimed {
				return err
			}
			_, err = a.stop(stopCtx, record.Identity, 0)
			return err
		})
		cancel()
		if claimed {
			expired = append(expired, record.Identity)
		}
		if err != nil {
			_ = a.quarantine(ctx, record.Identity, err)
		}
	}
	return expired, nil
}
func (a *NodeAgent) Inventory(ctx context.Context) ([]map[string]any, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	rows, err := a.db.QueryContext(ctx, "SELECT "+nodeColumns+" FROM executions ORDER BY execution_key")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	inventory := []map[string]any{}
	for rows.Next() {
		row, err := scanNodeRecord(rows)
		if err != nil {
			return nil, err
		}
		var deadline any
		if row.Deadline.Valid {
			deadline = row.Deadline.Float64
		}
		inventory = append(inventory, map[string]any{"execution_key": row.Key, "job_id": row.Identity.JobID, "attempt_id": row.Identity.AttemptID, "component_id": row.Identity.ComponentID, "epoch": row.Identity.Epoch, "state": row.State, "cpu_millis": row.CPUMillis, "memory_bytes": row.MemoryBytes, "disk_bytes": row.DiskBytes, "lease_until": row.LeaseUntil, "deadline": deadline, "boot_id": row.BootID, "stopped": nodeFlag(row.Stopped), "disk_released": nodeFlag(row.DiskReleased), "retained_output_bytes": row.RetainedOutputBytes, "auxiliary_bytes": row.AuxiliaryBytes})
	}
	return inventory, rows.Err()
}

var _ FullBackend = (*NodeAgent)(nil)

func nodeFlag(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func nodeSpecMatches(stored string, expected []byte) bool {
	var spec ExecutionSpec
	if err := json.Unmarshal([]byte(stored), &spec); err != nil {
		return false
	}
	encoded, err := spec.Canonical()
	return err == nil && string(encoded) == string(expected)
}
