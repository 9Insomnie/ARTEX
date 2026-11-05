package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/acceptance"
	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func writeGoalVerificationError(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	if errors.Is(err, db.ErrGoalVerificationInvalid) {
		code = http.StatusBadRequest
	}
	if errors.Is(err, db.ErrGoalVerificationConflict) {
		code = http.StatusConflict
	}
	writeErr(w, code, err.Error())
}
func decodeGoalVerification(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		writeErr(w, 400, "验收参数无效: "+err.Error())
		return false
	}
	return true
}
func (s *Server) goalVerificationTask(w http.ResponseWriter, r *http.Request) (*Task, bool) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return nil, false
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, "任务正在删除")
		return nil, false
	}
	return t, true
}
func (s *Server) listGoalVerifications(w http.ResponseWriter, r *http.Request) {
	t, ok := s.goalVerificationTask(w, r)
	if !ok {
		return
	}
	defer s.engine.decInflight(t.ID)
	items, err := t.Store.GoalVerifications(r.Context())
	if err != nil {
		writeGoalVerificationError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func (s *Server) setGoalAcceptance(w http.ResponseWriter, r *http.Request) {
	t, ok := s.goalVerificationTask(w, r)
	if !ok {
		return
	}
	defer s.engine.decInflight(t.ID)
	var spec acceptance.Spec
	if !decodeGoalVerification(w, r, &spec) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("gid"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "bad goal id")
		return
	}
	if err := t.Store.SetGoalAcceptance(r.Context(), id, spec); err != nil {
		writeGoalVerificationError(w, err)
		return
	}
	s.reviveTask(t)
	t.Notify()
	n, err := t.Store.GetNode(id)
	if err != nil {
		writeGoalVerificationError(w, err)
		return
	}
	writeJSON(w, 200, goalDTO(n))
}
func (s *Server) submitGoalVerification(w http.ResponseWriter, r *http.Request) {
	t, ok := s.goalVerificationTask(w, r)
	if !ok {
		return
	}
	defer s.engine.decInflight(t.ID)
	var request struct {
		EvidenceID int64  `json:"evidence_id"`
		Reason     string `json:"reason"`
	}
	if !decodeGoalVerification(w, r, &request) {
		return
	}
	gid, err := strconv.ParseInt(r.PathValue("gid"), 10, 64)
	if err != nil || gid <= 0 {
		writeErr(w, 400, "bad goal id")
		return
	}
	root := filepath.Join(s.m.dir, "tasks", t.ID)
	result, err := t.Store.SubmitGoalVerification(r.Context(), gid, request.EvidenceID, request.Reason, "ARTEX", root)
	if err != nil {
		writeGoalVerificationError(w, err)
		return
	}
	if err := s.finishGoalVerification(r.Context(), t, result); err != nil {
		writeGoalVerificationError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) reviewGoalVerification(w http.ResponseWriter, r *http.Request) {
	t, ok := s.goalVerificationTask(w, r)
	if !ok {
		return
	}
	defer s.engine.decInflight(t.ID)
	var request struct {
		Decision string `json:"decision"`
		Note     string `json:"note"`
	}
	if !decodeGoalVerification(w, r, &request) {
		return
	}
	if request.Decision != "accept" && request.Decision != "reject" {
		writeErr(w, 400, "decision 必须为 accept 或 reject")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("vid"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "bad verification id")
		return
	}
	result, err := t.Store.ReviewGoalVerification(r.Context(), id, request.Decision == "accept", "ARTEX", request.Note)
	if err != nil {
		writeGoalVerificationError(w, err)
		return
	}
	if err := s.finishGoalVerification(r.Context(), t, result); err != nil {
		writeGoalVerificationError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) finishGoalVerification(ctx context.Context, t *Task, result *db.GoalVerification) error {
	if result.AllMet {
		completed, err := s.m.completeAcceptedTask(ctx, t)
		if err != nil {
			return err
		}
		if completed {
			s.engine.cancelExec(t.ID, agent.AbortGoalMet)
			go s.reconcileConcurrency()
		}
	}
	t.Notify()
	return nil
}
func (m *Manager) completeAcceptedTask(ctx context.Context, t *Task) (bool, error) {
	return m.completeGoalTask(ctx, t, false)
}
func (m *Manager) completeIdleTask(ctx context.Context, t *Task) (bool, error) {
	return m.completeGoalTask(ctx, t, true)
}
func (m *Manager) completeGoalTask(ctx context.Context, t *Task, idle bool) (bool, error) {
	m.taskStateMu.Lock()
	defer m.taskStateMu.Unlock()
	id, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return false, err
	}
	var completed bool
	if idle {
		completed, err = t.Store.CompleteIdleTask(ctx, id)
	} else {
		completed, err = t.Store.CompleteTaskIfGoalsMet(ctx, id)
	}
	if err != nil || !completed {
		return completed, err
	}
	t.updateLifecycle(func(state *taskLifecycleState) {
		state.Status = "done"
		if state.CompletedAt == 0 {
			state.CompletedAt = time.Now().Unix()
		}
		state.Paused, state.Queued, state.QueuedAt, state.QueueMode = false, false, 0, ""
	})
	return true, nil
}

// SQL invalidation is atomic with evidence changes. Mirror its paused lifecycle
// into the single-process engine before admitting any further task work.
func (s *Server) syncInvalidatedGoalTasks() {
	rows, err := s.m.pg.Query(`SELECT DISTINCT t.id FROM tasks t JOIN exploration_nodes g ON g.exploration_id=t.exploration_id
WHERE t.deleted_at IS NULL AND t.paused AND g.kind='goal' AND g.payload->>'acceptance_status'='stale'`)
	if err != nil {
		return
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		t, ok := s.m.Task(id)
		if !ok {
			continue
		}
		state := t.lifecycleSnapshot()
		if state.Paused && state.Status != "done" {
			continue
		}
		s.engine.Pause(id, agent.AbortGoalEvidenceChanged)
		_ = s.m.SetTaskStatus(id, "running")
		_ = s.m.SetTaskPaused(id, true)
	}
}
