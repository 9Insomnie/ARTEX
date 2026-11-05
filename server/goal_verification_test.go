package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestGoalVerificationHTTPRequiresOperatorAndCompletesTask(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s := &Server{m: m, ctx: ctx, engine: NewEngine(m), jwtKey: []byte("acceptance-test-key-32-bytes-long!")}
	task, err := m.CreateTask("acceptance API", "review candidate", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskNum, _ := parseTaskID(task.ID)
	defer m.pg.DeleteTask(taskNum)
	g, err := task.Store.AddGoal(map[string]any{"text": "human verifies outcome"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	e, err := task.Store.AddNode(db.KindFact, map[string]any{"summary": "candidate", "evidence": "command output"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body string, authenticated bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if authenticated {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	path := fmt.Sprintf("/api/tasks/%s/goals/%d/verification", task.ID, g)
	request := fmt.Sprintf(`{"evidence_id":%d,"reason":"candidate"}`, e)
	if w := call(http.MethodPost, path, request, false); w.Code != 401 {
		t.Fatalf("unauthorized status=%d", w.Code)
	}
	w := call(http.MethodPost, path, request, true)
	if w.Code != 200 {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	var v db.GoalVerification
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.Status != "needs_review" {
		t.Fatalf("self accepted: %s", w.Body.String())
	}
	reviewPath := fmt.Sprintf("/api/tasks/%s/goal-verifications/%d/review", task.ID, v.ID)
	if w := call(http.MethodPost, reviewPath, `{"decision":"accept","note":""}`, true); w.Code != 400 {
		t.Fatalf("accepted review without reason: %d", w.Code)
	}
	w = call(http.MethodPost, reviewPath, `{"decision":"accept","note":"checked original evidence"}`, true)
	if w.Code != 200 {
		t.Fatalf("review: %d %s", w.Code, w.Body.String())
	}
	stored, err := m.pg.GetTask(taskNum)
	if err != nil || stored.Status != "done" || task.lifecycleSnapshot().Status != "done" {
		t.Fatalf("task not completed: %+v %v", stored, err)
	}
	if w := call(http.MethodPost, reviewPath, `{"decision":"accept","note":"replay"}`, true); w.Code != 409 {
		t.Fatalf("review replay=%d", w.Code)
	}
	// Subsequent evidence withdrawal revokes the decision in SQL and synchronizes
	// a paused task into the engine, without restarting model work.
	if err := task.Store.SetNodeState(e, "dismissed"); err != nil {
		t.Fatal(err)
	}
	s.syncInvalidatedGoalTasks()
	stored, err = m.pg.GetTask(taskNum)
	if err != nil || stored.Status != "running" || !stored.Paused {
		t.Fatalf("invalidated task not paused: %+v %v", stored, err)
	}
	state := task.lifecycleSnapshot()
	if !state.Paused || state.Status != "running" {
		t.Fatalf("stale in-memory state: %+v", state)
	}
	n, _ := task.Store.GetNode(g)
	if n.State != "open" {
		t.Fatal("stale goal remained met")
	}
}
