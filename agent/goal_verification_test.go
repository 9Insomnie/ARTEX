package agent

import (
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestModelGoalToolsCannotBypassAcceptance(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	exp, err := d.CreateExploration("goal tool fixture", "test acceptance")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, exp)
	s := d.Exploration(exp)
	g, err := s.AddGoal(map[string]any{"text": "prove result"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.AddNode(db.KindFact, map[string]any{"evidence": "candidate trace", "summary": "claim"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	tools := NewToolSet(s, "planner")
	body, _ := json.Marshal(map[string]any{"goal_id": g, "evidence_id": e, "reason": "model asserts completion"})
	result, err := tools.proveGoal().Call(t.Context(), body, nil)
	if err != nil || result.IsError {
		t.Fatalf("submit: %+v %v", result, err)
	}
	var v db.GoalVerification
	if err := json.Unmarshal([]byte(result.Flatten()), &v); err != nil {
		t.Fatal(err)
	}
	if v.Status != "needs_review" || tools.GoalMet {
		t.Fatalf("model marked goal complete: %+v", v)
	}
	var reply map[string]any
	if err := json.Unmarshal([]byte(result.Flatten()), &reply); err != nil {
		t.Fatal(err)
	}
	if _, ok := reply["snapshot"]; ok {
		t.Fatal("full evidence snapshot leaked into model context")
	}
	result, err = tools.goalMet().Call(t.Context(), json.RawMessage(`{"reason":"override"}`), nil)
	if err != nil || !result.IsError || tools.GoalMet {
		t.Fatalf("legacy bypass succeeded: %+v %v", result, err)
	}
	n, _ := s.GetNode(g)
	if n.State != "open" {
		t.Fatalf("goal state=%s", n.State)
	}
}
