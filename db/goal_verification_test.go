package db

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/acceptance"
)

func verificationFixture(t *testing.T) (*DB, *ExplorationStore, int64, int64) {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	exp, err := d.CreateExploration("acceptance fixture", "review evidence")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, exp); d.Close() })
	s := d.Exploration(exp)
	goal, err := s.AddGoal(map[string]any{"text": "validate outcome"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	ev, err := s.AddNode(KindFact, map[string]any{"summary": "candidate", "evidence": "recorded command output", "confidence": "observed"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	return d, s, goal, ev
}

func TestGoalVerificationRequiresHumanAndRecordsDecisionAtomically(t *testing.T) {
	d, s, g, e := verificationFixture(t)
	v, err := s.SubmitGoalVerification(t.Context(), g, e, "candidate conclusion", "planner", "")
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != "needs_review" || v.AllMet {
		t.Fatalf("model accepted own claim: %+v", v)
	}
	n, _ := s.GetNode(g)
	if n.State != "open" {
		t.Fatalf("goal changed prematurely: %s", n.State)
	}
	actionable, err := s.HasActionableGoal()
	if err != nil || actionable {
		t.Fatalf("review wait still triggers planning: %v %v", actionable, err)
	}
	duplicate, err := s.SubmitGoalVerification(t.Context(), g, e, "same evidence", "planner", "")
	if err != nil || duplicate.ID != v.ID {
		t.Fatalf("not idempotent: %+v %v", duplicate, err)
	}
	v, err = s.ReviewGoalVerification(t.Context(), v.ID, true, "ARTEX", "checked original evidence and acceptance conditions")
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != "accepted" || !v.AllMet {
		t.Fatalf("review result: %+v", v)
	}
	n, _ = s.GetNode(g)
	if n.State != "met" {
		t.Fatal("accepted goal not met")
	}
	var edges int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_edges WHERE src_id=$1 AND dst_id=$2 AND rel='proves'`, e, g).Scan(&edges); err != nil || edges != 1 {
		t.Fatalf("proof missing: %d %v", edges, err)
	}
	if _, err := s.ReviewGoalVerification(t.Context(), v.ID, true, "ARTEX", "duplicate"); !errors.Is(err, ErrGoalVerificationConflict) {
		t.Fatalf("duplicate review err=%v", err)
	}
}

func TestGoalVerificationRejectsChangedEvidenceAndRules(t *testing.T) {
	d, s, g, e := verificationFixture(t)
	v, err := s.SubmitGoalVerification(t.Context(), g, e, "candidate", "planner", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE exploration_nodes SET payload=payload||'{"evidence":"changed"}'::jsonb WHERE id=$1`, e); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReviewGoalVerification(t.Context(), v.ID, true, "ARTEX", "old snapshot"); !errors.Is(err, ErrGoalVerificationConflict) {
		t.Fatalf("accepted stale evidence: %v", err)
	}
	if err := s.SetGoalAcceptance(t.Context(), g, acceptance.Spec{Type: "confirmed_findings", MinCount: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReviewGoalVerification(t.Context(), v.ID, true, "ARTEX", "old rule"); !errors.Is(err, ErrGoalVerificationConflict) {
		t.Fatalf("accepted stale rule: %v", err)
	}
	records, err := s.GoalVerifications(t.Context())
	if err != nil || records[0].Status != "stale" {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	if err := s.UpdateGoalPayload(g, "new goal", "XSS"); err != nil {
		t.Fatal(err)
	}
	n, _ := s.GetNode(g)
	spec, version, _ := GoalAcceptance(n.Payload)
	if n.State != "open" || spec.Type != "confirmed_findings" || version != 3 {
		t.Fatalf("goal edit lost policy/version: %s", n.Payload)
	}
}

func TestGoalVerificationCannotUseOriginDismissedOrUnrelatedEvidence(t *testing.T) {
	d, s, g, e := verificationFixture(t)
	other, err := d.CreateExploration("unrelated", "other")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, other)
	foreign, err := d.Exploration(other).AddNode(KindFact, map[string]any{"evidence": "foreign"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := s.AddNode(KindFact, map[string]any{"evidence": "task description"}, 0, "origin", "system", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeState(e, "dismissed"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{foreign, origin, e} {
		if _, err := s.SubmitGoalVerification(t.Context(), g, id, "claim", "planner", ""); !errors.Is(err, ErrGoalVerificationInvalid) {
			t.Fatalf("accepted evidence %d: %v", id, err)
		}
	}
}

func TestGoalVerificationRollsBackGoalEdgeAndAuditOnFailure(t *testing.T) {
	d, s, g, e := verificationFixture(t)
	v, err := s.SubmitGoalVerification(t.Context(), g, e, "candidate", "planner", "")
	if err != nil {
		t.Fatal(err)
	}
	// A database failure after the decision write must roll back every write.
	_, err = d.Exec(`CREATE FUNCTION fail_acceptance_goal_test() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='goal' AND NEW.state='met' THEN RAISE EXCEPTION 'fixture failure'; END IF; RETURN NEW; END $$;
CREATE TRIGGER fail_acceptance_goal_test BEFORE UPDATE ON exploration_nodes FOR EACH ROW EXECUTE FUNCTION fail_acceptance_goal_test()`)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DROP TRIGGER fail_acceptance_goal_test ON exploration_nodes; DROP FUNCTION fail_acceptance_goal_test()`)
	if _, err := s.ReviewGoalVerification(t.Context(), v.ID, true, "ARTEX", "checked"); err == nil {
		t.Fatal("ignored database failure")
	}
	n, _ := s.GetNode(g)
	if n.State != "open" {
		t.Fatal("goal update survived rollback")
	}
	var status string
	_ = d.QueryRow(`SELECT status FROM goal_verifications WHERE id=$1`, v.ID).Scan(&status)
	if status != "needs_review" {
		t.Fatalf("audit survived partial transaction: %s", status)
	}
	var count int
	_ = d.QueryRow(`SELECT count(*) FROM exploration_edges WHERE dst_id=$1 AND rel='proves'`, g).Scan(&count)
	if count != 0 {
		t.Fatal("proof survived rollback")
	}
}

func TestGoalVerificationChecksCanonicalCountAndArtifact(t *testing.T) {
	d, s, g, e := verificationFixture(t)
	if err := s.SetGoalAcceptance(t.Context(), g, acceptance.Spec{Type: "confirmed_findings", MinCount: 1, VulnClass: "XSS"}); err != nil {
		t.Fatal(err)
	}
	f, err := s.RecordFinding(t.Context(), RecordFindingInput{ExplorationID: s.ID(), VulnClass: "XSS", Severity: "low", Summary: "candidate", Evidence: "raw output", Worker: "worker"})
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.SubmitGoalVerification(t.Context(), g, f.NodeID, "count", "planner", "")
	if err != nil || v.Status != "needs_more_evidence" {
		t.Fatalf("counted pending finding: %+v %v", v, err)
	}
	if _, err := d.SetFindingStatus(f.FindingID, FindingConfirmed); err != nil {
		t.Fatal(err)
	}
	v, err = s.SubmitGoalVerification(t.Context(), g, f.NodeID, "count", "planner", "")
	if err != nil || v.Status != "accepted" {
		t.Fatalf("count rule failed: %+v %v", v, err)
	}
	if err := s.SetGoalAcceptance(t.Context(), g, acceptance.Spec{Type: "artifact", Path: "report.json", Format: "json"}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "report.json"), []byte(`{"result":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	v, err = s.SubmitGoalVerification(t.Context(), g, e, "artifact", "planner", root)
	if err != nil || v.Status != "accepted" {
		t.Fatalf("artifact rule failed: %+v %v", v, err)
	}
	var snapshot map[string]any
	if err := json.Unmarshal(v.Snapshot, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot["artifact"] == nil {
		t.Fatal("artifact hash not preserved")
	}
}

func TestGoalVerificationConcurrentFinalApprovals(t *testing.T) {
	_, s, g, e := verificationFixture(t)
	g2, err := s.AddGoal(map[string]any{"text": "second outcome"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	v1, err := s.SubmitGoalVerification(t.Context(), g, e, "first", "planner", "")
	if err != nil {
		t.Fatal(err)
	}
	v2, err := s.SubmitGoalVerification(t.Context(), g2, e, "second", "planner", "")
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan *GoalVerification, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, v := range []*GoalVerification{v1, v2} {
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			r, err := s.ReviewGoalVerification(t.Context(), id, true, "ARTEX", "verified")
			results <- r
			errs <- err
		}(v.ID)
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	final := 0
	for result := range results {
		if result.AllMet {
			final++
		}
	}
	if final != 1 {
		t.Fatalf("expected one final approval, got %d", final)
	}
}

func TestGoalVerificationRevokesAcceptedEvidence(t *testing.T) {
	d, s, g, e := verificationFixture(t)
	v, err := s.SubmitGoalVerification(t.Context(), g, e, "candidate", "planner", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReviewGoalVerification(t.Context(), v.ID, true, "ARTEX", "checked"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeState(e, "dismissed"); err != nil {
		t.Fatal(err)
	}
	n, _ := s.GetNode(g)
	if n.State != "open" {
		t.Fatal("withdrawn evidence left goal accepted")
	}
	var status string
	if err := d.QueryRow(`SELECT status FROM goal_verifications WHERE id=$1`, v.ID).Scan(&status); err != nil || status != "stale" {
		t.Fatalf("status=%s err=%v", status, err)
	}
	if yes, err := s.HasActionableGoal(); err != nil || yes {
		t.Fatalf("invalidated evidence triggered planning: %v %v", yes, err)
	}
	if err := s.SetNodeState(e, "confirmed"); err != nil {
		t.Fatal(err)
	}
	newRequest, err := s.SubmitGoalVerification(t.Context(), g, e, "restored evidence", "planner", "")
	if err != nil || newRequest.Status != "needs_review" || newRequest.ID == v.ID {
		t.Fatalf("restored evidence cannot be reviewed: %+v %v", newRequest, err)
	}
}

func TestGoalVerificationRevokesCountWhenSupportingFindingChanges(t *testing.T) {
	d, s, g, _ := verificationFixture(t)
	if err := s.SetGoalAcceptance(t.Context(), g, acceptance.Spec{Type: "confirmed_findings", MinCount: 2}); err != nil {
		t.Fatal(err)
	}
	fs := []*RecordedFinding{}
	for range 2 {
		f, err := s.RecordFinding(t.Context(), RecordFindingInput{ExplorationID: s.ID(), VulnClass: "test", Severity: "low", Summary: "candidate", Evidence: "trace", Worker: "worker"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.SetFindingStatus(f.FindingID, FindingConfirmed); err != nil {
			t.Fatal(err)
		}
		fs = append(fs, f)
	}
	v, err := s.SubmitGoalVerification(t.Context(), g, fs[0].NodeID, "two confirmed findings", "planner", "")
	if err != nil || v.Status != "accepted" {
		t.Fatalf("count=%+v %v", v, err)
	}
	if _, err := d.SetFindingStatus(fs[1].FindingID, FindingFalsePositive); err != nil {
		t.Fatal(err)
	}
	n, _ := s.GetNode(g)
	if n.State != "open" {
		t.Fatal("changed supporting finding did not revoke acceptance")
	}
}
