package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/acceptance"
)

var ErrGoalVerificationConflict = errors.New("验收条件或证据已变化，请重新提交")
var ErrGoalVerificationInvalid = errors.New("无效的目标验收请求")

type GoalVerification struct {
	ID          int64           `json:"id,string"`
	GoalID      int64           `json:"goal_id,string"`
	EvidenceID  int64           `json:"evidence_id,string"`
	GoalVersion int             `json:"goal_version"`
	Status      string          `json:"status"`
	Reason      string          `json:"reason"`
	Note        string          `json:"note"`
	SubmittedBy string          `json:"submitted_by"`
	ReviewedBy  string          `json:"reviewed_by"`
	ReviewNote  string          `json:"review_note"`
	Snapshot    json.RawMessage `json:"snapshot"`
	CreatedAt   time.Time       `json:"created_at"`
	DecidedAt   *time.Time      `json:"decided_at,omitempty"`
	AllMet      bool            `json:"all_met"`
}

func GoalAcceptance(payload json.RawMessage) (acceptance.Spec, int, string) {
	var p struct {
		Spec    acceptance.Spec `json:"acceptance_spec"`
		Version int             `json:"acceptance_version"`
		Status  string          `json:"acceptance_status"`
	}
	_ = json.Unmarshal(payload, &p)
	if p.Spec.Type == "" {
		p.Spec.Type = "manual"
	}
	if p.Version < 1 {
		p.Version = 1
	}
	return p.Spec, p.Version, p.Status
}

func goalVerificationError(message string) error {
	return fmt.Errorf("%w: %s", ErrGoalVerificationInvalid, message)
}

func digestJSON(value any) string {
	b, _ := json.Marshal(value)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (s *ExplorationStore) lockGoal(ctx context.Context, tx *sql.Tx, id int64) (json.RawMessage, string, error) {
	// Serialize acceptance across this exploration so concurrent final goals
	// observe each other's commits when computing AllMet.
	var exp int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM explorations WHERE id=$1 FOR UPDATE`, s.expID).Scan(&exp); err != nil {
		return nil, "", err
	}
	var raw []byte
	var state string
	err := tx.QueryRowContext(ctx, `SELECT payload,state FROM exploration_nodes WHERE id=$1 AND exploration_id=$2 AND kind='goal' FOR UPDATE`, id, s.expID).Scan(&raw, &state)
	if err == sql.ErrNoRows {
		return nil, "", goalVerificationError("目标不存在于本任务")
	}
	return raw, state, err
}

// SetGoalAcceptance is a human/API-only policy mutation. Agent tools never
// expose it. Editing a policy invalidates previous decisions and evidence edges.
func (s *ExplorationStore) SetGoalAcceptance(ctx context.Context, goalID int64, spec acceptance.Spec) error {
	if err := spec.Validate(); err != nil {
		return goalVerificationError(err.Error())
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	raw, _, err := s.lockGoal(ctx, tx, goalID)
	if err != nil {
		return err
	}
	_, version, _ := GoalAcceptance(raw)
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	p["acceptance_spec"], p["acceptance_version"], p["acceptance_status"] = spec, version+1, "not_submitted"
	updated, _ := json.Marshal(p)
	if _, err := tx.ExecContext(ctx, `UPDATE exploration_nodes SET payload=$1,state='open',completed_at=NULL,content_version=content_version+1 WHERE id=$2`, string(updated), goalID); err != nil {
		return err
	}
	if err := staleGoalVerifications(ctx, tx, goalID); err != nil {
		return err
	}
	return tx.Commit()
}

func staleGoalVerifications(ctx context.Context, tx *sql.Tx, goalID int64) error {
	if _, err := tx.ExecContext(ctx, `UPDATE goal_verifications SET status='stale',note='目标或验收条件已修改，原结论失效' WHERE goal_id=$1 AND status IN ('accepted','needs_review')`, goalID); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM exploration_edges WHERE dst_id=$1 AND rel='proves'`, goalID)
	return err
}

// evidenceSnapshot locks the cited node and verifies current task/source access.
// Text and confidence remain claims; only host-recorded tool outputs are tagged
// as provenance, and manual review remains required for semantic conclusions.
func (s *ExplorationStore) evidenceSnapshot(ctx context.Context, tx *sql.Tx, id int64) (map[string]any, string, error) {
	var exp int64
	var kind, state string
	var payload []byte
	var updatedAt time.Time
	err := tx.QueryRowContext(ctx, `SELECT n.exploration_id,n.kind,n.state,n.payload,n.updated_at FROM exploration_nodes n
WHERE n.id=$1 AND (n.exploration_id=$2 OR EXISTS(
 SELECT 1 FROM tasks owner JOIN task_relations r ON r.task_id=owner.id JOIN tasks source ON source.id=r.source_task_id
 WHERE owner.exploration_id=$2 AND source.exploration_id=n.exploration_id AND owner.deleted_at IS NULL AND source.deleted_at IS NULL)) FOR SHARE OF n`, id, s.expID).Scan(&exp, &kind, &state, &payload, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, "", goalVerificationError("证据不存在于本任务或直接关联任务")
	}
	if err != nil {
		return nil, "", err
	}
	if (kind != KindFact && kind != KindFinding) || state != "confirmed" {
		return nil, "", goalVerificationError("证据必须是未撤销的事实或漏洞，不能使用任务根节点")
	}
	if len(payload) > 256<<10 {
		return nil, "", goalVerificationError("证据节点过大，请引用精简事实和原始记录")
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, "", err
	}
	if claims["evidence"] == nil || claims["evidence"] == "" {
		return nil, "", goalVerificationError("证据节点没有 evidence 内容")
	}
	snapshot := map[string]any{"node_id": id, "exploration_id": exp, "kind": kind, "state": state, "claims": claims, "updated_at": updatedAt.UTC()}
	if kind == KindFinding {
		var findingID, evidenceVersion int64
		var findingStatus, rowVersion string
		if err := tx.QueryRowContext(ctx, `SELECT id,status,evidence_version,xmin::text FROM findings WHERE node_id=$1 FOR SHARE`, id).Scan(&findingID, &findingStatus, &evidenceVersion, &rowVersion); err != nil {
			if err == sql.ErrNoRows {
				return nil, "", goalVerificationError("漏洞证据缺少权威记录")
			}
			return nil, "", err
		}
		if findingStatus == FindingFalsePositive {
			return nil, "", goalVerificationError("已判为误报的漏洞不能作为验收证据")
		}
		snapshot["finding"] = map[string]any{"finding_id": findingID, "status": findingStatus, "evidence_version": evidenceVersion, "row_version": rowVersion}
		var refs []byte
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(jsonb_build_object('snapshot_id',s.id,'request_sha256',s.req_hash,'response_sha256',s.resp_hash,'url',s.url,'method',s.method,'status',s.status) ORDER BY b.position),'[]'::jsonb) FROM finding_traffic_bindings b JOIN traffic_evidence_snapshots s ON s.id=b.snapshot_id WHERE b.finding_id=$1`, findingID).Scan(&refs); err != nil {
			return nil, "", err
		}
		snapshot["traffic_snapshots"] = json.RawMessage(refs)
	}
	// Stable identity excludes tool-result previews. A newly recorded execution
	// must not make an unchanged cited node appear to be a different version.
	hash := digestJSON(snapshot)
	rows, err := tx.QueryContext(ctx, `SELECT a.id,a.tool,a.tool_use_id,a.detail FROM activity a
JOIN exploration_edges e ON e.src_id=a.node_id AND e.dst_id=$1 AND e.rel='yields'
WHERE a.exploration_id=$2 AND a.kind='tool_result' AND NOT a.is_error
AND a.tool NOT IN ('record_fact','report_finding','insert_assets') ORDER BY a.id DESC LIMIT 10`, id, exp)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	provenance := []map[string]any{}
	for rows.Next() {
		var aid int64
		var tool, call, detail string
		if err := rows.Scan(&aid, &tool, &call, &detail); err != nil {
			return nil, "", err
		}
		provenance = append(provenance, map[string]any{"activity_id": aid, "tool": tool, "tool_use_id": call, "output_sha256": digestJSON(detail)})
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	snapshot["tool_records"], snapshot["node_sha256"] = provenance, hash
	return snapshot, hash, nil
}

// SubmitGoalVerification is the sole model-facing acceptance entry point.
// Artifact I/O happens before acquiring SQL locks; its rule version is checked
// again under lock. An artifact result proves properties at the recorded time.
func (s *ExplorationStore) SubmitGoalVerification(ctx context.Context, goalID, evidenceID int64, reason, actor, artifactRoot string) (*GoalVerification, error) {
	if goalID <= 0 || evidenceID <= 0 || strings.TrimSpace(reason) == "" || len(reason) > 4000 {
		return nil, goalVerificationError("目标、证据与验收理由必填，理由最多 4000 字节")
	}
	node, err := s.GetNode(goalID)
	if err != nil {
		return nil, err
	}
	if node == nil || node.Kind != KindGoal {
		return nil, goalVerificationError("目标不存在于本任务")
	}
	spec, version, _ := GoalAcceptance(node.Payload)
	if err := spec.Validate(); err != nil {
		return nil, goalVerificationError(err.Error())
	}
	var artifact *acceptance.ArtifactResult
	var artifactErr error
	if spec.Type == "artifact" {
		artifact, artifactErr = acceptance.CheckArtifact(ctx, artifactRoot, spec)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	raw, state, err := s.lockGoal(ctx, tx, goalID)
	if err != nil {
		return nil, err
	}
	current, currentVersion, _ := GoalAcceptance(raw)
	if currentVersion != version || digestJSON(current) != digestJSON(spec) {
		return nil, ErrGoalVerificationConflict
	}
	if state != "open" {
		return nil, goalVerificationError("目标已完成或已放弃，无需提交验收")
	}
	snapshot, hash, err := s.evidenceSnapshot(ctx, tx, evidenceID)
	if err != nil {
		return nil, err
	}
	status, note := "needs_review", "自然语言结论需要人工审阅；模型不能自行确认目标达成"
	snapshot["rule"], snapshot["rule_version"] = spec, version
	if spec.Type == "artifact" {
		if artifactErr != nil {
			status, note = "needs_more_evidence", artifactErr.Error()
		} else {
			status, note = "accepted", "产物格式和配置属性检查通过；不代表产物中的业务结论已验证"
			snapshot["artifact"] = artifact
		}
	}
	if spec.Type == "confirmed_findings" {
		// Use canonical finding states, not model-written summaries or a capped
		// graph overview. Lock the supporting records until the decision commits.
		rows, err := tx.QueryContext(ctx, `SELECT f.id,f.node_id,f.evidence_version FROM findings f JOIN exploration_nodes n ON n.id=f.node_id
WHERE n.exploration_id=$1 AND n.state='confirmed' AND f.status='confirmed' AND ($2='' OR f.vulnclass=$2)
ORDER BY (f.node_id=$4) DESC,f.id LIMIT $3 FOR SHARE OF f,n`, s.expID, spec.VulnClass, spec.MinCount, evidenceID)
		if err != nil {
			return nil, err
		}
		matches := []map[string]any{}
		cited := false
		for rows.Next() {
			var fid, nid, ev int64
			if err := rows.Scan(&fid, &nid, &ev); err != nil {
				rows.Close()
				return nil, err
			}
			matches = append(matches, map[string]any{"finding_id": fid, "node_id": nid, "evidence_version": ev})
			cited = cited || nid == evidenceID
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		snapshot["confirmed_findings"] = matches
		if len(matches) >= spec.MinCount && cited {
			status, note = "accepted", "后端已核对配置要求的已确认漏洞数量"
		} else {
			status, note = "needs_more_evidence", "已确认漏洞数量不足，或引用证据不在匹配结果中；待处理漏洞不计入"
		}
	}
	out := &GoalVerification{GoalID: goalID, EvidenceID: evidenceID, GoalVersion: version, Status: status, Reason: strings.TrimSpace(reason), Note: note, SubmittedBy: actor}
	out.Snapshot, _ = json.Marshal(snapshot)
	fingerprint := digestJSON([]any{goalID, version, hash, snapshot["artifact"], snapshot["confirmed_findings"], status})
	// Identical submissions are idempotent, including pending manual reviews.
	err = tx.QueryRowContext(ctx, `INSERT INTO goal_verifications(exploration_id,goal_id,evidence_id,goal_version,status,reason,note,submitted_by,snapshot,fingerprint)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(goal_id,fingerprint) DO UPDATE SET fingerprint=EXCLUDED.fingerprint
RETURNING id,status,note,reason,submitted_by,snapshot,created_at`, s.expID, goalID, evidenceID, version, status, out.Reason, note, actor, string(out.Snapshot), fingerprint).Scan(&out.ID, &out.Status, &out.Note, &out.Reason, &out.SubmittedBy, &out.Snapshot, &out.CreatedAt)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE goal_verifications SET status='stale',note='已由新的验收申请替代' WHERE goal_id=$1 AND id<>$2 AND status='needs_review'`, goalID, out.ID); err != nil {
		return nil, err
	}
	if err := s.applyGoalVerification(ctx, tx, out); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *ExplorationStore) applyGoalVerification(ctx context.Context, tx *sql.Tx, v *GoalVerification) error {
	state := "open"
	if v.Status == "accepted" {
		state = "met"
	}
	if _, err := tx.ExecContext(ctx, `UPDATE exploration_nodes SET state=$1,payload=jsonb_set(payload,'{acceptance_status}',to_jsonb($2::text)),content_version=content_version+1,completed_at=CASE WHEN $1='met' THEN now() ELSE NULL END WHERE id=$3 AND exploration_id=$4 AND kind='goal'`, state, v.Status, v.GoalID, s.expID); err != nil {
		return err
	}
	if v.Status == "accepted" {
		if _, err := tx.ExecContext(ctx, `INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id) VALUES($1,$2,'proves',$3) ON CONFLICT DO NOTHING`, s.expID, v.EvidenceID, v.GoalID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE goal_verifications SET decided_at=COALESCE(decided_at,now()) WHERE id=$1`, v.ID); err != nil {
			return err
		}
	}
	return tx.QueryRowContext(ctx, `SELECT count(*)>0 AND bool_and(state='met') FROM exploration_nodes WHERE exploration_id=$1 AND kind='goal'`, s.expID).Scan(&v.AllMet)
}

func (s *ExplorationStore) ReviewGoalVerification(ctx context.Context, id int64, approve bool, reviewer, note string) (*GoalVerification, error) {
	if strings.TrimSpace(note) == "" || len(note) > 4000 {
		return nil, goalVerificationError("人工审阅必须填写理由，最多 4000 字节")
	}
	// Resolve the goal first, then use the same lock order as model submissions.
	var gid int64
	if err := s.db.QueryRowContext(ctx, `SELECT goal_id FROM goal_verifications WHERE id=$1 AND exploration_id=$2`, id, s.expID).Scan(&gid); err != nil {
		return nil, goalVerificationError("验收申请不存在")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	raw, state, err := s.lockGoal(ctx, tx, gid)
	if err != nil {
		return nil, err
	}
	v, err := scanGoalVerification(tx.QueryRowContext(ctx, `SELECT `+goalVerificationCols+` FROM goal_verifications WHERE id=$1 AND exploration_id=$2 FOR UPDATE`, id, s.expID))
	if err != nil {
		return nil, err
	}
	_, version, _ := GoalAcceptance(raw)
	if state != "open" || v.Status != "needs_review" || version != v.GoalVersion {
		return nil, ErrGoalVerificationConflict
	}
	_, hash, err := s.evidenceSnapshot(ctx, tx, v.EvidenceID)
	if err != nil {
		return nil, err
	}
	var snapshot struct {
		Hash string `json:"node_sha256"`
	}
	if err := json.Unmarshal(v.Snapshot, &snapshot); err != nil {
		return nil, err
	}
	if hash != snapshot.Hash {
		return nil, ErrGoalVerificationConflict
	}
	v.Status = "rejected"
	if approve {
		v.Status = "accepted"
	}
	v.ReviewedBy, v.ReviewNote = reviewer, strings.TrimSpace(note)
	v.Note = "人工审阅未通过"
	if approve {
		v.Note = "人工已核对目标条件与证据并确认通过"
	}
	if _, err := tx.ExecContext(ctx, `UPDATE goal_verifications SET status=$1,note=$2,reviewed_by=$3,review_note=$4,decided_at=now() WHERE id=$5`, v.Status, v.Note, reviewer, v.ReviewNote, id); err != nil {
		return nil, err
	}
	if err := s.applyGoalVerification(ctx, tx, v); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return v, nil
}

const goalVerificationCols = `id,goal_id,evidence_id,goal_version,status,reason,note,submitted_by,reviewed_by,review_note,snapshot,created_at,decided_at`

func scanGoalVerification(row interface{ Scan(...any) error }) (*GoalVerification, error) {
	v := &GoalVerification{}
	err := row.Scan(&v.ID, &v.GoalID, &v.EvidenceID, &v.GoalVersion, &v.Status, &v.Reason, &v.Note, &v.SubmittedBy, &v.ReviewedBy, &v.ReviewNote, &v.Snapshot, &v.CreatedAt, &v.DecidedAt)
	return v, err
}
func (s *ExplorationStore) GoalVerifications(ctx context.Context) ([]*GoalVerification, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+goalVerificationCols+` FROM goal_verifications WHERE exploration_id=$1 ORDER BY id DESC LIMIT 100`, s.expID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*GoalVerification{}
	for rows.Next() {
		v, err := scanGoalVerification(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Waiting goals remain open for task lifecycle purposes, but do not trigger
// repeated paid planning rounds while the operator is reviewing the evidence.
func (s *ExplorationStore) HasActionableGoal() (bool, error) {
	var yes bool
	err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM exploration_nodes WHERE exploration_id=$1 AND kind='goal' AND state='open' AND COALESCE(payload->>'acceptance_status','') NOT IN ('needs_review','stale'))`, s.expID).Scan(&yes)
	return yes, err
}
func (s *ExplorationStore) AllGoalsMet(ctx context.Context) (bool, error) {
	var yes bool
	err := s.db.QueryRowContext(ctx, `SELECT count(*)>0 AND bool_and(state='met') FROM exploration_nodes WHERE exploration_id=$1 AND kind='goal'`, s.expID).Scan(&yes)
	return yes, err
}

func (s *ExplorationStore) CompleteTaskIfGoalsMet(ctx context.Context, taskID int64) (bool, error) {
	return s.completeGoalTask(ctx, taskID, false)
}
func (s *ExplorationStore) CompleteIdleTask(ctx context.Context, taskID int64) (bool, error) {
	return s.completeGoalTask(ctx, taskID, true)
}
func (s *ExplorationStore) completeGoalTask(ctx context.Context, taskID int64, idle bool) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var exp int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM explorations WHERE id=$1 FOR UPDATE`, s.expID).Scan(&exp); err != nil {
		return false, err
	}
	res, err := tx.ExecContext(ctx, `UPDATE tasks SET status='done',completed_at=COALESCE(completed_at,now()),paused=false,queued=false,queued_at=NULL,queue_mode=''
WHERE id=$1 AND exploration_id=$2 AND deleted_at IS NULL AND status NOT IN ('failed','timeout')
AND ($3 OR EXISTS(SELECT 1 FROM exploration_nodes WHERE exploration_id=$2 AND kind='goal'))
AND NOT EXISTS(SELECT 1 FROM exploration_nodes WHERE exploration_id=$2 AND kind='goal' AND state<>'met' AND (NOT $3 OR state='open'))
AND (NOT $3 OR NOT EXISTS(SELECT 1 FROM exploration_nodes WHERE exploration_id=$2 AND kind='intent' AND state IN ('open','running')))`, taskID, s.expID, idle)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n > 0, nil
}
