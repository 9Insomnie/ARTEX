"use client";

import * as React from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { api } from "@/lib/api";
import type { GoalAcceptanceSpec, GoalVerification, TaskGoal } from "@/lib/types";

const labels: Record<string, string> = {
  not_submitted: "待提交证据", needs_review: "等待人工审阅", accepted: "验收通过",
  needs_more_evidence: "需补充证据", rejected: "审阅未通过", stale: "已失效", legacy_met: "历史完成状态（未重新验收）",
};

function GoalRule({ taskId, goal, onChange }: { taskId: string; goal: TaskGoal; onChange: () => Promise<void> }) {
  const [spec, setSpec] = React.useState<GoalAcceptanceSpec>(goal.acceptance_spec ?? { type: "manual" });
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  const [evidenceId, setEvidenceId] = React.useState("");
  const [reason, setReason] = React.useState("");
  const saved = JSON.stringify(goal.acceptance_spec ?? { type: "manual" });
  React.useEffect(() => { setSpec(JSON.parse(saved)); }, [saved, goal.acceptance_version]);
  const save = async () => {
    setBusy(true); setError("");
    try { await api.setGoalAcceptance(taskId, goal.id, spec); await onChange(); }
    catch (e) { setError(e instanceof Error ? e.message : "保存失败"); }
    finally { setBusy(false); }
  };
  const submit = async () => {
    setBusy(true); setError("");
    try {
      const id = Number(evidenceId);
      if (!Number.isSafeInteger(id) || id <= 0) throw new Error("请输入有效的证据节点 ID");
      await api.submitGoalVerification(taskId, goal.id, id, reason);
      setReason(""); await onChange();
    } catch (e) { setError(e instanceof Error ? e.message : "提交失败"); }
    finally { setBusy(false); }
  };
  return <details className="rounded-md border p-3">
    <summary className="cursor-pointer text-sm">{goal.text} · {labels[goal.acceptance_status ?? ""] ?? (goal.state === "met" ? "历史完成状态" : "待提交证据")}</summary>
    <div className="mt-3 space-y-2">
      <NativeSelect aria-label="验收方式" value={spec.type} onChange={(e) => setSpec(e.target.value === "confirmed_findings" ? { type: "confirmed_findings", min_count: 1 } : e.target.value === "artifact" ? { type: "artifact", path: "", format: "json" } : { type: "manual" })}>
        <NativeSelectOption value="manual">人工审阅目标与证据</NativeSelectOption>
        <NativeSelectOption value="confirmed_findings">已确认漏洞数量</NativeSelectOption>
        <NativeSelectOption value="artifact">产物格式与内容属性</NativeSelectOption>
      </NativeSelect>
      {spec.type === "confirmed_findings" && <div className="space-y-2">
        <Input aria-label="最少已确认漏洞数" type="number" min={1} max={1000} value={spec.min_count ?? 1} onChange={(e) => setSpec({ ...spec, min_count: Number(e.target.value) })} />
        <Input placeholder="漏洞类别（可选，精确匹配）" value={spec.vulnclass ?? ""} onChange={(e) => setSpec({ ...spec, vulnclass: e.target.value })} />
        <p className="text-muted-foreground text-xs">仅统计本任务已标记为“已确认”的漏洞；待处理记录不计入。此规则核验数量，漏洞真实性仍需审阅或复测。</p>
      </div>}
      {spec.type === "artifact" && <div className="space-y-2">
        <Input aria-label="产物相对路径" placeholder="相对任务目录的路径，如 i123/report.json" value={spec.path ?? ""} onChange={(e) => setSpec({ ...spec, path: e.target.value })} />
        <NativeSelect aria-label="产物格式" value={spec.format ?? "json"} onChange={(e) => setSpec({ ...spec, format: e.target.value as GoalAcceptanceSpec["format"], required_headings: undefined })}>
          <NativeSelectOption value="json">JSON</NativeSelectOption><NativeSelectOption value="markdown">Markdown</NativeSelectOption><NativeSelectOption value="text">非空文本</NativeSelectOption>
        </NativeSelect>
        <Input placeholder="预期 SHA-256（可选）" value={spec.sha256 ?? ""} onChange={(e) => setSpec({ ...spec, sha256: e.target.value })} />
        {spec.format === "markdown" && <Input placeholder="必需标题，用逗号分隔（可选）" value={(spec.required_headings ?? []).join(",")} onChange={(e) => setSpec({ ...spec, required_headings: e.target.value.split(",").map((x) => x.trim()).filter(Boolean) })} />}
        <p className="text-muted-foreground text-xs">检查文件存在、格式、摘要和标题；不自动证明报告中的业务结论。</p>
      </div>}
      <p className="text-muted-foreground text-xs">修改条件会使已有验收结论失效，目标重新进入待验收状态。</p>
      <Button size="sm" variant="outline" disabled={busy || saved === JSON.stringify(spec)} onClick={() => void save()}>保存验收条件</Button>
      {goal.state === "open" && <div className="space-y-2 border-t pt-2">
        <p className="text-xs text-muted-foreground">也可手动提交已有证据。证据 ID 使用探索图中的事实或漏洞节点编号。</p>
        <Input aria-label="证据节点 ID" placeholder="证据节点 ID" value={evidenceId} onChange={(e) => setEvidenceId(e.target.value)} />
        <Input aria-label="提交验收理由" placeholder="该证据如何满足目标条件" value={reason} onChange={(e) => setReason(e.target.value)} />
        <Button size="sm" variant="outline" disabled={busy || !reason.trim() || !evidenceId || saved !== JSON.stringify(spec)} onClick={() => void submit()}>提交证据申请验收</Button>
      </div>}
      {error && <p role="alert" className="text-destructive text-sm">{error}</p>}
    </div>
  </details>;
}

export function GoalAcceptancePanel({ taskId, goals, onChange }: { taskId: string; goals: TaskGoal[]; onChange: () => Promise<void> }) {
  const [items, setItems] = React.useState<GoalVerification[]>([]);
  const [error, setError] = React.useState("");
  const [notes, setNotes] = React.useState<Record<string, string>>({});
  const [busy, setBusy] = React.useState(false);
  const signature = goals.map((g) => `${g.id}:${g.acceptance_version}:${g.acceptance_status}`).join("|");
  const refresh = React.useCallback(async () => {
    const result = await api.goalVerifications(taskId); setItems(result);
  }, [taskId]);
  React.useEffect(() => {
    let active = true;
    setItems([]); setError("");
    api.goalVerifications(taskId).then((result) => { if (active) setItems(result); }).catch((e) => { if (active) setError(e instanceof Error ? e.message : "读取失败"); });
    return () => { active = false; };
  }, [taskId, signature]);
  const review = async (item: GoalVerification, decision: "accept" | "reject") => {
    setBusy(true); setError("");
    try { await api.reviewGoalVerification(taskId, item.id, decision, notes[item.id] ?? ""); await onChange(); await refresh(); }
    catch (e) { setError(e instanceof Error ? e.message : "审阅失败"); }
    finally { setBusy(false); }
  };
  return <Card>
    <CardHeader><CardTitle className="text-base">目标验收</CardTitle><CardDescription>模型提交候选证据，按保存的条件检查。自然语言目标由你审阅，等待审阅时不再触发新的规划调用。</CardDescription></CardHeader>
    <CardContent className="space-y-3">
      {goals.map((goal) => <GoalRule key={goal.id} taskId={taskId} goal={goal} onChange={onChange} />)}
      <Button size="sm" variant="outline" onClick={() => void refresh().catch((e) => setError(String(e)))}>刷新验收记录</Button>
      {error && <p role="alert" className="text-destructive text-sm">{error}</p>}
      {items.length === 0 && <p className="text-muted-foreground text-sm">暂无验收申请。Agent 找到候选证据后会提交申请。</p>}
      {items.map((item) => <div key={item.id} className="space-y-2 rounded-md border p-3 text-sm">
        <div className="font-medium">目标 #{item.goal_id} · {labels[item.status] ?? item.status}</div>
        <div>证据节点 #{item.evidence_id} · 条件版本 {item.goal_version}</div>
        <p>{item.reason}</p><p className="text-muted-foreground">{item.note}</p>
        <details><summary className="cursor-pointer">查看证据快照与检查结果</summary><pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap rounded bg-muted p-2 text-xs">{JSON.stringify(item.snapshot, null, 2)}</pre></details>
        {item.reviewed_by && <p>审阅人：{item.reviewed_by} · {item.review_note}</p>}
        {item.status === "needs_review" && <div className="space-y-2">
          <Input aria-label={`验收申请 ${item.id} 的审阅理由`} placeholder="核对目标条件与证据后填写理由" value={notes[item.id] ?? ""} onChange={(e) => setNotes({ ...notes, [item.id]: e.target.value })} />
          <div className="flex gap-2">
            <Button size="sm" disabled={busy || !notes[item.id]?.trim()} onClick={() => void review(item, "accept")}>确认通过</Button>
            <Button size="sm" variant="outline" disabled={busy || !notes[item.id]?.trim()} onClick={() => void review(item, "reject")}>不通过，补充证据</Button>
          </div>
        </div>}
      </div>)}
      {items.length >= 100 && <p className="text-muted-foreground text-xs">显示最近 100 条验收记录。</p>}
    </CardContent>
  </Card>;
}
