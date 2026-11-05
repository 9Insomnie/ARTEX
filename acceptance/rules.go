// Package acceptance defines user-owned, deterministic goal acceptance rules.
// Model-produced prose is never itself an automatic acceptance rule.
package acceptance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

type Spec struct {
	Type             string   `json:"type"`
	MinCount         int      `json:"min_count,omitempty"`
	VulnClass        string   `json:"vulnclass,omitempty"`
	Path             string   `json:"path,omitempty"`
	Format           string   `json:"format,omitempty"`
	SHA256           string   `json:"sha256,omitempty"`
	RequiredHeadings []string `json:"required_headings,omitempty"`
}

func (s Spec) Validate() error {
	switch s.Type {
	case "manual":
		if s.MinCount != 0 || s.VulnClass != "" || s.Path != "" || s.Format != "" || s.SHA256 != "" || len(s.RequiredHeadings) > 0 {
			return errors.New("人工验收不能包含自动规则参数")
		}
	case "confirmed_findings":
		if s.MinCount < 1 || s.MinCount > 1000 {
			return errors.New("已确认漏洞数量必须在 1 到 1000 之间")
		}
		if s.Path != "" || s.Format != "" || s.SHA256 != "" || len(s.RequiredHeadings) > 0 {
			return errors.New("漏洞数量规则不能包含产物参数")
		}
	case "artifact":
		if !filepath.IsLocal(s.Path) || s.Path == "." {
			return errors.New("产物路径必须是任务目录内的相对文件路径")
		}
		if s.Format != "json" && s.Format != "markdown" && s.Format != "text" {
			return errors.New("产物格式必须为 json、markdown 或 text")
		}
		if s.MinCount != 0 || s.VulnClass != "" {
			return errors.New("产物规则不能包含漏洞数量参数")
		}
		if s.SHA256 != "" {
			b, err := hex.DecodeString(s.SHA256)
			if err != nil || len(b) != 32 {
				return errors.New("sha256 必须是 64 位十六进制摘要")
			}
		}
		if len(s.RequiredHeadings) > 20 || (len(s.RequiredHeadings) > 0 && s.Format != "markdown") {
			return errors.New("仅 Markdown 可设置必需标题，最多 20 条")
		}
		for _, h := range s.RequiredHeadings {
			if strings.TrimSpace(h) == "" || len(h) > 256 {
				return errors.New("必需标题不能为空且不能超过 256 字节")
			}
		}
	default:
		return errors.New("未知验收类型")
	}
	return nil
}

type ArtifactResult struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
	Format string `json:"format"`
}

// CheckArtifact checks a bounded, root-confined file. OpenRoot prevents symlink
// traversal outside the task, including races between path resolution and open.
// This proves the configured file properties, not the truth of its conclusions.
func CheckArtifact(ctx context.Context, root string, spec Spec) (*ArtifactResult, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if spec.Type != "artifact" || root == "" {
		return nil, errors.New("产物验证缺少任务目录")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("打开任务目录: %w", err)
	}
	defer r.Close()
	f, err := r.Open(spec.Path)
	if err != nil {
		return nil, fmt.Errorf("打开验收产物: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const maxBytes = 2 << 20
	if !info.Mode().IsRegular() || info.Size() > maxBytes {
		return nil, errors.New("验收产物必须为不超过 2 MiB 的普通文件")
	}
	body, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(body) == 0 || len(body) > maxBytes {
		return nil, errors.New("验收产物为空或超过 2 MiB")
	}
	if !utf8.Valid(body) || bytes.IndexByte(body, 0) >= 0 {
		return nil, errors.New("验收产物必须是有效的 UTF-8 文本")
	}
	hash := sha256.Sum256(body)
	result := &ArtifactResult{Path: spec.Path, SHA256: hex.EncodeToString(hash[:]), Bytes: len(body), Format: spec.Format}
	if spec.SHA256 != "" && !strings.EqualFold(spec.SHA256, result.SHA256) {
		return nil, errors.New("产物 SHA-256 与验收规则不符")
	}
	if spec.Format == "json" && !json.Valid(body) {
		return nil, errors.New("产物不是有效 JSON")
	}
	if spec.Format == "markdown" {
		headings := map[string]bool{}
		fence := ""
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "```") || strings.HasPrefix(line, "~~~") {
				marker := line[:3]
				if fence == "" {
					fence = marker
				} else if fence == marker {
					fence = ""
				}
				continue
			}
			if fence != "" {
				continue
			}
			trimmed := strings.TrimLeft(line, "#")
			if len(trimmed) < len(line) && len(line)-len(trimmed) <= 6 && strings.HasPrefix(trimmed, " ") {
				headings[strings.TrimSpace(strings.TrimRight(trimmed, "#"))] = true
			}
		}
		for _, h := range spec.RequiredHeadings {
			if !headings[strings.TrimSpace(h)] {
				return nil, fmt.Errorf("产物缺少标题: %s", h)
			}
		}
	}
	return result, nil
}
