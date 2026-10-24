package scripts_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const integrationCommit = "fd7ae306728da551a0e37ede98f0ef878f1b9467"

type pushPayload struct {
	Ref     string           `json:"ref"`
	Before  string           `json:"before"`
	After   string           `json:"after"`
	Forced  bool             `json:"forced"`
	Deleted bool             `json:"deleted"`
	Commits []map[string]any `json:"commits"`
}

func loadGateScript(t *testing.T, relativePath string) string {
	t.Helper()
	path := filepath.Join("..", relativePath)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read workflow %s: %v", path, err)
	}
	lines := strings.Split(string(contents), "\n")
	jobStart := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == "alpha_publish_gate:" && leadingSpaces(line) == 2 {
			jobStart = i
			break
		}
	}
	if jobStart < 0 {
		t.Fatalf("workflow %s has no alpha_publish_gate job", path)
	}

	stepStart := -1
	for i := jobStart + 1; i < len(lines); i++ {
		if leadingSpaces(lines[i]) == 2 && strings.TrimSpace(lines[i]) != "" && !strings.HasPrefix(strings.TrimSpace(lines[i]), "#") {
			break
		}
		if strings.TrimSpace(lines[i]) == "id: evaluate" && leadingSpaces(lines[i]) == 8 {
			stepStart = i
			break
		}
	}
	if stepStart < 0 {
		t.Fatalf("workflow %s has no evaluate step", path)
	}

	runLine := -1
	for i := stepStart + 1; i < len(lines); i++ {
		if leadingSpaces(lines[i]) == 8 && strings.TrimSpace(lines[i]) == "run: |" {
			runLine = i
			break
		}
	}
	if runLine < 0 {
		t.Fatalf("workflow %s evaluate step has no literal run block", path)
	}

	blockIndent := -1
	var scriptLines []string
	for i := runLine + 1; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			scriptLines = append(scriptLines, "")
			continue
		}
		indent := leadingSpaces(line)
		if indent <= 8 {
			break
		}
		if blockIndent < 0 {
			blockIndent = indent
		}
		if indent < blockIndent {
			t.Fatalf("workflow %s run block has inconsistent indentation at line %d", path, i+1)
		}
		scriptLines = append(scriptLines, line[blockIndent:])
	}
	if blockIndent < 0 {
		t.Fatalf("workflow %s evaluate step run block is empty", path)
	}
	return strings.TrimRight(strings.Join(scriptLines, "\n"), "\n")
}

func leadingSpaces(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

func TestAlphaPublishGateCopiesMatch(t *testing.T) {
	buildScript := loadGateScript(t, "workflows/build.yml")
	cmfaScript := loadGateScript(t, "workflows/trigger-cmfa-update.yml")
	if buildScript != cmfaScript {
		t.Fatal("build and CMFA workflows must run identical publish-gate logic")
	}
}

func TestAlphaPublishGatePayloadSemantics(t *testing.T) {
	pythonBin := os.Getenv("PYTHON_BIN")
	if pythonBin == "" {
		pythonBin = "python3"
	}
	script := loadGateScript(t, "workflows/build.yml")

	validPayload := func(commits []string) pushPayload {
		entries := make([]map[string]any, 0, len(commits))
		for _, id := range commits {
			entries = append(entries, map[string]any{"id": id})
		}
		if len(commits) > 0 {
			entries = append(entries, map[string]any{"id": strings.Repeat("2", 40)})
		}
		return pushPayload{
			Ref:     "refs/heads/Alpha",
			Before:  strings.Repeat("1", 40),
			After:   strings.Repeat("2", 40),
			Commits: entries,
		}
	}

	truncated := make([]string, 2047)
	for i := range truncated {
		truncated[i] = fmt.Sprintf("%040x", i+10)
	}
	oversized := make([]string, 2048)
	for i := range oversized {
		oversized[i] = fmt.Sprintf("%040x", i+20)
	}

	tests := []struct {
		name      string
		eventName string
		ref       string
		sha       string
		payload   any
		raw       []byte
		want      bool
	}{
		{
			name:      "Alpha push contains exact M6.1 marker",
			eventName: "push",
			ref:       "refs/heads/Alpha",
			sha:       strings.Repeat("2", 40),
			payload:   validPayload([]string{strings.Repeat("3", 40), integrationCommit}),
			want:      false,
		},
		{
			name:      "ordinary Alpha push has a complete list without marker",
			eventName: "push",
			ref:       "refs/heads/Alpha",
			sha:       strings.Repeat("2", 40),
			payload:   validPayload([]string{strings.Repeat("3", 40)}),
			want:      true,
		},
		{
			name:      "later Alpha push does not include marker already in before history",
			eventName: "push",
			ref:       "refs/heads/Alpha",
			sha:       strings.Repeat("4", 40),
			payload: pushPayload{
				Ref:     "refs/heads/Alpha",
				Before:  integrationCommit,
				After:   strings.Repeat("4", 40),
				Commits: []map[string]any{{"id": strings.Repeat("5", 40)}, {"id": strings.Repeat("4", 40)}},
			},
			want: true,
		},
		{
			name:      "Alpha push with empty commit list fails closed",
			eventName: "push",
			ref:       "refs/heads/Alpha",
			sha:       strings.Repeat("2", 40),
			payload:   validPayload(nil),
			want:      false,
		},
		{
			name:      "Alpha push with missing commit list fails closed",
			eventName: "push",
			ref:       "refs/heads/Alpha",
			sha:       strings.Repeat("2", 40),
			raw:       []byte(`{"ref":"refs/heads/Alpha","before":"1111111111111111111111111111111111111111","after":"2222222222222222222222222222222222222222"}`),
			want:      false,
		},
		{
			name:      "Alpha push with malformed commit ID fails closed",
			eventName: "push",
			ref:       "refs/heads/Alpha",
			sha:       strings.Repeat("2", 40),
			payload:   validPayload([]string{"not-a-sha"}),
			want:      false,
		},
		{
			name:      "Alpha push at GitHub payload commit limit fails closed",
			eventName: "push",
			ref:       "refs/heads/Alpha",
			sha:       strings.Repeat("2", 40),
			payload:   validPayload(truncated),
			want:      false,
		},
		{
			name:      "Alpha push above payload commit limit fails closed",
			eventName: "push",
			ref:       "refs/heads/Alpha",
			sha:       strings.Repeat("2", 40),
			payload:   validPayload(oversized),
			want:      false,
		},
		{
			name:      "Alpha push with invalid JSON fails closed",
			eventName: "push",
			ref:       "refs/heads/Alpha",
			sha:       strings.Repeat("2", 40),
			raw:       []byte(`{"ref":`),
			want:      false,
		},
		{
			name:      "Alpha push with after SHA mismatch fails closed",
			eventName: "push",
			ref:       "refs/heads/Alpha",
			sha:       strings.Repeat("9", 40),
			payload:   validPayload([]string{strings.Repeat("3", 40)}),
			want:      false,
		},
		{
			name:      "Alpha push with truncated commit list missing its tip fails closed",
			eventName: "push",
			ref:       "refs/heads/Alpha",
			sha:       strings.Repeat("2", 40),
			payload: map[string]any{
				"ref":     "refs/heads/Alpha",
				"before":  strings.Repeat("1", 40),
				"after":   strings.Repeat("2", 40),
				"forced":  false,
				"deleted": false,
				"commits": []map[string]any{{"id": strings.Repeat("3", 40)}},
			},
			want: false,
		},
		{
			name:      "forced Alpha push fails closed",
			eventName: "push",
			ref:       "refs/heads/Alpha",
			sha:       strings.Repeat("2", 40),
			payload: func() pushPayload {
				payload := validPayload([]string{strings.Repeat("3", 40)})
				payload.Forced = true
				return payload
			}(),
			want: false,
		},
		{
			name:      "Alpha push with missing forced flag fails closed",
			eventName: "push",
			ref:       "refs/heads/Alpha",
			sha:       strings.Repeat("2", 40),
			raw:       []byte(`{"ref":"refs/heads/Alpha","before":"1111111111111111111111111111111111111111","after":"2222222222222222222222222222222222222222","deleted":false,"commits":[{"id":"3333333333333333333333333333333333333333"},{"id":"2222222222222222222222222222222222222222"}]}`),
			want:      false,
		},
		{
			name:      "Alpha push with malformed push flag fails closed",
			eventName: "push",
			ref:       "refs/heads/Alpha",
			sha:       strings.Repeat("2", 40),
			payload: map[string]any{
				"ref":     "refs/heads/Alpha",
				"before":  strings.Repeat("1", 40),
				"after":   strings.Repeat("2", 40),
				"forced":  "false",
				"deleted": false,
				"commits": []map[string]any{{"id": strings.Repeat("3", 40)}},
			},
			want: false,
		},
		{
			name:      "PR event leaves gate output open for existing PR conditions",
			eventName: "pull_request",
			ref:       "refs/pull/12/merge",
			sha:       strings.Repeat("2", 40),
			payload:   map[string]any{"commits": []any{}},
			want:      true,
		},
		{
			name:      "Tag push leaves tag behavior open",
			eventName: "push",
			ref:       "refs/tags/v1.2.3",
			sha:       strings.Repeat("2", 40),
			payload:   map[string]any{},
			want:      true,
		},
		{
			name:      "workflow_dispatch leaves manual release behavior open",
			eventName: "workflow_dispatch",
			ref:       "refs/heads/Alpha",
			sha:       strings.Repeat("2", 40),
			payload:   map[string]any{},
			want:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var payload []byte
			if test.raw != nil {
				payload = test.raw
			} else {
				var err error
				payload, err = json.Marshal(test.payload)
				if err != nil {
					t.Fatalf("marshal payload: %v", err)
				}
			}
			if got := executeGate(t, script, pythonBin, test.eventName, test.ref, test.sha, payload); got != test.want {
				t.Fatalf("publish_allowed = %v, want %v", got, test.want)
			}
		})
	}
}

func executeGate(t *testing.T, script, pythonBin, eventName, ref, sha string, payload []byte) bool {
	t.Helper()
	tempDir := t.TempDir()
	eventPath := filepath.Join(tempDir, "event.json")
	outputPath := filepath.Join(tempDir, "output.txt")
	summaryPath := filepath.Join(tempDir, "summary.md")
	if err := os.WriteFile(eventPath, payload, 0o600); err != nil {
		t.Fatalf("write event payload: %v", err)
	}
	if err := os.WriteFile(outputPath, nil, 0o600); err != nil {
		t.Fatalf("create output file: %v", err)
	}
	if err := os.WriteFile(summaryPath, nil, 0o600); err != nil {
		t.Fatalf("create summary file: %v", err)
	}

	command := exec.Command("bash", "-e", "-o", "pipefail", "-c", script)
	command.Env = testEnvironment(eventPath, outputPath, summaryPath, pythonBin, eventName, ref, sha)
	var logs bytes.Buffer
	command.Stdout = &logs
	command.Stderr = &logs
	if err := command.Run(); err != nil {
		t.Fatalf("run gate: %v\n%s", err, logs.String())
	}
	output, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read gate output: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if strings.HasPrefix(line, "publish_allowed=") {
			return strings.TrimPrefix(line, "publish_allowed=") == "true"
		}
	}
	t.Fatalf("publish_allowed output missing; logs:\n%s", logs.String())
	return false
}

func testEnvironment(eventPath, outputPath, summaryPath, pythonBin, eventName, ref, sha string) []string {
	blocked := map[string]bool{
		"EVENT_NAME": true, "EVENT_REF": true, "EVENT_SHA": true,
		"GITHUB_EVENT_PATH": true, "GITHUB_OUTPUT": true, "GITHUB_STEP_SUMMARY": true,
		"PYTHON_BIN": true,
	}
	environment := make([]string, 0, len(os.Environ())+7)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !blocked[key] {
			environment = append(environment, entry)
		}
	}
	return append(environment,
		"EVENT_NAME="+eventName,
		"EVENT_REF="+ref,
		"EVENT_SHA="+sha,
		"GITHUB_EVENT_PATH="+eventPath,
		"GITHUB_OUTPUT="+outputPath,
		"GITHUB_STEP_SUMMARY="+summaryPath,
		"PYTHON_BIN="+pythonBin,
	)
}
