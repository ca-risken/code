package gitleaks

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"unicode/utf8"

	"github.com/ca-risken/core/proto/ai"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

const findingContextBytes = 1024

var errUnterminatedFinalLine = errors.New("reported line follows an unterminated final line")

func readFindingSample(ctx context.Context, repo *git.Repository, leak report.Finding, rule *config.Rule) (*ai.ClassifySensitiveContentRequest, error) {
	if leak.StartLine < 1 || leak.EndLine < leak.StartLine || leak.File == "." || !fs.ValidPath(leak.File) || !plumbing.IsHash(leak.Commit) {
		return nil, nil
	}

	// History scans must use the detected commit rather than the working tree.
	commit, err := repo.CommitObject(plumbing.NewHash(leak.Commit))
	if err != nil {
		return nil, errors.New("failed to read detected commit from clone")
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, errors.New("failed to read detected commit tree")
	}
	file, err := tree.File(leak.File)
	if err != nil {
		return nil, errors.New("failed to read detected file from clone")
	}
	if !file.Mode.IsRegular() && file.Mode != filemode.Executable {
		return nil, nil
	}
	reader, err := file.Reader()
	if err != nil {
		return nil, errors.New("failed to open detected file blob")
	}
	if file.Size > maxCoreTextBytes {
		req, err := readLargeFindingSample(ctx, reader, leak, rule)
		_ = reader.Close()
		if !errors.Is(err, errUnterminatedFinalLine) {
			return req, err
		}
		if leak.StartLine != leak.EndLine {
			return nil, nil
		}
		// v8.8.6 can report an unterminated single-line diff one line late.
		// Retry only against that known final line and verify the match again.
		leak.StartLine--
		leak.EndLine--
		reader, err = file.Reader()
		if err != nil {
			return nil, errors.New("failed to reopen detected file blob")
		}
		defer func() { _ = reader.Close() }()
		return readLargeFindingSample(ctx, reader, leak, rule)
	}

	defer func() { _ = reader.Close() }()
	text, err := io.ReadAll(io.LimitReader(reader, maxCoreTextBytes+1))
	if err != nil {
		return nil, errors.New("failed to read detected file blob")
	}
	if len(text) > maxCoreTextBytes || !validSourceText(text) {
		return nil, nil
	}
	if req := findingSample(text, leak); req != nil {
		return req, nil
	}
	if len(text) == 0 || text[len(text)-1] == '\n' || leak.StartLine != leak.EndLine ||
		leak.StartLine != bytes.Count(text, []byte{'\n'})+2 || !hasMatchEvidence(leak, rule) {
		return nil, nil
	}
	lastLine := bytes.LastIndexByte(text, '\n') + 1
	skippedColumns := max(0, leak.StartColumn-2)
	if skippedColumns >= len(text)-lastLine {
		return nil, nil
	}
	offset := lastLine + skippedColumns
	start, end := verifiedSecretRange(text[offset:], leak, rule, skippedColumns)
	if end <= start {
		return nil, nil
	}
	return classificationRequest(leak.File, text, matchByteScope(offset+start, offset+end)), nil
}

func readLargeFindingSample(ctx context.Context, reader io.Reader, leak report.Finding, rule *config.Rule) (*ai.ClassifySensitiveContentRequest, error) {
	if !hasMatchEvidence(leak, rule) {
		return nil, nil
	}
	// In Gitleaks v8.8.6, columns after a newline count that preceding byte.
	// Read from the earlier possible start. Verify the actual match below.
	skippedColumns := max(0, leak.StartColumn-2)
	input := bufio.NewReader(reader)
	before, err := readBeforeMatch(ctx, input, leak.StartLine, skippedColumns)
	if errors.Is(err, io.EOF) {
		return nil, nil
	}
	if errors.Is(err, errUnterminatedFinalLine) {
		return nil, err
	}
	if err != nil {
		return nil, errors.New("failed to read source before detected value")
	}
	after, err := io.ReadAll(io.LimitReader(input, maxCoreTextBytes+findingContextBytes+utf8.UTFMax))
	if err != nil {
		return nil, errors.New("failed to read source around detected value")
	}
	start, end := verifiedSecretRange(after, leak, rule, skippedColumns)
	if end <= start || end-start > maxCoreTextBytes {
		return nil, nil
	}

	text := append(before, after...)
	start, end = start+len(before), end+len(before)
	budget := maxCoreTextBytes - (end - start)
	left := max(0, start-min(findingContextBytes, budget/2))
	right := min(len(text), end+min(findingContextBytes, budget-budget/2))
	for left < start && !utf8.RuneStart(text[left]) {
		left++
	}
	for right > end && right < len(text) && !utf8.RuneStart(text[right]) {
		right--
	}
	sample := text[left:right]
	if !validSourceText(sample) {
		return nil, nil
	}
	return classificationRequest(leak.File, sample, matchByteScope(start-left, end-left)), nil
}

func matchByteScope(start, end int) string {
	return fmt.Sprintf("Assess only the detected value at bytes %d through %d of the supplied text, counting from byte 1, inclusive.", start+1, end)
}

func hasMatchEvidence(leak report.Finding, rule *config.Rule) bool {
	return rule != nil && rule.Regex != nil && leak.StartColumn > 0 && leak.EndColumn > 0 && leak.Match != "" && leak.Secret != ""
}

// readBeforeMatch advances to the candidate without retaining whole lines.
func readBeforeMatch(ctx context.Context, input *bufio.Reader, line, columns int) ([]byte, error) {
	before := make([]byte, 0, 2*findingContextBytes)
	keep := func(chunk []byte) {
		if len(chunk) >= findingContextBytes {
			before = append(before[:0], chunk[len(chunk)-findingContextBytes:]...)
			return
		}
		if len(before)+len(chunk) > cap(before) {
			n := copy(before, before[len(before)-findingContextBytes:])
			before = before[:n]
		}
		before = append(before, chunk...)
	}
	var partialLine bool
	for line > 1 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		chunk, err := input.ReadSlice('\n')
		switch {
		case err == nil:
			line--
			partialLine = false
		case errors.Is(err, bufio.ErrBufferFull):
			partialLine = true
		case errors.Is(err, io.EOF) && line == 2 && (partialLine || len(chunk) > 0):
			return nil, errUnterminatedFinalLine
		default:
			return nil, err
		}
		keep(chunk)
	}
	for columns > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		chunk, err := input.Peek(min(columns, input.Size()))
		if err != nil {
			return nil, err
		}
		if bytes.IndexByte(chunk, '\n') >= 0 {
			return nil, io.EOF
		}
		keep(chunk)
		n, _ := input.Discard(len(chunk))
		columns -= n
	}
	return before[max(0, len(before)-findingContextBytes):], nil
}

func verifiedSecretRange(text []byte, leak report.Finding, rule *config.Rule, skippedColumns int) (int, int) {
	var lastLineStart int
	for range leak.EndLine - leak.StartLine {
		newline := bytes.IndexByte(text[lastLineStart:], '\n')
		if newline < 0 {
			return 0, 0
		}
		lastLineStart += newline + 1
	}
	lastLine := text[lastLineStart:]
	lineBytes := len(lastLine)
	if newline := bytes.IndexByte(lastLine, '\n'); newline >= 0 {
		lineBytes = newline
	}
	lastColumn := leak.EndColumn
	if leak.StartLine == leak.EndLine {
		lastColumn -= skippedColumns
	}
	if lastColumn < 1 || lastColumn-1 > lineBytes {
		return 0, 0
	}

	var foundStart, foundEnd int
	firstColumn := leak.StartColumn - 1 - skippedColumns
	for startShift := range 2 {
		start := firstColumn - startShift
		for endShift := range 2 {
			if leak.StartLine == leak.EndLine && startShift != endShift {
				continue
			}
			endColumn := lastColumn - endShift
			end := lastLineStart + endColumn
			if start < 0 || endColumn < 0 || endColumn > lineBytes || end <= start {
				continue
			}
			lo, hi := verifyReportedMatch(text[start:end], leak, rule)
			if hi <= lo {
				continue
			}
			lo, hi = lo+start, hi+start
			if foundEnd != 0 && (foundStart != lo || foundEnd != hi) {
				return 0, 0
			}
			foundStart, foundEnd = lo, hi
		}
	}
	return foundStart, foundEnd
}

func verifyReportedMatch(raw []byte, leak report.Finding, rule *config.Rule) (int, int) {
	bounds := rule.Regex.FindIndex(raw)
	if bounds == nil || bounds[0] != 0 || bounds[1] != len(raw) {
		return 0, 0
	}
	match := bytes.TrimLeft(raw, "\n")
	offset := len(raw) - len(match)
	match = bytes.TrimRight(match, "\n")
	start, end := 0, len(match)
	if group := rule.SecretGroup; group != 0 {
		// Gitleaks extracts its capture group from the newline-trimmed match.
		indices := rule.Regex.FindSubmatchIndex(match)
		if group < 0 || group >= len(indices)/2 {
			return 0, 0
		}
		start, end = indices[2*group], indices[2*group+1]
		if start < 0 || end <= start {
			return 0, 0
		}
	}
	candidate := report.Finding{Match: string(match), Secret: string(match[start:end])}
	if leak.Secret == redactedSecret {
		candidate.Redact()
	}
	if candidate.Match != leak.Match || candidate.Secret != leak.Secret {
		return 0, 0
	}
	return offset + start, offset + end
}

func validSourceText(text []byte) bool {
	return utf8.Valid(text) && bytes.IndexByte(text, 0) < 0
}
