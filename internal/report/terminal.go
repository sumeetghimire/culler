package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/sumeetghimire/culler/internal/model"
)

// ANSI colour codes — disabled automatically when not a TTY.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiGreen  = "\033[32m"
	ansiGray   = "\033[90m"
	ansiRedBg  = "\033[41m"
)

// Terminal renders results to an ANSI-coloured table on stdout.
type Terminal struct {
	out   io.Writer
	color bool
}

// NewTerminal creates a Terminal reporter. Color is auto-detected from stdout.
func NewTerminal(w io.Writer) *Terminal {
	color := false
	if f, ok := w.(*os.File); ok {
		color = isTerminal(f)
	}
	return &Terminal{out: w, color: color}
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

// Print writes the triage report. If all is false, only ACT NOW and OUT-OF-CYCLE are shown.
func (t *Terminal) Print(result *model.ScanResult, showAll bool) {
	counts := tierCounts(result.Findings)
	total := len(result.Findings)

	// Summary line
	summary := fmt.Sprintf("%d findings → %s ACT NOW · %s OUT-OF-CYCLE · %s SCHEDULED · %s DEFER",
		total,
		t.color2(fmt.Sprintf("%d", counts[model.TierActNow]), ansiRed+ansiBold),
		t.color2(fmt.Sprintf("%d", counts[model.TierOutOfCycle]), ansiYellow+ansiBold),
		t.color2(fmt.Sprintf("%d", counts[model.TierScheduled]), ansiCyan+ansiBold),
		t.color2(fmt.Sprintf("%d", counts[model.TierDefer]), ansiGray),
	)
	fmt.Fprintln(t.out, summary)

	// Filter findings to display
	var visible []model.EnrichedFinding
	for _, f := range result.Findings {
		if showAll || f.Tier == model.TierActNow || f.Tier == model.TierOutOfCycle {
			visible = append(visible, f)
		}
	}

	if len(visible) == 0 {
		fmt.Fprintln(t.out, t.color1("\nNo findings to display.", ansiGreen))
		return
	}

	fmt.Fprintln(t.out)

	tw := tabwriter.NewWriter(t.out, 0, 0, 2, ' ', 0)

	// Header
	fmt.Fprintln(tw, t.color1("CVE/ID\tPACKAGE\tVERSION\tFIX\tEPSS\tKEV\tTIER\tWHY", ansiBold))
	fmt.Fprintln(tw, strings.Repeat("─", 10)+"\t"+
		strings.Repeat("─", 20)+"\t"+
		strings.Repeat("─", 10)+"\t"+
		strings.Repeat("─", 10)+"\t"+
		strings.Repeat("─", 12)+"\t"+
		strings.Repeat("─", 5)+"\t"+
		strings.Repeat("─", 5)+"\t"+
		strings.Repeat("─", 35))

	for _, f := range visible {
		fixVer := "-"
		if len(f.FixedIn) > 0 {
			fixVer = f.FixedIn[0]
		}
		epssStr := "-"
		if f.EPSS.Score > 0 {
			epssStr = fmt.Sprintf("%.4f (%d%%)", f.EPSS.Score, int(f.EPSS.Percentile*100))
		}
		kevStr := " "
		if f.KEV.InKEV {
			kevStr = t.color1("KEV✓", ansiRed+ansiBold)
		}
		tierStr := tierLabel(f.Tier, t.color)
		why := ""
		if len(f.Reasoning) > 0 {
			why = f.Reasoning[0]
		}

		pkg := f.Package
		if len(pkg) > 22 {
			pkg = pkg[:19] + "..."
		}
		ver := f.Version
		if len(ver) > 12 {
			ver = ver[:9] + "..."
		}

		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			f.ID, pkg, ver, fixVer, epssStr, kevStr, tierStr, why)
	}
	tw.Flush()

	if !showAll && (counts[model.TierScheduled]+counts[model.TierDefer]) > 0 {
		fmt.Fprintf(t.out, t.color1("\n%d SCHEDULED and %d DEFER findings hidden. Use --all to show all.\n",
			ansiGray),
			counts[model.TierScheduled], counts[model.TierDefer])
	}

	// Footnotes
	fmt.Fprintln(t.out)
	fmt.Fprintln(t.out, t.color1("Note: EPSS scores lag new exploits by days–weeks. KEV is not exhaustive.", ansiGray))
}

func (t *Terminal) color1(s, code string) string {
	if !t.color {
		return s
	}
	return code + s + ansiReset
}

func (t *Terminal) color2(s, code string) string {
	return t.color1(s, code)
}

func tierCounts(findings []model.EnrichedFinding) map[model.Tier]int {
	m := map[model.Tier]int{}
	for _, f := range findings {
		m[f.Tier]++
	}
	return m
}

func tierLabel(tier model.Tier, color bool) string {
	if !color {
		return tier.Label()
	}
	switch tier {
	case model.TierActNow:
		return ansiRed + ansiBold + "NOW" + ansiReset
	case model.TierOutOfCycle:
		return ansiYellow + ansiBold + "OOC" + ansiReset
	case model.TierScheduled:
		return ansiCyan + "SCHED" + ansiReset
	case model.TierDefer:
		return ansiGray + "DEFER" + ansiReset
	}
	return tier.Label()
}
