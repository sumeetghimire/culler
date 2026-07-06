package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/sumeetghimire/culler/internal/model"
)

// WriteMarkdown writes a Markdown report suitable for PR comments.
func WriteMarkdown(w io.Writer, result *model.ScanResult, showAll bool) error {
	counts := tierCounts(result.Findings)
	total := len(result.Findings)

	fmt.Fprintf(w, "## culler Vulnerability Triage Report\n\n")
	fmt.Fprintf(w, "**%d findings** → 🔴 %d ACT NOW · 🟠 %d OUT-OF-CYCLE · 🟡 %d SCHEDULED · ⚪ %d DEFER\n\n",
		total,
		counts[model.TierActNow], counts[model.TierOutOfCycle],
		counts[model.TierScheduled], counts[model.TierDefer])

	if counts[model.TierActNow]+counts[model.TierOutOfCycle] == 0 {
		fmt.Fprintln(w, "✅ No ACT NOW or OUT-OF-CYCLE findings.")
		return nil
	}

	tiers := []model.Tier{model.TierActNow, model.TierOutOfCycle}
	if showAll {
		tiers = append(tiers, model.TierScheduled, model.TierDefer)
	}

	for _, tier := range tiers {
		var tFindings []model.EnrichedFinding
		for _, f := range result.Findings {
			if f.Tier == tier {
				tFindings = append(tFindings, f)
			}
		}
		if len(tFindings) == 0 {
			continue
		}

		fmt.Fprintf(w, "### %s %s\n\n", tierEmoji(tier), tier.String())
		fmt.Fprintln(w, "| CVE | Package | Version | Fix | EPSS | KEV | Why |")
		fmt.Fprintln(w, "|-----|---------|---------|-----|------|-----|-----|")
		for _, f := range tFindings {
			fixVer := "-"
			if len(f.FixedIn) > 0 {
				fixVer = "`" + f.FixedIn[0] + "`"
			}
			epssStr := "-"
			if f.EPSS.Score > 0 {
				epssStr = fmt.Sprintf("%.4f (%d%%)", f.EPSS.Score, int(f.EPSS.Percentile*100))
			}
			kev := ""
			if f.KEV.InKEV {
				kev = "✓"
				if f.KEV.RansomwareCampaign {
					kev = "✓ ransomware"
				}
			}
			why := strings.Join(f.Reasoning, "; ")
			fmt.Fprintf(w, "| `%s` | %s | `%s` | %s | %s | %s | %s |\n",
				f.ID, f.Package, f.Version, fixVer, epssStr, kev, why)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "---")
	fmt.Fprintln(w, "*Note: EPSS scores lag new exploits by days–weeks. KEV is not exhaustive. This is decision support, not a guarantee.*")
	return nil
}

func tierEmoji(t model.Tier) string {
	switch t {
	case model.TierActNow:
		return "🔴"
	case model.TierOutOfCycle:
		return "🟠"
	case model.TierScheduled:
		return "🟡"
	case model.TierDefer:
		return "⚪"
	}
	return ""
}
