package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sumeetghimire/culler/internal/decide"
	"github.com/sumeetghimire/culler/internal/enrich"
	"github.com/sumeetghimire/culler/internal/model"
	"github.com/sumeetghimire/culler/internal/parsers"
	"github.com/sumeetghimire/culler/internal/policy"
	"github.com/sumeetghimire/culler/internal/report"
)

var version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var (
		flagAll     bool
		flagFormat  string
		flagOffline bool
		flagOutput  string
		flagPolicy  string
		flagFailOn  string
		flagMinTier string
	)

	root := &cobra.Command{
		Use:   "culler [file]",
		Short: "Vulnerability triage engine — prioritize what actually needs fixing",
		Args:  cobra.ArbitraryArgs,
		Long: `culler ingests scanner output (Grype, Trivy, OSV-Scanner) or a CycloneDX SBOM,
enriches every CVE with CISA KEV, FIRST EPSS, and Vulnrichment SSVC data, and produces
a prioritized remediation queue: ACT NOW / OUT-OF-CYCLE / SCHEDULED / DEFER.

Examples:
  grype dir:. -o json | culler
  trivy fs --format json . | culler
  culler scan report.json
  culler scan report.json --all --format markdown
  culler explain CVE-2021-44228
  culler update`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				stat, _ := os.Stdin.Stat()
				if (stat.Mode() & os.ModeCharDevice) != 0 {
					return cmd.Help()
				}
			}
			var input io.Reader = os.Stdin
			if len(args) > 0 {
				f, err := os.Open(args[0])
				if err != nil {
					return fmt.Errorf("cannot open %s: %w", args[0], err)
				}
				defer f.Close()
				input = f
			}
			return runScan(input, scanOpts{
				showAll: flagAll, offline: flagOffline, format: flagFormat,
				output: flagOutput, policyPath: flagPolicy,
				failOn: flagFailOn, minTier: flagMinTier,
			})
		},
	}
	root.Flags().BoolVar(&flagAll, "all", false, "Show all findings (not just ACT NOW and OUT-OF-CYCLE)")
	root.Flags().StringVar(&flagFormat, "format", "terminal", "Output format: terminal, json, sarif, markdown")
	root.Flags().StringVarP(&flagOutput, "output", "o", "", "Write output to file instead of stdout")
	root.Flags().BoolVar(&flagOffline, "offline", false, "Use cached feeds only; do not make network requests")
	root.Flags().StringVar(&flagPolicy, "policy", "", "Path to .culler.yaml policy file (default: .culler.yaml)")
	root.Flags().StringVar(&flagFailOn, "fail-on", "", "Exit 1 if any finding at or above tier: act-now, out-of-cycle, scheduled")
	root.Flags().StringVar(&flagMinTier, "min-tier", "", "Only show findings at or above tier")

	// scan subcommand
	scanCmd := &cobra.Command{
		Use:   "scan [file]",
		Short: "Scan a vulnerability report file (or stdin)",
		RunE: func(cmd *cobra.Command, args []string) error {
			var input io.Reader = os.Stdin
			if len(args) > 0 {
				f, err := os.Open(args[0])
				if err != nil {
					return fmt.Errorf("cannot open %s: %w", args[0], err)
				}
				defer f.Close()
				input = f
			}
			return runScan(input, scanOpts{
				showAll: flagAll, offline: flagOffline, format: flagFormat,
				output: flagOutput, policyPath: flagPolicy,
				failOn: flagFailOn, minTier: flagMinTier,
			})
		},
	}
	scanCmd.Flags().BoolVar(&flagAll, "all", false, "Show all findings")
	scanCmd.Flags().StringVar(&flagFormat, "format", "terminal", "Output format: terminal, json, sarif, markdown")
	scanCmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Write output to file")
	scanCmd.Flags().BoolVar(&flagOffline, "offline", false, "Use cached feeds only")
	scanCmd.Flags().StringVar(&flagPolicy, "policy", "", "Path to .culler.yaml policy file")
	scanCmd.Flags().StringVar(&flagFailOn, "fail-on", "", "Exit 1 if any finding at or above tier: act-now, out-of-cycle, scheduled")
	scanCmd.Flags().StringVar(&flagMinTier, "min-tier", "", "Only show findings at or above tier")

	// explain subcommand
	explainCmd := &cobra.Command{
		Use:   "explain <CVE-ID>",
		Short: "Show full reasoning for a CVE from the last scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExplain(args[0])
		},
	}

	// update subcommand
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Force refresh of all threat-intel feeds",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate()
		},
	}

	// version subcommand
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Show version and feed ages",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("culler %s\n", version)
			fmt.Printf("  KEV:  %s\n", enrich.FeedAge("kev.json"))
			fmt.Printf("  EPSS: %s\n", enrich.FeedAge("epss_scores.csv.gz"))
		},
	}

	root.AddCommand(scanCmd, explainCmd, updateCmd, versionCmd)
	return root
}

type scanOpts struct {
	showAll    bool
	offline    bool
	format     string
	output     string
	policyPath string
	failOn     string
	minTier    string
}

func runScan(input io.Reader, opts scanOpts) error {
	// Parse
	findings, source, err := parsers.Parse(input)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}
	if len(findings) == 0 {
		fmt.Fprintln(os.Stderr, "No findings in input.")
		return nil
	}

	// Load enrichers
	kevE := &enrich.KEVEnricher{}
	epssE := &enrich.EPSSEnricher{}
	vrE := enrich.NewVulnrichmentEnricher(opts.offline)

	fmt.Fprintf(os.Stderr, "culler: loading threat-intel feeds...\n")
	if err := kevE.Load(opts.offline); err != nil {
		return fmt.Errorf("KEV enricher: %w", err)
	}
	if err := epssE.Load(opts.offline); err != nil {
		return fmt.Errorf("EPSS enricher: %w", err)
	}
	fmt.Fprintf(os.Stderr, "culler: KEV %d entries · EPSS %d entries · Vulnrichment (per-CVE)\n",
		kevE.Count(), epssE.Count())

	// Decide
	cfg := decide.DefaultConfig()
	enriched := decide.Run(findings, []decide.Enrich{kevE, epssE, vrE}, cfg)

	// Apply policy
	pol, err := policy.Load(opts.policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		pol = &policy.Config{}
	}
	enriched, suppressed := policy.Apply(enriched, pol)
	var warnings []string
	if len(suppressed) > 0 {
		warnings = append(warnings, fmt.Sprintf("Suppressed by policy: %s", strings.Join(suppressed, ", ")))
		fmt.Fprintf(os.Stderr, "culler: %d finding(s) suppressed by policy\n", len(suppressed))
	}

	result := &model.ScanResult{
		Findings: enriched,
		ScanTime: time.Now(),
		Source:   source,
		Warnings: warnings,
	}

	// Persist last scan for `explain`
	persistLastScan(result)

	// Determine output writer
	out := io.Writer(os.Stdout)
	if opts.output != "" {
		f, err := os.Create(opts.output)
		if err != nil {
			return fmt.Errorf("cannot create output file %s: %w", opts.output, err)
		}
		defer f.Close()
		out = f
	}

	// Write report
	switch opts.format {
	case "terminal", "":
		r := report.NewTerminal(out)
		r.Print(result, opts.showAll)
	case "json":
		if err := report.WriteJSON(out, result); err != nil {
			return err
		}
	case "sarif":
		if err := report.WriteSARIF(out, result); err != nil {
			return err
		}
	case "markdown", "md":
		if err := report.WriteMarkdown(out, result, opts.showAll); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported format %q (available: terminal, json, sarif, markdown)", opts.format)
	}

	// --fail-on exit code
	if opts.failOn != "" {
		threshold := parseTier(opts.failOn)
		for _, f := range result.Findings {
			if f.Tier <= threshold {
				os.Exit(1)
			}
		}
	}

	return nil
}

func runExplain(cveID string) error {
	result, err := loadLastScan()
	if err != nil {
		return fmt.Errorf("no last scan found — run a scan first: %w", err)
	}

	id := strings.ToUpper(cveID)
	for _, f := range result.Findings {
		if strings.EqualFold(f.ID, id) {
			fmt.Printf("=== %s ===\n", f.ID)
			fmt.Printf("Package:    %s %s\n", f.Package, f.Version)
			fmt.Printf("Ecosystem:  %s\n", f.Ecosystem)
			fmt.Printf("Source:     %s\n", f.Source)
			fmt.Printf("Tier:       %s\n", f.Tier.String())
			fmt.Println()
			fmt.Println("--- CVSS ---")
			if f.Finding.CVSS != nil {
				fmt.Printf("  Score:       %.1f\n", f.Finding.CVSS.Score)
				fmt.Printf("  Vector:      %s\n", f.Finding.CVSS.Vector)
				fmt.Printf("  Version:     %s\n", f.Finding.CVSS.Version)
				fmt.Printf("  Provenance:  %s\n", f.Finding.CVSS.Provenance)
			} else {
				fmt.Println("  (no CVSS data)")
			}
			fmt.Println()
			fmt.Println("--- EPSS ---")
			if f.EPSS.Score > 0 {
				fmt.Printf("  Score:       %.4f\n", f.EPSS.Score)
				fmt.Printf("  Percentile:  %.1f%%\n", f.EPSS.Percentile*100)
			} else {
				fmt.Println("  (no EPSS data)")
			}
			fmt.Println()
			fmt.Println("--- KEV ---")
			if f.KEV.InKEV {
				fmt.Printf("  In KEV:      yes\n")
				fmt.Printf("  Date added:  %s\n", f.KEV.DateAdded)
				fmt.Printf("  Ransomware:  %v\n", f.KEV.RansomwareCampaign)
			} else {
				fmt.Println("  Not in KEV")
			}
			fmt.Println()
			if f.SSVC != nil {
				fmt.Println("--- SSVC (Vulnrichment) ---")
				fmt.Printf("  Exploitation:     %s\n", f.SSVC.Exploitation)
				fmt.Printf("  Automatable:      %s\n", f.SSVC.Automatable)
				fmt.Printf("  TechnicalImpact:  %s\n", f.SSVC.TechnicalImpact)
				fmt.Println()
			}
			fmt.Println("--- Decision Reasoning ---")
			for i, r := range f.Reasoning {
				fmt.Printf("  %d. %s\n", i+1, r)
			}
			if len(f.FixedIn) > 0 {
				fmt.Printf("\nFix available: %s\n", strings.Join(f.FixedIn, ", "))
			}
			return nil
		}
	}
	return fmt.Errorf("%s not found in last scan (scanned %s)", id, result.ScanTime.Format("2006-01-02 15:04"))
}

func runUpdate() error {
	kevE := &enrich.KEVEnricher{}
	epssE := &enrich.EPSSEnricher{}

	fmt.Fprintln(os.Stderr, "Refreshing feeds...")
	enrich.DeleteCache("kev.json")
	enrich.DeleteCache("epss_scores.csv.gz")

	if err := kevE.Load(false); err != nil {
		return err
	}
	if err := epssE.Load(false); err != nil {
		return err
	}
	fmt.Printf("KEV:  %d entries, updated %s\n", kevE.Count(), kevE.FeedDate().Format("2006-01-02 15:04"))
	fmt.Printf("EPSS: %d entries, updated %s\n", epssE.Count(), epssE.FeedDate().Format("2006-01-02 15:04"))
	return nil
}

// persistLastScan saves the scan result to cache for use by `explain`.
func persistLastScan(result *model.ScanResult) {
	path, err := enrich.LastScanPath()
	if err != nil {
		return
	}
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(result)
}

func loadLastScan() (*model.ScanResult, error) {
	path, err := enrich.LastScanPath()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("no cached scan at %s", path)
	}
	defer f.Close()
	var result model.ScanResult
	if err := json.NewDecoder(f).Decode(&result); err != nil {
		return nil, fmt.Errorf("corrupt scan cache: %w", err)
	}
	return &result, nil
}

func parseTier(s string) model.Tier {
	switch strings.ToLower(strings.ReplaceAll(s, "_", "-")) {
	case "act-now":
		return model.TierActNow
	case "out-of-cycle":
		return model.TierOutOfCycle
	case "scheduled":
		return model.TierScheduled
	}
	return model.TierDefer
}
