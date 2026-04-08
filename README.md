# MITRE ATT&CK Coverage Dashboard v2

A production-shaped detection coverage analytics tool. Pulls live MITRE ATT&CK data, ingests detection rules from Sigma, Wazuh, and JSON, and produces honest coverage scores weighted by your actual data source availability. Multi-page Streamlit UI with a real ATT&CK matrix heatmap, threat actor comparison, ATT&CK Navigator export, and PDF reports for executives.

## Why this exists

Every Tier 1 defense contractor running a SOC has the same checklist for ATT&CK coverage assessments: which techniques can we detect, which ones can't we, and where are the data source gaps that make our reported coverage a lie. Most teams answer this in a sprawling Excel spreadsheet that nobody trusts. This dashboard answers it in 30 seconds with auditable math, and exports the result in three formats so you can hand it to whoever needs it.

## What's new in v2

| Capability | v1 | v2 |
|---|---|---|
| Storage | JSON file | SQLite with foreign keys, indexes, transactions |
| Pages | 4 tabs | 7-page sidebar nav with isolated views |
| Coverage math | Naive (any rule = covered) | Naive **and** weighted by data source availability |
| Visualization | Bar chart + treemap | Real ATT&CK matrix heatmap (Navigator-style layout) |
| Threat actors | Not supported | 130+ groups parsed from STIX, per-group coverage |
| Data sources | Not tracked | Editable inventory with quality scoring |
| Rule ingestion | Manual JSON only | Sigma directory, Sigma upload, JSON, Wazuh XML |
| Export | None | ATT&CK Navigator JSON, PDF report, CSV |
| Tests | None | 25+ pytest cases across 4 modules |
| Container | None | Multi-stage Dockerfile with healthcheck, non-root user |
| CI | None | Lint + test + image build on push |

## Architecture

```
                 ┌──────────────────────────────────────┐
                 │       Streamlit multi-page UI         │
                 │                                       │
                 │  Overview · Matrix · Rules · Actors  │
                 │      Import · Export · Data Sources  │
                 └────────┬─────────────────────────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
    ┌─────────▼─────────┐    ┌────────▼────────┐
    │   AttackData       │    │   RuleStore     │
    │   (STIX parser)    │    │   (SQLite)      │
    │                    │    │                 │
    │  - techniques      │    │  - rules        │
    │  - groups          │    │  - mappings     │
    │  - data sources    │    │  - data sources │
    └─────────┬──────────┘    └────────┬────────┘
              │                        │
              │   ┌────────────────────┴───┐
              └──►│   Coverage engine      │
                  │   - naive scoring       │
                  │   - weighted scoring    │
                  └──┬─────────────────────┘
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
   ┌─────────┐ ┌─────────┐ ┌─────────┐
   │ Matrix  │ │ Navig.  │ │  PDF    │
   │ heatmap │ │ JSON    │ │ report  │
   └─────────┘ └─────────┘ └─────────┘
```

## Project layout

```
attack-dashboard/
├── app/
│   ├── main.py                Streamlit entry, sidebar nav
│   ├── attack_loader.py       STIX parser (techniques, groups, data sources)
│   ├── db.py                  SQLite RuleStore
│   ├── importers.py           Sigma + JSON + Wazuh XML importers
│   ├── coverage.py            Naive and weighted coverage math
│   ├── navigator.py           ATT&CK Navigator JSON exporter
│   ├── report.py              PDF report generator (reportlab)
│   └── views/
│       ├── overview.py        KPI metrics + tactic charts
│       ├── matrix.py          Real ATT&CK matrix heatmap with drilldown
│       ├── rules_view.py      Browse + manual add
│       ├── threat_actors.py   Per-group coverage analysis
│       ├── import_view.py     4 import sources
│       ├── export_view.py     Navigator + PDF + CSV
│       └── data_sources_view.py  Inventory editor
├── tests/
│   ├── test_db.py             Storage round-trips
│   ├── test_importers.py      Sigma + Wazuh + technique normalization
│   ├── test_coverage.py       Naive + weighted scoring math
│   └── test_navigator.py      Layer JSON structure
├── data/
│   ├── sample_rules/          5 sample Sigma rules to demo the importer
│   └── enterprise-attack.json STIX cache (auto-fetched)
├── .streamlit/config.toml     Theme + server config
├── Dockerfile                 Multi-stage, non-root, healthcheck
├── docker-compose.yml
├── Makefile
├── requirements.txt
├── requirements-dev.txt
└── .github/workflows/ci.yml
```

## Quick start

```bash
git clone <this-repo>
cd attack-dashboard

make install
make run            # opens at http://localhost:8501
```

Or in Docker:

```bash
make up             # docker compose up -d
```

First-time workflow:

1. Open http://localhost:8501
2. Go to **Data Sources** and click "Seed all ATT&CK data sources as enabled"
3. Disable the data sources you do not actually collect (this drives the weighted score)
4. Go to **Import** and import the sample Sigma rules from `data/sample_rules`, or run `make seed`
5. Go to **Overview** to see your coverage
6. Go to **ATT&CK Matrix** to see the heatmap with drilldown
7. Go to **Threat Actors**, pick APT29, and see how well your rules cover their techniques
8. Go to **Export** to generate a Navigator JSON layer or a PDF report

## The seven views

**Overview** — Top-line metrics (rule count, coverage %, weighted coverage %), stacked bar chart of covered vs uncovered techniques per tactic, naive vs weighted comparison so you can see your blind spots at a glance, full tactic detail table.

**ATT&CK Matrix** — Real heatmap laid out like the official Navigator. Tactics are columns, techniques are stacked beneath each tactic. Cell color reflects coverage state: green (covered, full data), orange (covered, partial data), gray (covered, no data source), red (uncovered). Click into any technique by ID for detection guidance, required data sources, and the rules currently covering it.

**Rules** — Browse with search across name, source, and technique ID. Inline expand to view rule metadata and raw content. Manual add form with technique multi-select.

**Threat Actors** — Pick from 130+ MITRE-tracked threat groups parsed from intrusion-set STIX objects. See coverage of that specific group's techniques as a donut chart and a per-technique table. Top 10 most active groups leaderboard with your coverage per group.

**Import** — Four ingestion paths: Sigma directory scan (point at SigmaHQ/sigma to ingest the whole community ruleset), Sigma file upload, JSON file, Wazuh local_rules.xml. Technique IDs are extracted automatically from `attack.tXXXX` tags or `<mitre><id>` elements.

**Export** — ATT&CK Navigator layer JSON (opens directly in the official Navigator UI), multi-page PDF report with executive summary and tactic breakdown for compliance reviews, raw CSV for downstream analysis.

**Data Sources** — Editable inventory of every ATT&CK data source. Toggle enabled/disabled, set quality from 0.0 to 1.0, add notes. The weighted coverage score uses this as input. Also shows which techniques each data source unlocks so you can prioritize collection.

## The weighted score

Naive coverage counts a technique as covered if any rule mentions it. That's the score every spreadsheet uses, and it lies. If your rules say you cover T1003 (OS Credential Dumping) but you do not collect Process Memory or Process Access, you cannot actually detect it.

Weighted coverage is:

```
weighted_score(t) = is_covered(t) * (sum of available data source quality / required data source count)
```

So a technique with rules but no data sources scores 0.0, and a technique with rules and partial data sources scores somewhere in between. The dashboard surfaces both numbers side by side. The gap between them is your honest blind spot.

## Skills demonstrated

Detection engineering, MITRE ATT&CK fluency, threat-informed defense, STIX 2.1 parsing, data visualization, multi-format rule ingestion, full-stack Python (SQLite + Streamlit + Plotly + reportlab), coverage analytics methodology, container hardening, test-driven development, CI/CD.

## Skills mapped to job postings

- **"MITRE ATT&CK alignment"** — full Enterprise matrix coverage with weighted scoring
- **"Detection coverage assessments"** — produces auditable artifacts in 30 seconds
- **"Threat-informed defense"** — per-actor coverage analysis against 130+ groups
- **"Sigma rules"** — directory and file importers with technique extraction
- **"Wazuh / SIEM content"** — XML importer for production rule sets
- **"Compliance reporting"** — PDF generator suitable for CMMC, FedRAMP, DoD CDM reviews
- **"Python data tooling"** — pandas, plotly, SQLite, reportlab, Streamlit
- **"Testing"** — 25+ pytest cases including the coverage math itself

## Example: importing the SigmaHQ community rules

```bash
git clone https://github.com/SigmaHQ/sigma /tmp/sigma
make run
# In the browser: Import -> Sigma directory -> /tmp/sigma/rules
```

You will end up with several thousand rules mapped against the live ATT&CK matrix, and the Overview page will tell you exactly which tactics and techniques the community ruleset does not cover. That gap analysis alone is worth the deployment.

## Production hardening notes

The current setup is appropriate for a single analyst or a small team. To scale:

1. Move SQLite to PostgreSQL behind a connection pool
2. Put Streamlit behind nginx with OAuth or SSO
3. Pull rules continuously from your SIEM API instead of one-shot imports
4. Schedule a nightly job that auto-refreshes the ATT&CK STIX bundle and the coverage cache
5. Add row-level audit logging for every rule add/delete
6. Replace the in-process cache with Redis if multiple users will hit it

## Extension ideas

- Per-platform filtering (Windows / Linux / macOS / Cloud) using the platforms field in the technique data
- Diff two coverage states across time (Q1 vs Q2) to show progress
- Score covered techniques by adversary usage frequency, so you prioritize gaps that real groups exploit
- Auto-suggest rules to write next based on highest-impact uncovered techniques
- Integration with Atomic Red Team so you can launch the test for any uncovered technique with one click
- Pull from VECTR if you want to combine purple team test results with detection coverage
