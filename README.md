![Alt text](assets/logo_mission.png)


# OcculusINT
OcculusINT is a lightweight OSINT tool designed to identify an organization's internet-facing assets and associated vulnerabilities, inspired by BitSight's approach to external risk exposure.

---

## Structure

### Root 
```cpp
OcculusINT/
├── main.py                   ← Central CLI entry point
├── README.md                 ← Project documentation
├── requirements.txt          ← All dependencies
├── LICENSE                   ← MIT License
├── targets/                  ← Generated output files (.txt, .csv)
└── occulusint/               ← Python modules (importable)
```

### Core Modules 
```cpp
occulusint/
├── __init__.py
├── core/
│   ├── __init__.py
│   └── domain_filter.py      ← Scoring + filtering logic
├── recon/
│   ├── __init__.py
│   ├── domains_discovery.py     ← crt.sh extraction
│   ├── subdomains.py         ← Sub3num wrapper
│   └── resolve.py            ← DNS resolution
├── enrich/
│   ├── __init__.py
│   └── ip_enrichment.py      ← ASN, GEO, Cloud, etc.
└── vuln/
    ├── __init__.py
    └── passive_vuln.py       ← Shodan OSINT + CVSS scoring
```
---

## What is OcculusINT?

OcculusINT is a modular and extensible OSINT toolkit designed to map and score an organization's external digital footprint. It leverages certificate transparency logs, passive DNS, IP enrichment, Google dorking, and scoring heuristics to generate actionable recon data — all without touching the target.

---

## Features

- Domain discovery via certificate logs (crt.sh)
- Subdomain enumeration (via Sub3num)
- Google Dork-based surface scraping
- DNS resolution & IP mapping
- ASN & geolocation enrichment (RDAP + ip-api)
- Cloud provider detection (AWS, Azure, GCP, OVH…)
- Passive vulnerability scan via Shodan (CVSS-aware scoring)
- Heuristic scoring system for triage
- Exportable results (CSV, TXT)
- One-file CLI orchestration: `main.py`

---

## Installation

```bash
git clone https://github.com/DavidOteria/OcculusINT.git
cd OcculusINT
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

--- 

## Usage

Launch the tool with:

```bash
python main.py <command> <args>
```

Available commands:

- discover → Get domains from crt.sh via keyword
- enum → Enumerate subdomains from a list of domains
- googledork → Extract subdomains via Google results
- resolve → Resolve all domains to IP addresses
- enrich → Enrich IPs with ASN, geolocation, provider
- passive-vuln → Passive vuln scan + scoring
- update-nvd → Refresh local CVSS feed
- filter → Score and filter most relevant domains

## Examples 

```bash 
python main.py discover exmple
python main.py enum targets/example_domains.txt
python main.py googledork example.com
python main.py resolve targets/example_subdomains.txt
python main.py enrich targets/example_subdomains_resolved.csv
python main.py passive-vuln targets/example_subdomains_resolved.csv YOUR_SHODAN_KEY
python main.py update-nvd 
python main.py filter targets/example_subdomains.txt example1 example2 example3
```

---

## Scoring Logic

Each domain is assigned a score from 0 to 100 based on:

- Match with keywords (test, google, etc.)
- Trusted TLD (.fr, .com, .net)
- Brand variants (e.g. domainexemple, domain-exemple, exemple-cardif)
- Subdomain depth and pattern
- HTTP 200 availability
- WHOIS organization match
- SOA records / NS affinity
- Language detection on content
- Domain age
- Cloud provider hints

Low-quality TLDs, dev/test keywords, and long or unresolved domains are penalized.

---

### Vuln Scoring grid

- **TLS (max 25)**

- **Vulnerabilities (max 35)**  

- **Exposure (max 25)**

- **Hygiene (max 15)**

Total = TLS + Vuln + Exposure + Hygiene **(0 → 100)**.

## Output Files

All outputs are saved to the /targets/ directory:

- <keyword>_domains.txt
- <domain>_subdomains.txt
- ..._resolved.csv
- ..._enriched.csv
- ..._filtered.txt
- ..._vuln.csv
- ..._vuln_score.csv

--- 

## Passive Design 

OcculusINT performs no intrusive scanning by default. All data is collected from passive sources (crt.sh, DNS, WHOIS, etc.).

--- 

## Modular By Nature

ll core functionalities are separated into modules:

```cpp
occulusint/
├── recon/
├── core/
├── enrich/
└── vuln/
```

You can reuse or plug in new engines easily.

---

## To-do (or contribute!)

- Passive vulnerability scan via Shodan / Censys
- Automated branch/infrastructure classification
- Export to JSON / Markdown report
- CLI installable via pip (occulusint)

## Licence 
MIT License — see LICENSE.