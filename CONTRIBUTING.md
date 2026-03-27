# Contributing to Enterprise Detection Engineering Lab

Thank you for your interest in contributing. This guide covers how to add
detection rules, improve automation scripts, or expand the lab documentation.

---

## Getting Started

```bash
git clone https://github.com/ChandraVerse/enterprise-detection-engineering-lab.git
cd enterprise-detection-engineering-lab
pip install -r requirements.txt
```

---

## How to Contribute

### Adding a Detection Rule

1. **Identify a technique** from MITRE ATT&CK not yet covered by this lab
2. **Create the Sigma rule** in `detection-rules/sigma/` following the naming convention:
   `<tactic>_<technique_short_name>.yml`
3. **Convert to KQL and SPL**:
   ```bash
   python automation/scripts/sigma_converter.py
   ```
4. **Update the mapping file**: Add your rule entry to
   `mitre-attack/mappings/rule_technique_mapping.json`
5. **Update the Navigator layer**: Add the technique to
   `mitre-attack/navigator/coverage_layer.json`
6. **Write a simulation playbook** in `adversary-simulation/scenarios/`
7. **Update the README table** in both `README.md` and `detection-rules/README.md`

### Sigma Rule Requirements

Every Sigma rule MUST include:
- [ ] `title` — human-readable name
- [ ] `id` — unique UUIDv4 (generate with `python3 -c "import uuid; print(uuid.uuid4())"`)
- [ ] `status` — `production`, `test`, or `experimental`
- [ ] `description` — what the rule detects and why it matters
- [ ] `references` — ATT&CK URL + tool/technique documentation
- [ ] `author` — your name
- [ ] `date` — YYYY/MM/DD
- [ ] `tags` — ATT&CK tactic and technique tags (e.g. `attack.credential_access`)
- [ ] `logsource` — product + category
- [ ] `detection` — selection + filters + condition
- [ ] `falsepositives` — at least one documented FP
- [ ] `level` — `critical`, `high`, `medium`, or `low`

### Improving Automation Scripts

- Follow PEP 8 style (enforced with `flake8`)
- Add docstrings to all functions and classes
- Include `argparse` CLI with `--help` for every script
- Add unit tests for new functions in `tests/`

---

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/new-rule-t1059`
3. Commit with [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat(detection-rules):` — new rule
   - `fix(automation):` — bug fix in scripts
   - `docs:` — documentation only
   - `refactor:` — code restructure
4. Push and open a PR with:
   - Description of what technique is covered
   - Simulation steps used to validate the rule
   - Screenshot of alert firing in Elastic (if available)

---

## Code Style

```bash
# Format Python
black automation/scripts/

# Lint
flake8 automation/scripts/ --max-line-length=100

# Run tests
pytest tests/ -v
```

---

## Reporting False Positives

Open a GitHub Issue with the label `false-positive` and include:
- Rule name and file
- Environment details (Windows version, software causing FP)
- Sysmon event XML or raw log
- Suggested filter to add to the Sigma rule

---

## Contact

**Author**: Chandra Sekhar Chakraborty  
📧 chakrabortychandrasekhar185@gmail.com  
🔗 [GitHub](https://github.com/ChandraVerse)
