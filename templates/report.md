# Secrets Scan Report

**Repository:** {{repo_path}}
**Scan Date:** {{scan_date}}
**Gitleaks Version:** {{gitleaks_version}}

## Summary
| Source | Findings |
|--------|----------|
| Default Rules | {{default_count}} |
| Custom Rules | {{custom_count}} |
| **Total Unique** | **{{total_count}}** |

## Findings by Rule
{{#each rule_groups}}
### {{rule_id}} ({{count}})
{{#each findings}}
- `{{file}}:{{line}}` -- `{{match_preview}}`
  Context:
  ```
  {{context}}
  ```
{{/each}}
{{/each}}

## Recommendations
1. Rotate any exposed credentials immediately
2. Move secrets to environment variables or secret management systems
3. Add .env files and secret configs to .gitignore
4. Review historical commits for previously leaked secrets
