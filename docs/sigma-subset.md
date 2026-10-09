# Tested Sigma subset

IRForge imports one YAML document (maximum 256 KiB) for `product: windows`, `category: process_creation`. Supported fields are Image, CommandLine and ParentImage. Field maps use AND. Lists use OR; the `all` modifier uses AND. Conditions support named selections, lowercase `and`, `or`, `not` and parentheses. Case-insensitive exact comparison, contains, startswith and endswith are supported. Unmodified string values may have a single leading/trailing `*`; interior wildcards, `?`, regex, aggregation, timeframe, correlations, lists of selection maps, null values, special YAML tags, aliases exceeding structural bounds, duplicate keys and multiple documents fail explicitly.

ParentImage retains the full provider image path: it is never weakened to basename matching. Missing fields fail positive predicates; a negated selection follows ordinary Boolean Sigma selection semantics. ETW missing command lines are visibly incomplete, not reconstructed. No claim of full Sigma support is made.

The five samples under `rules/sigma` are original MIT-licensed IRForge examples. Import retains the identifier, author/origin, license, descriptions and mapped technique tags. The compiled JSON is validated through the same rule parser before output is written. Upstream packs require separate license and equivalence review.

```powershell
build/mingw/irforge.exe rules import-sigma --input rules/sigma/01-sample.yml --out out/imported-new-rule.json
build/mingw/irforge.exe rules validate --dir rules/internal
build/mingw/irforge.exe rules list --dir rules/internal
build/mingw/irforge.exe rules test --dir rules --events C:/Evidence/recording.jsonl
```

The original `rules` directory retains eight v0.1 rules and deterministic scores. Select `rules/internal` explicitly for the expanded 37-rule pack, including 25 atomic rules validated with positive and independently chosen legitimate-use negative cases in the separately maintained local suite. Development fixtures are excluded from the release repository. Behavioral matches guide triage and require human review. ATT&CK mappings resolve offline from the bundled reviewed Enterprise v18.0 subset; they do not prove an attack.
