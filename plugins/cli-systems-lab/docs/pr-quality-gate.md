### Amac
- CLI Systems Lab plugin paketini PR-oncesi kalite kapisindan gecirmek; UI scaffold, preview, pattern secimi, snapshot dogrulama ve yeni plugin-self-check workflow'unun merge-oncesi durumunu belgelemek.

### Degisiklik Ozeti
- Plugin icin path-filtered GitHub Actions workflow eklendi; artik changeset yalniz plugins/cli-systems-lab path'inde oldugunda self-check kosacak.
- Plugin-local ci_self_check entrypoint'i tum shell syntax, template, pattern, preview, snapshot ve manifest parse adimlarini tek komutta topladi.
- README, manifest ve skill akisi pluginin yeni CI/self-check yetenekleriyle hizalandi; yerelde self-check kaniti uretildi.

### Nasil test edildi
- `bash -n /Users/batuhanyuksel/Documents/security/plugins/cli-systems-lab/scripts/ci_self_check.sh` -> passed
- `bash /Users/batuhanyuksel/Documents/security/plugins/cli-systems-lab/scripts/ci_self_check.sh` -> passed
- `ruby -e 'require "yaml"; YAML.load_file("/Users/batuhanyuksel/Documents/security/.github/workflows/cli-systems-lab-self-check.yml"); puts "ok"'` -> passed
- `bash /Users/batuhanyuksel/Documents/security/plugins/cli-systems-lab/scripts/smoke_cli_ui_templates.sh` -> passed
- `bash /Users/batuhanyuksel/Documents/security/plugins/cli-systems-lab/scripts/smoke_cli_ui_patterns.sh` -> passed
- `bash /Users/batuhanyuksel/Documents/security/plugins/cli-systems-lab/scripts/smoke_cli_ui_previews.sh` -> passed
- `bash /Users/batuhanyuksel/Documents/security/plugins/cli-systems-lab/scripts/smoke_cli_ui_snapshots.sh` -> passed
- `node -e 'JSON.parse(require("fs").readFileSync("/Users/batuhanyuksel/Documents/security/plugins/cli-systems-lab/.codex-plugin/plugin.json","utf8")); console.log("ok")'` -> passed

### Riskler ve mitigasyonlar
- Risk: Template runtime komutlari gercek framework dependency kurulumuyla end-to-end calistirilmadi / Mitigasyon: Preview.sh snapshotlari merge-oncesi contract olarak tutuldu; sonraki adimda framework-native CI smoke eklenmeli.
- Risk: Yeni GitHub workflow yerelde dogrulandi ama GitHub runner ustunde henuz ilk green run kaniti yok / Mitigasyon: Workflow merge veya push sonrasi ilk Action kosusu izlenmeli ve gerekirse ubuntu imajina gore ince ayar yapilmali.
- Risk: Pattern secimi marker tabanli heuristic kullaniyor; karmasik hibrit repolarda en dar template secimi her zaman ideal olmayabilir / Mitigasyon: Preview ve pattern-plan ciktisi kullaniciya acik tutuldu; ileri adimda agirlikli scoring veya override parametresi eklenmeli.

### Guvenlik notlari
- Secret/PII: Plugin path icinde hardcoded token, key, password veya private-key marker'i icin hizli rg taramasinda bulgu cikmadi.
- Input validation: Scriptlerin flag-value guardlari, katalog tabanli preview secimi ve scaffold sinirlari mevcut; heuristic pattern secimi ise davranissal risk olarak izlenmeli.
- Auth/permission: Workflow sadece checkout ve node setup ile plugin-local shell komutlari calistiriyor; auth veya permission kapsam genislemesi yapan bir degisiklik yok.
