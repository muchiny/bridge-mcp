<!-- Recherche générée par workflow multi-agent (29 agents, 129 idées candidates → 12 lentilles). 2026-06-23. -->

# bridge-mcp — Synthèse recherche : combler les angles morts k8s / GitOps / Ansible / AWX pour un pilotage par agent IA

*Cible : opérateur solo, stack k8s + ansible + AWX, bridge-mcp piloté par agents IA. Surface actuelle : 357 outils, 75 groupes.*

## 1. TL;DR

- **Le trou n°1 est le couple preview → wait.** Un agent qui propose un changement k8s ne peut aujourd'hui qu'appliquer à l'aveugle (`ssh_k8s_apply --dry-run=server` valide mais ne montre pas le delta) puis deviner que c'est fini (polling de `ssh_k8s_get` en boucle, brûle des tokens). `ssh_k8s_diff` + `ssh_k8s_wait` ferment la boucle `diff → apply → wait → events` — le plus haut levier du lot, effort `small`.
- **`ssh_k8s_events` dédié** (tri par `.lastTimestamp`, filtre Warning) est le premier réflexe de triage. Aujourd'hui atteignable seulement via `ssh_k8s_get resource=events` (non trié, mauvaise forme). Petit effort, valeur élevée, requêté en permanence en incident.
- **Helm n'a aucune preview offline.** `ssh_helm_template` (render client-side, zéro cluster) est le keystone : valider tags d'image / limits / securityContext avant toute mutation, et socle de `ssh_helm_diff` et de l'audit supply-chain. Plus `ssh_helm_get` (extraire values/manifest réels d'une release).
- **Ansible casse silencieusement sur les vars vaultées.** Threader `vault_password_file` / `vault_id` sur `ssh_ansible_playbook/recap/run_background/adhoc` est ~1 ligne par builder et débloque la cause n°1 d'échec d'un vrai play (`trivial`/high).
- **AWX ne sait piloter que des job templates simples.** Les workflows (WJT launch/status/nodes), les approvals (un workflow gated *hang* indéfiniment via le bridge aujourd'hui) et `relaunch hosts=failed` sont la plus grosse lacune fonctionnelle du groupe — tous class (b) `small` réutilisant `AwxCommandBuilder` GET/POST.
- **Param `context` multi-cluster** sur tous les `ssh_k8s_*` / `ssh_helm_*` : class (a) `trivial`, multiplie la valeur de tout le reste. À faire en premier.
- **Prometheus est le grand absent observabilité.** `ssh_prom_query`/`query_range` débloque SLO, burn-rate, corrélation. Pour un homelab sous kube-prometheus-stack c'est la source de signal la plus utilisée — aucun historique aujourd'hui (`ssh_k8s_top` = snapshot live).
- **Le feature agent-définissant : runbook *tool-aware* (`ssh_runbook_run`).** Aujourd'hui `ssh_runbook_execute` est plan-only + shell-string-only. Un step qui invoque un outil enregistré par nom (`tool: ssh_k8s_rollout`) à travers `StandardToolHandler` (validation, retry, réduction, destructive_hint gratuits) transforme chaque orchestrateur ci-dessous en fichier YAML au lieu de Rust sur mesure. `large` mais débloque tout le reste.

## 2. Top 10 priorisé

Tri par (valeur DESC, effort ASC).

| # | Idée | Domaine | Outils proposés | Effort | Valeur | Pourquoi |
|---|------|---------|-----------------|--------|--------|----------|
| 1 | Param `context` multi-cluster | K8s/Helm | `context=` sur tous `ssh_k8s_*` / `ssh_helm_*` | trivial | high | Rend chaque outil k8s/helm multi-cluster pour ~0 coût (mime `kubectl_bin`/`KUBECONFIG`). À faire en premier, multiplie tout le reste. |
| 2 | Passthrough vault Ansible | Ansible | `vault_password_file`/`vault_id` sur `ssh_ansible_playbook/recap/run_background/adhoc` | trivial | high | Débloque la cause n°1 d'échec d'un vrai play (vars vaultées inutilisables aujourd'hui). ~1 ligne/builder. |
| 3 | `ssh_k8s_events` dédié | K8s core | `ssh_k8s_events` | small | high | Premier réflexe de triage ; tri `.lastTimestamp` + Warning baked-in. (complète `ssh_k8s_get resource=events` mal formé) |
| 4 | `ssh_k8s_diff` (preview d'apply) | K8s core | `ssh_k8s_diff` | small | high | Le gate « montre-moi ce que tu vas faire » qui se branche sur l'élicitation. Réutilise le staging file/stdin d'apply. (complète `apply --dry-run=server`) |
| 5 | `ssh_k8s_wait` | K8s core | `ssh_k8s_wait` | small | high | Primitive de synchro manquante : convertit une boucle de polling token-hungry en un appel déterministe. Composé dans les runbooks. |
| 6 | `ssh_helm_template` | Helm | `ssh_helm_template` | small | high | Render offline (zéro cluster) : valider un chart avant mutation. Socle de `helm_diff` + audit supply-chain. |
| 7 | AWX workflows (launch/status/nodes) | AWX | `ssh_awx_workflow_templates`, `_launch`, `_status`, `_nodes` | small | high | Plus grosse lacune fonctionnelle AWX : un vrai pipeline AWX = un workflow, pas 5 templates séquencés à la main. Réutilise `build_api_call`. |
| 8 | AWX approvals list/approve/deny | AWX | `ssh_awx_approvals`, `_approval_approve`, `_approval_deny` | small | high | Un workflow gated *hang* indéfiniment via le bridge aujourd'hui. Dovetail parfait avec l'élicitation déjà en place. |
| 9 | `ssh_awx_job_relaunch` (hosts=failed) | AWX | `ssh_awx_job_relaunch` | trivial | high | Verbe canonique de récupération post-échec ; 1 POST `{"hosts":"failed"}`. Meilleur ratio valeur/effort du groupe. |
| 10 | `ssh_helm_get` (extraire l'état déployé) | Helm | `ssh_helm_get` | small | high | values/manifest/hooks/notes réels d'une release — base de drift, triage, rollback evidence-based. (`ssh_helm_status` = proxy faible) |

## 3. Par domaine

*(doublons inter-lentilles fusionnés ; partiels marqués)*

### K8s — core (workload & troubleshooting)

- **`ssh_k8s_diff`** — `kubectl diff -f <manifest|->`, render unifié du delta avant apply [small/high] *(complète `apply --dry-run=server`)*
- **`ssh_k8s_events`** — events triés `.lastTimestamp`, filtre Warning, `--for` object-scoping [small/high] *(complète `ssh_k8s_get resource=events`)*
- **`ssh_k8s_wait`** — `kubectl wait --for=condition=...|delete|jsonpath=...`, primitive de synchro [small/high]
- **`ssh_k8s_set` + `ssh_k8s_patch`** — mutation in-place chirurgicale (`set image deployment/api app=img:v2`, `patch --type=merge`) ; seuls apply/scale/rollout existent [small/high]
- **Deepen `ssh_k8s_logs`** — `-l`/selector, `--all-containers`, `--since-time`, `--limit-bytes` (one-shot-safe ; `-f` exclu, besoin sessions) [trivial/high] *(complète l'existant)*
- **`ssh_k8s_restart` (alias) + débloquer rollout pause/resume** — pause/resume actuellement BLOQUÉ par `validate_rollout_action` (footgun pour un canary staged) [trivial/high] *(complète `ssh_k8s_rollout`)*
- **`ssh_k8s_debug`** — ephemeral container (netshoot/busybox) pour pods distroless où exec échoue ; node debug [small/medium]
- **`ssh_k8s_explain` + `ssh_k8s_api_resources`** — introspection schéma live (réduit les manifests hallucinés ; valeur *parce que* le consommateur est un agent) [small/medium]
- **Deepen `ssh_k8s_scale`** — `--current-replicas` (garde optimiste anti-race avec HPA), `-l` ; documenter scale-to-zero [trivial/medium] *(complète l'existant)*
- **`ssh_k8s_kustomize` + `-k` sur apply** — render overlay vers stdout ; apply est `-f`-only [small/medium]

### K8s — cluster & RBAC admin

- **Node maintenance : `ssh_k8s_drain` / `ssh_k8s_cordon` / `ssh_k8s_uncordon`** — split pour annotations propres (drain=destructive→élicitation, cordon/uncordon=mutating_idempotent) ; zéro capacité node aujourd'hui [small/high]
- **`ssh_k8s_auth_can_i` (+ `ssh_k8s_who_can`)** — pré-flight RBAC, transforme un 403 cryptique mid-runbook en blocage lisible ; `--as` pour audit SA [small→medium/high (medium si SA cluster-admin, fréquent en homelab)]
- **`ssh_k8s_cluster_info` / `ssh_k8s_health`** — rollup control-plane (`--raw /readyz?verbose`, version skew, componentstatuses) ; synergie `ssh_incident_*` [small/medium] *(componentstatuses partiellement via `ssh_k8s_get`)*
- **CSR : `ssh_k8s_csr_list` / `_approve` / `_deny`** — bootstrap kubelet, cert-manager edge cases ; complète `ssh_cert_*` [small/low — plus basse priorité du set gardé]

### GitOps — ArgoCD & Flux *(groupe absent ; confirmer Argo vs Flux avant build)*

- **`ssh_argocd_app_list` + `_app_get`** — inventaire + santé/drift (Synced/OutOfSync, Healthy/Degraded), flags `drifted_only`/`refresh=hard` ; entrée de tout le reste [medium (création groupe)/high]
- **`ssh_argocd_app_diff`** — live-vs-Git desired (la *vraie* preview-of-sync, pas un dry-run serveur) [small/high]
- **`ssh_argocd_app_sync`** — `--prune` (destructive→élicitation) / `--dry-run` / `--resource` sélectif [small/high]
- **`ssh_argocd_app_history` + `_app_rollback`** — IR : last-good revision → rollback (caveat auto-sync re-syncs) [small/high]
- **`ssh_argocd_app_wait`** — block until synced & healthy (timeout < command timeout) [small/medium]
- **`ssh_argocd_proj_list` (+ `_repo_list`)** — diagnostic « destination not permitted » / repo inaccessible [small/low]
- **`ssh_flux_reconcile`** — équivalent Flux d'argocd sync, flag `with_source` first-class ; premier outil flux à builder [medium (création groupe)/high]
- **`ssh_flux_get`** — sources/kustomizations/helmreleases + colonne Message (pourquoi pas Ready) [small/high] *(complète `ssh_k8s_get` sur les CRD Flux, sans les colonnes synthétisées)*
- **`ssh_flux_suspend` / `_resume`** — escape hatch « laisse-moi hotfix sans que Flux revert » [small/high]
- **`ssh_flux_diff`** — preview-before-reconcile (caveat : besoin sources via `--path` sur le bridge) [small/medium]
- **`ssh_gitops_drift`** — sweep unifié cross-controller (argocd OutOfSync + flux NotReady → table normalisée), detect-and-skip si un CLI absent ; outil de standup matinal [medium/high — build en dernier, dépend des reads par-moteur]

### Helm — depth + supply chain

- **`ssh_helm_template`** — render client-side offline ; keystone, dont dépend diff [small/high]
- **`ssh_helm_diff`** — `helm diff upgrade` (plugin) ou fallback `template | get manifest` ; `--detailed-exitcode` = signal no-op machine [medium/high]
- **`ssh_helm_get`** — values/manifest/hooks/notes/metadata `--revision` ; counterpart read de template [small/high] *(`ssh_helm_status` = proxy faible)*
- **Richer value-setting** — `--set-string`/`--set-file`/`--set-json` + (upgrade) `--reset-values`/`--reuse-values` ; `--set-file` secret via stdin (pas argv, audit) [small/high] *(complète le `HashMap<String,String>` plat de install/upgrade)*
- **`ssh_helm_repo`** — action enum add/update/list/remove ; install/upgrade supposent le chart déjà résolvable [small/high]
- **`ssh_helm_pull` + `ssh_helm_verify`** — staging air-gapped (pull connecté → install isolé), `--prov`/`--verify` + cosign optionnel comme gate provenance ; complète `ssh_sbom_generate`/`ssh_vuln_scan` [medium/high]
- **`ssh_helm_show`** — chart/values/readme/crds avant d'écrire un override [small/medium]
- **`ssh_helm_lint`** — parité avec `ssh_ansible_lint`, `--strict` + structuré [trivial/medium]
- **`ssh_helm_registry`** — login/logout OCI, password via `--password-stdin` (Vault-sourced, hors command string) [small/medium]
- **`ssh_helm_dependency`** — build/update/list sous-charts (umbrella) [small/medium]

### Ansible — execution depth + qualité/idempotence/drift

- **Passthrough vault** — `vault_password_file`/`vault_id` sur playbook/recap/run_background/adhoc [trivial/high] *(complète l'existant ; cause n°1 d'échec)*
- **`ssh_ansible_vault`** — lifecycle view/encrypt/decrypt/rekey/encrypt_string (verbe enum ; view=read_only, reste=mutating) ; ssh_vault_* = HashiCorp, sans rapport [small→medium/high]
- **`ssh_ansible_doc`** — argspec module en `--json` au lieu d'halluciner les params ; révèle les plugins installés [small/high]
- **`ssh_ansible_list`** — mode enum tasks/tags/hosts (blast-radius avant pull-the-trigger), honore les mêmes sélecteurs [small/high]
- **`ssh_ansible_syntax_check`** — `--syntax-check`, gate le moins cher (distinct de `--check` qui connecte, et de lint) [small/high]
- **`ssh_ansible_idempotence`** — run-twice + assert second run = 0 changed, retourne offenders typés ; invariant correctness IaC [medium/high]
- **`ssh_ansible_drift`** — `--check --diff` fleet → matrice host×task×ok/changed, scope param single/fleet ; terraform-plan pour Ansible [medium/high] *(complète `--check`/`--diff` existants ; famille `ssh_env_drift`/`ssh_fleet_diff`)*
- **`ssh_ansible_summarize`** — digest typé per-host depuis callback json / artifact run-id (stdout ansible = gouffre à tokens) [small/high] *(complète recap/events grep)*
- **`ssh_ansible_lint` profils** — `--profile production`/`--skip-list`/`--warn-list` + gate `fail_on_severity` [trivial/high] *(complète `--format`-only)*
- **`ssh_ansible_secrets_scan`** — smells de secrets en clair dans vars/host_vars (file:line, match redacted) ; aucun scanner Ansible-aware [medium/high]
- **`--start-at-task`** sur playbook — reprise après échec task N (forks déjà couvert) [trivial/medium]
- **`ssh_ansible_galaxy`** — install -r requirements.yml (90% du cas) + list ; deps absentes = échec silencieux [small/medium]
- **`ssh_ansible_preflight`** — ping + interpreter probe + become check par host ; tue la mauvaise-attribution privilège→logique [small/medium]
- **`ssh_ansible_inventory_diff`** — diff vs snapshot source-of-truth (added/removed/changed) [small/medium] *(complète `ssh_ansible_inventory` sans diff)*
- **`ssh_ansible_facts_diff`** — snapshot facts puis diff sous-ensembles (packages/services/kernel) [medium/medium — question persistance] *(complète `ssh_ansible_facts` sans snapshot)*
- **Dynamic inventory** — `inventory_source` + `--graph/--vars` JSON-enrichi pour plugins cloud/k8s [small/medium] *(mostly (a) ; complète l'existant)*
- **`ssh_ansible_runner_*`** — vrai ansible-runner (events structurés vs nohup+grep) [medium/medium]
- **`ssh_ansible_navigator_run`** — Execution Environment (image AAP) `-m stdout` ; élimine le drift « marche dans AWX, casse sur le bridge » [medium/medium — footprint lourd]

### AWX / AAP — control-plane depth

- **Workflows : `ssh_awx_workflow_templates` / `_launch` / `_status` / `_nodes`** — pipeline réel = workflow ; `_nodes` résout quel node a échoué → feed `ssh_awx_job_stdout` [small/high]
- **Approvals : `ssh_awx_approvals` / `_approval_approve` / `_approval_deny`** — un workflow gated hang sinon ; `_deny`=destructive auto-résolu [small/high]
- **`ssh_awx_job_relaunch`** — `{"hosts":"failed"}`, récupération canonique [trivial/high] *(complète launch+cancel)*
- **`ssh_awx_jobs` + `ssh_awx_activity`** — feed cross-type global + activity_stream (qui-a-changé-quoi) ; aucun feed/audit aujourd'hui [small/high] *(complète les reads job_id-only)*
- **`ssh_awx_survey_get` (+ `_set`)** — lire le survey_spec avant launch pour construire un extra_vars valide ; de-risque le launch existant [small/high] *(`template_detail` n'expose pas utilement le spec)*
- **Inventory write : `ssh_awx_host_add` / `_host_remove` / `_inventory_sync`** — ferme la boucle IaC→config-mgmt (terraform spin-up → register AWX) ; `host_remove` = premier handler DELETE [medium/high] *(complète les reads)*
- **`ssh_awx_project_status` + `_project_playbooks`** — lire l'outcome du sync + playbooks/branch dispo (sinon `ssh_awx_project_sync` est aveugle) [small/medium] *(complète le trigger sync)*
- **`ssh_awx_schedules` + `_schedule_toggle`** — « qu'est-ce qui tourne ce soir » + kill-switch maintenance ; toggle needs PATCH [small/medium]
- **RBAC audit : `ssh_awx_access_list` / `_roles` / `_org_members`** — read-only, « qui peut lancer prod-deploy » [small/medium — medium pour solo]
- **Prérequis : `HttpMethod::Patch` + préfixe API configurable** — débloque tout le write-side (toggle/edit) ; gateway-aware AAP 2.5 (`/api/gateway/v1`, `/api/controller/v2`) ; PATCH inconditionnellement requis par schedules/inventory [medium/medium — *enabler, pas feature standalone*]

### Observabilité & SRE

- **`ssh_prom_query` + `ssh_prom_query_range`** — PromQL instant + range ; keystone qui débloque SLO/burn-rate/corrélation ; `prometheus_url` default depuis section `observability:` config [medium/high — build en premier]
- **`ssh_prom_labels` / `_targets` / `_rules`** — discovery métriques + santé scrape-targets (un exporter down explique la data manquante) + rules/alerts firing [small/high]
- **`ssh_alertmgr_list` / `_silence` / `_expire`** — silence pendant fenêtre maintenance puis expire ; `ssh_alert_*` = awk interne, pas Alertmanager [medium/high]
- **`ssh_loki_query` + `ssh_loki_labels`** — LogQL cross-pod/label/time-ranged ; comble les gaps selector/time de `ssh_k8s_logs` sans streaming [medium/high] *(`ssh_log_*` = journalctl/grep mono-host)*
- **`ssh_slo_snapshot`** — composite good/total + burn-rate multi-window → verdict (« budget 23%, 6h burn 4.2x → fast-burn ») ; gate `ssh_canary_exec`/`ssh_helm_upgrade` [medium/high — dépend du groupe prom]
- **`ssh_obs_correlate`** — flagship : alert → workload → logs → deploy en un artefact corrélé par temps/ownership [large/high — séquencer en dernier, dépend prom/AM/Loki] *(complète `ssh_incident_correlate` qui opère sur logs host)*
- **`ssh_probe_http`** — probe blackbox/curl applicatif (status 2xx, TLS expiry, latence) post-déploiement [small/medium] *(complète `ssh_net_*` L3/L4)*
- **`ssh_grafana_annotate` (+ `_render`)** — marqueur déploiement sur les dashboards humains (situational awareness partagée) [small/medium]
- **`ssh_trace_get` / `_search`** — Tempo/Jaeger span-flattening [medium/low — seulement si tracing confirmé in-stack]

### DX agent & efficacité tokens *(cross-cutting)*

- **`suggested_next` (champ d'erreur universel)** — table signature→hint dans le payload d'erreur (CrashLoopBackOff → `logs previous=true`) ; transforme un dead-end en recovery one-hop [small/high]
- **`ssh_k8s_bundle` (+ `ssh_service_bundle`)** — un appel = get -o wide + events triés + Conditions de describe + N log lines + owner chain ; « pourquoi mon pod crashe » coûte ~5 round-trips aujourd'hui [medium/high]
- **`ssh_k8s_can_i` + `ssh_capability_check` (+ `ssh_preflight`)** — pré-flight RBAC/binaire/no-op « will this succeed » [small/high]
- **`verdict` (champ résultat universel)** — `{ok|changed|nochange|failed|degraded}` dérivé en post_process ; peupler `OUTPUT_SCHEMA` (déjà const, null partout) top ~30 outils [medium/high]
- **Fan-out keyed : `hosts[]`/`namespaces[]`** sur reads structurés → enveloppe mergée `{hostA:{...}}` + roll-up ; généralise le pattern `_multi` aux outils typés [medium/high] *(complète exec/metrics/log `_multi`)*
- **`idempotency_key` + `change_receipt`** — retries agent safe + reçu auditable pré/post (replicas 3→5) [medium/high]
- **Watch borné delta** — `watch_until=rollout-complete`, retourne deltas + verdict terminal (pas un stream) ; réutilise le poll-loop de `ssh_awx_job_follow` [medium/high] *(complète `ssh_awx_job_follow`)*
- **`preset=` / `ssh_reduction_presets`** — bibliothèque jq/columns nommée (`preset=triage`) ; supprime les « agent a écrit du mauvais jsonpath » [small/medium]
- **`cache_ttl`/`cache_bypass` (+ `ssh_session_cache_stats`)** — cache TTL court args-keyed pour reads (l'agent re-fetch la même liste 3x) [medium/medium] *(`OutputCache` = pagination-only)*

### Sécurité, policy-as-code & change control

- **`ssh_policy_conftest` / `_kubeconform` / `_kyverno`** — nouveau groupe `policy` validant manifests rendus avant cluster ; flag `policy_gate=` sur apply/install/upgrade + plan terraform JSON [medium/high — *cœur de la lentille* ; requiert conftest/kubeconform sur le bridge]
- **`ssh_audit_query`** — query le propre audit log du bridge (actor/host/tool/destructive/window) ; capture existe (`security/audit.rs`) mais aucun read [small/medium] *(complète l'audit write-only)*
- **`ssh_k8s_drift_check`** — refuse apply si le cluster a divergé out-of-band (ne clobber pas un hotfix manuel) ; dépend de `ssh_k8s_diff` [small/medium] *(complète `ssh_env_drift`)*
- **`ssh_terraform_policy` + `detailed_exitcode`** — `-detailed-exitcode` (2=drift) signal machine + conftest sur plan JSON ; NE PAS re-proposer plan_file (déjà implémenté) [small/medium] *(complète terraform)*

*(diff/wait/events/can-i/helm template/get/show/verify déjà listés sous K8s/Helm)*

### Orchestration & runbooks higher-order

- **`ssh_runbook_run` (tool-aware steps)** — step invoque un outil par nom+args via la registry, capture structurée `save_as`, honore destructive_hint ; **build en premier**, débloque tous les orchestrateurs ci-dessous en YAML [large/high] *(complète `ssh_runbook_execute` plan-only/shell-only)*
- **`ssh_fleet_runbook` (foreach)** — itère host-group/liste/inventory AWX, concurrence bornée, agrégation + rollout staged dev→staging→prod (halt on first fail) [medium/medium] *(complète `ssh_rolling_exec`/`ssh_exec_multi` shell-only hors engine)*
- **`ssh_k8s_incident_triage`** — chaîne read-only get→describe→events→logs --previous→top + cross-ref helm/rollout/AWX history → hypothèse rankée + remédiation suggérée (non exécutée) [medium/high — dépend du leaf `ssh_k8s_events`] *(complète `ssh_incident_triage` host-OS)*
- **`ssh_awx_job_diagnose`** — pure composition sur les reads AWX existants : classifie (unreachable/task/timeout/cred) + suggère relaunch ; pas de nouveau transport [small/high]
- **`ssh_deploy_timeline`** — feed « qu'est-ce qui a déployé juste avant le crash » mergeant helm/rollout/AWX/terraform history [medium/high] *(complète `ssh_incident_timeline` host-OS)*
- **`ssh_deploy_guard`** — transaction mutation → health-check borné → auto-rollback si unhealthy ; garde-fou autonomie le plus réutilisable [medium/high — dépend `ssh_k8s_wait`]
- **`ssh_deploy_pipeline`** — golden path lint → preview → approval (élicitation) → apply → verify → notify, backend par `kind` [medium/high — runbook flagship une fois l'engine + leaves landés]
- **`ssh_drift_remediate`** — boucle fermée diff → gate → re-apply → re-verify drift=0 [medium/high — dépend leaf `ssh_k8s_diff`]
- **`ssh_sentinel_*`** — drift/health planifié (cron/timer sur bridge), alerte sur change-of-state [large/low — *stretch* ; le modèle one-shot SSH combat le scheduling persistant ; approximable via `ssh_cron_add`/`ssh_timer_*`]

### Nouveaux adaptateurs / APIs directes

- **Adaptateur K8s natif (kube-rs)** — `Protocol::Kube`, débloque l'infaisable en one-shot SSH : logs `-f`, `wait` (watch API), exec stdin/tty, `cp`, port-forward ; re-route les 9 outils existants transparemment [large/high — *class (d)*, seule classe touchant le dispatch core]
- **Adaptateur Prometheus/Thanos** — curl-over-SSH (pattern AWX éprouvé), pourrait graduer en (d) HTTP natif [medium/high]
- **AWX gateway-aware (AAP 2.5)** — promouvoir le builder curl en client version-aware (`/api/gateway/v1`, `/api/controller/v2`) + PATCH/PUT [medium/high]
- **Vault dynamic-secrets / transit / lease** — étendre le KV statique : creds courts mint+auto-revoke (fit agent-safety), transit encrypt sans voir la clé, lease revoke [small/high] *(complète `ssh_vault_read/write/list/status`)*
- **Adaptateur Alertmanager** — alerts groupées + silences TTL-bornés [medium/medium]
- **Adaptateur Loki** — query/query_range LogQL + labels [medium/medium — confirmer Loki vs ELK]
- **Adaptateur registry (skopeo/crane/oras)** — inspect/tags/digest/copy/delete, daemon-free, digest-pinning + promotion staging→prod ; comble le gap Helm-OCI [medium/medium]
- **Adaptateur etcd (etcdctl)** — snapshot-before-change + health/leader/quota ; fit air-gapped self-hosted [medium/medium — n/a si managé EKS/GKE]
- **Adaptateur Talos/k0s (talosctl)** — cluster API-managed shell-less, fit air-gapped premium ; health/upgrade/reboot/etcd-snapshot [medium/medium — confirmer distro]

## 4. Killer combos

1. **`diff → policy → apply → wait` (change-control k8s).** `ssh_k8s_diff` (delta réel) → `ssh_policy_conftest`/`kubeconform` (gate org standards) → élicitation avec le diff en payload → `ssh_k8s_apply` → `ssh_k8s_wait --for=condition=Available`. Transforme l'apply à l'aveugle en transaction reviewable. Toutes les pièces sont `small` sauf le groupe policy (`medium`).

2. **Auto-triage incident k8s+AWX+deploy (`ssh_k8s_incident_triage` + `ssh_deploy_timeline` + `ssh_awx_job_diagnose`).** Un symptôme → chaîne read-only get/describe/`ssh_k8s_events`/logs --previous + cross-ref `ssh_helm_history`/rollout history/jobs AWX → hypothèse rankée + remédiation suggérée non exécutée. Collapse 6-10 appels manuels en un artefact structuré. Pour un opérateur solo sans on-call, le plus gros payoff quotidien.

3. **GitOps drift sweep + remediation (`ssh_gitops_drift` → `ssh_argocd_app_diff`/`ssh_flux_diff` → gate → `ssh_argocd_app_sync`/`ssh_flux_reconcile`).** Standup matinal : un appel, posture GitOps complète cross-controller ; puis preview → approval → reconcile → re-verify. Composé sur la famille `ssh_env_drift`/`ssh_incident_*` existante.

4. **`ssh_deploy_guard` self-healing.** `ssh_helm_upgrade` → `ssh_k8s_wait`/rollout status dans une fenêtre bornée → si unhealthy, `ssh_helm_rollback` auto (gated). Garde-fou autonomie le plus réutilisable : l'agent ne peut pas laisser un cluster à moitié cassé. Générique sur helm/k8s/ansible.

5. **`ssh_deploy_pipeline` golden path (en YAML via `ssh_runbook_run`).** `ssh_ansible_lint`/`ssh_helm_lint` → `ssh_helm_template`+`ssh_helm_diff`/`ssh_k8s_diff` → approval élicitation → apply → `ssh_k8s_wait`/`helm test` → `ssh_notify`. Encode « fais-le safely, à chaque fois » pour un opérateur sans CI/CD ni reviewer — la discipline qu'une équipe fournirait. Devient un fichier YAML une fois l'engine tool-aware + les leaves landés.

## 5. Quick wins (effort trivial/small, à knock-out en premier)

- **`context=` sur tous `ssh_k8s_*`/`ssh_helm_*`** (a/trivial) — fait *avant* tout le reste, multiplie la valeur.
- **`vault_password_file`/`vault_id`** sur playbook/recap/run_background/adhoc (a/trivial).
- **`ssh_awx_job_relaunch`** — 1 POST `{"hosts":"failed"}` (b/trivial).
- **Débloquer rollout `pause`/`resume`** — retirer 2 entrées de l'allowlist + schema enum (a/trivial).
- **Deepen `ssh_k8s_logs`** (`-l`/`--all-containers`/`--since-time`/`--limit-bytes`) (a/trivial).
- **Deepen `ssh_k8s_scale`** (`--current-replicas`, doc scale-to-zero) (a/trivial).
- **`ssh_ansible_lint` profils** (`--profile`/`--skip-list`/`fail_on_severity`) (a/trivial).
- **`--start-at-task`** sur playbook (a/trivial).
- **`--set-string`/`--set-file`/`--set-json` + `--reuse-values`/`--reset-values`** sur helm install/upgrade (a/small).
- **`ssh_helm_lint`** — parité `ssh_ansible_lint` (b/trivial).
- **`detailed_exitcode`** sur `ssh_terraform_plan` (a/trivial).
- **`suggested_next`** — table de hints incrémentale dans le path d'erreur (small).
- **`ssh_k8s_events`, `ssh_k8s_diff`, `ssh_k8s_wait`, `ssh_helm_template`, `ssh_helm_get`** — les 5 leaves `small` multiplicateurs.

## 6. Anti-recommandations

- **`ssh_molecule_run`** — *éviter/différer* : gated par molecule + driver container/vagrant sur le bridge ; pour un solo homelab le leverage est conditionnel, et `ssh_ansible_idempotence` couvre déjà l'assertion d'idempotence pour qui n'est pas sur molecule. Effort `medium` pour valeur `low`.
- **`ssh_sentinel_*` (scheduling persistant)** — *différer* : le modèle one-shot SSH-exec combat frontalement le scheduling durable + état cross-runs ; plus basse confiance à shipper proprement. Approximable aujourd'hui en câblant un runbook dans `ssh_cron_add`/`ssh_timer_*` plutôt qu'un nouveau sous-système. Effort `large`/valeur `low`.
- **`ssh_trace_get`/`_search` (Tempo/Jaeger)** — *différer* : plafond élevé mais valeur seulement si le tracing tourne réellement in-stack (bien moins certain que Prometheus/Loki en homelab). Ne builder qu'après confirmation ; plus basse priorité du set observabilité.
- **`ssh_k8s_csr_*`** — *plus basse priorité du set gardé* : 3 wrappers cheap mais fréquence faible en homelab single-admin ; ne pas prioriser avant la boucle RBAC/cert principale.
- **Adaptateur Talos/k0s** — *conditionnel* : ne builder que si les clusters air-gapped tournent réellement Talos/k0s ; pour du kubeadm vanilla, replier sur les idées kube natif + etcd au lieu d'un groupe dédié.

*Note transversale : confirmer **Argo vs Flux** et **Loki vs ELK/OpenSearch** avant de builder les groupes correspondants — même effort, même forme, mais l'adaptateur à choisir dépend du stack réel de l'opérateur.*
