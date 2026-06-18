# bridge-mcp Constitution

## Core Principles

### I. Architecture Hexagonale Stricte

Le projet DOIT suivre une architecture hexagonale (ports & adapters) :

- Chaque couche a une responsabilite unique et des dependances
  unidirectionnelles : `domain/ -> ports/ -> adapters/ -> infrastructure/`
- Les contrats entre couches sont definis par des traits dans `ports/`
  avec `#[async_trait]` + `Send + Sync`
- L'injection de dependances se fait via `ToolContext` (struct DI container)
- Toute nouvelle fonctionnalite DOIT definir le port d'abord, puis l'adapter
- Aucun import direct entre adapters — la communication passe
  toujours par les ports (`RemoteExecutor`, `ToolHandler`, `SshExecutor`)

**Rationale** : Garantit que les 338 tools restent decouplees des 13 protocoles
de transport. Un nouveau protocole = un nouvel adapter, zero changement
dans les handlers existants.

### II. Purete du Domaine (NON-NEGOTIABLE)

Le module `domain/` ne DOIT avoir AUCUNE dependance externe d'I/O :

- Pas de `reqwest`, `tokio::fs`, `russh`, `winrm-rs` ou tout crate effectuant des operations I/O
- Seules dependances autorisees : `serde`, `thiserror`, `uuid`
- Les erreurs domaine utilisent `thiserror` exclusivement
- Les erreurs application utilisent `anyhow::Result`
- Le domaine contient les command builders (36 Linux + 13 Windows),
  les validators, et la logique de sanitisation

**Rationale** : Un domaine pur permet des tests unitaires rapides,
deterministes et sans mock d'infrastructure. Les 65 command builders
ne savent pas si la commande sera executee via SSH, WinRM, ou PSRP.

### III. Feature Gates et Compilation Conditionnelle

Chaque protocole non-SSH DOIT etre feature-gated :

- Un protocole = un feature flag dans `Cargo.toml`
- Les imports, les `mod` declarations, et les match arms utilisent `#[cfg(feature = "...")]`
- `cargo check` DOIT passer sans erreur avec et sans chaque feature
- Les feature bundles (`air-gapped`, `all-protocols`, `cloud`) regroupent les protocoles par use case
- Un feature PEUT impliquer un autre (`psrp` implique `winrm`)

**Rationale** : Le binaire de base (SSH-only) reste leger (~15 MB).
Les protocoles sont opt-in pour eviter les dependances inutiles
dans les environnements contraints.

### IV. Discipline de Test

Le projet DOIT maintenir une couverture de test rigoureuse :

- Tests unitaires inline `#[cfg(test)]` dans chaque module
- Tests d'integration dans `tests/`
- 57 fuzz targets dans `fuzz/`
- `.unwrap()` est INTERDIT dans le code de production
- Les assertions de comptage dans les tests du registre DOIVENT etre
  mises a jour quand on ajoute/supprime des tools
- `pretty_assertions` pour des diffs lisibles

**Rationale** : 338 tools x 13 protocoles = surface d'erreur massive.
La couverture de test est le seul filet de securite viable.

### V. Securite Zero-Trust

- `#![forbid(unsafe_code)]` — aucun code unsafe dans le projet
- Les credentials (`password`, `passphrase`) DOIVENT utiliser `Zeroizing<String>`
- Les commandes DOIVENT passer par `CommandValidator` et `Sanitizer`
- `cargo-deny` pour les advisories de securite et les licences
- Les connexions TLS utilisent `rustls` (pas d'OpenSSL sauf CredSSP opt-in)

**Rationale** : Le bridge est un point de passage pour des commandes
sur des serveurs critiques. Toute faille est amplifiee par le nombre
d'hotes connectes.

### VI. Simplicite et YAGNI

- Pas de sur-ingenierie : seuls les changements directement necessaires
- Pas d'abstractions prematurees
- Le pattern matching DOIT etre exhaustif (pas de `_` catch-all sur les enums importants)
- La complexite ajoutee DOIT etre justifiee dans le Complexity Tracking
- Pas de duplication de fonctionnalites entre protocoles

**Rationale** : 338 tools dans 74 groupes — la complexite existante
est deja haute. Chaque ajout doit etre chirurgical.

## Contraintes Techniques

- **Langage** : Rust, edition 2024, MSRV 1.94
- **Runtime async** : `tokio` (full features)
- **CLI** : `clap` 4 (derive API, feature-gated)
- **SSH** : `russh` 0.58 + `russh-sftp` 2.1
- **Serialisation** : `serde` + `serde_json` + `serde-saphyr` (YAML)
- **Securite** : `secrecy`/`zeroize` pour les credentials, `rustls` pour TLS
- **Logging** : `tracing` (logs structures)
- **Ligne max** : 100 caracteres (rustfmt)
- **Clippy** : `-D warnings` sur tous les groupes de lint
- **WSL Safety** : pas de `-j 4+` sur cargo test, pas de mutants full-crate

## Processus de Developpement

- `cargo fmt --check` DOIT passer avant tout commit
- `cargo clippy` DOIT produire 0 warning
- `cargo test` DOIT passer (6300+ tests) avant toute merge
- Les revues de code DOIVENT verifier la conformite hexagonale
- Toute nouvelle feature suit le cycle : port -> adapter -> handler -> tests
- Les tests de comptage du registre DOIVENT refleter le nombre exact de tools

## Governance

Cette constitution est le document de reference pour toutes les
decisions de developpement sur bridge-mcp.

**Version**: 1.0.0 | **Ratified**: 2026-04-12 | **Last Amended**: 2026-04-12
