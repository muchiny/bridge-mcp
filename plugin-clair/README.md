# mode-clair

Un seul endroit à regarder pendant que Claude travaille : ce qu'il fait, sur
quelle machine, pourquoi, si tu dois agir, et la suite. Le plugin suit les
sessions **Superpowers**, les workflows **ultracode** et les appels à
**bridge-mcp**, et les montre sous forme de pipeline coloré.

Il ne fait qu'observer. Il ne bloque, ne réécrit et ne lance rien. Il n'ouvre
aucune connexion réseau et n'appelle pas le modèle.

## Installation

Dans une session Claude Code, dans un terminal :

```text
/plugin install mode-clair --marketplace muchiny/bridge-mcp
```

Réponds `y` pour ajouter la marketplace, puis choisis la portée. Il faut
Claude Code 2.1.296 ou plus récent : les mods sont encore en accès anticipé.

Pour l'essayer depuis ce dépôt sans l'installer :

```text
claude --plugin-dir ./plugin-clair
```

## Ce que tu vois

### La bande au-dessus de la saisie

Elle n'apparaît que lorsqu'il se passe quelque chose, et se replie avec `[-]`.

```text
plan « Ajouter l'export CSV »   ✓ cadrage ── ✓ spec ── ✓ plan ── ● tâches 3 sur 7 ── ○ relecture finale ── ○ fin
tâche 3 « Écrire le fichier CSV » : ● coder (test d'abord) → ○ relire → ○ corriger si besoin    pour toi : rien à faire
```

Pendant un workflow ultracode, les phases du script deviennent le pipeline,
avec les agents en cours de la phase active. Quand un formulaire du bridge
attend ta réponse, la droite de la bande passe en jaune :
`⚠ à toi : réponds au formulaire (web-02)`.

### Sous chaque appel au bridge

La rangée du résultat commence par la machine, ce qui s'est passé, et le
parcours de l'appel dans le bridge. La sortie habituelle reste dessous.

```text
✗ ● web-02 · refusé · Command denied: blacklist
✓ permission ── ○ accord ── ✓ validation ── ✗ liste noire ── ○ web-02 ── ✓ réponse
Rien n'est parti vers web-02.
```

### Le panneau `/clair`

Tape `/clair`. En plein écran, à partir de 110 colonnes, le panneau s'ancre à
droite de la conversation, sinon il s'ouvre au-dessus de la saisie. Il montre :

- le plan ou le workflow en cours, en pipeline vertical ;
- les machines touchées ;
- le pipeline du dernier appel de la machine choisie (Tab, puis Entrée) ;
- ce qui est à regarder : refus, machines injoignables, échecs, sorties tronquées.

### La ligne d'état

Une seule entrée courte, par exemple `clair · tâche 3 sur 7 · rien pour toi`
ou `clair · ⚠ web-02 attend ton accord`.

## Les signes

| Signe | Couleur | Sens |
| --- | --- | --- |
| `✓` | vert | fait |
| `●` | accent de Claude Code, ou la couleur de la machine | en cours, ou exécuté sur cette machine |
| `○` | gris | à venir, ou pas nécessaire |
| `⚠` | jaune | à toi : ta réponse est attendue |
| `✗` | rouge | problème : refusé, injoignable, échec ou tronqué |
| `✎` | gras | modifié : l'appel a pu changer la machine |

Les couleurs viennent du thème de Claude Code. Chaque machine a une couleur
fixe, tirée de son nom, dans une palette lisible par les personnes daltoniennes
rouge-vert. Le nom de la machine est toujours écrit à côté.

## D'où viennent les informations

| Ce qui est montré | Source |
| --- | --- |
| étape Superpowers | les skills appelés (`superpowers:brainstorming`, `writing-plans`, `subagent-driven-development`…), et l'écriture des fichiers `docs/superpowers/specs/` et `docs/superpowers/plans/` |
| tâches du plan | les titres `### Task N: …` du fichier de plan |
| tâche en cours, coder ou relire | la description des appels `Agent` (`Task 3`, `Review`) |
| phases d'un workflow | le bloc `meta` du script, puis le journal du run |
| appels au bridge | les outils MCP dont le nom de serveur contient `bridge`, et les commandes `bridge-mcp tool …` lancées dans Bash |
| résultat d'un appel | le texte de la réponse du bridge (`Command denied`, `[exit:N]`, `SSH connection failed`…) |
| « à toi » | le formulaire de confirmation que le bridge ouvre (hook `Elicitation`) |

## Limites connues

- **Ordre du parcours.** Il suit le bridge tel qu'il est aujourd'hui : la
  confirmation est demandée avant la liste noire. Tu peux donc confirmer une
  commande que la liste noire refusera ensuite. C'est un défaut connu du
  bridge (voir `CLAUDE.md`), pas du plugin.
- **Le formulaire ne dit pas de quel appel il s'agit.** Le plugin l'attribue à
  l'appel MCP du bridge le plus récent encore en cours. Avec plusieurs appels
  destructifs en même temps, il peut se tromper de machine.
- **Le journal d'un workflow n'est pas documenté par Claude Code.** S'il change
  de format, les phases restent affichées sans avancer, mais le plugin n'invente
  rien.
- **Superpowers est reconnu à ses noms.** Un plan sans titres `### Task N`, ou
  des agents dont la description ne nomme pas la tâche, laissent la bande à
  « tâches » sans numéro.
- **Lecture ou modification.** En MCP, c'est l'annotation du bridge qui le dit.
  En CLI, c'est le nom de l'outil qui décide. Une commande libre (`ssh_exec`)
  compte toujours comme « modifié ».
- **Couleur par machine, pas par tag.** Le plugin ne lit pas ta configuration.
- **Surfaces.** La bande et les rangées se dessinent dans le terminal, dans
  l'app de bureau et dans VS Code. Le panneau ancré demande le plein écran.
  Rien ne se dessine avec `claude -p`.

## Développement

```text
claude plugin validate plugin-clair
claude plugin test plugin-clair
```

La logique est dans `hooks/model.ts`, sans `$` ni horloge, ce qui la rend
testable seule (`tests/model.test.ts`). L'affichage est dans
`hooks/register.tsx`, testé sur les surfaces `terminal` et `desktop`
(`tests/ui.test.tsx`). Le contrat d'état est dans `types/index.d.ts`.
