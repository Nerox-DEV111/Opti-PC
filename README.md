# ⚡ Opti-PC

Outil d'optimisation Windows 10 / 11 en un seul fichier `.exe` (aucune installation).

## Utilisation

1. Téléchargez **[`dist/Opti-PC.exe`](dist/Opti-PC.exe)**.
2. Double-cliquez dessus → acceptez la demande administrateur (UAC).
   - Si Windows SmartScreen affiche « Windows a protégé votre ordinateur » : **Informations complémentaires → Exécuter quand même** (l'exécutable n'est pas signé numériquement).
3. Tapez **`D`** pour un diagnostic, puis **`A`** pour tout optimiser (ou le numéro d'un module).
4. Redémarrez le PC à la fin.

## Ce que fait chaque module

| # | Module | Détails | Réversible |
|---|--------|---------|-----------|
| **D** | **Diagnostic** | Détecte les vrais goulots d'étranglement : Windows sur disque dur, RAM insuffisante, une seule barrette (pas de double canal), XMP/EXPO désactivé, pilote graphique ancien, disque plein, trop de programmes au démarrage, PC jamais redémarré – avec un conseil pour chaque point | – |
| **S** | **Analyse de sécurité** | Voir la section ci-dessous | – |
| 1 | Point de restauration | Créé automatiquement avant « Tout optimiser » | – |
| 2 | Nettoyage en profondeur | %TEMP%, Windows\Temp, cache Windows Update, rapports d'erreurs, crash dumps, caches de shaders (DirectX/NVIDIA/AMD/Intel), caches navigateurs (Chrome, Edge, Brave, Opera, Firefox), Discord, miniatures, corbeille. **Historique, mots de passe et cookies ne sont pas touchés.** | Non (fichiers supprimés) |
| 3 | Plan d'alimentation | « Performances optimales » (ou « Performances élevées »), disques jamais en veille, suspension USB désactivée | Oui |
| 4 | Effets visuels | Animations, transparence, ombres, Aero Peek coupés – lissage des polices conservé | Oui |
| 5 | Jeux | Mode Jeu, planification GPU matérielle, priorités CPU/GPU/E-S des jeux, Game DVR désactivé, accélération souris désactivée | Oui |
| 6 | Réseau | Vidage DNS, suppression de la limitation réseau, Nagle désactivé (ping), TCP autotuning + RSS | Oui |
| 7 | Confidentialité / arrière-plan | Télémétrie, ID publicitaire, suggestions & pubs, recherche Bing, préchargement d'Edge, services (DiagTrack, WAP Push, RetailDemo, Maps, Fax) et tâches de collecte de données | Oui |
| 8 | Réactivité | Menus instantanés, priorité au premier plan, pas de délai au démarrage, arrêt plus rapide | Oui |
| 9 | Disques | `defrag /O` : TRIM pour SSD, défragmentation pour HDD | – |
| 10 | Hibernation | Supprime `hiberfil.sys` (plusieurs Go). Ignoré sur PC portable en mode « Tout » | Oui |
| 11 | Réparer Windows | DISM RestoreHealth + SFC + nettoyage des composants (manuel, 15-45 min) | – |
| 12 | Démarrage | Liste les programmes lancés au démarrage et ouvre le Gestionnaire des tâches | – |
| 13 | Mettre à jour les applications | `winget upgrade --all` : met à jour tous les logiciels installés (après confirmation) | – |
| 14 | Supprimer les applis inutiles | Candy Crush, Disney+, Clipchamp, Actualités, Météo, Solitaire, Cortana… Liste affichée avant confirmation, réinstallables via le Store | Via le Store |
| **A** | **Tout optimiser** | Point de restauration puis modules 2 à 10 | |
| **R** | **Restaurer** | Remet tous les réglages modifiés à leurs valeurs Windows par défaut | |

## 🛡️ Analyse de sécurité (S)

Deux modes : **rapide** (5-15 min) ou **complète** (1-3 h, Defender vérifie *tous* les fichiers de tous les disques).

| Contrôle | Ce qui est détecté |
|----------|--------------------|
| **Microsoft Defender** | Mise à jour des signatures puis analyse rapide/complète ; protection en temps réel désactivée ; **exclusions ajoutées par un malware** (disque entier, `.exe`, dossiers AppData...) ; menaces trouvées |
| **Démarrage automatique (backdoors)** | Clés Run/RunOnce, dossiers Démarrage, tâches planifiées, services, détournement de Winlogon, *Image File Execution Options*, AppInit_DLLs, abonnements WMI, remplacement de sethc/utilman (porte dérobée de l'écran de connexion). Chaque programme est vérifié : signature numérique, emplacement, PowerShell caché/encodé, faux noms système (`svchost.exe` hors de System32), double extension (`.pdf.exe`) |
| **Voleurs de jetons (token grabbers)** | Injection dans Discord (`discord_desktop_core\index.js`) avec **réparation proposée** ; fichiers contenant des webhooks Discord, bots Telegram ou du code de vol de jetons/mots de passe dans AppData, Temp, Téléchargements |
| **Processus et réseau** | Programmes non signés lancés depuis AppData/Temp qui communiquent sur Internet ou écoutent un port (RAT) ; faux processus système |
| **Détournement réseau** | Fichier `hosts` bloquant les sites d'antivirus, proxy imposé |

À la fin : résumé, **deuxième vérification par Defender** des fichiers suspects, conseils si une menace est trouvée
(changement des mots de passe depuis un autre appareil, **Defender hors ligne**), et rapport `.txt` enregistré sur le Bureau.

> ⚠️ Aucun outil ne peut garantir à 100 % l'absence de malware. Un « suspect » n'est pas forcément dangereux :
> en cas de doute, envoyez le fichier sur [virustotal.com](https://www.virustotal.com). L'analyse ne supprime
> jamais de fichier d'elle-même (seule la réparation de Discord est proposée, avec sauvegarde).

### Ce qu'Opti-PC ne fait volontairement PAS
Désactiver Windows Defender, le pare-feu ou Windows Update, supprimer des applications système, modifier le BCD
ou le fichier d'échange : ces « optimisations » rendent le PC moins sûr ou instable pour un gain nul ou négligeable.

### Effets secondaires à connaître
- Edge peut afficher « Géré par votre organisation » (stratégies de préchargement/arrière-plan). Annulable avec **R**.
- Le Game DVR désactivé coupe l'enregistrement vidéo de la Xbox Game Bar.
- L'accélération de la souris est désactivée (préféré pour les jeux) : le curseur peut sembler un peu différent.

## Compiler soi-même

```bash
go install github.com/tc-hib/go-winres@latest
./build.sh            # -> dist/Opti-PC.exe
```

Le code est en Go (`main.go`, `tweaks.go`, `extras.go`, `scan*.go`, `system.go`, `ui.go`) et se compile depuis Linux, macOS ou Windows.
L'icône est générée par `go run tools/genicon/main.go`.
