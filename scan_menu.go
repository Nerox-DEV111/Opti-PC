package main

// Module « S » : analyse de sécurité complète. Orchestre les contrôles de
// scan_persistence.go, scan_stealer.go et scan_defender.go, puis affiche
// un résumé, propose des actions et enregistre un rapport sur le Bureau.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func securityScan() {
	section("Analyse de sécurité")
	fmt.Println("  Recherche : chevaux de Troie, backdoors, voleurs de jetons (Discord, navigateurs),")
	fmt.Println("  programmes malveillants au démarrage, connexions suspectes, antivirus désactivé.")
	fmt.Println()
	fmt.Printf("  %s Analyse rapide   %s\n", col(cCyan+cBold, "[1]"), col(cDim, "(5 à 15 min) contrôles ciblés + analyse rapide Defender"))
	fmt.Printf("  %s Analyse complète %s\n", col(cCyan+cBold, "[2]"), col(cDim, "(1 à 3 h) idem + Defender vérifie TOUS les fichiers de tous les disques"))
	fmt.Printf("  %s Retour\n", col(cCyan+cBold, "[0]"))

	var full bool
	switch readLine(col(cBold, "\n  Votre choix : ")) {
	case "1":
		full = false
	case "2":
		full = true
	default:
		return
	}

	findings = nil
	start := time.Now()
	scanPersistence()
	scanStealers()
	scanDefender(full)
	securitySummary(full, time.Since(start))
}

func countSev(sev severity) int {
	n := 0
	for _, f := range findings {
		if f.sev == sev {
			n++
		}
	}
	return n
}

func securitySummary(full bool, d time.Duration) {
	dangers, suspects := countSev(sevDanger), countSev(sevSuspect)

	fmt.Println()
	fmt.Println(col(cBold, "  ══════════════ RÉSULTAT DE L'ANALYSE ══════════════"))
	fmt.Printf("  Durée : %s\n\n", d.Round(time.Second))

	switch {
	case dangers == 0 && suspects == 0:
		fmt.Println(col(cGreen+cBold, "  Aucune menace détectée. Votre PC semble sain."))
	case dangers == 0:
		fmt.Println(col(cYellow+cBold, fmt.Sprintf("  Aucune menace confirmée, mais %d élément(s) à vérifier.", suspects)))
	default:
		fmt.Println(col(cRed+cBold, fmt.Sprintf("  %d MENACE(S) PROBABLE(S) et %d élément(s) suspect(s) !", dangers, suspects)))
	}

	for _, sev := range []severity{sevDanger, sevSuspect} {
		for _, f := range findings {
			if f.sev != sev {
				continue
			}
			tag := col(cYellow, "SUSPECT")
			if sev == sevDanger {
				tag = col(cRed+cBold, "DANGER ")
			}
			fmt.Printf("  %s [%s] %s\n", tag, f.category, f.title)
			if f.path != "" {
				fmt.Println("          " + col(cDim, f.path))
			}
		}
	}

	if dangers+suspects > 0 {
		offerDefenderRecheck()
	}
	if dangers > 0 {
		infectionAdvice()
	} else if suspects > 0 {
		fmt.Println()
		fmt.Println(col(cDim, "  Un élément « suspect » n'est pas forcément dangereux (ex. petit logiciel non signé)."))
		fmt.Println(col(cDim, "  Si vous ne reconnaissez pas un programme, recherchez son nom sur Internet ou"))
		fmt.Println(col(cDim, "  envoyez le fichier sur virustotal.com pour un deuxième avis."))
	}
	if !full && dangers > 0 {
		fmt.Println(col(cYellow, "\n  Conseil : lancez aussi l'analyse COMPLÈTE [2] pour vérifier tous les fichiers."))
	}
	saveSecurityReport(full, d)
}

// offerDefenderRecheck propose de faire analyser par Defender chaque fichier
// signalé par les contrôles maison (deuxième avis sur des signatures réelles).
func offerDefenderRecheck() {
	var paths []string
	seen := map[string]bool{}
	for _, f := range findings {
		if f.path == "" || f.category == "Antivirus" || (f.sev != sevDanger && f.sev != sevSuspect) {
			continue
		}
		key := strings.ToLower(f.path)
		if seen[key] {
			continue
		}
		if st, err := os.Stat(f.path); err != nil || st.IsDir() {
			continue
		}
		seen[key] = true
		paths = append(paths, f.path)
	}
	if len(paths) == 0 {
		return
	}
	fmt.Println()
	if !confirm(fmt.Sprintf("  Faire vérifier ces %d fichier(s) par Microsoft Defender ?", len(paths))) {
		return
	}
	for _, p := range paths {
		clean, threat, err := defenderScanFile(p)
		name := filepath.Base(p)
		switch {
		case err != nil:
			fmt.Printf("  %s %s : %v\n", col(cYellow, "[??]"), name, err)
		case clean:
			fmt.Printf("  %s %s : rien de connu par Defender\n", col(cGreen, "[OK]"), name)
		default:
			fmt.Printf("  %s %s : %s\n", col(cRed+cBold, "[VIRUS]"), name, col(cRed+cBold, threat))
			findings = append(findings, finding{sevDanger, "Antivirus", "Confirmé par Defender : " + threat, "", p})
		}
	}
	fmt.Println(col(cDim, "  « Rien de connu » ne garantit pas l'innocence : un voleur de jetons récent"))
	fmt.Println(col(cDim, "  peut être inconnu des antivirus pendant quelques jours."))
}

func infectionAdvice() {
	fmt.Println()
	fmt.Println(col(cRed+cBold, "  QUE FAIRE MAINTENANT ?"))
	steps := []string{
		"Depuis un AUTRE appareil (téléphone) : changez votre mot de passe Discord – cela",
		"   déconnecte immédiatement les jetons volés – et activez l'authentification à 2 facteurs.",
		"Changez aussi les mots de passe enregistrés dans vos navigateurs (e-mail en premier,",
		"   puis banque, Steam, Epic, réseaux sociaux) et déconnectez les autres sessions.",
		"Ne vous connectez à aucun compte sur ce PC tant qu'il n'est pas nettoyé.",
		"Lancez « Microsoft Defender hors ligne » (proposé ci-dessous) : il analyse le PC avant",
		"   le démarrage de Windows, là où les malwares ne peuvent pas se cacher.",
		"Deuxième avis gratuit : Malwarebytes Free ou ESET Online Scanner.",
		"Si la menace revient malgré tout : sauvegardez vos fichiers et réinstallez Windows.",
	}
	n := 0
	for _, s := range steps {
		if strings.HasPrefix(s, "   ") {
			fmt.Println("     " + s[3:])
			continue
		}
		n++
		fmt.Printf("  %d. %s\n", n, s)
	}
	fmt.Println()
	if confirm("  Lancer Microsoft Defender hors ligne maintenant ? (le PC va redémarrer, ~15 min)") {
		if _, err := powershell("Start-MpWDOScan"); err != nil {
			fmt.Println(col(cRed, "  Impossible de lancer Defender hors ligne (un autre antivirus est peut-être actif)."))
		}
	}
}

// desktopDir renvoie le vrai dossier Bureau (gère la redirection OneDrive).
func desktopDir() string {
	if d := regString(HKCU, `Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`, "Desktop"); d != "" {
		if d = expandWinEnv(d); d != "" {
			if st, err := os.Stat(d); err == nil && st.IsDir() {
				return d
			}
		}
	}
	return filepath.Join(os.Getenv("USERPROFILE"), "Desktop")
}

func saveSecurityReport(full bool, d time.Duration) {
	var b strings.Builder
	mode := "rapide"
	if full {
		mode = "complète"
	}
	fmt.Fprintf(&b, "Opti-PC %s - Rapport d'analyse de sécurité\r\n", version)
	fmt.Fprintf(&b, "Date : %s - Analyse %s - Durée : %s\r\n", time.Now().Format("02/01/2006 15:04"), mode, d.Round(time.Second))
	fmt.Fprintf(&b, "Système : %s\r\n\r\n", windowsVersion())
	fmt.Fprintf(&b, "Menaces probables : %d - Éléments suspects : %d\r\n\r\n", countSev(sevDanger), countSev(sevSuspect))
	labels := map[severity]string{sevDanger: "DANGER ", sevSuspect: "SUSPECT", sevInfo: "INFO   ", sevOK: "OK     "}
	for _, sev := range []severity{sevDanger, sevSuspect, sevInfo, sevOK} {
		for _, f := range findings {
			if f.sev != sev {
				continue
			}
			fmt.Fprintf(&b, "[%s] [%s] %s\r\n", labels[sev], f.category, f.title)
			if f.detail != "" {
				fmt.Fprintf(&b, "          %s\r\n", f.detail)
			}
			if f.path != "" {
				fmt.Fprintf(&b, "          Fichier : %s\r\n", f.path)
			}
		}
	}
	name := "Opti-PC_securite_" + time.Now().Format("2006-01-02_15h04") + ".txt"
	path := filepath.Join(desktopDir(), name)
	// BOM UTF-8 pour que le Bloc-notes affiche correctement les accents.
	if err := os.WriteFile(path, append([]byte{0xEF, 0xBB, 0xBF}, []byte(b.String())...), 0o644); err == nil {
		fmt.Println()
		fmt.Println(col(cBlue, "  Rapport enregistré sur le Bureau : ") + name)
	}
}
