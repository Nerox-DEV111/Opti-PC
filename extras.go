package main

// Diagnostic du PC, mises à jour des applications, suppression des applis préinstallées.

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ================================================================ D. Diagnostic

// Script PowerShell (guillemets simples uniquement) qui renvoie des lignes CLE=VALEUR.
const diagScript = `$ProgressPreference='SilentlyContinue'; ` +
	`try { $n=(Get-Partition -DriveLetter $env:SystemDrive.Substring(0,1) -ErrorAction Stop | Get-Disk).Number; ` +
	`$d=Get-PhysicalDisk | Where-Object { $_.DeviceId -eq [string]$n } | Select-Object -First 1; ` +
	`'MEDIA=' + $d.MediaType; 'BUS=' + $d.BusType; 'DISKNAME=' + $d.FriendlyName } catch {}; ` +
	`try { $m=@(Get-CimInstance Win32_PhysicalMemory); 'RAMSTICKS=' + $m.Count; ` +
	`'RAMCONF=' + $m[0].ConfiguredClockSpeed; 'RAMSPEED=' + $m[0].Speed; 'RAMTYPE=' + $m[0].SMBIOSMemoryType } catch {}; ` +
	`try { $o=Get-CimInstance Win32_OperatingSystem; 'UPTIMEH=' + [int]((Get-Date) - $o.LastBootUpTime).TotalHours } catch {}; ` +
	`try { $g=Get-CimInstance Win32_VideoController | Where-Object { $_.Name -notmatch 'Microsoft|Virtual|Parsec|Remote' } | ` +
	`Sort-Object AdapterRAM -Descending | Select-Object -First 1; 'GPU=' + $g.Name; 'GPUDATE=' + $g.DriverDate.ToString('yyyy-MM-dd') } catch {}`

func diagnostic() {
	section("Diagnostic du PC")
	info("Analyse en cours...")
	out, _ := powershell(diagScript)
	d := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, found := strings.Cut(strings.TrimSpace(l), "="); found {
			d[k] = strings.TrimSpace(v)
		}
	}
	atoi := func(k string) int { n, _ := strconv.Atoi(d[k]); return n }
	laptop := hasBattery()
	fmt.Println()

	// --- Disque système
	switch {
	case strings.EqualFold(d["BUS"], "NVMe"):
		ok("Windows est sur un SSD NVMe (le plus rapide) : %s", d["DISKNAME"])
	case strings.EqualFold(d["MEDIA"], "SSD"):
		ok("Windows est sur un SSD : %s", d["DISKNAME"])
	case strings.EqualFold(d["MEDIA"], "HDD"):
		warn("Windows est sur un DISQUE DUR (%s).", d["DISKNAME"])
		fmt.Println(col(cYellow, "       -> Passer à un SSD est LA meilleure amélioration possible : démarrage 5x plus rapide."))
	default:
		info("Type du disque système non déterminé.")
	}

	// --- Espace disque
	if free, size := diskFree(systemDrive()); size > 0 {
		pct := float64(free) * 100 / float64(size)
		if pct < 15 {
			warn("Disque %s presque plein : %s libres (%.0f %%).", systemDrive(), humanSize(int64(free)), pct)
			fmt.Println(col(cYellow, "       -> Gardez au moins 15 % libre (module 2, désinstallez des jeux/logiciels inutilisés)."))
		} else {
			ok("Espace disque suffisant : %s libres (%.0f %%)", humanSize(int64(free)), pct)
		}
	}

	// --- Quantité de RAM
	total, _, load := memory()
	gb := int((total + (1 << 29)) >> 30)
	switch {
	case gb == 0:
	case gb < 8:
		warn("Seulement %d Go de RAM.", gb)
		fmt.Println(col(cYellow, "       -> 16 Go sont recommandés : c'est une amélioration très efficace et peu chère."))
	case gb < 16:
		info("%d Go de RAM : suffisant pour la bureautique, 16 Go conseillés pour les jeux récents.", gb)
	default:
		ok("%d Go de RAM", gb)
	}
	if load >= 85 {
		warn("Mémoire utilisée à %d %% en ce moment : fermez des programmes inutiles.", load)
	}

	// --- Double canal
	if n := atoi("RAMSTICKS"); n == 1 && !laptop {
		warn("Une seule barrette de RAM détectée.")
		fmt.Println(col(cYellow, "       -> Avec 2 barrettes identiques (double canal), gain jusqu'à +20 % en jeu."))
	} else if n >= 2 {
		ok("%d barrettes de RAM (double canal possible)", n)
	}

	// --- Fréquence RAM / XMP-EXPO (PC fixes uniquement)
	conf, rated, typ := atoi("RAMCONF"), atoi("RAMSPEED"), atoi("RAMTYPE")
	if conf > 0 && !laptop {
		xmpOff := rated > conf+100 ||
			(typ == 26 && conf <= 2400) || // DDR4
			(typ == 34 && conf <= 4800) // DDR5
		if xmpOff {
			warn("RAM à %d MT/s : le profil XMP / EXPO est probablement désactivé.", conf)
			fmt.Println(col(cYellow, "       -> Activez XMP (Intel) ou EXPO (AMD) dans le BIOS : gain gratuit de 5 à 15 % en jeu."))
		} else {
			ok("RAM à %d MT/s", conf)
		}
	}

	// --- Pilote graphique
	if gpu := d["GPU"]; gpu != "" {
		if t, err := time.Parse("2006-01-02", d["GPUDATE"]); err == nil {
			age := int(time.Since(t).Hours() / 24)
			if age > 180 {
				warn("Pilote graphique de %s daté de %d mois.", gpu, age/30)
				fmt.Println(col(cYellow, "       -> Mettez-le à jour : NVIDIA App, AMD Adrenalin ou Intel Driver Assistant."))
			} else {
				ok("Pilote graphique récent : %s", gpu)
			}
		}
	}

	// --- Temps depuis le dernier redémarrage
	if h := atoi("UPTIMEH"); h > 72 {
		warn("PC non redémarré depuis %d jours.", h/24)
		fmt.Println(col(cYellow, "       -> Redémarrez (Arrêter ne vide pas la mémoire à cause du démarrage rapide)."))
	} else if d["UPTIMEH"] != "" {
		ok("Redémarré récemment (%d h)", h)
	}

	// --- Programmes au démarrage
	if n := len(startupEntries()); n > 10 {
		warn("%d programmes se lancent au démarrage.", n)
		fmt.Println(col(cYellow, "       -> Désactivez ceux qui sont inutiles (module 12)."))
	} else {
		ok("%d programme(s) au démarrage", n)
	}

	// --- Plan d'alimentation
	if out, err := runQuiet("powercfg", "/getactivescheme"); err == nil {
		o := strings.ToLower(out)
		if strings.Contains(o, guidOptiPC) || strings.Contains(o, guidHigh) {
			ok("Plan d'alimentation hautes performances actif")
		} else {
			warn("Plan d'alimentation non optimisé -> module 3.")
		}
	}

	fmt.Println()
	if nWarn == 0 {
		fmt.Println(col(cGreen+cBold, "  Aucun point faible détecté. Votre PC est en bonne forme !"))
	} else {
		fmt.Println(col(cYellow+cBold, fmt.Sprintf("  %d point(s) à améliorer : suivez les conseils ci-dessus.", nWarn)))
	}
}

// ================================================================ 13. Mises à jour

func updateApps() {
	section("Mise à jour des applications")
	if _, err := exec.LookPath("winget"); err != nil {
		fail("winget introuvable : installez « Programme d'installation d'application » depuis le Microsoft Store.")
		return
	}
	info("Recherche des mises à jour disponibles...\n")
	runLive("winget", "upgrade", "--accept-source-agreements")
	if !confirm("\n  Installer toutes ces mises à jour ?") {
		return
	}
	err := runLive("winget", "upgrade", "--all", "--silent",
		"--accept-source-agreements", "--accept-package-agreements")
	fmt.Println()
	if err != nil {
		warn("Certaines applications n'ont pas pu être mises à jour (souvent car elles sont ouvertes).")
	} else {
		ok("Applications mises à jour")
	}
}

// ================================================================ 14. Applis préinstallées

var bloatware = []struct{ pattern, label string }{
	{"king.com.*", "Candy Crush et autres jeux King"},
	{"Disney.*", "Disney+"},
	{"Clipchamp.Clipchamp", "Clipchamp"},
	{"Microsoft.BingNews", "Actualités"},
	{"Microsoft.BingWeather", "Météo"},
	{"Microsoft.GetHelp", "Obtenir de l'aide"},
	{"Microsoft.Getstarted", "Astuces"},
	{"Microsoft.MicrosoftSolitaireCollection", "Microsoft Solitaire Collection"},
	{"Microsoft.People", "Contacts"},
	{"Microsoft.WindowsFeedbackHub", "Hub de commentaires"},
	{"Microsoft.WindowsMaps", "Cartes"},
	{"Microsoft.ZuneVideo", "Films et TV"},
	{"Microsoft.MicrosoftOfficeHub", "Accueil Microsoft 365 (pas Office lui-même)"},
	{"Microsoft.549981C3F5F10", "Cortana"},
	{"Microsoft.Microsoft3DViewer", "Visionneuse 3D"},
	{"Microsoft.MixedReality.Portal", "Portail de réalité mixte"},
	{"Microsoft.SkypeApp", "Skype"},
	{"Microsoft.PowerAutomateDesktop", "Power Automate"},
	{"MicrosoftCorporationII.MicrosoftFamily", "Microsoft Family"},
}

var safePkgName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func bloatLabel(name string) string {
	for _, b := range bloatware {
		if p, wild := strings.CutSuffix(b.pattern, "*"); (wild && strings.HasPrefix(name, p)) || name == b.pattern {
			return b.label
		}
	}
	return name
}

func removeBloatware() {
	section("Applications préinstallées inutiles")
	patterns := make([]string, len(bloatware))
	for i, b := range bloatware {
		patterns[i] = "'" + b.pattern + "'"
	}
	out, err := powershell(`$p=@(` + strings.Join(patterns, ",") + `); ` +
		`Get-AppxPackage | Where-Object { $n=$_.Name; [bool]($p | Where-Object { $n -like $_ }) } | ForEach-Object { $_.Name }`)
	if err != nil {
		fail("Impossible de lister les applications : %s", lastLine(out))
		return
	}
	var found []string
	seen := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		n := strings.TrimSpace(l)
		if n != "" && safePkgName.MatchString(n) && !seen[n] {
			seen[n] = true
			found = append(found, n)
		}
	}
	if len(found) == 0 {
		ok("Aucune application inutile trouvée : déjà propre !")
		return
	}
	fmt.Println("\n  Applications trouvées :")
	for _, n := range found {
		fmt.Printf("  %s %-40s %s\n", col(cCyan, "•"), bloatLabel(n), col(cDim, n))
	}
	fmt.Println(col(cDim, "\n  Elles restent réinstallables gratuitement depuis le Microsoft Store."))
	if !confirm(fmt.Sprintf("  Supprimer ces %d application(s) ?", len(found))) {
		return
	}
	for _, n := range found {
		_, err := powershell(`Get-AppxPackage -Name '` + n + `' | Remove-AppxPackage -ErrorAction Stop`)
		check("Supprimée : "+bloatLabel(n), err)
	}
}
