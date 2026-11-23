// Opti-PC : outil d'optimisation Windows en console.
//
// Compilation (depuis n'importe quel OS) : voir build.sh / README.md
package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const version = "1.1.0"

const banner = `
   ____         __  _        ____   ______
  / __ \ ____  / /_(_)      / __ \ / ____/
 / / / // __ \/ __/ /______/ /_/ // /
/ /_/ // /_/ / /_/ /______/ ____// /___
\____// .___/\__/_/      /_/     \____/
     /_/                                   `

func main() {
	setupConsole()

	if !isAdmin() {
		fmt.Println("Opti-PC a besoin des droits administrateur. Relance en cours...")
		if err := relaunchAsAdmin(); err != nil {
			fmt.Println("\nImpossible d'obtenir les droits administrateur :", err)
			fmt.Println("Faites un clic droit sur Opti-PC.exe > « Exécuter en tant qu'administrateur ».")
			pause()
		}
		return
	}

	for {
		showHeader()
		showMenu()
		choice := strings.ToUpper(readLine(col(cBold, "\n  Votre choix : ")))

		switch choice {
		case "Q", "0":
			return
		case "A":
			optimizeAll()
		case "R":
			restoreAll()
		default:
			m := findModule(choice)
			if m == nil {
				continue
			}
			resetCounters()
			m.apply()
			summary()
		}
		pause()
	}
}

func findModule(key string) *module {
	for i := range modules {
		if modules[i].key == key {
			return &modules[i]
		}
	}
	return nil
}

func showHeader() {
	clearScreen()
	fmt.Println(col(cCyan+cBold, banner))
	fmt.Println(col(cDim, "        Optimiseur Windows - version "+version))
	fmt.Println()

	total, avail, load := memory()
	free, size := diskFree(systemDrive())
	fmt.Printf("  %s %s\n", col(cBlue, "Système :"), windowsVersion())
	if c := cpuName(); c != "" {
		fmt.Printf("  %s %s\n", col(cBlue, "Processeur :"), c)
	}
	if total > 0 {
		fmt.Printf("  %s %s utilisés sur %s (%d %%)\n", col(cBlue, "Mémoire :"),
			humanSize(int64(total-avail)), humanSize(int64(total)), load)
	}
	if size > 0 {
		fmt.Printf("  %s %s libres sur %s\n", col(cBlue, "Disque "+systemDrive()+" :"),
			humanSize(int64(free)), humanSize(int64(size)))
	}
}

func showMenu() {
	fmt.Println()
	fmt.Println(col(cBold, "  ─────────────────────────── MENU ───────────────────────────"))
	for _, m := range modules {
		fmt.Printf("  %s %-32s %s\n", col(cCyan+cBold, fmt.Sprintf("[%2s]", m.key)), m.title, col(cDim, m.desc))
	}
	fmt.Println()
	fmt.Printf("  %s %s\n", col(cGreen+cBold, "[ A]"), col(cGreen+cBold, "TOUT OPTIMISER (recommandé : point de restauration + 2 à 10)"))
	fmt.Printf("  %s %s\n", col(cYellow+cBold, "[ R]"), "Restaurer les paramètres Windows par défaut")
	fmt.Printf("  %s %s\n", col(cRed+cBold, "[ Q]"), "Quitter")
}

func summary() {
	fmt.Printf("\n  Résultat : %s, %s, %s\n",
		col(cGreen, fmt.Sprintf("%d réussi(s)", nOK)),
		col(cYellow, fmt.Sprintf("%d avertissement(s)", nWarn)),
		col(cRed, fmt.Sprintf("%d échec(s)", nFail)))
}

func optimizeAll() {
	fmt.Println()
	fmt.Println(col(cBold, "  Cette option va appliquer toutes les optimisations (modules 2 à 10)."))
	fmt.Println(col(cDim, "  Un point de restauration sera créé d'abord. Tout est réversible avec [R]"))
	fmt.Println(col(cDim, "  sauf le nettoyage des fichiers (supprimés définitivement)."))
	if !confirm("\n  Lancer l'optimisation complète ?") {
		return
	}
	start := time.Now()
	resetCounters()

	if !createRestorePoint() {
		if !confirm("  Continuer sans point de restauration ?") {
			return
		}
	}

	laptop := hasBattery()
	for _, m := range modules {
		if !m.inAll {
			continue
		}
		if m.key == "10" && laptop {
			section("Hibernation")
			info("PC portable détecté : hibernation conservée (utile sur batterie).")
			continue
		}
		m.apply()
	}

	fmt.Println()
	fmt.Println(col(cGreen+cBold, "  ══════════ OPTIMISATION TERMINÉE ══════════"))
	fmt.Printf("  Durée : %s\n", time.Since(start).Round(time.Second))
	summary()
	askReboot()
}

func restoreAll() {
	fmt.Println()
	fmt.Println(col(cBold, "  Remet les réglages modifiés par Opti-PC à leurs valeurs Windows par défaut."))
	fmt.Println(col(cDim, "  (Pour un retour complet, vous pouvez aussi utiliser le point de restauration"))
	fmt.Println(col(cDim, "   via « rstrui.exe ».)"))
	if !confirm("\n  Restaurer les paramètres par défaut ?") {
		return
	}
	resetCounters()
	for _, m := range modules {
		if m.restore != nil {
			m.restore()
		}
	}
	summary()
	askReboot()
}

func askReboot() {
	fmt.Println()
	if confirm("  Un redémarrage est nécessaire pour tout appliquer. Redémarrer maintenant ?") {
		fmt.Println("  Redémarrage dans 10 secondes... (annuler : shutdown /a)")
		runQuiet("shutdown", "/r", "/t", "10", "/c", "Redémarrage par Opti-PC")
		os.Exit(0)
	}
}
