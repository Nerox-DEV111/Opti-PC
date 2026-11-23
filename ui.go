package main

// Affichage console : couleurs, messages, saisie utilisateur.

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const (
	cReset  = "\x1b[0m"
	cBold   = "\x1b[1m"
	cDim    = "\x1b[2m"
	cRed    = "\x1b[91m"
	cGreen  = "\x1b[92m"
	cYellow = "\x1b[93m"
	cBlue   = "\x1b[94m"
	cCyan   = "\x1b[96m"
)

var stdin = bufio.NewReader(os.Stdin)

func col(c, s string) string {
	if !useColor {
		return s
	}
	return c + s + cReset
}

func clearScreen() {
	if useColor {
		fmt.Print("\x1b[2J\x1b[3J\x1b[H")
	} else {
		runLive("cmd", "/c", "cls")
	}
}

// Compteurs du module en cours.
var nOK, nWarn, nFail int

func resetCounters() { nOK, nWarn, nFail = 0, 0, 0 }

func section(title string) {
	fmt.Println()
	fmt.Println(col(cBold+cCyan, "=== "+title+" ==="))
}

func ok(format string, a ...interface{}) {
	nOK++
	fmt.Println("  " + col(cGreen, "[OK]") + " " + fmt.Sprintf(format, a...))
}

func warn(format string, a ...interface{}) {
	nWarn++
	fmt.Println("  " + col(cYellow, "[!!]") + " " + fmt.Sprintf(format, a...))
}

func fail(format string, a ...interface{}) {
	nFail++
	fmt.Println("  " + col(cRed, "[XX]") + " " + fmt.Sprintf(format, a...))
}

func info(format string, a ...interface{}) {
	fmt.Println("  " + col(cBlue, "[..]") + " " + fmt.Sprintf(format, a...))
}

// check affiche OK ou ÉCHEC selon err.
func check(label string, err error) {
	if err != nil {
		fail("%s : %v", label, err)
	} else {
		ok("%s", label)
	}
}

func readLine(prompt string) string {
	fmt.Print(prompt)
	s, _ := stdin.ReadString('\n')
	return strings.TrimSpace(s)
}

func confirm(question string) bool {
	r := strings.ToLower(readLine(col(cYellow, question+" (O/N) : ")))
	return r == "o" || r == "oui" || r == "y" || r == "yes"
}

func pause() {
	readLine(col(cDim, "\nAppuyez sur Entrée pour continuer..."))
}
