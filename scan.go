package main

// Base commune de l'analyse de sécurité : format des résultats, vérification
// des signatures numériques, extraction de chemins. Utilisée par
// scan_defender.go, scan_persistence.go et scan_stealer.go.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

type severity int

const (
	sevOK      severity = iota // élément vérifié, sain
	sevInfo                    // information neutre
	sevSuspect                 // suspect : à vérifier par l'utilisateur
	sevDanger                  // menace probable
)

type finding struct {
	sev      severity
	category string // ex. « Defender », « Persistance », « Vol de jetons »
	title    string
	detail   string
	path     string // fichier concerné (vide si aucun)
}

var findings []finding

// report affiche immédiatement un résultat et l'enregistre pour le résumé final.
func report(sev severity, category, title, detail, path string) {
	findings = append(findings, finding{sev, category, title, detail, path})
	switch sev {
	case sevDanger:
		fmt.Println("  " + col(cRed+cBold, "[DANGER]") + " " + col(cRed+cBold, title))
	case sevSuspect:
		fmt.Println("  " + col(cYellow+cBold, "[SUSPECT]") + " " + col(cYellow, title))
	case sevInfo:
		fmt.Println("  " + col(cBlue, "[..]") + " " + title)
	default:
		fmt.Println("  " + col(cGreen, "[OK]") + " " + title)
	}
	if detail != "" {
		fmt.Println("           " + col(cDim, detail))
	}
	if path != "" {
		fmt.Println("           " + col(cDim, "Fichier : "+path))
	}
}

// psQuote entoure une chaîne de guillemets simples PowerShell.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// psLines exécute un script PowerShell et renvoie les lignes non vides de sa sortie.
func psLines(script string) ([]string, error) {
	out, err := powershell("$ProgressPreference='SilentlyContinue'; " + script)
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, err
}

// ---------------------------------------------------------------- Signatures

type sigInfo struct {
	Status string // Valid, NotSigned, HashMismatch, NotTrusted, UnknownError, Missing...
	Signer string // nom de l'éditeur (CN du certificat), vide si non signé
}

func (s sigInfo) valid() bool { return s.Status == "Valid" }

// signatures vérifie la signature Authenticode de plusieurs fichiers en un seul
// appel PowerShell. Les fichiers absents ont le statut « Missing ».
func signatures(paths []string) map[string]sigInfo {
	res := map[string]sigInfo{}
	var todo []string
	seen := map[string]bool{}
	for _, p := range paths {
		if p == "" || seen[strings.ToLower(p)] {
			continue
		}
		seen[strings.ToLower(p)] = true
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			res[p] = sigInfo{Status: "Missing"}
			continue
		}
		todo = append(todo, p)
	}
	if len(todo) == 0 {
		return res
	}
	tmp, err := os.CreateTemp("", "optipc-sig-*.txt")
	if err != nil {
		return res
	}
	defer os.Remove(tmp.Name())
	tmp.WriteString(strings.Join(todo, "\r\n"))
	tmp.Close()

	lines, _ := psLines(`Get-Content -LiteralPath ` + psQuote(tmp.Name()) + ` -Encoding UTF8 | ForEach-Object { $p=$_; ` +
		`try { $s=Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop; $n=''; ` +
		`if ($s.SignerCertificate) { $n=$s.SignerCertificate.Subject }; $s.Status.ToString() + '|' + $n + '|' + $p } ` +
		`catch { 'UnknownError||' + $p } }`)
	for _, l := range lines {
		parts := strings.SplitN(l, "|", 3)
		if len(parts) != 3 {
			continue
		}
		res[parts[2]] = sigInfo{Status: parts[0], Signer: signerName(parts[1])}
	}
	return res
}

// signerName extrait le CN d'un sujet de certificat (« CN=Microsoft Corporation, O=... »).
func signerName(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CN=") {
			return strings.Trim(part[3:], `"`)
		}
	}
	return subject
}

// ---------------------------------------------------------------- Chemins

// expandWinEnv développe les variables %VAR% de Windows.
func expandWinEnv(s string) string {
	if out, err := registry.ExpandString(s); err == nil {
		return out
	}
	return s
}

// exeFromCommand extrait le chemin de l'exécutable d'une ligne de commande
// (clé Run, tâche planifiée, service...). Gère les guillemets, %VAR%,
// \SystemRoot\, \??\ et les chemins relatifs de pilotes.
func exeFromCommand(cmd string) string {
	cmd = strings.TrimSpace(expandWinEnv(cmd))
	if cmd == "" {
		return ""
	}
	var p string
	if strings.HasPrefix(cmd, `"`) {
		if end := strings.Index(cmd[1:], `"`); end >= 0 {
			p = cmd[1 : end+1]
		} else {
			p = strings.Trim(cmd, `"`)
		}
	} else {
		low := strings.ToLower(cmd)
		cut := -1
		for _, ext := range []string{".exe", ".com", ".scr", ".bat", ".cmd", ".sys", ".dll"} {
			if i := strings.Index(low, ext); i >= 0 && (cut < 0 || i < cut) {
				cut = i + len(ext)
			}
		}
		if cut > 0 {
			p = cmd[:cut]
		} else {
			p = strings.Fields(cmd)[0]
		}
	}
	p = strings.TrimPrefix(p, `\??\`)
	sysRoot := os.Getenv("SystemRoot")
	if strings.HasPrefix(strings.ToLower(p), `\systemroot\`) {
		p = sysRoot + p[len(`\systemroot`):]
	} else if strings.HasPrefix(strings.ToLower(p), `system32\`) {
		p = filepath.Join(sysRoot, p)
	}
	// Nom simple sans dossier (ex. « rundll32.exe ») -> System32.
	if !strings.ContainsAny(p, `\/`) {
		cand := filepath.Join(sysRoot, "System32", p)
		if _, err := os.Stat(cand); err == nil {
			p = cand
		}
	}
	return p
}

// isUserWritable indique si un chemin se trouve dans un dossier où n'importe quel
// programme peut écrire sans droits administrateur (emplacement typique des malwares).
func isUserWritable(p string) bool {
	low := strings.ToLower(filepath.Clean(p))
	dirs := []string{
		os.Getenv("APPDATA"), os.Getenv("LOCALAPPDATA"), os.Getenv("TEMP"),
		os.Getenv("USERPROFILE") + `\Downloads`, os.Getenv("USERPROFILE") + `\Desktop`,
		os.Getenv("PUBLIC"), os.Getenv("SystemRoot") + `\Temp`,
	}
	for _, d := range dirs {
		if d == "" || strings.HasPrefix(d, `\`) {
			continue
		}
		if strings.HasPrefix(low, strings.ToLower(filepath.Clean(d))+`\`) {
			return true
		}
	}
	return false
}
