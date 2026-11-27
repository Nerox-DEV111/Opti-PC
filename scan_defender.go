package main

// Contrôle de Microsoft Defender : antivirus tiers, état de la protection,
// exclusions (souvent ajoutées par les malwares), mise à jour des signatures,
// analyse rapide ou complète et historique des menaces détectées.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

const catAV = "Antivirus"

// defenderPath renvoie le chemin de MpCmdRun.exe, ou "" si Defender est introuvable.
func defenderPath() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	p := filepath.Join(pf, "Windows Defender", "MpCmdRun.exe")
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		return p
	}
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	matches, _ := filepath.Glob(filepath.Join(pd, "Microsoft", "Windows Defender", "Platform", "*", "MpCmdRun.exe"))
	var found []string
	for _, m := range matches {
		if st, err := os.Stat(m); err == nil && !st.IsDir() {
			found = append(found, m)
		}
	}
	if len(found) == 0 {
		return ""
	}
	// Dossiers de la forme « 4.18.24090.11-0 » : on garde la version la plus récente.
	sort.Slice(found, func(i, j int) bool {
		return mpVersionLess(filepath.Base(filepath.Dir(found[i])), filepath.Base(filepath.Dir(found[j])))
	})
	return found[len(found)-1]
}

// mpVersionLess compare deux numéros de version « a.b.c.d-e » numériquement.
func mpVersionLess(a, b string) bool {
	split := func(s string) []string {
		return strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' })
	}
	pa, pb := split(a), split(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, ea := strconv.Atoi(pa[i])
		nb, eb := strconv.Atoi(pb[i])
		if ea != nil || eb != nil {
			if pa[i] != pb[i] {
				return pa[i] < pb[i]
			}
			continue
		}
		if na != nb {
			return na < nb
		}
	}
	return len(pa) < len(pb)
}

// ---------------------------------------------------------------- Analyse principale

func scanDefender(full bool) {
	section("Antivirus Microsoft Defender")

	thirdParty := mpThirdPartyAV()
	mp := defenderPath()
	if mp == "" {
		detail := "MpCmdRun.exe est absent : Defender a peut-être été supprimé ou endommagé."
		if len(thirdParty) > 0 {
			detail = "MpCmdRun.exe est absent. Un autre antivirus est installé (" + strings.Join(thirdParty, ", ") + ")."
		}
		report(sevSuspect, catAV, "Defender introuvable", detail, "")
		return
	}

	mpCheckStatus(len(thirdParty) > 0)
	mpCheckPolicies(len(thirdParty) > 0)
	mpCheckExclusions()
	mpUpdateSignatures(mp)

	start := time.Now()
	code := mpRunScan(mp, full, len(thirdParty) > 0)
	mpListThreats(start, code == 2)
}

// mpThirdPartyAV renvoie les antivirus tiers enregistrés dans le Centre de sécurité.
func mpThirdPartyAV() []string {
	lines, _ := psLines(`try { Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ` +
		`ForEach-Object { 'AV|' + [string]$_.productState + '|' + $_.displayName } } catch { 'ERR|' + $_.Exception.Message }`)
	var names []string
	seen := map[string]bool{}
	for _, l := range lines {
		parts := strings.SplitN(l, "|", 3)
		if len(parts) != 3 || parts[0] != "AV" {
			continue
		}
		name := strings.TrimSpace(parts[2])
		low := strings.ToLower(name)
		// Attention : « Bitdefender » contient « defender ».
		if name == "" || seen[low] || strings.Contains(low, "windows defender") ||
			strings.Contains(low, "microsoft defender") || low == "defender" {
			continue
		}
		seen[low] = true
		state := "état inconnu"
		if st, err := strconv.ParseUint(parts[1], 10, 32); err == nil {
			// productState : le quartet 0xF000 vaut 1 quand l'antivirus est actif.
			if (st>>12)&0xF == 1 {
				state = "actif"
			} else {
				state = "inactif"
			}
		}
		names = append(names, name)
		report(sevInfo, catAV, "Antivirus tiers installé : "+name+" ("+state+")",
			"Defender est alors souvent en mode passif ou désactivé : c'est normal.", "")
	}
	return names
}

// mpCheckStatus contrôle l'état de la protection Defender (Get-MpComputerStatus).
func mpCheckStatus(thirdParty bool) {
	lines, err := psLines(`try { $s=Get-MpComputerStatus -ErrorAction Stop; ` +
		`'AV|' + $s.AntivirusEnabled; 'RTP|' + $s.RealTimeProtectionEnabled; 'AGE|' + $s.AntivirusSignatureAge; ` +
		`'TAMPER|' + $s.IsTamperProtected; 'MODE|' + $s.AMRunningMode; 'VER|' + $s.AntivirusSignatureVersion } ` +
		`catch { 'ERR|' + $_.Exception.Message }`)
	vals := map[string]string{}
	for _, l := range lines {
		if k, v, ok := strings.Cut(l, "|"); ok {
			if _, dup := vals[k]; !dup {
				vals[k] = strings.TrimSpace(v)
			}
		}
	}
	if _, ok := vals["AV"]; !ok {
		msg := vals["ERR"]
		if msg == "" && err != nil {
			msg = err.Error()
		}
		if thirdParty {
			report(sevInfo, catAV, "État de Defender illisible (normal avec un antivirus tiers)", msg, "")
		} else {
			report(sevSuspect, catAV, "État de Defender illisible : le service est peut-être arrêté", msg, "")
		}
		return
	}

	isTrue := func(k string) bool { return strings.EqualFold(vals[k], "True") }
	isFalse := func(k string) bool { return strings.EqualFold(vals[k], "False") }

	mode := vals["MODE"]
	lowMode := strings.ToLower(mode)
	passive := strings.Contains(lowMode, "passive")
	if mode != "" {
		switch {
		case passive:
			report(sevInfo, catAV, "Defender en mode passif ("+mode+")",
				"Un autre antivirus assure la protection en temps réel ; Defender peut quand même analyser.", "")
		case strings.Contains(lowMode, "not running"):
			if thirdParty {
				report(sevInfo, catAV, "Defender n'est pas actif (un autre antivirus le remplace)", "Mode : "+mode, "")
			} else {
				report(sevDanger, catAV, "Defender n'est pas actif et aucun autre antivirus n'est installé",
					"Mode : "+mode+". Les malwares désactivent souvent l'antivirus.", "")
			}
		}
	}

	if isFalse("AV") && !thirdParty && !strings.Contains(lowMode, "not running") {
		report(sevDanger, catAV, "Antivirus Defender désactivé",
			"Aucun autre antivirus n'est installé : le PC n'est pas protégé.", "")
	}

	switch {
	case isTrue("RTP"):
		report(sevOK, catAV, "Protection en temps réel activée", "", "")
	case isFalse("RTP") && thirdParty:
		report(sevInfo, catAV, "Protection en temps réel de Defender désactivée (antivirus tiers présent)", "", "")
	case isFalse("RTP") && passive:
		report(sevInfo, catAV, "Protection en temps réel de Defender inactive (mode passif)", "", "")
	case isFalse("RTP"):
		report(sevDanger, catAV, "Protection en temps réel DÉSACTIVÉE",
			"Aucun autre antivirus n'est installé. Les malwares désactivent souvent cette protection. "+
				"Réactivez-la : Sécurité Windows > Protection contre les virus et menaces.", "")
	}

	if age, e := strconv.Atoi(vals["AGE"]); e == nil {
		ver := ""
		if vals["VER"] != "" {
			ver = " (version " + vals["VER"] + ")"
		}
		switch {
		case age >= 65535:
			report(sevSuspect, catAV, "Signatures antivirus jamais mises à jour", "Une mise à jour va être tentée.", "")
		case age > 7:
			report(sevSuspect, catAV, fmt.Sprintf("Signatures antivirus anciennes : %d jours%s", age, ver),
				"Une mise à jour va être tentée. Des signatures bloquées peuvent indiquer un malware.", "")
		default:
			report(sevOK, catAV, fmt.Sprintf("Signatures antivirus à jour (%d jour(s))%s", age, ver), "", "")
		}
	}

	switch {
	case isTrue("TAMPER"):
		report(sevOK, catAV, "Protection contre les falsifications activée", "", "")
	case isFalse("TAMPER") && !thirdParty:
		report(sevSuspect, catAV, "Protection contre les falsifications désactivée",
			"Elle empêche les malwares de modifier les réglages de Defender. "+
				"Activez-la : Sécurité Windows > Protection contre les virus et menaces > Gérer les paramètres.", "")
	case isFalse("TAMPER"):
		report(sevInfo, catAV, "Protection contre les falsifications désactivée (antivirus tiers présent)", "", "")
	}
}

// mpCheckPolicies détecte Defender désactivé par stratégie dans le registre
// (technique classique des malwares).
func mpCheckPolicies(thirdParty bool) {
	const base = `SOFTWARE\Policies\Microsoft\Windows Defender`
	checks := []struct{ path, name, label string }{
		{base, "DisableAntiSpyware", "Defender désactivé par stratégie (DisableAntiSpyware)"},
		{base, "DisableAntiVirus", "Defender désactivé par stratégie (DisableAntiVirus)"},
		{base + `\Real-Time Protection`, "DisableRealtimeMonitoring", "Protection en temps réel désactivée par stratégie"},
		{base + `\Real-Time Protection`, "DisableBehaviorMonitoring", "Surveillance des comportements désactivée par stratégie"},
		{base + `\Real-Time Protection`, "DisableIOAVProtection", "Analyse des fichiers téléchargés désactivée par stratégie"},
	}
	for _, c := range checks {
		if mpRegDWord(c.path, c.name) != 1 {
			continue
		}
		detail := `Clé HKLM\` + c.path + ` : ` + c.name + ` = 1. Les malwares utilisent cette clé pour neutraliser Defender.`
		if thirdParty {
			report(sevSuspect, catAV, c.label, detail, "")
		} else {
			report(sevDanger, catAV, c.label, detail, "")
		}
	}
}

func mpRegDWord(path, name string) int64 {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return -1
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return -1
	}
	return int64(v)
}

// mpRegValueNames renvoie les noms de valeurs d'une clé HKLM (les exclusions
// Defender sont stockées sous forme de noms de valeurs).
func mpRegValueNames(path string) []string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadValueNames(-1)
	return names
}

// ---------------------------------------------------------------- Exclusions

type mpExclusion struct {
	kind   string // PATH, PROC, EXT
	value  string
	source string
}

func mpCheckExclusions() {
	var list []mpExclusion
	seen := map[string]bool{}
	add := func(kind, value, source string) {
		value = strings.TrimSpace(value)
		if value == "" || strings.HasPrefix(strings.ToUpper(value), "N/A") {
			return // « N/A: Must be an administrator to view exclusions »
		}
		key := kind + "|" + strings.ToLower(value)
		if seen[key] {
			return
		}
		seen[key] = true
		list = append(list, mpExclusion{kind, value, source})
	}

	lines, err := psLines(`try { $p=Get-MpPreference -ErrorAction Stop; 'OK|'; ` +
		`foreach($x in @($p.ExclusionPath)){ if($x){ 'PATH|' + $x } }; ` +
		`foreach($x in @($p.ExclusionProcess)){ if($x){ 'PROC|' + $x } }; ` +
		`foreach($x in @($p.ExclusionExtension)){ if($x){ 'EXT|' + $x } } } ` +
		`catch { 'ERR|' + $_.Exception.Message }`)
	readOK := false
	for _, l := range lines {
		k, v, ok := strings.Cut(l, "|")
		if !ok {
			continue
		}
		switch k {
		case "OK":
			readOK = true
		case "PATH", "PROC", "EXT":
			add(k, v, "")
		}
	}

	// Exclusions imposées par stratégie, et copie directe du registre (utile si
	// Get-MpPreference échoue parce que le service Defender est arrêté).
	for _, r := range []struct{ key, kind, source string }{
		{`SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths`, "PATH", "stratégie"},
		{`SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes`, "PROC", "stratégie"},
		{`SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions`, "EXT", "stratégie"},
		{`SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`, "PATH", ""},
		{`SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes`, "PROC", ""},
		{`SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions`, "EXT", ""},
	} {
		for _, n := range mpRegValueNames(r.key) {
			add(r.kind, n, r.source)
		}
	}

	if len(list) == 0 {
		if readOK {
			report(sevOK, catAV, "Aucune exclusion dans Defender", "", "")
		} else {
			msg := ""
			if err != nil {
				msg = err.Error()
			}
			report(sevInfo, catAV, "Exclusions de Defender illisibles", msg, "")
		}
		return
	}

	for _, e := range list {
		sev, reason := mpClassifyExclusion(e)
		var title, path string
		switch e.kind {
		case "PATH":
			title = "Exclusion de dossier/fichier : " + e.value
			path = expandWinEnv(e.value)
		case "PROC":
			title = "Exclusion de processus : " + e.value
			if strings.ContainsAny(e.value, `\/`) {
				path = expandWinEnv(e.value)
			}
		default:
			title = "Exclusion d'extension : " + e.value
		}
		if e.source != "" {
			title += " (" + e.source + ")"
		}
		// Les chemins avec jokers ne sont pas des fichiers à réanalyser.
		if strings.ContainsAny(path, "*?") {
			path = ""
		}
		report(sev, catAV, title, reason, path)
	}
	info("Pour retirer une exclusion : Sécurité Windows > Protection contre les virus et menaces >")
	info("Gérer les paramètres > Exclusions.")
}

var (
	mpDriveRoot = regexp.MustCompile(`^[A-Za-z]:$`)
	mpDangerExt = map[string]bool{
		"exe": true, "dll": true, "ps1": true, "psm1": true, "bat": true, "cmd": true, "vbs": true,
		"vbe": true, "js": true, "jse": true, "wsf": true, "hta": true, "scr": true, "com": true,
		"pif": true, "msi": true, "lnk": true, "cpl": true, "sys": true, "jar": true, "tmp": true,
	}
	mpLOLBins = map[string]bool{
		"powershell.exe": true, "pwsh.exe": true, "cmd.exe": true, "wscript.exe": true, "cscript.exe": true,
		"mshta.exe": true, "rundll32.exe": true, "regsvr32.exe": true, "msiexec.exe": true, "explorer.exe": true,
		"svchost.exe": true, "conhost.exe": true, "dllhost.exe": true, "java.exe": true, "javaw.exe": true,
		"python.exe": true, "pythonw.exe": true, "node.exe": true, "wmic.exe": true, "certutil.exe": true,
	}
	mpUserMarkers = []string{`\appdata\`, `\temp\`, `\tmp\`, `\downloads\`, `\desktop\`, `\users\public\`}
)

const mpGeneric = "Exclusion à vérifier : les malwares ajoutent souvent des exclusions pour ne pas être détectés."

// mpClassifyExclusion attribue une gravité à une exclusion Defender.
func mpClassifyExclusion(e mpExclusion) (severity, string) {
	v := strings.TrimSpace(expandWinEnv(e.value))
	switch e.kind {
	case "EXT":
		ext := strings.ToLower(strings.TrimLeft(v, "*."))
		if mpDangerExt[ext] || ext == "" || ext == "*" {
			return sevDanger, "Tous les fichiers ." + ext + " de l'ordinateur échappent à l'antivirus : typique d'un malware."
		}
		return sevSuspect, mpGeneric

	case "PROC":
		base := strings.ToLower(filepath.Base(v))
		if strings.ContainsAny(v, `\/`) && (isUserWritable(v) || mpHasUserMarker(v)) {
			return sevDanger, "Programme situé dans un dossier modifiable sans droits administrateur : emplacement typique des malwares."
		}
		if mpLOLBins[base] {
			return sevDanger, "Tout ce que lance " + base + " échappe à l'antivirus : technique utilisée par les malwares."
		}
		if v == "*" || strings.HasPrefix(base, "*") {
			return sevDanger, "Exclusion de processus générique : de nombreux programmes échappent à l'antivirus."
		}
		if !strings.ContainsAny(v, `\/`) {
			return sevSuspect, mpGeneric + " Seul le nom est indiqué : un programme de ce nom placé n'importe où est ignoré."
		}
		return sevSuspect, mpGeneric

	default: // PATH
		trimmed := strings.TrimRight(v, `\/*`)
		if trimmed == "" || mpDriveRoot.MatchString(trimmed) || v == "*" {
			return sevDanger, "Un disque entier est exclu : l'antivirus n'analyse plus rien à cet endroit."
		}
		if isUserWritable(v) || isUserWritable(trimmed+`\x`) || mpHasUserMarker(v) {
			return sevDanger, "Dossier modifiable sans droits administrateur (AppData, Temp, Téléchargements...) : emplacement typique des malwares."
		}
		if mpCoversUserDir(trimmed) {
			return sevDanger, "Ce dossier englobe des dossiers utilisateur (AppData, Temp...) : une très grande partie du PC n'est plus analysée."
		}
		return sevSuspect, mpGeneric
	}
}

func mpHasUserMarker(p string) bool {
	low := strings.ToLower(strings.ReplaceAll(p, "/", `\`)) + `\`
	for _, m := range mpUserMarkers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

// mpCoversUserDir indique si le dossier p contient un dossier où les
// utilisateurs peuvent écrire (ex. exclusion de C:\Users ou C:\Windows).
func mpCoversUserDir(p string) bool {
	lp := strings.ToLower(filepath.Clean(p))
	for _, d := range []string{
		os.Getenv("USERPROFILE"), os.Getenv("APPDATA"), os.Getenv("LOCALAPPDATA"), os.Getenv("TEMP"),
		os.Getenv("PUBLIC"), os.Getenv("ProgramData"), os.Getenv("SystemRoot") + `\Temp`,
	} {
		if d == "" || strings.HasPrefix(d, `\`) {
			continue
		}
		ld := strings.ToLower(filepath.Clean(d))
		if ld == lp || strings.HasPrefix(ld, lp+`\`) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- Signatures et analyse

func mpUpdateSignatures(mp string) {
	info("Mise à jour des signatures Defender (peut prendre quelques minutes)...")
	out, err := runQuiet(mp, "-SignatureUpdate")
	if err == nil {
		report(sevOK, catAV, "Signatures antivirus mises à jour", "", "")
		return
	}
	report(sevInfo, catAV, "Mise à jour des signatures impossible (PC hors ligne ?)",
		mpErrDetail(err, out)+" L'analyse continue avec les signatures actuelles.", "")
}

// mpRunScan lance l'analyse Defender en affichant sa progression.
// Renvoie le code de sortie de MpCmdRun (0 = rien, 2 = menaces, -1 = non lancé).
func mpRunScan(mp string, full, thirdParty bool) int {
	scanType, label := "1", "rapide"
	fmt.Println()
	if full {
		scanType, label = "2", "complète"
		info("Analyse COMPLÈTE : chaque fichier de chaque disque est examiné.")
		info("Comptez 1 à 3 heures selon la taille des disques. Vous pouvez laisser le PC tourner")
		info("(ne le mettez pas en veille) et revenir plus tard.")
	} else {
		info("Analyse rapide : mémoire, démarrage et emplacements utilisés par les malwares (quelques minutes).")
	}
	fmt.Println()
	err := runLive(mp, "-Scan", "-ScanType", scanType)
	fmt.Println()
	code := 0
	if err != nil {
		code = exitCode(err)
	}
	switch code {
	case 0:
		report(sevOK, catAV, "Analyse "+label+" Defender terminée", "", "")
	case 2:
		report(sevInfo, catAV, "Analyse "+label+" Defender terminée : des menaces ont été trouvées", "Détail ci-dessous.", "")
	default:
		detail := mpErrDetail(err, "")
		if thirdParty {
			report(sevInfo, catAV, "L'analyse Defender n'a pas pu aboutir (un autre antivirus est actif)",
				detail+" Lancez plutôt une analyse avec votre antivirus.", "")
		} else {
			report(sevSuspect, catAV, "L'analyse Defender n'a pas pu aboutir", detail+
				" Defender a peut-être été désactivé ou endommagé.", "")
		}
	}
	return code
}

// mpErrDetail formate une erreur MpCmdRun (codes HRESULT) avec la dernière ligne utile de sa sortie.
func mpErrDetail(err error, out string) string {
	var s string
	if c := exitCode(err); c >= 0 {
		s = fmt.Sprintf("Code d'erreur %#x.", uint32(c))
	} else if err != nil {
		s = "Erreur : " + err.Error() + "."
	}
	lines := strings.Split(strings.ReplaceAll(out, "\r", ""), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			if len(l) > 160 {
				l = l[:160] + "..."
			}
			s += " " + l
			break
		}
	}
	return strings.TrimSpace(s)
}

// ---------------------------------------------------------------- Historique des menaces

var mpThreatStatus = map[string]string{
	"0": "état inconnu", "1": "détectée, non traitée", "2": "nettoyée", "3": "mise en quarantaine",
	"4": "supprimée", "5": "autorisée par l'utilisateur", "6": "bloquée", "102": "échec de la mise en quarantaine",
	"103": "échec de la suppression", "104": "échec de l'autorisation", "105": "abandonnée",
	"107": "échec du blocage",
}

// mpListThreats affiche les menaces détectées par Defender ces 30 derniers jours.
func mpListThreats(scanStart time.Time, scanFound bool) {
	lines, err := psLines(`try { $lim=(Get-Date).AddDays(-30); $names=@{}; ` +
		`Get-MpThreat -ErrorAction SilentlyContinue | ForEach-Object { $names[[string]$_.ThreatID]=$_.ThreatName }; ` +
		`$det=@(Get-MpThreatDetection -ErrorAction Stop); 'OK|'; ` +
		`$det | Where-Object { $_.InitialDetectionTime -ge $lim } | ForEach-Object { ` +
		`$n=$names[[string]$_.ThreatID]; if(-not $n){ $n='ID ' + $_.ThreatID }; ` +
		`$r=(@($_.Resources) | Where-Object { $_ } | ForEach-Object { [string]$_ }) -join ' ; '; ` +
		`$t=''; if($_.InitialDetectionTime){ $t=$_.InitialDetectionTime.ToString('s') }; ` +
		`'T|' + $n + '|' + $t + '|' + $_.ActionSuccess + '|' + $_.ThreatStatusID + '|' + $r } } ` +
		`catch { 'ERR|' + $_.Exception.Message }`)

	readOK := false
	errMsg := ""
	type threat struct{ name, when, success, status, resources string }
	var threats []threat
	seen := map[string]bool{}
	for _, l := range lines {
		if strings.HasPrefix(l, "OK|") {
			readOK = true
			continue
		}
		if strings.HasPrefix(l, "ERR|") {
			errMsg = strings.TrimPrefix(l, "ERR|")
			continue
		}
		parts := strings.SplitN(l, "|", 6)
		if len(parts) != 6 || parts[0] != "T" {
			continue
		}
		t := threat{strings.TrimSpace(parts[1]), parts[2], parts[3], strings.TrimSpace(parts[4]), strings.TrimSpace(parts[5])}
		key := strings.ToLower(t.name + "|" + t.resources)
		if seen[key] {
			continue
		}
		seen[key] = true
		threats = append(threats, t)
	}

	if len(threats) == 0 {
		switch {
		case scanFound:
			report(sevDanger, catAV, "Defender a signalé des menaces pendant l'analyse",
				"Le détail n'a pas pu être lu : ouvrez Sécurité Windows > Protection contre les virus et menaces > Historique de protection.", "")
		case readOK:
			report(sevOK, catAV, "Aucune menace détectée par Defender", "Historique des 30 derniers jours vérifié.", "")
		default:
			if errMsg == "" && err != nil {
				errMsg = err.Error()
			}
			report(sevInfo, catAV, "Historique des menaces Defender illisible", errMsg, "")
		}
		return
	}

	for _, t := range threats {
		var files []string
		for _, r := range strings.Split(t.resources, " ; ") {
			r = strings.TrimSpace(r)
			// Format « file:_C:\chemin », « containerfile:_... », « process:_pid:... », « regkey:_... ».
			if kind, v, ok := strings.Cut(r, ":_"); ok {
				if strings.EqualFold(kind, "file") || strings.EqualFold(kind, "containerfile") {
					files = append(files, v)
				}
				continue
			}
			if r != "" {
				files = append(files, r)
			}
		}

		st := mpThreatStatus[t.status]
		if st == "" {
			st = "état " + t.status
		}
		handled := strings.EqualFold(t.success, "True") && (t.status == "2" || t.status == "3" || t.status == "4" || t.status == "6")
		var detail strings.Builder
		if handled {
			fmt.Fprintf(&detail, "Déjà neutralisée par Defender (%s).", st)
		} else {
			fmt.Fprintf(&detail, "NON neutralisée (%s) : action nécessaire dans Sécurité Windows.", st)
		}
		if when, e := time.ParseInLocation("2006-01-02T15:04:05", t.when, time.Local); e == nil {
			fmt.Fprintf(&detail, " Détectée le %s", when.Format("02/01/2006 à 15:04"))
			if !when.Before(scanStart.Add(-time.Minute)) {
				detail.WriteString(" (pendant cette analyse)")
			}
			detail.WriteString(".")
		}
		path := ""
		if len(files) > 0 {
			path = files[0]
			if len(files) > 1 {
				fmt.Fprintf(&detail, " Autres fichiers : %s", strings.Join(files[1:], " ; "))
			}
		} else if t.resources != "" {
			fmt.Fprintf(&detail, " Élément : %s", t.resources)
		}
		title := "Menace détectée : " + t.name
		if handled {
			title += " (neutralisée)"
		}
		report(sevDanger, catAV, title, detail.String(), path)
	}
}

// ---------------------------------------------------------------- Analyse d'un fichier

// defenderScanFile fait analyser un seul fichier par Defender, sans action
// corrective. clean = true si rien n'est trouvé ; threat contient le nom de la
// menace si Defender en signale une.
func defenderScanFile(path string) (clean bool, threat string, err error) {
	mp := defenderPath()
	if mp == "" {
		return false, "", errors.New("Defender introuvable")
	}
	if abs, e := filepath.Abs(path); e == nil {
		path = abs
	}
	out, runErr := runQuiet(mp, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation")
	if runErr == nil {
		return true, "", nil
	}
	if exitCode(runErr) != 2 {
		return false, "", fmt.Errorf("analyse impossible (%s)", mpErrDetail(runErr, out))
	}
	var names []string
	for _, l := range strings.Split(strings.ReplaceAll(out, "\r", ""), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if (k == "threat" || k == "menace") && v != "" {
			dup := false
			for _, n := range names {
				dup = dup || n == v
			}
			if !dup {
				names = append(names, v)
			}
		}
	}
	if len(names) == 0 {
		return false, "menace détectée (nom inconnu)", nil
	}
	return false, strings.Join(names, ", "), nil
}
