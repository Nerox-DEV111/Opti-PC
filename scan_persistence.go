package main

// Analyse de la persistance (backdoors, chevaux de Troie) : inventaire de tous
// les emplacements où Windows peut lancer du code automatiquement, à la manière
// d'Autoruns (clés Run, dossiers Démarrage, tâches planifiées, services,
// Winlogon, IFEO, AppInit_DLLs, abonnements WMI, outils d'accessibilité), en
// signalant ce qu'utilisent typiquement les RAT, backdoors et voleurs de données.

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const persistCat = "Persistance"

// persistEntry est un programme lancé automatiquement (clé Run, raccourci du
// dossier Démarrage, tâche planifiée, service).
type persistEntry struct {
	where  string // emplacement lisible, ex. « Clé Run HKCU : Foo »
	cmd    string // ligne de commande complète
	exe    string // exécutable résolu
	msTask bool   // tâche planifiée sous \Microsoft\
	direct bool   // fichier exécutable posé directement dans un dossier Démarrage
}

// Noms de programmes système souvent imités par les malwares.
var persistSystemNames = map[string]bool{
	"svchost.exe": true, "csrss.exe": true, "lsass.exe": true, "winlogon.exe": true,
	"explorer.exe": true, "services.exe": true, "smss.exe": true, "dllhost.exe": true,
	"conhost.exe": true, "runtimebroker.exe": true, "taskhostw.exe": true, "spoolsv.exe": true,
}

// Extensions exécutables (fichier lancé directement par Windows).
var persistExecExts = map[string]bool{
	".exe": true, ".scr": true, ".com": true, ".pif": true, ".bat": true, ".cmd": true,
	".vbs": true, ".vbe": true, ".js": true, ".jse": true, ".wsf": true, ".hta": true, ".ps1": true,
}

// Extensions de documents utilisées pour camoufler un exécutable (« facture.pdf.exe »).
var persistDocExts = map[string]bool{
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true,
	".pptx": true, ".rtf": true, ".txt": true, ".jpg": true, ".jpeg": true, ".png": true,
	".gif": true, ".bmp": true, ".mp3": true, ".mp4": true, ".avi": true, ".mkv": true,
	".zip": true, ".rar": true, ".7z": true, ".htm": true, ".html": true, ".csv": true,
}

// Outils d'accessibilité lançables depuis l'écran de connexion (cible classique
// de la porte dérobée « sticky keys »).
var persistAccessibility = []string{"sethc.exe", "utilman.exe", "osk.exe", "Magnify.exe", "Narrator.exe"}

// Cibles IFEO lançables depuis l'écran de connexion.
var persistIFEOAccessibility = []string{"sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe", "atbroker.exe"}

var persistIEX = regexp.MustCompile(`(?i)(^|[^a-z0-9_.-])iex([^a-z0-9_-]|$)`)

func scanPersistence() {
	section("Programmes à démarrage automatique (backdoors)")
	if !isAdmin() {
		info("Sans droits administrateur, certaines tâches et certains services peuvent être invisibles.")
	}
	info("Inventaire des clés Run, dossiers Démarrage, tâches planifiées et services...")

	var entries []persistEntry

	// 1. Clés Run / RunOnce.
	runKeys := []struct{ path, label string }{
		{`Software\Microsoft\Windows\CurrentVersion\Run`, "Clé Run"},
		{`Software\Microsoft\Windows\CurrentVersion\RunOnce`, "Clé RunOnce"},
		{`Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "Clé Run (32 bits)"},
		{`Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, "Clé RunOnce (32 bits)"},
		{`Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, "Clé Run (stratégie)"},
	}
	for _, hive := range []string{"HKCU", "HKLM"} {
		root := HKCU
		if hive == "HKLM" {
			root = HKLM
		}
		for _, rk := range runKeys {
			vals := regValues(root, rk.path)
			names := make([]string, 0, len(vals))
			for n := range vals {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				cmd := strings.TrimSpace(vals[n])
				if cmd == "" {
					continue
				}
				label := n
				if label == "" {
					label = "(par défaut)"
				}
				entries = append(entries, persistEntry{
					where: rk.label + " " + hive + " : " + label,
					cmd:   cmd,
					exe:   persistResolve(exeFromCommand(cmd)),
				})
			}
		}
	}

	// 2. Dossiers Démarrage.
	type lnkFile struct{ path, where string }
	var lnks []lnkFile
	type urlFile struct{ path, where string }
	var urls []urlFile
	startDirs := []struct{ env, sub, label string }{
		{"APPDATA", `Microsoft\Windows\Start Menu\Programs\Startup`, "Dossier Démarrage (utilisateur)"},
		{"ProgramData", `Microsoft\Windows\Start Menu\Programs\StartUp`, "Dossier Démarrage (tous les utilisateurs)"},
	}
	for _, sd := range startDirs {
		base := os.Getenv(sd.env)
		if base == "" {
			continue
		}
		dir := filepath.Join(base, sd.sub)
		des, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, de := range des {
			if de.IsDir() || strings.EqualFold(de.Name(), "desktop.ini") {
				continue
			}
			p := filepath.Join(dir, de.Name())
			where := sd.label + " : " + de.Name()
			ext := strings.ToLower(filepath.Ext(de.Name()))
			switch {
			case ext == ".lnk":
				lnks = append(lnks, lnkFile{p, where})
			case ext == ".url":
				urls = append(urls, urlFile{p, where})
			case persistExecExts[ext]:
				entries = append(entries, persistEntry{where: where, cmd: p, exe: p, direct: true})
			}
		}
	}

	// 3, 4, 7, 8. Un seul appel PowerShell pour les tâches, services, AppInit_DLLs,
	// abonnements WMI et la résolution des raccourcis.
	var ps strings.Builder
	ps.WriteString(`try { Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object { $t = $_; foreach ($a in $t.Actions) { if ($a.Execute) { 'T' + [char]9 + $t.TaskPath + $t.TaskName + [char]9 + ([string]$a.Execute -replace '[\t\r\n]+',' ') + [char]9 + ([string]$a.Arguments -replace '[\t\r\n]+',' ') } } } } catch { 'TERR' }; `)
	ps.WriteString(`try { Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName } | ForEach-Object { 'S' + [char]9 + $_.Name + [char]9 + ([string]$_.DisplayName -replace '[\t\r\n]+',' ') + [char]9 + ([string]$_.PathName -replace '[\t\r\n]+',' ') } } catch { 'SERR' }; `)
	ps.WriteString(`foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) { try { $p = Get-ItemProperty -LiteralPath $k -ErrorAction Stop; 'A' + [char]9 + $k + [char]9 + [string]$p.LoadAppInit_DLLs + [char]9 + ([string]$p.AppInit_DLLs -replace '[\t\r\n]+',' ') } catch {} }; `)
	ps.WriteString(`try { Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction Stop | ForEach-Object { 'WC' + [char]9 + ([string]$_.Name -replace '[\t\r\n]+',' ') + [char]9 + ((([string]$_.ExecutablePath) + ' ' + ([string]$_.CommandLineTemplate)).Trim() -replace '\s+',' ') } } catch {}; `)
	ps.WriteString(`try { Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer -ErrorAction Stop | ForEach-Object { $s = ([string]$_.ScriptText -replace '\s+',' ').Trim(); if ($s.Length -gt 100) { $s = $s.Substring(0,100) }; 'WS' + [char]9 + ([string]$_.Name -replace '[\t\r\n]+',' ') + [char]9 + [string]$_.ScriptingEngine + [char]9 + $s } } catch {}; `)
	if len(lnks) > 0 {
		quoted := make([]string, len(lnks))
		for i, l := range lnks {
			quoted[i] = psQuote(l.path)
		}
		ps.WriteString(`try { $sh = New-Object -ComObject WScript.Shell; foreach ($p in @(` + strings.Join(quoted, ",") +
			`)) { try { $l = $sh.CreateShortcut($p); 'L' + [char]9 + $p + [char]9 + [string]$l.TargetPath + [char]9 + ([string]$l.Arguments -replace '[\t\r\n]+',' ') } catch {} } } catch {}; `)
	}
	lines, _ := psLines(ps.String())

	type appInit struct{ key, load, dlls string }
	var appInits []appInit
	type wmiItem struct{ kind, name, text string }
	var wmis []wmiItem
	lnkTargets := map[string][2]string{}
	tasksOK, servicesOK := false, false
	for _, l := range lines {
		f := strings.Split(l, "\t")
		get := func(i int) string {
			if i < len(f) {
				return strings.TrimSpace(f[i])
			}
			return ""
		}
		switch f[0] {
		case "T":
			tasksOK = true
			name, execute, args := get(1), get(2), get(3)
			if execute == "" {
				continue
			}
			entries = append(entries, persistEntry{
				where:  "Tâche planifiée : " + name,
				cmd:    strings.TrimSpace(execute + " " + args),
				exe:    persistResolve(exeFromCommand(execute)),
				msTask: strings.HasPrefix(strings.ToLower(name), `\microsoft\`),
			})
		case "S":
			servicesOK = true
			name, disp, pathName := get(1), get(2), get(3)
			if pathName == "" {
				continue
			}
			label := name
			if disp != "" && disp != name {
				label = disp + " (" + name + ")"
			}
			entries = append(entries, persistEntry{
				where: "Service : " + label,
				cmd:   pathName,
				exe:   persistResolve(exeFromCommand(pathName)),
			})
		case "A":
			appInits = append(appInits, appInit{get(1), get(2), get(3)})
		case "WC", "WS":
			if f[0] == "WC" {
				wmis = append(wmis, wmiItem{"CommandLineEventConsumer", get(1), get(2)})
			} else {
				wmis = append(wmis, wmiItem{"ActiveScriptEventConsumer (" + get(2) + ")", get(1), get(3)})
			}
		case "L":
			lnkTargets[strings.ToLower(get(1))] = [2]string{get(2), get(3)}
		}
	}
	if !tasksOK {
		info("Tâches planifiées : inventaire impossible ou aucune tâche active.")
	}
	if !servicesOK {
		info("Services : inventaire impossible.")
	}

	for _, l := range lnks {
		t, found := lnkTargets[strings.ToLower(l.path)]
		if !found || t[0] == "" {
			report(sevInfo, persistCat, l.where+" — cible du raccourci non résolue",
				"Raccourci sans cible lisible (raccourci d'application ou d'installeur).", "")
			continue
		}
		if st, err := os.Stat(t[0]); err == nil && st.IsDir() {
			continue
		}
		entries = append(entries, persistEntry{
			where: l.where,
			cmd:   strings.TrimSpace(`"` + t[0] + `" ` + t[1]),
			exe:   persistResolve(t[0]),
		})
	}

	// 6. Image File Execution Options : débogueurs détournés.
	type ifeoItem struct{ where, target, dbg, exe string }
	var ifeos []ifeoItem
	for _, base := range []string{
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
	} {
		for _, sub := range regSubKeys(HKLM, base) {
			dbg := strings.TrimSpace(regString(HKLM, base+`\`+sub, "Debugger"))
			if dbg == "" {
				continue
			}
			where := "IFEO : " + sub
			if strings.Contains(base, "WOW6432Node") {
				where = "IFEO (32 bits) : " + sub
			}
			ifeos = append(ifeos, ifeoItem{where, sub, dbg, persistResolve(exeFromCommand(dbg))})
		}
	}

	// 9. Outils d'accessibilité.
	sysRoot := persistSysRoot()
	var accPaths []string
	for _, n := range persistAccessibility {
		accPaths = append(accPaths, filepath.Join(sysRoot, "System32", n))
	}

	// Vérification groupée de toutes les signatures (un seul appel PowerShell).
	var paths []string
	for _, e := range entries {
		paths = append(paths, e.exe)
	}
	for _, it := range ifeos {
		paths = append(paths, it.exe)
	}
	paths = append(paths, accPaths...)
	info("Vérification des signatures numériques de %d éléments...", len(paths))
	sigs := map[string]sigInfo{}
	for k, v := range signatures(paths) {
		sigs[strings.ToLower(k)] = v
	}
	lookup := func(p string) (sigInfo, bool) {
		if p == "" {
			return sigInfo{Status: "Missing"}, true
		}
		s, ok := sigs[strings.ToLower(p)]
		return s, ok
	}

	// Évaluation des éléments de démarrage.
	okCount, unverified := 0, 0
	for _, e := range entries {
		sig, known := lookup(e.exe)
		cmdShort := "Commande : " + persistShort(e.cmd, 220)
		if reason, p := persistCmdDanger(e.cmd, e.exe); reason != "" {
			if p == "" && !persistInSystemDir(e.exe) && sig.Status != "Missing" {
				p = e.exe
			}
			report(sevDanger, persistCat, e.where+" — "+reason, cmdShort, p)
			continue
		}
		if sig.Status == "Missing" {
			if !e.msTask {
				report(sevInfo, persistCat, e.where+" — entrée orpheline (programme introuvable)",
					"Reste sans danger d'un logiciel désinstallé. "+cmdShort, "")
			}
			continue
		}
		if persistDoubleExt(e.exe) {
			report(sevDanger, persistCat, e.where+" — fichier à double extension (camouflage)",
				"Un exécutable déguisé en document est une technique typique des chevaux de Troie. "+cmdShort, e.exe)
			continue
		}
		if persistImpostor(e.exe) {
			report(sevDanger, persistCat, e.where+" — se fait passer pour un programme Windows",
				persistBase(e.exe)+" ne devrait se trouver que dans le dossier Windows. "+cmdShort, e.exe)
			continue
		}
		if !known {
			unverified++
			if e.direct {
				report(sevSuspect, persistCat, e.where+" — fichier exécutable placé directement dans le dossier Démarrage", cmdShort, e.exe)
			}
			continue
		}
		if !sig.valid() {
			switch {
			case e.direct || isUserWritable(e.exe):
				where := "dans un dossier modifiable par l'utilisateur"
				if e.direct {
					where = "posé directement dans le dossier Démarrage"
				}
				report(sevDanger, persistCat, e.where+" — programme "+persistSigText(sig)+" "+where,
					"Emplacement typique des backdoors et voleurs de mots de passe. "+cmdShort, e.exe)
			default:
				report(sevSuspect, persistCat, e.where+" — programme "+persistSigText(sig), cmdShort, e.exe)
			}
			continue
		}
		switch {
		case e.msTask:
			// Tâche Windows signée : ignorée.
		case e.direct:
			report(sevSuspect, persistCat, e.where+" — fichier exécutable placé directement dans le dossier Démarrage",
				"Signé par "+persistSigner(sig)+". "+cmdShort, e.exe)
		default:
			okCount++
		}
	}

	// .url dans un dossier Démarrage : ouvert à chaque connexion.
	for _, u := range urls {
		target := persistURLTarget(u.path)
		report(sevSuspect, persistCat, u.where+" — raccourci Internet ouvert à chaque démarrage",
			"Cible : "+persistShort(target, 200), u.path)
	}

	// 5. Winlogon.
	const winlogon = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	winlogonClean := true
	if shell := strings.TrimSpace(regString(HKLM, winlogon, "Shell")); shell != "" && !strings.EqualFold(shell, "explorer.exe") {
		winlogonClean = false
		report(sevDanger, persistCat, "Winlogon HKLM : valeur Shell détournée",
			"Valeur : « "+shell+" » (attendu : explorer.exe). Un programme se lance à la place ou en plus du bureau.",
			persistExtraExe(shell, "explorer.exe"))
	}
	if shell := strings.TrimSpace(regString(HKCU, winlogon, "Shell")); shell != "" && !strings.EqualFold(shell, "explorer.exe") {
		winlogonClean = false
		report(sevDanger, persistCat, "Winlogon HKCU : valeur Shell définie pour l'utilisateur",
			"Valeur : « "+shell+" ». Un programme remplace ou complète le bureau à chaque connexion.",
			persistExtraExe(shell, "explorer.exe"))
	}
	if ui := strings.TrimSpace(regString(HKLM, winlogon, "Userinit")); ui != "" && !persistUserinitOK(ui) {
		winlogonClean = false
		report(sevDanger, persistCat, "Winlogon HKLM : valeur Userinit détournée",
			`Valeur : « `+ui+` » (attendu : C:\Windows\system32\userinit.exe,). Un programme se lance à chaque connexion.`,
			persistExtraExe(ui, "userinit.exe"))
	}
	if winlogonClean {
		report(sevOK, persistCat, "Winlogon : Shell et Userinit d'origine", "", "")
	}

	// 6. IFEO (évaluation).
	ifeoClean := true
	for _, it := range ifeos {
		sig, known := lookup(it.exe)
		isAcc := false
		for _, a := range persistIFEOAccessibility {
			if strings.EqualFold(it.target, a) {
				isAcc = true
			}
		}
		if !isAcc && strings.EqualFold(persistBase(it.exe), "vsjitdebugger.exe") && known && sig.valid() {
			continue // débogueur Visual Studio : légitime
		}
		ifeoClean = false
		detail := "Débogueur : " + persistShort(it.dbg, 200)
		switch {
		case isAcc:
			report(sevDanger, persistCat, it.where+" — porte dérobée sur l'écran de connexion",
				"Windows lance ce programme à la place de "+it.target+", accessible sans mot de passe depuis l'écran de connexion (backdoor classique). "+detail, it.exe)
		case known && sig.valid():
			report(sevSuspect, persistCat, it.where+" — programme remplacé par un autre",
				"Windows lance un autre programme (signé par "+persistSigner(sig)+") à la place de "+it.target+". Légitime s'il s'agit d'un outil que vous avez installé (ex. Process Explorer). "+detail, it.exe)
		default:
			report(sevDanger, persistCat, it.where+" — programme détourné (Image File Execution Options)",
				"Windows lance un autre programme à la place de "+it.target+". "+detail, it.exe)
		}
	}
	if ifeoClean {
		report(sevOK, persistCat, "Aucun détournement de programme (Image File Execution Options)", "", "")
	}

	// 7. AppInit_DLLs.
	appInitClean := true
	for _, a := range appInits {
		if a.dlls == "" {
			continue
		}
		where := "AppInit_DLLs"
		if strings.Contains(a.key, "WOW6432Node") {
			where = "AppInit_DLLs (32 bits)"
		}
		first := strings.FieldsFunc(a.dlls, func(r rune) bool { return r == ',' || r == ' ' })
		p := ""
		if len(first) > 0 {
			p = strings.Trim(first[0], `"`)
		}
		appInitClean = false
		if a.load == "1" {
			report(sevDanger, persistCat, where+" — DLL injectée dans tous les programmes",
				"Valeur : « "+a.dlls+" » (LoadAppInit_DLLs = 1). Technique d'injection utilisée par les rootkits et keyloggers.", p)
		} else {
			report(sevInfo, persistCat, where+" — DLL déclarée mais chargement désactivé",
				"Valeur : « "+a.dlls+" » (LoadAppInit_DLLs = "+a.load+").", "")
		}
	}
	if appInitClean {
		report(sevOK, persistCat, "AppInit_DLLs : aucune DLL injectée", "", "")
	}

	// 8. Abonnements WMI.
	wmiClean := true
	for _, w := range wmis {
		if strings.EqualFold(w.name, "SCM Event Log Consumer") {
			continue
		}
		wmiClean = false
		p := ""
		if strings.HasPrefix(w.kind, "CommandLine") {
			p = persistResolve(exeFromCommand(w.text))
			if persistInSystemDir(p) {
				p = ""
			}
			if _, err := os.Stat(p); err != nil {
				p = ""
			}
		}
		report(sevDanger, persistCat, "Abonnement WMI : "+w.name+" — exécution cachée de code",
			w.kind+" : "+persistShort(w.text, 200)+". Technique de persistance « sans fichier » des backdoors avancées.", p)
	}
	if wmiClean {
		report(sevOK, persistCat, "Aucun abonnement WMI suspect", "", "")
	}

	// 9. Outils d'accessibilité remplacés.
	accClean := true
	for _, p := range accPaths {
		sig, known := lookup(p)
		if !known || sig.Status == "Missing" {
			continue
		}
		if sig.valid() && strings.Contains(strings.ToLower(sig.Signer), "microsoft") {
			continue
		}
		accClean = false
		report(sevDanger, persistCat, filepath.Base(p)+" remplacé — porte dérobée sur l'écran de connexion",
			"Ce fichier système n'a pas une signature Microsoft valide (statut : "+sig.Status+", éditeur : "+persistSigner(sig)+
				"). Il peut être lancé sans mot de passe depuis l'écran de connexion.", p)
	}
	if accClean {
		report(sevOK, persistCat, "Outils d'accessibilité de l'écran de connexion d'origine", "", "")
	}

	if unverified > 0 {
		info("%d éléments de démarrage n'ont pas pu être vérifiés (contrôle de signature indisponible).", unverified)
	}
	if okCount > 0 {
		report(sevOK, persistCat, fmt.Sprintf("%d éléments de démarrage vérifiés et signés", okCount), "", "")
	}
}

// ---------------------------------------------------------------- Helpers

func persistSysRoot() string {
	if r := os.Getenv("SystemRoot"); r != "" {
		return strings.TrimRight(r, `\`)
	}
	return `C:\Windows`
}

// persistBase renvoie le nom de fichier d'un chemin Windows (séparateurs \ ou /).
func persistBase(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// persistInSystemDir indique si le chemin est dans System32 ou SysWOW64.
func persistInSystemDir(p string) bool {
	low := strings.ToLower(p)
	root := strings.ToLower(persistSysRoot())
	return strings.HasPrefix(low, root+`\system32\`) || strings.HasPrefix(low, root+`\syswow64\`)
}

// persistResolve complète un nom de programme sans dossier (« explorer.exe »,
// « cmd ») en cherchant comme Windows : System32, Windows, SysWOW64, puis PATH.
func persistResolve(p string) string {
	p = strings.Trim(strings.TrimSpace(p), `"`)
	if p == "" || strings.ContainsAny(p, `\/`) {
		return p
	}
	root := persistSysRoot()
	names := []string{p}
	if filepath.Ext(p) == "" {
		names = append(names, p+".exe")
	}
	for _, n := range names {
		for _, d := range []string{root + `\System32`, root, root + `\SysWOW64`} {
			c := d + `\` + n
			if st, err := os.Stat(c); err == nil && !st.IsDir() {
				return c
			}
		}
	}
	if lp, err := exec.LookPath(p); err == nil {
		if abs, err := filepath.Abs(lp); err == nil {
			return abs
		}
		return lp
	}
	return p
}

// persistArgPaths extrait les chemins de fichiers cités dans une ligne de commande.
func persistArgPaths(cmd string) []string {
	var toks []string
	var cur strings.Builder
	inQ := false
	for _, r := range cmd {
		switch {
		case r == '"':
			inQ = !inQ
		case (r == ' ' || r == '\t') && !inQ:
			if cur.Len() > 0 {
				toks = append(toks, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		toks = append(toks, cur.String())
	}
	var out []string
	for _, t := range toks {
		t = strings.Trim(t, `'`)
		if i := strings.Index(t, `:\`); i >= 1 {
			t = t[i-1:]
		} else if i := strings.Index(t, `\\`); i >= 0 {
			t = t[i:]
		} else {
			continue
		}
		if i := strings.IndexAny(t, ",;"); i >= 0 {
			t = t[:i]
		}
		t = strings.Trim(t, `'`)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// persistCmdDanger détecte dans une ligne de commande les techniques typiques
// des malwares. Renvoie la raison (vide si rien) et le fichier en cause éventuel.
func persistCmdDanger(cmd, exe string) (string, string) {
	low := strings.ToLower(expandWinEnv(cmd))
	base := strings.ToLower(persistBase(exe))

	if strings.Contains(low, "powershell") || strings.Contains(low, "pwsh") {
		toks := strings.Fields(strings.NewReplacer(`"`, " ", "'", " ").Replace(low))
		for i, t := range toks {
			if len(t) < 2 || (t[0] != '-' && t[0] != '/') {
				continue
			}
			f := t[1:]
			if f == "e" || f == "ec" || (strings.HasPrefix(f, "en") && strings.HasPrefix("encodedcommand", f)) {
				return "PowerShell avec commande encodée (-EncodedCommand)", ""
			}
			if strings.HasPrefix("windowstyle", f) && i+1 < len(toks) {
				if n := toks[i+1]; n == "hidden" || n == "h" || n == "1" {
					return "PowerShell lancé en fenêtre cachée (-WindowStyle Hidden)", ""
				}
			}
		}
		if persistIEX.MatchString(low) || strings.Contains(low, "invoke-expression") {
			return "PowerShell exécutant du code dynamique (IEX / Invoke-Expression)", ""
		}
	}
	for _, k := range []string{"downloadstring", "downloadfile", "downloaddata", "net.webclient", "start-bitstransfer", "invoke-webrequest"} {
		if strings.Contains(low, k) {
			return "télécharge du code depuis Internet au démarrage (" + k + ")", ""
		}
	}
	if strings.Contains(low, "frombase64string") {
		return "décode un contenu caché en Base64 (FromBase64String)", ""
	}
	if base == "mshta.exe" || strings.Contains(low, "mshta") {
		return "mshta exécute un script HTA (technique courante des malwares)", ""
	}
	if strings.Contains(low, "javascript:") || strings.Contains(low, "vbscript:") {
		return "exécute un script intégré à la ligne de commande", ""
	}
	if strings.Contains(low, "regsvr32") && (strings.Contains(low, "/i:http") || strings.Contains(low, "-i:http") || strings.Contains(low, "scrobj")) {
		return "regsvr32 charge un script distant (technique « Squiblydoo »)", ""
	}
	if strings.Contains(low, "certutil") && (strings.Contains(low, "urlcache") || strings.Contains(low, "-decode") || strings.Contains(low, "/decode")) {
		return "certutil détourné pour télécharger ou décoder un fichier", ""
	}
	if strings.Contains(low, "bitsadmin") && strings.Contains(low, "/transfer") {
		return "bitsadmin détourné pour télécharger un fichier", ""
	}

	// Interpréteur ou rundll32 lançant un fichier situé dans un dossier utilisateur.
	host := ""
	switch {
	case base == "rundll32.exe" || strings.Contains(low, "rundll32"):
		host = "rundll32 charge une DLL"
	case base == "wscript.exe" || base == "cscript.exe" || strings.Contains(low, "wscript") || strings.Contains(low, "cscript"):
		host = "script VBS/JS lancé"
	case base == "powershell.exe" || base == "pwsh.exe":
		host = "script lancé"
	case base == "cmd.exe":
		// Les installeurs (OneDrive, Edge...) laissent souvent un « cmd /c del ... »
		// dans RunOnce pour supprimer leurs fichiers temporaires : sans danger.
		cleanup := false
		for _, w := range strings.Fields(strings.NewReplacer(`"`, " ", "&", " ").Replace(low)) {
			if w == "del" || w == "erase" || w == "rmdir" || w == "rd" {
				cleanup = true
			}
		}
		if !cleanup {
			host = "script lancé"
		}
	}
	if host != "" {
		lowExe := strings.ToLower(exe)
		for _, a := range persistArgPaths(expandWinEnv(cmd)) {
			if strings.ToLower(a) == lowExe {
				continue
			}
			if isUserWritable(a) {
				return host + " depuis un dossier modifiable par l'utilisateur", a
			}
		}
	}
	return "", ""
}

// persistDoubleExt détecte une extension cachée (« photo.jpg.exe ») ou le
// caractère d'inversion de sens d'écriture (RLO) utilisé pour camoufler un nom.
func persistDoubleExt(p string) bool {
	name := strings.ToLower(persistBase(p))
	if strings.ContainsRune(name, '\u202e') {
		return true
	}
	ext := filepath.Ext(name)
	if !persistExecExts[ext] {
		return false
	}
	rest := strings.TrimRight(strings.TrimSuffix(name, ext), " .")
	return persistDocExts[filepath.Ext(rest)]
}

// persistImpostor indique un exécutable portant le nom d'un programme système
// mais situé hors de son dossier d'origine.
func persistImpostor(p string) bool {
	name := strings.ToLower(persistBase(p))
	if !persistSystemNames[name] {
		return false
	}
	i := strings.LastIndexAny(p, `\/`)
	if i < 0 {
		return false // nom seul : résolu par Windows dans ses dossiers système
	}
	dir := strings.ToLower(strings.TrimRight(p[:i], `\/`))
	root := strings.ToLower(persistSysRoot())
	if dir == root+`\system32` || dir == root+`\syswow64` {
		return false
	}
	return !(name == "explorer.exe" && dir == root)
}

// persistUserinitOK vérifie que Userinit vaut C:\Windows\system32\userinit.exe(,).
func persistUserinitOK(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimSpace(strings.TrimSuffix(v, ","))
	return v == `c:\windows\system32\userinit.exe` || v == strings.ToLower(persistSysRoot())+`\system32\userinit.exe`
}

// persistExtraExe renvoie le premier programme d'une liste (séparée par des
// virgules) qui n'est pas le programme attendu.
func persistExtraExe(v, expected string) string {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" || strings.EqualFold(persistBase(strings.Trim(part, `"`)), expected) {
			continue
		}
		p := persistResolve(exeFromCommand(part))
		if _, err := os.Stat(p); err == nil {
			return p
		}
		return ""
	}
	return ""
}

func persistSigText(s sigInfo) string {
	switch s.Status {
	case "NotSigned":
		return "non signé"
	case "HashMismatch":
		return "à la signature invalide (fichier modifié)"
	case "NotTrusted":
		return "à la signature non approuvée"
	case "UnknownError", "":
		return "à la signature illisible"
	default:
		return "à la signature non valide (" + s.Status + ")"
	}
}

func persistSigner(s sigInfo) string {
	if s.Signer == "" {
		return "inconnu"
	}
	return s.Signer
}

// persistURLTarget lit la cible (URL=) d'un raccourci Internet .url.
func persistURLTarget(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return "illisible"
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if len(l) > 4 && strings.EqualFold(l[:4], "url=") {
			return l[4:]
		}
	}
	return "inconnue"
}

func persistShort(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
