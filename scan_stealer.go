package main

// Analyse « vol de jetons, mots de passe et chevaux de Troie » : injection dans
// Discord (token grabber), fichiers de type info-stealer dans les dossiers de
// l'utilisateur, processus suspects connectés à Internet (RAT), détournement
// réseau (fichier hosts, proxy).
//
// Cette analyse ne supprime jamais rien d'elle-même : seule la réparation de
// Discord est proposée, après confirmation, avec une sauvegarde du fichier.
//
// Les chaînes caractéristiques des voleurs de données (adresses de webhooks,
// noms de fichiers des navigateurs...) sont stockées masquées (stlDeob) pour
// qu'Opti-PC lui-même ne contienne pas ces motifs en clair : sinon une copie
// d'Opti-PC présente dans Téléchargements serait signalée par sa propre
// analyse, et certains antivirus pourraient le prendre pour un voleur.

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// ================================================================ Logique pure
// (sans appel système : testable sur n'importe quelle plateforme)

// stlDeob décode une chaîne masquée (XOR glissant + hexadécimal).
func stlDeob(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		return ""
	}
	for i := range b {
		b[i] ^= byte(0x5A + 7*i)
	}
	return string(b)
}

var (
	// discord(?:app)?\.com/api/(?:v\d+/)?webhooks
	stlWebhookRe = regexp.MustCompile(stlDeob("3e081b0c190fe0a3ada3c1d7de9c839fe4b2b7b2c98c84922d212f2d6879481815687738333f0c041d12f3"))
	// local storage[\\/'"\s,+]{1,8}leveldb
	stlLevelDBRe = regexp.MustCompile(stlDeob("360e0b0e1a5df7fffdebc1c0cbeee09fe5f6fa8395c1dfa679383c2f634949455f2d2c2d"))
	// Jeton Discord en clair : (?:^|[^\w-])[\w-]{24,28}\.[\w-]{6}\.[\w-]{27,40}(?:$|[^\w-])
	stlTokenRe = regexp.MustCompile(stlDeob("725e52310a26dad7e5b4fd8ef5e9cbee97aaeaebcadfcc865e274b4b690871480c3c14610d0113462f02b2b0a2a1acde828e829bba968a8795c4adde"))

	stlTelegram   = stlDeob("3b1101410218e8eef5ebc1ca80dacea4e5b3b7ab") // api.telegram.org/bot
	stlLoginData  = stlDeob("360e0f06185de0eae6f8")                     // login data
	stlEncKey     = stlDeob("3f0f0b1d0f0df0eef6c6cbc2d7")               // encrypted_key
	stlDqw        = stlDeob("3e101f5b0144f3eceafad19d")                 // préfixe des jetons chiffrés
	stlCrypt      = stlDeob("3913111f0208eafbe0f6d4c2cdc1d8a2beb0")     // cryptunprotectdata
	stlLocalState = stlDeob("360e0b0e1a5df7fff3edc5")                   // local state
	stlDCore      = stlDeob("3e081b0c190fe0d4f6fcd3ccdadacc9ca9beaaba") // nom du module cœur de Discord
	stlTokRegexes = []string{                                           // expressions régulières de jetons écrites dans le code source d'un voleur
		stlDeob("013d1f422b06b6bf"), stlDeob("215715335826d8fcbfc4db9599"), stlDeob("370709335826d8fcbfc4db9f9a"),
		stlDeob("013d34185b20ffb9a6"), stlDeob("215715332a53dfd7ceee8dfad5878b"), stlDeob("370709332a53dfd7ceee8dfad58d88"),
	}
)

// Indicateurs de vol de données détectés dans le contenu d'un fichier.
const (
	iocWebhook  = "webhook"
	iocTelegram = "telegram"
	iocLevelDB  = "leveldb"
	iocLogin    = "login"
	iocDqw      = "dqw"
	iocTokRegex = "tokregex"
	iocToken    = "token"
	iocCrypt    = "crypt"
	iocInjector = "injector"
)

// iocLabels décrit chaque indicateur pour l'utilisateur.
var iocLabels = map[string]string{
	iocWebhook:  "adresse de webhook Discord (envoi de données à un pirate)",
	iocTelegram: "adresse d'un bot Telegram (envoi de données à un pirate)",
	iocLevelDB:  "lecture du stockage local de Discord (là où est rangé le jeton)",
	iocLogin:    "lecture des mots de passe enregistrés du navigateur",
	iocDqw:      "décodage de jetons Discord chiffrés",
	iocTokRegex: "recherche de jetons Discord (expression régulière)",
	iocToken:    "jeton Discord écrit en clair",
	iocCrypt:    "déchiffrement des données du navigateur (DPAPI)",
	iocInjector: "modification du module cœur de Discord (injecteur)",
}

// Indicateurs « faibles » : présents aussi dans des navigateurs/applications
// légitimes basés sur Chromium.
var iocWeak = map[string]bool{iocLogin: true, iocCrypt: true}

// iocScanner cherche les indicateurs dans un fichier lu par morceaux.
type iocScanner struct {
	binary bool // fichier binaire : on cherche aussi les chaînes UTF-16 (.NET)
	tail   []byte
	low    []byte
	strip  []byte
	flags  map[string]bool // sous-motifs vus
}

func newIOCScanner(binary bool) *iocScanner {
	return &iocScanner{binary: binary, flags: map[string]bool{}}
}

const iocOverlap = 256

// feed analyse un morceau du fichier (les motifs à cheval sur deux morceaux
// sont trouvés grâce au recouvrement).
func (s *iocScanner) feed(chunk []byte) {
	buf := append(s.tail, chunk...)
	s.low = stlASCIILower(s.low[:0], buf)
	s.scanLower(s.low)
	if s.binary {
		// Chaînes UTF-16LE : on retire les octets nuls.
		s.strip = s.strip[:0]
		for _, c := range s.low {
			if c != 0 {
				s.strip = append(s.strip, c)
			}
		}
		s.scanLower(s.strip)
	} else if stlTokenRe.Match(buf) {
		s.flags[iocToken] = true
	}
	if len(buf) > iocOverlap {
		buf = buf[len(buf)-iocOverlap:]
	}
	s.tail = append(s.tail[:0:0], buf...)
}

func (s *iocScanner) scanLower(b []byte) {
	f := s.flags
	if !f[iocWebhook] && stlWebhookRe.Match(b) {
		f[iocWebhook] = true
	}
	if !f[iocTelegram] && bytes.Contains(b, []byte(stlTelegram)) {
		f[iocTelegram] = true
	}
	if !f["ldb"] && stlLevelDBRe.Match(b) {
		f["ldb"] = true
	}
	if !f["discord"] && bytes.Contains(b, []byte("discord")) {
		f["discord"] = true
	}
	if !f["logindata"] && bytes.Contains(b, []byte(stlLoginData)) {
		f["logindata"] = true
	}
	if !f["enckey"] && bytes.Contains(b, []byte(stlEncKey)) {
		f["enckey"] = true
	}
	if !f[iocDqw] && bytes.Contains(b, []byte(stlDqw)) {
		f[iocDqw] = true
	}
	if !f["cryptapi"] && bytes.Contains(b, []byte(stlCrypt)) {
		f["cryptapi"] = true
	}
	if !f["localstate"] && bytes.Contains(b, []byte(stlLocalState)) {
		f["localstate"] = true
	}
	if !f[iocInjector] && bytes.Contains(b, []byte(stlDCore)) {
		f[iocInjector] = true
	}
	if !f[iocTokRegex] {
		for _, p := range stlTokRegexes {
			if bytes.Contains(b, []byte(p)) {
				f[iocTokRegex] = true
				break
			}
		}
	}
}

// hits renvoie les indicateurs trouvés (les paires sont combinées ici).
func (s *iocScanner) hits() []string {
	f := s.flags
	var out []string
	add := func(k string, cond bool) {
		if cond {
			out = append(out, k)
		}
	}
	add(iocWebhook, f[iocWebhook])
	add(iocTelegram, f[iocTelegram])
	add(iocLevelDB, f["ldb"] && f["discord"])
	add(iocLogin, f["logindata"] && f["enckey"])
	add(iocDqw, f[iocDqw])
	add(iocTokRegex, f[iocTokRegex])
	add(iocToken, f[iocToken])
	add(iocCrypt, f["cryptapi"] && f["localstate"])
	add(iocInjector, f[iocInjector])
	return out
}

// iocScanBytes analyse un contenu complet (utilisé par les tests).
func iocScanBytes(data []byte, binary bool, chunk int) []string {
	s := newIOCScanner(binary)
	for len(data) > 0 {
		n := chunk
		if n > len(data) {
			n = len(data)
		}
		s.feed(data[:n])
		data = data[n:]
	}
	return s.hits()
}

func stlASCIILower(dst, src []byte) []byte {
	for _, c := range src {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst = append(dst, c)
	}
	return dst
}

// iocScore donne la gravité d'un fichier selon ses indicateurs :
// 0 = rien, 1 = suspect, 2 = danger.
func iocScore(hits []string, binary bool) int {
	if len(hits) == 0 {
		return 0
	}
	allWeak := true
	for _, h := range hits {
		if h == iocWebhook || h == iocTelegram {
			return 2
		}
		if !iocWeak[h] {
			allWeak = false
		}
	}
	if binary && allWeak {
		return 1 // navigateurs et applications Electron contiennent ces chaînes
	}
	if len(hits) >= 2 {
		return 2
	}
	return 1
}

// Résultat de l'analyse d'un fichier index.js du module cœur de Discord.
const (
	discClean = iota
	discMod
	discInjected
)

var (
	discCleanRe  = regexp.MustCompile(`^module\.exports\s*=\s*require\(\s*(['"])\./core\.asar['"]\s*\)\s*;?$`)
	discModWords = []string{"betterdiscord", "vencord", "replugged", "powercord"}
	discBadWords = []string{"http", "fetch(", "xmlhttprequest", "child_process", "eval(", "token",
		"webhook", "buffer.from", "atob(", "net.request", "function(", "=>", "new function"}
)

// discordClassify analyse le contenu de discord_desktop_core\index.js.
func discordClassify(content []byte) (state int, reason string) {
	content = bytes.TrimPrefix(content, []byte("\xef\xbb\xbf"))
	text := strings.TrimSpace(string(content))
	low := strings.ToLower(text)
	if stlWebhookRe.MatchString(low) {
		return discInjected, "le fichier contient l'adresse d'un webhook Discord : votre jeton est envoyé à un pirate"
	}
	if discCleanRe.MatchString(text) {
		return discClean, ""
	}
	for _, w := range discModWords {
		if !strings.Contains(low, w) {
			continue
		}
		bad := len(text) > 2048
		for _, b := range discBadWords {
			if strings.Contains(low, b) {
				bad = true
			}
		}
		if !bad {
			return discMod, "le fichier charge un mod de Discord (" + w + ")"
		}
		return discInjected, "le fichier mentionne un mod (" + w + ") mais contient aussi du code inconnu"
	}
	return discInjected, fmt.Sprintf("le fichier contient %d caractères de code ajouté au lieu de la seule ligne d'origine", len(text))
}

// hostsEntry est une ligne active du fichier hosts.
type hostsEntry struct{ ip, host string }

// parseHosts lit le contenu du fichier hosts (commentaires ignorés).
func parseHosts(data string) []hostsEntry {
	data = strings.TrimPrefix(data, "\ufeff")
	var out []hostsEntry
	for _, line := range strings.Split(data, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		for _, h := range f[1:] {
			out = append(out, hostsEntry{f[0], strings.ToLower(h)})
		}
	}
	return out
}

var (
	hostsLongWords  = []string{"windowsupdate", "defender", "kaspersky", "malwarebytes", "bitdefender", "virustotal", "smartscreen", "wdcp"}
	hostsShortWords = []string{"avast", "eset", "norton", "mcafee", "avg", "drweb", "sophos", "trendmicro", "f-secure", "emsisoft", "zemana", "hitmanpro"}
	hostsTelemetry  = []string{"telemetry", "vortex", "watson", "settings-win", "data.microsoft", "events.data", "diagnostic", "feedback", "ads", "adnxs", "msads"}
)

// hostsSecurityDomain indique si un domaine appartient à Windows Update, à
// Microsoft ou à un éditeur d'antivirus (cible typique des malwares).
func hostsSecurityDomain(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, w := range hostsLongWords {
		if strings.Contains(host, w) {
			return true
		}
	}
	for _, label := range strings.Split(host, ".") {
		for _, w := range hostsShortWords {
			if strings.HasPrefix(label, w) {
				return true
			}
		}
	}
	if strings.Contains(host, "microsoft") {
		// Les listes « anti-pistage » bloquent souvent la télémétrie : légitime.
		for _, w := range hostsTelemetry {
			if strings.Contains(host, w) {
				return false
			}
		}
		return true
	}
	return false
}

// hostsIsLocalName indique les entrées standard (localhost...).
func hostsIsLocalName(host string) bool {
	switch host {
	case "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback":
		return true
	}
	return false
}

// ipIsPublic indique si une adresse IP est routable sur Internet.
func ipIsPublic(s string) bool {
	if i := strings.IndexByte(s, '%'); i >= 0 { // fe80::1%12
		s = s[:i]
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.Equal(net.IPv4bcast))
}

// stlConn est une connexion TCP d'un processus.
type stlConn struct {
	state, laddr, raddr string
	lport, rport        int
}

type stlProc struct {
	pid   int
	name  string
	path  string
	conns []stlConn
}

// parseProcLine lit une ligne « P|pid|nom|chemin|état,local,port,distant,port;... ».
func parseProcLine(line string) (stlProc, bool) {
	parts := strings.SplitN(line, "|", 5)
	if len(parts) != 5 || parts[0] != "P" {
		return stlProc{}, false
	}
	pid, err := strconv.Atoi(parts[1])
	if err != nil {
		return stlProc{}, false
	}
	p := stlProc{pid: pid, name: parts[2], path: parts[3]}
	for _, c := range strings.Split(parts[4], ";") {
		f := strings.Split(strings.TrimSpace(c), ",")
		if len(f) != 5 {
			continue
		}
		lp, _ := strconv.Atoi(f[2])
		rp, _ := strconv.Atoi(f[4])
		p.conns = append(p.conns, stlConn{state: f[0], laddr: f[1], lport: lp, raddr: f[3], rport: rp})
	}
	return p, true
}

// procNetwork renvoie les connexions établies vers Internet et les ports en
// écoute accessibles depuis le réseau.
func procNetwork(conns []stlConn) (remote, listen []string) {
	seenR, seenL := map[string]bool{}, map[string]bool{}
	for _, c := range conns {
		switch strings.ToLower(c.state) {
		case "established":
			if ipIsPublic(c.raddr) {
				k := net.JoinHostPort(c.raddr, strconv.Itoa(c.rport))
				if !seenR[k] {
					seenR[k] = true
					remote = append(remote, k)
				}
			}
		case "listen":
			ip := net.ParseIP(c.laddr)
			if ip != nil && ip.IsLoopback() {
				continue
			}
			k := strconv.Itoa(c.lport)
			if !seenL[k] {
				seenL[k] = true
				listen = append(listen, k)
			}
		}
	}
	return remote, listen
}

var (
	dblInner = map[string]bool{".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
		".ppt": true, ".pptx": true, ".txt": true, ".rtf": true, ".jpg": true, ".jpeg": true, ".png": true,
		".gif": true, ".bmp": true, ".mp3": true, ".mp4": true, ".avi": true, ".mkv": true, ".mov": true,
		".wav": true, ".zip": true, ".rar": true, ".7z": true, ".csv": true, ".odt": true, ".html": true, ".htm": true}
	dblOuter = map[string]bool{".exe": true, ".scr": true, ".bat": true, ".cmd": true, ".vbs": true,
		".js": true, ".com": true, ".pif": true, ".hta": true, ".ps1": true, ".jar": true, ".lnk": true}
)

// isDoubleExt détecte les noms piégés du type « facture.pdf.exe ».
func isDoubleExt(name string) bool {
	name = strings.ToLower(strings.TrimRight(name, " ."))
	outer := filepath.Ext(name)
	if !dblOuter[outer] {
		return false
	}
	inner := filepath.Ext(strings.TrimRight(strings.TrimSuffix(name, outer), " "))
	return dblInner[inner]
}

// ================================================================ Analyse

const stlCat = "Vol de jetons"

func scanStealers() {
	section("Vol de jetons, mots de passe et chevaux de Troie")
	start := len(findings)

	stlScanDiscord()

	procs := stlProcesses()
	files := stlScanFiles(procs)

	// Une seule vérification des signatures pour tous les fichiers et processus.
	var paths []string
	for _, f := range files {
		if f.needSig {
			paths = append(paths, f.path)
		}
	}
	for _, p := range procs {
		if p.path != "" && (isUserWritable(p.path) || stlSysName(p.name)) {
			paths = append(paths, p.path)
		}
	}
	var sigs map[string]sigInfo
	if len(paths) > 0 {
		info("Vérification des signatures numériques de %d fichier(s)...", len(paths))
		sigs = stlLowerSigs(signatures(paths))
	}

	stlReportFiles(files, sigs, procs)
	stlReportProcesses(procs, sigs)
	stlScanNetwork()

	bad := false
	for _, f := range findings[start:] {
		if f.sev >= sevSuspect {
			bad = true
		}
	}
	if !bad {
		report(sevOK, stlCat, "Aucun signe de vol de jetons ou de cheval de Troie", "", "")
	}
}

func stlLowerSigs(m map[string]sigInfo) map[string]sigInfo {
	out := make(map[string]sigInfo, len(m))
	for k, v := range m {
		out[strings.ToLower(k)] = v
	}
	return out
}

func stlSig(sigs map[string]sigInfo, path string) sigInfo {
	if s, ok := sigs[strings.ToLower(path)]; ok {
		return s
	}
	return sigInfo{Status: "Unchecked"} // vérification impossible (PowerShell en échec ?)
}

// ---------------------------------------------------------------- Discord

var discordExes = []string{"Discord.exe", "DiscordCanary.exe", "DiscordPTB.exe", "DiscordDevelopment.exe"}

type discFile struct {
	path   string
	state  int
	reason string
}

func stlScanDiscord() {
	const cat = "Discord"
	appdata, local := os.Getenv("APPDATA"), os.Getenv("LOCALAPPDATA")
	var bases []string
	for _, n := range []string{"discord", "discordcanary", "discordptb", "discorddevelopment"} {
		if appdata != "" {
			bases = append(bases, filepath.Join(appdata, n))
		}
	}
	for _, n := range []string{"Discord", "DiscordCanary", "DiscordPTB", "DiscordDevelopment"} {
		if local != "" {
			bases = append(bases, filepath.Join(local, n))
		}
	}

	installed := false
	seen := map[string]bool{}
	var indexes []string
	for _, b := range bases {
		if st, err := os.Stat(b); err != nil || !st.IsDir() {
			continue
		}
		installed = true
		for _, pat := range []string{
			filepath.Join(b, "app-*", "modules", stlDCore+"-*", stlDCore, "index.js"),
			filepath.Join(b, "*", "modules", stlDCore, "index.js"), // anciennes versions
		} {
			m, _ := filepath.Glob(pat)
			for _, p := range m {
				if !seen[strings.ToLower(p)] {
					seen[strings.ToLower(p)] = true
					indexes = append(indexes, p)
				}
			}
		}
	}
	if !installed {
		report(sevInfo, cat, "Discord n'est pas installé : rien à vérifier", "", "")
		return
	}
	if len(indexes) == 0 {
		report(sevInfo, cat, "Discord est installé mais son module principal est introuvable (pas encore mis à jour ?)", "", "")
		return
	}

	var toFix []discFile
	clean := 0
	for _, p := range indexes {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		if st.Size() > 5<<20 {
			toFix = append(toFix, discFile{p, discInjected, "fichier anormalement gros"})
		} else if data, err := os.ReadFile(p); err == nil {
			state, reason := discordClassify(data)
			if state == discClean {
				clean++
			} else {
				toFix = append(toFix, discFile{p, state, reason})
			}
		}
		dir := filepath.Dir(p)
		if fi, err := os.Stat(filepath.Join(dir, "initiation")); err == nil && fi.IsDir() {
			report(sevDanger, cat, "Discord : dossier « initiation » créé par un voleur de jetons",
				"Ce dossier est laissé par les injections connues (token grabbers). Il prouve une infection, passée ou présente.",
				filepath.Join(dir, "initiation"))
		}
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			n := strings.ToLower(e.Name())
			if e.IsDir() || n == "index.js" || !strings.HasSuffix(n, ".js") {
				continue
			}
			report(sevSuspect, cat, "Fichier JavaScript inhabituel dans le module principal de Discord",
				"Ce dossier ne contient normalement que index.js, core.asar et package.json.", filepath.Join(dir, e.Name()))
		}
	}

	for _, f := range toFix {
		if f.state == discMod {
			report(sevSuspect, cat, "Discord modifié par un mod (BetterDiscord, Vencord...)",
				strings.ToUpper(f.reason[:1])+f.reason[1:]+". Sans danger si VOUS l'avez installé ; sinon, c'est peut-être un voleur de jetons déguisé.", f.path)
		} else {
			report(sevDanger, cat, "Discord modifié : injection de vol de jeton",
				strings.ToUpper(f.reason[:1])+f.reason[1:]+". Le code injecté vole votre compte Discord (et souvent vos moyens de paiement) à chaque démarrage.", f.path)
		}
	}
	if len(toFix) == 0 {
		report(sevOK, cat, fmt.Sprintf("Discord n'a pas été modifié (%d fichier(s) vérifié(s))", clean), "", "")
		return
	}
	stlFixDiscord(toFix)
}

func stlFixDiscord(files []discFile) {
	fmt.Println()
	info("Pour réparer, Discord doit être complètement fermé (y compris l'icône près de l'horloge).")
	if confirm("  Fermer Discord maintenant ?") {
		for _, exe := range discordExes {
			runQuiet("taskkill", "/F", "/IM", exe)
		}
		time.Sleep(2 * time.Second)
	}
	fixed := 0
	for _, f := range files {
		q := "  Restaurer le fichier d'origine de Discord (une sauvegarde sera conservée) ?"
		if f.state == discMod {
			q = "  Si vous n'avez PAS installé ce mod vous-même, restaurer le fichier d'origine ?"
		}
		fmt.Println("  " + col(cDim, f.path))
		if !confirm(q) {
			continue
		}
		if err := stlRestoreDiscordIndex(f.path); err != nil {
			fail("Réparation impossible : %v (Discord est-il bien fermé ?)", err)
			continue
		}
		ok("Fichier restauré (copie de l'ancien : index.js.infecte.bak)")
		fixed++
	}
	if fixed > 0 {
		fmt.Println()
		warn("Le fichier est réparé, mais votre jeton a peut-être déjà été volé :")
		info("1. Changez votre mot de passe Discord (cela déconnecte le pirate) et activez la double authentification.")
		info("2. Dans Discord : Paramètres > Appareils, déconnectez les appareils inconnus.")
		info("3. Le programme qui a fait l'injection est sans doute encore sur le PC : il recommencera.")
		info("   Lancez aussi l'analyse des programmes au démarrage et une analyse antivirus complète.")
		info("4. Changez aussi les mots de passe enregistrés dans votre navigateur, depuis un autre appareil sain.")
	}
}

// stlRestoreDiscordIndex sauvegarde index.js puis réécrit son contenu d'origine.
func stlRestoreDiscordIndex(p string) error {
	old, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	bak := p + ".infecte.bak"
	for i := 1; ; i++ {
		if _, err := os.Stat(bak); os.IsNotExist(err) {
			break
		}
		bak = fmt.Sprintf("%s.infecte.%d.bak", p, i)
		if i > 50 {
			return fmt.Errorf("trop de sauvegardes existantes")
		}
	}
	if err := os.WriteFile(bak, old, 0o644); err != nil {
		return fmt.Errorf("sauvegarde : %w", err)
	}
	os.Chmod(p, 0o666) // retire l'attribut « lecture seule » posé par certains voleurs
	return os.WriteFile(p, []byte("module.exports = require('./core.asar');"), 0o644)
}

// ---------------------------------------------------------------- Fichiers

type stlFile struct {
	path    string
	ext     string
	binary  bool
	hits    []string
	score   int
	scr     bool // économiseur d'écran (.scr) : souvent un exécutable déguisé
	dblExt  bool
	rootExe bool // exécutable posé à la racine d'AppData / LocalAppData / Temp
	needSig bool
	inTemp  bool
}

var (
	stlTextExt = map[string]bool{".bat": true, ".cmd": true, ".vbs": true, ".js": true, ".ps1": true,
		".py": true, ".pyw": true, ".hta": true}
	stlBinExt  = map[string]bool{".exe": true, ".scr": true, ".dll": true, ".jar": true}
	stlSkipDir = map[string]bool{"node_modules": true, ".git": true, "user data": true, "packages": true,
		"cache": true, "code cache": true, "gpucache": true, "service worker": true, "indexeddb": true,
		"cachestorage": true, "blob_storage": true, "crashpad": true, "__pycache__": true,
		"site-packages": true, "dawncache": true, "grshadercache": true, "shadercache": true,
		"webcache": true, "inetcache": true, "$recycle.bin": true}
)

const (
	stlMaxFiles   = 20000
	stlMaxSize    = 30 << 20
	stlMaxBytes   = 4 << 30
	stlMaxContent = 4 * time.Minute
)

func stlScanFiles(procs []stlProc) []stlFile {
	const cat = "Fichiers suspects"
	env := os.Getenv
	type root struct {
		dir   string
		depth int
		kind  string // "appdata", "local", "temp" ou ""
	}
	startupUser := filepath.Join(env("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`)
	startupAll := filepath.Join(env("ProgramData"), `Microsoft\Windows\Start Menu\Programs\StartUp`)
	var roots []root
	add := func(dir string, depth int, kind string) {
		if dir == "" || strings.HasPrefix(dir, `\`) || len(dir) < 4 {
			return
		}
		roots = append(roots, root{filepath.Clean(dir), depth, kind})
	}
	add(env("APPDATA"), 3, "appdata")
	add(env("LOCALAPPDATA"), 0, "local")
	add(filepath.Join(env("LOCALAPPDATA"), "Temp"), 2, "temp")
	add(env("TEMP"), 2, "temp")
	add(filepath.Join(env("USERPROFILE"), "Downloads"), 2, "")
	add(filepath.Join(env("USERPROFILE"), "Desktop"), 1, "")
	add(env("PUBLIC"), 2, "")
	add(startupUser, 0, "")
	add(startupAll, 0, "")

	self, _ := os.Executable()
	self = strings.ToLower(self)
	running := map[string]bool{}
	for _, p := range procs {
		if p.path != "" {
			running[strings.ToLower(p.path)] = true
		}
	}
	autostart := map[string]bool{}
	for _, e := range startupEntries() {
		if p := exeFromCommand(e.cmd); p != "" {
			autostart[strings.ToLower(p)] = true
		}
	}

	info("Analyse des fichiers des dossiers utilisateur (quelques minutes au maximum)...")
	var out []stlFile
	seen := map[string]bool{}
	doneRoots := map[string]bool{}
	examined, entries := 0, 0
	var bytesRead int64
	began := time.Now()
	contentStopped := false
	buf := make([]byte, 1<<20)
	stopped := false

	for _, r := range roots {
		key := strings.ToLower(r.dir)
		if doneRoots[key] {
			continue
		}
		doneRoots[key] = true
		if st, err := os.Stat(r.dir); err != nil || !st.IsDir() {
			continue
		}
		filepath.WalkDir(r.dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			rel, _ := filepath.Rel(r.dir, p)
			depth := 0
			if rel != "." {
				depth = strings.Count(rel, string(filepath.Separator)) + 1
			}
			if d.IsDir() {
				if p == r.dir {
					return nil
				}
				low := strings.ToLower(p)
				if depth > r.depth || stlSkipDir[strings.ToLower(d.Name())] ||
					strings.HasSuffix(low, `\code\user`) || strings.HasSuffix(low, `\microsoft\windows\recent`) {
					return filepath.SkipDir
				}
				return nil
			}
			entries++
			if entries > 400000 {
				info("Trop de fichiers dans les dossiers utilisateur : analyse des fichiers arrêtée.")
				stopped = true
				return filepath.SkipAll
			}
			if !d.Type().IsRegular() {
				return nil
			}
			low := strings.ToLower(p)
			if seen[low] || low == self {
				return nil
			}
			seen[low] = true
			ext := strings.ToLower(filepath.Ext(d.Name()))
			dbl := isDoubleExt(d.Name())
			if !stlTextExt[ext] && !stlBinExt[ext] && !dbl {
				return nil
			}
			examined++
			if examined%2000 == 0 {
				info("%d fichiers examinés...", examined)
			}
			if examined > stlMaxFiles {
				info("Limite de %d fichiers atteinte : analyse des fichiers arrêtée.", stlMaxFiles)
				stopped = true
				return filepath.SkipAll
			}

			f := stlFile{path: p, ext: ext, binary: stlBinExt[ext], dblExt: dbl}
			f.scr = ext == ".scr"
			isExe := ext == ".exe" || ext == ".scr"
			atRoot := depth == 1
			if isExe && atRoot && (r.kind == "appdata" || r.kind == "local") {
				f.rootExe = true
			}
			if isExe && atRoot && r.kind == "temp" && (running[low] || autostart[low]) {
				f.rootExe = true
				f.inTemp = true
			}

			if (stlTextExt[ext] || stlBinExt[ext]) && !contentStopped {
				if time.Since(began) > stlMaxContent || bytesRead > stlMaxBytes {
					contentStopped = true
					info("Durée maximale atteinte : la suite est vérifiée sans lire le contenu des fichiers.")
				} else if fi, err := d.Info(); err == nil && fi.Size() <= stlMaxSize {
					n, hits := stlScanContent(p, f.binary, buf)
					bytesRead += n
					f.hits = hits
					f.score = iocScore(hits, f.binary)
				}
			}
			signable := ext == ".exe" || ext == ".dll" || ext == ".scr"
			f.needSig = signable && (f.score > 0 || f.scr || f.dblExt || f.rootExe)
			if f.score > 0 || f.scr || f.dblExt || f.rootExe {
				out = append(out, f)
			}
			return nil
		})
		if stopped {
			break
		}
	}
	report(sevInfo, cat, fmt.Sprintf("%d fichier(s) exécutable(s) ou script(s) examiné(s) en %s",
		min(examined, stlMaxFiles), time.Since(began).Round(time.Second)), "", "")
	return out
}

// stlScanContent lit un fichier par morceaux et renvoie les indicateurs trouvés.
func stlScanContent(p string, binary bool, buf []byte) (int64, []string) {
	fh, err := os.Open(p)
	if err != nil {
		return 0, nil
	}
	defer fh.Close()
	s := newIOCScanner(binary)
	var total int64
	for total < stlMaxSize {
		n, err := fh.Read(buf)
		if n > 0 {
			total += int64(n)
			s.feed(buf[:n])
		}
		if err == io.EOF || err != nil {
			break
		}
	}
	return total, s.hits()
}

func stlReportFiles(files []stlFile, sigs map[string]sigInfo, procs []stlProc) {
	const cat = "Fichiers suspects"
	running := map[string]bool{}
	for _, p := range procs {
		running[strings.ToLower(p.path)] = true
	}
	count := 0
	for _, f := range files {
		sig := sigInfo{}
		if f.needSig {
			sig = stlSig(sigs, f.path)
		}
		signed := f.needSig && sig.valid()
		signedTxt := "non signé"
		if signed {
			signedTxt = "signé par " + sig.Signer
		} else if sig.Status == "Unchecked" {
			signedTxt = "à la signature non vérifiable"
		} else if !f.needSig {
			signedTxt = ""
		}
		extra := ""
		if running[strings.ToLower(f.path)] {
			extra = " Il est EN COURS D'EXÉCUTION."
		}

		if f.score > 0 {
			sev := sevSuspect
			if f.score == 2 {
				sev = sevDanger
			}
			allWeak := true
			for _, h := range f.hits {
				if !iocWeak[h] {
					allWeak = false
				}
			}
			if signed && sev == sevDanger {
				sev = sevSuspect
			}
			// Une application signée de type navigateur contient ces chaînes : normal.
			if !(signed && allWeak) {
				var labels []string
				for _, h := range f.hits {
					labels = append(labels, iocLabels[h])
				}
				title := "Fichier contenant du code de vol de données"
				if sev == sevSuspect {
					title = "Fichier pouvant contenir du code de vol de données"
				}
				detail := "Indices : " + strings.Join(labels, " ; ") + "."
				if signedTxt != "" {
					detail += " Fichier " + signedTxt + "."
				}
				if !f.binary {
					detail += " Si c'est un script que vous avez écrit vous-même, ignorez ce message."
				} else {
					detail += " Ne l'ouvrez pas ; faites-le analyser sur virustotal.com ou par votre antivirus."
				}
				report(sev, cat, title, detail+extra, f.path)
				count++
				continue
			}
		}
		if signed {
			continue
		}
		switch {
		case f.dblExt:
			report(sevSuspect, cat, "Fichier à double extension (programme déguisé en document)",
				"Le nom imite un document ou une image mais c'est un programme : technique classique des malwares. Ne l'ouvrez pas."+extra, f.path)
			count++
		case f.scr:
			report(sevSuspect, cat, "Économiseur d'écran (.scr) non signé",
				"Un fichier .scr est un programme exécutable ; ce format est très utilisé pour diffuser des malwares."+extra, f.path)
			count++
		case f.rootExe:
			why := "Les programmes légitimes s'installent dans un sous-dossier, rarement à la racine de ce dossier."
			if f.inTemp {
				why = "Programme non signé lancé depuis le dossier temporaire (en cours d'exécution ou au démarrage)."
			}
			report(sevSuspect, cat, "Programme non signé à la racine d'un dossier système de l'utilisateur", why+extra, f.path)
			count++
		}
	}
	if count == 0 {
		report(sevOK, cat, "Aucun fichier de type voleur de données trouvé", "", "")
	}
}

// ---------------------------------------------------------------- Processus

var stlSysNames = map[string]bool{"svchost.exe": true, "csrss.exe": true, "lsass.exe": true,
	"winlogon.exe": true, "services.exe": true, "smss.exe": true, "explorer.exe": true,
	"dllhost.exe": true, "conhost.exe": true, "runtimebroker.exe": true, "wininit.exe": true,
	"taskhostw.exe": true, "spoolsv.exe": true}

func stlSysName(name string) bool { return stlSysNames[strings.ToLower(name)] }

// stlProcesses liste les processus avec leurs connexions réseau.
func stlProcesses() []stlProc {
	info("Lecture des processus et des connexions réseau...")
	script := `$c=@{}; ` +
		`try { Get-NetTCPConnection -State Established,Listen -ErrorAction Stop | ForEach-Object { ` +
		`$k=[int]$_.OwningProcess; if (-not $c.ContainsKey($k)) { $c[$k]=New-Object System.Collections.ArrayList }; ` +
		`[void]$c[$k].Add($_.State.ToString()+','+$_.LocalAddress+','+$_.LocalPort+','+$_.RemoteAddress+','+$_.RemotePort) } } catch {}; ` +
		`Get-CimInstance Win32_Process | ForEach-Object { $id=[int]$_.ProcessId; $n=''; ` +
		`if ($c.ContainsKey($id)) { $n=($c[$id] -join ';') }; 'P|'+$id+'|'+$_.Name+'|'+$_.ExecutablePath+'|'+$n }`
	lines, _ := psLines(script)
	var out []stlProc
	for _, l := range lines {
		if p, ok := parseProcLine(l); ok {
			out = append(out, p)
		}
	}
	return out
}

func stlReportProcesses(procs []stlProc, sigs map[string]sigInfo) {
	const cat = "Processus"
	if len(procs) == 0 {
		report(sevInfo, cat, "Impossible de lister les processus (PowerShell indisponible ?)", "", "")
		return
	}
	self, _ := os.Executable()
	sysRoot := strings.ToLower(filepath.Clean(os.Getenv("SystemRoot"))) + `\`
	if sysRoot == `\` || sysRoot == `.\` {
		sysRoot = `c:\windows\`
	}

	// Regroupe les instances d'un même exécutable.
	type group struct {
		name   string
		path   string
		pids   []int
		remote []string
		listen []string
	}
	groups := map[string]*group{}
	var order []string
	for _, p := range procs {
		if p.path == "" || p.pid == os.Getpid() || strings.EqualFold(p.path, self) {
			continue
		}
		k := strings.ToLower(p.path)
		g := groups[k]
		if g == nil {
			g = &group{name: p.name, path: p.path}
			groups[k] = g
			order = append(order, k)
		}
		g.pids = append(g.pids, p.pid)
		r, l := procNetwork(p.conns)
		g.remote = append(g.remote, r...)
		g.listen = append(g.listen, l...)
	}

	count := 0
	for _, k := range order {
		g := groups[k]
		pids := make([]string, len(g.pids))
		for i, id := range g.pids {
			pids[i] = strconv.Itoa(id)
		}
		pidTxt := "PID " + strings.Join(pids, ", ")

		if stlSysName(g.name) && !strings.HasPrefix(k, sysRoot) {
			report(sevSuspect, cat, "Processus « "+g.name+" » lancé hors du dossier Windows",
				"Ce nom imite un composant de Windows, qui ne s'exécute normalement que depuis "+os.Getenv("SystemRoot")+". "+pidTxt+".", g.path)
			count++
			continue
		}
		if !isUserWritable(g.path) {
			continue
		}
		sig := stlSig(sigs, g.path)
		if sig.valid() {
			continue
		}
		unchecked := sig.Status == "Unchecked"
		var nets []string
		if len(g.remote) > 0 {
			nets = append(nets, "connecté à "+strings.Join(stlFirst(stlUniq(g.remote), 5), ", "))
		}
		if len(g.listen) > 0 {
			nets = append(nets, "en écoute sur le port "+strings.Join(stlFirst(stlUniq(g.listen), 5), ", "))
		}
		if unchecked && len(nets) == 0 {
			continue // signature inconnue et aucune activité réseau : pas assez d'indices
		}
		if unchecked {
			report(sevSuspect, cat, "Programme connecté à Internet depuis un dossier utilisateur : "+g.name,
				"Signature numérique non vérifiable. "+strings.Join(nets, " ; ")+". "+pidTxt+".", g.path)
		} else if len(nets) > 0 {
			report(sevDanger, cat, "Programme non signé connecté à Internet depuis un dossier utilisateur : "+g.name,
				"Possible cheval de Troie / accès à distance (RAT) : "+strings.Join(nets, " ; ")+". "+pidTxt+
					". Si vous ne connaissez pas ce programme, déconnectez le PC d'Internet et lancez une analyse antivirus.", g.path)
		} else {
			report(sevSuspect, cat, "Programme non signé en cours d'exécution depuis un dossier utilisateur : "+g.name,
				"Les programmes légitimes sont presque toujours signés. Vérifiez que vous le connaissez. "+pidTxt+".", g.path)
		}
		count++
	}
	if count == 0 {
		report(sevOK, cat, fmt.Sprintf("Aucun processus suspect (%d processus vérifiés)", len(procs)), "", "")
	}
}

func stlUniq(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func stlFirst(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], fmt.Sprintf("et %d autre(s)", len(s)-n))
	}
	return s
}

// ---------------------------------------------------------------- Réseau

func stlScanNetwork() {
	const cat = "Réseau"
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	hostsPath := filepath.Join(sysRoot, `System32\drivers\etc\hosts`)
	if data, err := os.ReadFile(hostsPath); err != nil {
		report(sevInfo, cat, "Fichier hosts illisible : "+err.Error(), "", hostsPath)
	} else {
		var sec, public, other []string
		for _, e := range parseHosts(string(data)) {
			line := e.ip + " " + e.host
			switch {
			case hostsSecurityDomain(e.host):
				sec = append(sec, line)
			case hostsIsLocalName(e.host):
			case ipIsPublic(e.ip):
				public = append(public, line)
			default:
				other = append(other, line)
			}
		}
		if len(sec) > 0 {
			report(sevDanger, cat, "Fichier hosts : sites de sécurité bloqués ou détournés",
				"Les malwares bloquent ainsi l'antivirus et Windows Update. Entrées : "+strings.Join(stlFirst(sec, 6), " | "), hostsPath)
		}
		if len(public) > 0 {
			report(sevSuspect, cat, fmt.Sprintf("Fichier hosts : %d site(s) redirigé(s) vers une autre adresse Internet", len(public)),
				"Risque d'hameçonnage (faux site). Entrées : "+strings.Join(stlFirst(public, 6), " | "), hostsPath)
		}
		if len(other) > 0 {
			report(sevInfo, cat, fmt.Sprintf("Fichier hosts : %d entrée(s) personnalisée(s) (blocage ou réseau local)", len(other)),
				"Souvent ajoutées par un bloqueur de publicités ou un logiciel. Entrées : "+strings.Join(stlFirst(other, 5), " | "), hostsPath)
		}
		if len(sec)+len(public) == 0 {
			report(sevOK, cat, "Fichier hosts sain", "", "")
		}
	}

	const inet = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	var enable uint64
	if k, err := registry.OpenKey(HKCU, inet, registry.QUERY_VALUE); err == nil {
		enable, _, _ = k.GetIntegerValue("ProxyEnable")
		k.Close()
	}
	server := strings.TrimSpace(regString(HKCU, inet, "ProxyServer"))
	pac := strings.TrimSpace(regString(HKCU, inet, "AutoConfigURL"))
	proxyFound := false
	if enable == 1 && server != "" {
		report(sevSuspect, cat, "Un proxy intercepte le trafic Internet : "+server,
			"Normal en entreprise ou avec certains logiciels (VPN, antivirus, débogage). Sinon, un malware peut lire vos connexions. Réglage : Paramètres > Réseau et Internet > Proxy.", "")
		proxyFound = true
	}
	if pac != "" {
		report(sevSuspect, cat, "Script de configuration automatique du proxy : "+pac,
			"Ce script peut rediriger votre trafic. Normal en entreprise ; sinon, désactivez-le dans Paramètres > Réseau et Internet > Proxy.", "")
		proxyFound = true
	}
	if !proxyFound {
		report(sevOK, cat, "Aucun proxy configuré", "", "")
	}
}
