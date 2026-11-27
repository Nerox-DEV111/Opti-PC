package main

// Modules d'optimisation. Chaque réglage du registre stocke sa valeur
// optimisée ET sa valeur par défaut Windows, ce qui permet de tout annuler
// avec l'option « Restaurer ».

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

const (
	HKCU = registry.CURRENT_USER
	HKLM = registry.LOCAL_MACHINE
)

type module struct {
	key     string
	title   string
	desc    string
	inAll   bool   // inclus dans « Tout optimiser »
	apply   func() // applique l'optimisation
	restore func() // annule (nil = non réversible / rien à annuler)
}

var modules = []module{
	{"D", "Diagnostic du PC", "Trouve ce qui ralentit vraiment votre PC (disque, RAM, XMP, pilotes...)", false, diagnostic, nil},
	{"S", "Analyse de sécurité", "Virus, chevaux de Troie, backdoors, voleurs de jetons Discord/navigateurs", false, securityScan, nil},
	{"1", "Créer un point de restauration", "Sauvegarde de sécurité avant toute modification (recommandé)", false, func() { createRestorePoint() }, nil},
	{"2", "Nettoyage en profondeur", "Fichiers temporaires, caches, Windows Update, corbeille, navigateurs", true, cleanup, nil},
	{"3", "Plan d'alimentation maximal", "Active le mode « Performances optimales » de Windows", true, powerPlanApply, powerPlanRestore},
	{"4", "Effets visuels allégés", "Coupe animations, transparence et ombres (lissage des polices conservé)", true, visualApply, visualRestore},
	{"5", "Optimisations jeux", "Mode Jeu, planification GPU, priorités jeux, Game DVR off, souris brute", true, gamingApply, gamingRestore},
	{"6", "Optimisations réseau", "Vide le cache DNS, supprime la limitation réseau, réduit la latence", true, networkApply, networkRestore},
	{"7", "Confidentialité et arrière-plan", "Télémétrie, pubs, suggestions, services et tâches inutiles", true, privacyApply, privacyRestore},
	{"8", "Réactivité du système", "Menus instantanés, priorité au premier plan, démarrage plus rapide", true, responsivenessApply, responsivenessRestore},
	{"9", "Optimiser les disques", "TRIM pour SSD / défragmentation pour HDD", true, disksOptimize, nil},
	{"10", "Désactiver l'hibernation", "Libère plusieurs Go (hiberfil.sys), conservée sur PC portable", true, hibernateOff, hibernateOn},
	{"11", "Réparer Windows", "DISM + SFC : répare les fichiers système corrompus (15 à 45 min)", false, repairWindows, nil},
	{"12", "Programmes au démarrage", "Liste les programmes lancés au démarrage et ouvre le gestionnaire", false, startupPrograms, nil},
	{"13", "Mettre à jour les applications", "Met à jour tous les logiciels installés via winget", false, updateApps, nil},
	{"14", "Supprimer les applis inutiles", "Candy Crush, Clipchamp, Actualités... (réinstallables via le Store)", false, removeBloatware, nil},
}

// ================================================================ Registre

type regTweak struct {
	label string
	root  registry.Key
	path  string
	name  string
	value interface{} // valeur optimisée
	def   interface{} // valeur Windows par défaut (nil = supprimer la valeur)
}

func applyReg(ts []regTweak) {
	for _, t := range ts {
		check(t.label, regSet(t.root, t.path, t.name, t.value))
	}
}

func restoreReg(ts []regTweak) {
	for _, t := range ts {
		var err error
		if t.def == nil {
			err = regDelete(t.root, t.path, t.name)
		} else {
			err = regSet(t.root, t.path, t.name, t.def)
		}
		check(t.label+" (par défaut)", err)
	}
}

// ================================================================ 1. Point de restauration

func createRestorePoint() bool {
	section("Point de restauration")
	info("Création en cours (peut prendre 1 à 2 minutes)...")
	// Autorise plusieurs points de restauration par jour.
	regSet(HKLM, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore`, "SystemRestorePointCreationFrequency", 0)
	out, err := powershell(`$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'; ` +
		`Enable-ComputerRestore -Drive ($env:SystemDrive + '\'); ` +
		`Checkpoint-Computer -Description 'Opti-PC' -RestorePointType 'MODIFY_SETTINGS'`)
	if err != nil {
		fail("Échec de la création du point de restauration : %s", lastLine(out))
		return false
	}
	ok("Point de restauration « Opti-PC » créé")
	return true
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l
		}
	}
	return "erreur inconnue"
}

// ================================================================ 2. Nettoyage

type shQueryRBInfo struct {
	cbSize      uint32
	i64Size     int64
	i64NumItems int64
}

func recycleBinSize() int64 {
	proc := shell32.NewProc("SHQueryRecycleBinW")
	var q shQueryRBInfo
	q.cbSize = uint32(unsafe.Sizeof(q))
	r, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&q)))
	if r != 0 {
		return 0
	}
	return q.i64Size
}

func cleanup() {
	section("Nettoyage en profondeur")
	info("Astuce : fermez vos navigateurs et jeux pour un nettoyage plus complet.")
	freeBefore, _ := diskFree(systemDrive())

	local := os.Getenv("LOCALAPPDATA")
	win := os.Getenv("SystemRoot")
	pd := os.Getenv("ProgramData")

	groups := []struct {
		label string
		paths []string // dossiers (le contenu est vidé) – motifs glob acceptés
	}{
		{"Fichiers temporaires utilisateur", []string{os.Getenv("TEMP")}},
		{"Fichiers temporaires Windows", []string{win + `\Temp`}},
		{"Rapports d'erreurs Windows", []string{pd + `\Microsoft\Windows\WER\ReportArchive`, pd + `\Microsoft\Windows\WER\ReportQueue`, local + `\Microsoft\Windows\WER`}},
		{"Fichiers de vidage (crash dumps)", []string{local + `\CrashDumps`, win + `\Minidump`}},
		{"Cache de shaders DirectX", []string{local + `\D3DSCache`}},
		{"Cache de shaders NVIDIA", []string{local + `\NVIDIA\DXCache`, local + `\NVIDIA\GLCache`, pd + `\NVIDIA Corporation\NV_Cache`}},
		{"Cache de shaders AMD", []string{local + `\AMD\DxCache`, local + `\AMD\GLCache`, local + `\AMD\DxcCache`, local + `\AMD\VkCache`}},
		{"Cache Intel", []string{local + `\Intel\ShaderCache`}},
		{"Cache Google Chrome", browserCaches(local + `\Google\Chrome\User Data`)},
		{"Cache Microsoft Edge", browserCaches(local + `\Microsoft\Edge\User Data`)},
		{"Cache Brave", browserCaches(local + `\BraveSoftware\Brave-Browser\User Data`)},
		{"Cache Opera", []string{local + `\Opera Software\Opera Stable\Cache`, local + `\Opera Software\Opera GX Stable\Cache`}},
		{"Cache Mozilla Firefox", []string{local + `\Mozilla\Firefox\Profiles\*\cache2`}},
		{"Cache Discord", []string{os.Getenv("APPDATA") + `\discord\Cache`, os.Getenv("APPDATA") + `\discord\Code Cache`, os.Getenv("APPDATA") + `\discord\GPUCache`}},
	}

	for _, g := range groups {
		var freed int64
		found := false
		for _, p := range g.paths {
			// Sécurité : si une variable d'environnement est vide, le chemin
			// commencerait par « \ » (racine du disque) -> on l'ignore.
			if p == "" || strings.HasPrefix(p, `\`) {
				continue
			}
			matches, _ := filepath.Glob(p)
			for _, m := range matches {
				if st, err := os.Stat(m); err == nil && st.IsDir() {
					found = true
					freed += cleanDir(m)
				}
			}
		}
		if found {
			ok("%-36s %s libérés", g.label, humanSize(freed))
		}
	}

	// Cache des miniatures (une partie peut être verrouillée par l'Explorateur).
	if local != "" {
		if f := removeGlob(local + `\Microsoft\Windows\Explorer\thumbcache_*.db`); f > 0 {
			ok("%-36s %s libérés", "Cache des miniatures", humanSize(f))
		}
	}

	// Cache Windows Update (nécessite l'arrêt du service).
	info("Arrêt temporaire de Windows Update...")
	runQuiet("net", "stop", "wuauserv", "/y")
	runQuiet("net", "stop", "bits", "/y")
	var f int64
	if win != "" {
		f = cleanDir(win + `\SoftwareDistribution\Download`)
	}
	runQuiet("net", "start", "bits")
	runQuiet("net", "start", "wuauserv")
	ok("%-36s %s libérés", "Cache Windows Update", humanSize(f))

	// Cache d'optimisation de la distribution.
	if _, err := powershell(`Delete-DeliveryOptimizationCache -Force -ErrorAction Stop`); err == nil {
		ok("Cache d'optimisation de la distribution vidé")
	}

	// Corbeille.
	rb := recycleBinSize()
	emptyRecycleBin()
	ok("%-36s %s libérés", "Corbeille", humanSize(rb))

	freeAfter, _ := diskFree(systemDrive())
	if freeAfter > freeBefore {
		fmt.Println("\n  " + col(cBold+cGreen, fmt.Sprintf("Espace libéré sur %s : %s", systemDrive(), humanSize(int64(freeAfter-freeBefore)))))
	}
}

// browserCaches renvoie les motifs des dossiers cache de tous les profils
// d'un navigateur Chromium (les historiques, mots de passe et cookies ne sont PAS touchés).
func browserCaches(userData string) []string {
	return []string{
		userData + `\*\Cache`,
		userData + `\*\Code Cache`,
		userData + `\*\GPUCache`,
		userData + `\ShaderCache`,
		userData + `\GrShaderCache`,
	}
}

// ================================================================ 3. Alimentation

const (
	guidUltimate = "e9a42b02-d5df-448d-aa00-03f14749eb61" // modèle « Performances optimales »
	guidOptiPC   = "4f9f1c5e-7a2b-4d3c-9e8f-0a1b2c3d4e5f" // copie créée par Opti-PC
	guidHigh     = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" // Performances élevées
	guidBalanced = "381b4222-f694-41f0-9685-ff5bb260df2e" // Utilisation normale
)

// activatePowerPlan active « Performances optimales » (ou à défaut « Performances élevées »).
func activatePowerPlan() {
	if _, err := runQuiet("powercfg", "/setactive", guidOptiPC); err == nil {
		ok("Plan « Opti-PC Performances optimales » activé")
		return
	}
	runQuiet("powercfg", "/duplicatescheme", guidUltimate, guidOptiPC)
	runQuiet("powercfg", "/changename", guidOptiPC, "Opti-PC Performances optimales")
	if _, err := runQuiet("powercfg", "/setactive", guidOptiPC); err == nil {
		ok("Plan « Opti-PC Performances optimales » créé et activé")
		return
	}
	if _, err := runQuiet("powercfg", "/setactive", guidHigh); err == nil {
		ok("Plan « Performances élevées » activé (Performances optimales indisponible)")
		return
	}
	fail("Impossible de changer le plan d'alimentation (verrouillé par le fabricant ?)")
}

func powerPlanApply() {
	section("Plan d'alimentation maximal")
	activatePowerPlan()
	_, err := runQuiet("powercfg", "/change", "disk-timeout-ac", "0")
	check("Mise en veille des disques désactivée (sur secteur)", err)
	// Désactive la suspension sélective USB (évite les micro-coupures de périphériques).
	_, err = runQuiet("powercfg", "/setacvalueindex", "scheme_current",
		"2a737441-1930-4402-8d77-b2bebba308a3", "48e6b7a6-50f5-4782-a5d4-53bb8f07e226", "0")
	if err == nil {
		runQuiet("powercfg", "/setactive", "scheme_current")
		ok("Suspension sélective USB désactivée (sur secteur)")
	}
	if hasBattery() {
		warn("PC portable détecté : ce plan consomme plus de batterie. Restaurez avec [R] si besoin.")
	}
}

func powerPlanRestore() {
	section("Plan d'alimentation")
	_, err := runQuiet("powercfg", "/setactive", guidBalanced)
	check("Plan « Utilisation normale » réactivé", err)
	runQuiet("powercfg", "/delete", guidOptiPC)
	runQuiet("powercfg", "/setacvalueindex", guidBalanced,
		"2a737441-1930-4402-8d77-b2bebba308a3", "48e6b7a6-50f5-4782-a5d4-53bb8f07e226", "1")
	_, err = runQuiet("powercfg", "/change", "disk-timeout-ac", "20")
	check("Mise en veille des disques après 20 min (par défaut)", err)
}

// ================================================================ 4. Effets visuels

var visualTweaks = []regTweak{
	{"Effets visuels en mode personnalisé", HKCU, `Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects`, "VisualFXSetting", 3, 0},
	{"Animations de l'interface désactivées", HKCU, `Control Panel\Desktop`, "UserPreferencesMask",
		[]byte{0x90, 0x12, 0x03, 0x80, 0x10, 0x00, 0x00, 0x00}, []byte{0x9E, 0x3E, 0x07, 0x80, 0x12, 0x00, 0x00, 0x00}},
	{"Animation des fenêtres (réduire/agrandir)", HKCU, `Control Panel\Desktop\WindowMetrics`, "MinAnimate", "0", "1"},
	{"Animations de la barre des tâches", HKCU, `Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`, "TaskbarAnimations", 0, 1},
	{"Rectangle de sélection translucide", HKCU, `Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`, "ListviewAlphaSelect", 0, 1},
	{"Ombres sous les icônes du bureau", HKCU, `Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`, "ListviewShadow", 0, 1},
	{"Aero Peek", HKCU, `Software\Microsoft\Windows\DWM`, "EnableAeroPeek", 0, 1},
	{"Effets de transparence", HKCU, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, "EnableTransparency", 0, 1},
	{"Lissage des polices conservé", HKCU, `Control Panel\Desktop`, "FontSmoothing", "2", "2"},
}

func visualApply() {
	section("Effets visuels allégés")
	applyReg(visualTweaks)
	info("Prend effet après déconnexion ou redémarrage.")
}

func visualRestore() { section("Effets visuels"); restoreReg(visualTweaks) }

// ================================================================ 5. Jeux

const gamesTask = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games`

var gamingTweaks = []regTweak{
	{"Mode Jeu activé", HKCU, `Software\Microsoft\GameBar`, "AutoGameModeEnabled", 1, 1},
	{"Mode Jeu autorisé", HKCU, `Software\Microsoft\GameBar`, "AllowAutoGameMode", 1, 1},
	{"Enregistrement Game DVR désactivé", HKCU, `System\GameConfigStore`, "GameDVR_Enabled", 0, 1},
	{"Captures en arrière-plan désactivées", HKCU, `Software\Microsoft\Windows\CurrentVersion\GameDVR`, "AppCaptureEnabled", 0, nil},
	{"Game DVR désactivé (stratégie système)", HKLM, `SOFTWARE\Policies\Microsoft\Windows\GameDVR`, "AllowGameDVR", 0, nil},
	{"Planification GPU accélérée par le matériel", HKLM, `SYSTEM\CurrentControlSet\Control\GraphicsDrivers`, "HwSchMode", 2, nil},
	{"Priorité GPU des jeux : maximale", HKLM, gamesTask, "GPU Priority", 8, 8},
	{"Priorité CPU des jeux : haute", HKLM, gamesTask, "Priority", 6, 2},
	{"Catégorie de planification des jeux : haute", HKLM, gamesTask, "Scheduling Category", "High", "Medium"},
	{"Priorité E/S des jeux : haute", HKLM, gamesTask, "SFIO Priority", "High", "Normal"},
	{"Accélération de la souris désactivée", HKCU, `Control Panel\Mouse`, "MouseSpeed", "0", "1"},
	{"Accélération de la souris (seuil 1)", HKCU, `Control Panel\Mouse`, "MouseThreshold1", "0", "6"},
	{"Accélération de la souris (seuil 2)", HKCU, `Control Panel\Mouse`, "MouseThreshold2", "0", "10"},
}

func gamingApply() {
	section("Optimisations jeux")
	applyReg(gamingTweaks)
	info("La planification GPU nécessite une carte graphique compatible et un redémarrage.")
}

func gamingRestore() { section("Jeux"); restoreReg(gamingTweaks) }

// ================================================================ 6. Réseau

const (
	systemProfile = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile`
	tcpInterfaces = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`
)

var networkTweaks = []regTweak{
	{"Limitation du débit réseau supprimée", HKLM, systemProfile, "NetworkThrottlingIndex", uint32(0xFFFFFFFF), 10},
}

func networkApply() {
	section("Optimisations réseau")
	_, err := runQuiet("ipconfig", "/flushdns")
	check("Cache DNS vidé", err)
	_, err = runQuiet("netsh", "int", "tcp", "set", "global", "autotuninglevel=normal")
	check("Réglage automatique de la fenêtre TCP : normal", err)
	_, err = runQuiet("netsh", "int", "tcp", "set", "global", "rss=enabled")
	check("Mise à l'échelle côté réception (RSS) activée", err)
	applyReg(networkTweaks)

	n := 0
	for _, id := range regSubKeys(HKLM, tcpInterfaces) {
		p := tcpInterfaces + `\` + id
		if regSet(HKLM, p, "TcpAckFrequency", 1) == nil && regSet(HKLM, p, "TCPNoDelay", 1) == nil {
			n++
		}
	}
	ok("Algorithme de Nagle désactivé sur %d interface(s) (ping réduit en jeu)", n)
}

func networkRestore() {
	section("Réseau")
	restoreReg(networkTweaks)
	for _, id := range regSubKeys(HKLM, tcpInterfaces) {
		p := tcpInterfaces + `\` + id
		regDelete(HKLM, p, "TcpAckFrequency")
		regDelete(HKLM, p, "TCPNoDelay")
	}
	ok("Algorithme de Nagle réactivé")
}

// ================================================================ 7. Confidentialité / arrière-plan

const cdm = `Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager`

var privacyTweaks = []regTweak{
	{"Télémétrie réduite au minimum", HKLM, `SOFTWARE\Policies\Microsoft\Windows\DataCollection`, "AllowTelemetry", 0, nil},
	{"Identifiant publicitaire désactivé", HKCU, `Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo`, "Enabled", 0, 1},
	{"Installation silencieuse d'applis suggérées bloquée", HKCU, cdm, "SilentInstalledAppsEnabled", 0, 1},
	{"Suggestions dans le menu Démarrer désactivées", HKCU, cdm, "SystemPaneSuggestionsEnabled", 0, 1},
	{"Astuces et conseils Windows désactivés", HKCU, cdm, "SubscribedContent-338389Enabled", 0, 1},
	{"Suggestions dans les Paramètres désactivées", HKCU, cdm, "SubscribedContent-338393Enabled", 0, 1},
	{"Recherche Bing du menu Démarrer désactivée", HKCU, `Software\Microsoft\Windows\CurrentVersion\Search`, "BingSearchEnabled", 0, nil},
	{"Suggestions web de la recherche désactivées", HKCU, `Software\Policies\Microsoft\Windows\Explorer`, "DisableSearchBoxSuggestions", 1, nil},
	{"Edge : préchargement au démarrage désactivé", HKLM, `SOFTWARE\Policies\Microsoft\Edge`, "StartupBoostEnabled", 0, nil},
	{"Edge : exécution en arrière-plan désactivée", HKLM, `SOFTWARE\Policies\Microsoft\Edge`, "BackgroundModeEnabled", 0, nil},
}

type service struct{ name, label, optimized, def string }

var services = []service{
	{"DiagTrack", "Télémétrie (Expériences utilisateur connectées)", "disabled", "auto"},
	{"dmwappushservice", "Routage des messages push WAP", "disabled", "demand"},
	{"RetailDemo", "Démonstration en magasin", "disabled", "demand"},
	{"MapsBroker", "Gestionnaire des cartes téléchargées", "disabled", "delayed-auto"},
	{"Fax", "Télécopie", "disabled", "demand"},
}

var scheduledTasks = []string{
	`\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser`,
	`\Microsoft\Windows\Application Experience\ProgramDataUpdater`,
	`\Microsoft\Windows\Customer Experience Improvement Program\Consolidator`,
	`\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip`,
	`\Microsoft\Windows\Autochk\Proxy`,
	`\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector`,
}

func setService(s service, mode string, stop bool) {
	out, err := runQuiet("sc.exe", "config", s.name, "start=", mode)
	if err != nil {
		if exitCode(err) == 1060 { // service inexistant sur cette édition
			return
		}
		fail("Service %s : %s", s.label, lastLine(out))
		return
	}
	if stop {
		runQuiet("sc.exe", "stop", s.name)
		ok("Service désactivé : %s", s.label)
	} else {
		ok("Service rétabli : %s", s.label)
	}
}

func setTasks(enable bool) {
	flag, verb := "/Disable", "désactivée"
	if enable {
		flag, verb = "/Enable", "réactivée"
	}
	n := 0
	for _, t := range scheduledTasks {
		if _, err := runQuiet("schtasks", "/Change", "/TN", t, flag); err == nil {
			n++
		}
	}
	ok("%d tâche(s) planifiée(s) de collecte de données %s(s)", n, verb)
}

func privacyApply() {
	section("Confidentialité et arrière-plan")
	applyReg(privacyTweaks)
	for _, s := range services {
		setService(s, s.optimized, true)
	}
	setTasks(false)
}

func privacyRestore() {
	section("Confidentialité et arrière-plan")
	restoreReg(privacyTweaks)
	for _, s := range services {
		setService(s, s.def, false)
	}
	setTasks(true)
}

// ================================================================ 8. Réactivité

var responsivenessTweaks = []regTweak{
	{"Délai d'ouverture des menus : 400 → 0 ms", HKCU, `Control Panel\Desktop`, "MenuShowDelay", "0", "400"},
	{"Délai de lancement des programmes au démarrage supprimé", HKCU, `Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize`, "StartupDelayInMSec", 0, nil},
	{"Priorité CPU au programme au premier plan", HKLM, `SYSTEM\CurrentControlSet\Control\PriorityControl`, "Win32PrioritySeparation", 0x26, 2},
	{"CPU réservé aux tâches de fond : 20 % → 10 %", HKLM, systemProfile, "SystemResponsiveness", 10, 20},
	{"Arrêt du PC plus rapide (services : 5 s → 2 s)", HKLM, `SYSTEM\CurrentControlSet\Control`, "WaitToKillServiceTimeout", "2000", "5000"},
}

func responsivenessApply() {
	section("Réactivité du système")
	applyReg(responsivenessTweaks)
}

func responsivenessRestore() { section("Réactivité"); restoreReg(responsivenessTweaks) }

// ================================================================ 9. Disques

func disksOptimize() {
	section("Optimisation des disques")
	info("Windows choisit automatiquement : TRIM pour les SSD, défragmentation pour les HDD.")
	info("Sur un disque dur classique, cela peut prendre du temps...\n")
	err := runLive("defrag", "/C", "/O", "/H", "/U")
	fmt.Println()
	check("Optimisation de tous les disques", err)
}

// ================================================================ 10. Hibernation

func hibernateOff() {
	section("Hibernation")
	size := int64(0)
	if st, err := os.Stat(systemDrive() + "hiberfil.sys"); err == nil {
		size = st.Size()
	}
	_, err := runQuiet("powercfg", "/hibernate", "off")
	if err != nil {
		fail("Impossible de désactiver l'hibernation")
		return
	}
	if hasBattery() {
		warn("PC portable : la mise en veille prolongée n'est plus disponible (réactivable avec [R]).")
	}
	if size > 0 {
		ok("Hibernation désactivée : %s libérés", humanSize(size))
	} else {
		ok("Hibernation désactivée")
	}
}

func hibernateOn() {
	section("Hibernation")
	_, err := runQuiet("powercfg", "/hibernate", "on")
	check("Hibernation réactivée", err)
}

// ================================================================ 11. Réparation

func repairWindows() {
	section("Réparation de Windows")
	if !confirm("  Cette opération peut durer 15 à 45 minutes. Continuer ?") {
		return
	}
	info("Étape 1/3 : réparation de l'image système (DISM)...\n")
	check("DISM RestoreHealth", runLive("DISM", "/Online", "/Cleanup-Image", "/RestoreHealth"))
	info("Étape 2/3 : vérification des fichiers système (SFC)...\n")
	check("SFC scannow", runLive("sfc", "/scannow"))
	info("Étape 3/3 : nettoyage des anciennes versions de composants...\n")
	check("DISM StartComponentCleanup", runLive("DISM", "/Online", "/Cleanup-Image", "/StartComponentCleanup"))
}

// ================================================================ 12. Démarrage

type startupEntry struct{ name, cmd string }

// startupEntries liste les programmes lancés au démarrage (registre + dossiers Démarrage).
func startupEntries() []startupEntry {
	var list []startupEntry
	keys := []struct {
		root registry.Key
		path string
	}{
		{HKCU, `Software\Microsoft\Windows\CurrentVersion\Run`},
		{HKLM, `Software\Microsoft\Windows\CurrentVersion\Run`},
		{HKLM, `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`},
	}
	for _, k := range keys {
		for name, cmd := range regValues(k.root, k.path) {
			list = append(list, startupEntry{name, cmd})
		}
	}
	for _, dir := range []string{
		os.Getenv("APPDATA") + `\Microsoft\Windows\Start Menu\Programs\Startup`,
		os.Getenv("ProgramData") + `\Microsoft\Windows\Start Menu\Programs\StartUp`,
	} {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if strings.EqualFold(e.Name(), "desktop.ini") {
				continue
			}
			list = append(list, startupEntry{strings.TrimSuffix(e.Name(), ".lnk"), "(dossier Démarrage)"})
		}
	}
	return list
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-3]) + "..."
}

func startupPrograms() {
	section("Programmes lancés au démarrage")
	list := startupEntries()
	for _, e := range list {
		fmt.Printf("  %s %-28s %s\n", col(cCyan, "•"), truncate(e.name, 28), col(cDim, truncate(e.cmd, 70)))
	}
	fmt.Printf("\n  %d programme(s) au démarrage. Moins il y en a, plus Windows démarre vite.\n", len(list))
	if confirm("\n  Ouvrir le Gestionnaire des tâches pour en désactiver ?") {
		exec.Command("taskmgr.exe", "/0", "/startup").Start()
	}
}
