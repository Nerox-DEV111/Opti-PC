package main

// Fonctions utilitaires bas niveau Windows : droits admin, console, registre,
// exécution de commandes, informations système.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	shell32                  = windows.NewLazySystemDLL("shell32.dll")
	procSetConsoleTitleW     = kernel32.NewProc("SetConsoleTitleW")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemPowerStatus = kernel32.NewProc("GetSystemPowerStatus")
	procSHEmptyRecycleBinW   = shell32.NewProc("SHEmptyRecycleBinW")
)

// ---------------------------------------------------------------- Admin

func isAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// relaunchAsAdmin relance l'exécutable avec l'invite UAC.
func relaunchAsAdmin() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cwd, _ := os.Getwd()
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	dir, _ := windows.UTF16PtrFromString(cwd)
	args, _ := windows.UTF16PtrFromString(strings.Join(os.Args[1:], " "))
	return windows.ShellExecute(0, verb, file, args, dir, windows.SW_NORMAL)
}

// ---------------------------------------------------------------- Console

var useColor = true

func setupConsole() {
	title, _ := windows.UTF16PtrFromString("Opti-PC - Optimiseur Windows")
	procSetConsoleTitleW.Call(uintptr(unsafe.Pointer(title)))

	h := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		useColor = false
		return
	}
	if err := windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		useColor = false
	}
}

// ---------------------------------------------------------------- Commandes

// runQuiet exécute une commande sans afficher sa sortie.
func runQuiet(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// runLive exécute une commande en affichant sa sortie directement dans la console.
func runLive(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func powershell(script string) (string, error) {
	return runQuiet("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}

// ---------------------------------------------------------------- Registre

func regSet(root registry.Key, path, name string, v interface{}) error {
	k, _, err := registry.CreateKey(root, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	switch x := v.(type) {
	case uint32:
		return k.SetDWordValue(name, x)
	case int:
		return k.SetDWordValue(name, uint32(x))
	case string:
		return k.SetStringValue(name, x)
	case []byte:
		return k.SetBinaryValue(name, x)
	}
	return fmt.Errorf("type de valeur non géré : %T", v)
}

func regDelete(root registry.Key, path, name string) error {
	k, err := registry.OpenKey(root, path, registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

func regString(root registry.Key, path, name string) string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	s, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return s
}

func regSubKeys(root registry.Key, path string) []string {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	return names
}

// regValues renvoie les paires nom -> valeur (chaînes) d'une clé.
func regValues(root registry.Key, path string) map[string]string {
	out := map[string]string{}
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return out
	}
	defer k.Close()
	names, _ := k.ReadValueNames(-1)
	for _, n := range names {
		if s, _, err := k.GetStringValue(n); err == nil {
			out[n] = s
		}
	}
	return out
}

// ---------------------------------------------------------------- Fichiers

func dirSize(path string) int64 {
	var total int64
	filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			if info, err := d.Info(); err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}

// cleanDir supprime le contenu d'un dossier (pas le dossier lui-même).
// Les fichiers verrouillés sont ignorés. Renvoie le nombre d'octets libérés.
func cleanDir(path string) int64 {
	entries, err := os.ReadDir(path)
	if err != nil {
		return 0
	}
	before := dirSize(path)
	for _, e := range entries {
		os.RemoveAll(filepath.Join(path, e.Name()))
	}
	freed := before - dirSize(path)
	if freed < 0 {
		freed = 0
	}
	return freed
}

// removeGlob supprime les fichiers correspondant au motif. Renvoie les octets libérés.
func removeGlob(pattern string) int64 {
	matches, _ := filepath.Glob(pattern)
	var freed int64
	for _, m := range matches {
		info, err := os.Stat(m)
		if err != nil || info.IsDir() {
			continue
		}
		if os.Remove(m) == nil {
			freed += info.Size()
		}
	}
	return freed
}

func emptyRecycleBin() {
	// SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND
	procSHEmptyRecycleBinW.Call(0, 0, 0x7)
}

func humanSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d o", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %co", float64(b)/float64(div), "KMGTPE"[exp])
}

// ---------------------------------------------------------------- Infos système

func systemDrive() string {
	d := os.Getenv("SystemDrive")
	if d == "" {
		d = "C:"
	}
	return d + `\`
}

func diskFree(root string) (free, total uint64) {
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return 0, 0
	}
	var avail, tot, totFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &tot, &totFree); err != nil {
		return 0, 0
	}
	return totFree, tot
}

type memStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func memory() (total, avail uint64, load uint32) {
	var m memStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m)))
	if r == 0 {
		return 0, 0, 0
	}
	return m.TotalPhys, m.AvailPhys, m.MemoryLoad
}

type systemPowerStatus struct {
	ACLineStatus        byte
	BatteryFlag         byte
	BatteryLifePercent  byte
	SystemStatusFlag    byte
	BatteryLifeTime     uint32
	BatteryFullLifeTime uint32
}

// hasBattery indique si la machine est un portable (batterie détectée).
func hasBattery() bool {
	var s systemPowerStatus
	r, _, _ := procGetSystemPowerStatus.Call(uintptr(unsafe.Pointer(&s)))
	if r == 0 {
		return false
	}
	return s.BatteryFlag != 128 && s.BatteryFlag != 255
}

func windowsVersion() string {
	const p = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	name := regString(registry.LOCAL_MACHINE, p, "ProductName")
	build := regString(registry.LOCAL_MACHINE, p, "CurrentBuild")
	disp := regString(registry.LOCAL_MACHINE, p, "DisplayVersion")
	var b int
	fmt.Sscanf(build, "%d", &b)
	if b >= 22000 { // Windows 11 garde « Windows 10 » dans ProductName
		name = strings.Replace(name, "Windows 10", "Windows 11", 1)
	}
	s := name
	if disp != "" {
		s += " " + disp
	}
	if build != "" {
		s += " (build " + build + ")"
	}
	return s
}

func cpuName() string {
	return strings.TrimSpace(regString(registry.LOCAL_MACHINE,
		`HARDWARE\DESCRIPTION\System\CentralProcessor\0`, "ProcessorNameString"))
}

// exitCode extrait le code de sortie d'une erreur exec.
func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}
