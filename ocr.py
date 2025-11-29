import ctypes
import ctypes.wintypes as wt
import urllib.request
import urllib.parse
import argparse
import sys
import os
import struct
import ctypes
from ctypes import byref

ULONG = ctypes.c_ulong
ARGB = ctypes.c_uint32
HBITMAP = wt.HANDLE

class GdiplusStartupInput(ctypes.Structure):
    _fields_ = [
        ("GdiplusVersion", ULONG),
        ("DebugEventCallback", ctypes.c_void_p),
        ("SuppressBackgroundThread", ctypes.c_bool),
        ("SuppressExternalCodecs", ctypes.c_bool),
    ]

def gdiplus_startup():
    gdip = ctypes.WinDLL("gdiplus")
    token = ULONG(0)
    input_ = GdiplusStartupInput()
    input_.GdiplusVersion = 1
    input_.DebugEventCallback = None
    input_.SuppressBackgroundThread = False
    input_.SuppressExternalCodecs = False
    GdiplusStartup = gdip.GdiplusStartup
    GdiplusStartup.argtypes = [ctypes.POINTER(ULONG), ctypes.POINTER(GdiplusStartupInput), ctypes.c_void_p]
    GdiplusStartup.restype = ctypes.c_int
    status = GdiplusStartup(byref(token), byref(input_), None)
    if status != 0:
        return None, None
    return gdip, token

def gdiplus_shutdown(gdip, token):
    if not gdip or not token:
        return
    GdiplusShutdown = gdip.GdiplusShutdown
    GdiplusShutdown.argtypes = [ULONG]
    GdiplusShutdown.restype = None
    try:
        GdiplusShutdown(token)
    except Exception:
        pass

def create_hbitmap_from_file(path: str):
    gdip, token = gdiplus_startup()
    if not gdip:
        return None, None
    GdipCreateBitmapFromFile = gdip.GdipCreateBitmapFromFile
    GdipCreateBitmapFromFile.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
    GdipCreateBitmapFromFile.restype = ctypes.c_int
    bmp = ctypes.c_void_p()
    status = GdipCreateBitmapFromFile(path, byref(bmp))
    if status != 0 or not bmp:
        gdiplus_shutdown(gdip, token)
        return None, None
    GdipCreateHBITMAPFromBitmap = gdip.GdipCreateHBITMAPFromBitmap
    GdipCreateHBITMAPFromBitmap.argtypes = [ctypes.c_void_p, ctypes.POINTER(HBITMAP), ARGB]
    GdipCreateHBITMAPFromBitmap.restype = ctypes.c_int
    hbm = HBITMAP()
    status = GdipCreateHBITMAPFromBitmap(bmp, byref(hbm), ARGB(0xFFFFFFFF))
    if status != 0 or not hbm:
        gdiplus_shutdown(gdip, token)
        return None, None
    return (gdip, token, bmp), hbm

class CLSID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_ulong),
                ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort),
                ("Data4", ctypes.c_ubyte * 8)]

def save_bmp_from_file(src_path: str, dst_path: str):
    gdip, token = gdiplus_startup()
    if not gdip:
        return False
    GdipCreateBitmapFromFile = gdip.GdipCreateBitmapFromFile
    GdipCreateBitmapFromFile.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
    GdipCreateBitmapFromFile.restype = ctypes.c_int
    img = ctypes.c_void_p()
    if GdipCreateBitmapFromFile(src_path, byref(img)) != 0 or not img:
        gdiplus_shutdown(gdip, token)
        return False
    # BMP encoder CLSID {557CF400-1A04-11D3-9A73-0000F81EF32E}
    enc = CLSID(0x557CF400, 0x1A04, 0x11D3, (ctypes.c_ubyte * 8)(0x9A,0x73,0x00,0x00,0xF8,0x1E,0xF3,0x2E))
    GdipSaveImageToFile = gdip.GdipSaveImageToFile
    GdipSaveImageToFile.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.POINTER(CLSID), ctypes.c_void_p]
    GdipSaveImageToFile.restype = ctypes.c_int
    ok = (GdipSaveImageToFile(img, dst_path, byref(enc), None) == 0)
    gdiplus_shutdown(gdip, token)
    return ok

def delete_hbitmap(hbm):
    try:
        gdi32 = ctypes.WinDLL("gdi32")
        DeleteObject = gdi32.DeleteObject
        DeleteObject.argtypes = [HBITMAP]
        DeleteObject.restype = wt.BOOL
        DeleteObject(hbm)
    except Exception:
        pass

def fetch_bytes(url: str) -> bytes:
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "image/*"})
    try:
        with urllib.request.urlopen(req, context=ctx) as r:
            data = r.read()
    except Exception:
        import http.client
        u = urllib.parse.urlparse(url)
        conn = http.client.HTTPSConnection(u.hostname, u.port or 443, context=ctx)
        path = u.path + (('?' + u.query) if u.query else '')
        conn.request('GET', path, headers={"User-Agent":"Mozilla/5.0","Accept":"image/*","Connection":"close","Referer": f"{u.scheme}://{u.hostname}"})
        resp = conn.getresponse()
        data = resp.read()
    return data

def get_proc_by_name(hmod, name):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetProcAddress.argtypes = [wt.HMODULE, ctypes.c_void_p]
    kernel32.GetProcAddress.restype = ctypes.c_void_p
    ptr = kernel32.GetProcAddress(hmod, ctypes.c_char_p(name.encode("ascii")))
    return ptr

def get_proc_by_ordinal(hmod, ordinal: int):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetProcAddress.argtypes = [wt.HMODULE, ctypes.c_void_p]
    kernel32.GetProcAddress.restype = ctypes.c_void_p
    ptr = kernel32.GetProcAddress(hmod, ctypes.c_void_p(ordinal))
    return ptr

def make_func(ptr, argtypes, restype=ctypes.c_int):
    if not ptr:
        return None
    ftype = ctypes.WINFUNCTYPE(restype, *argtypes)
    return ftype(ptr)

def make_func_cdecl(ptr, argtypes, restype=ctypes.c_int):
    if not ptr:
        return None
    ftype = ctypes.CFUNCTYPE(restype, *argtypes)
    return ftype(ptr)

def try_signatures(func_ptr, img: bytes):
    out = ctypes.create_string_buffer(1024)
    in_arr = (ctypes.c_ubyte * len(img)).from_buffer_copy(img)
    variants = [
        ([ctypes.POINTER(ctypes.c_ubyte), wt.UINT, ctypes.c_char_p, wt.UINT], lambda f: f(in_arr, len(img), out, len(out))),
        ([ctypes.c_void_p, wt.UINT, ctypes.c_char_p, wt.UINT], lambda f: f(ctypes.cast(in_arr, ctypes.c_void_p), len(img), out, len(out))),
        ([ctypes.POINTER(ctypes.c_ubyte), wt.UINT, ctypes.c_char_p], lambda f: f(in_arr, len(img), out)),
        ([ctypes.c_void_p, wt.UINT, ctypes.c_char_p], lambda f: f(ctypes.cast(in_arr, ctypes.c_void_p), len(img), out)),
    ]
    for argt, inv in variants:
        for maker in (make_func, make_func_cdecl):
            fn = maker(func_ptr, argt)
            if not fn:
                continue
            try:
                rc = inv(fn)
            except Exception:
                continue
        txt = out.value.decode("utf-8", errors="ignore").strip()
        if txt:
            return rc, txt
    return None, None

def try_file_signatures(func_ptr, path: str):
    out = ctypes.create_string_buffer(1024)
    variants = [
        ([ctypes.c_char_p, ctypes.c_char_p, wt.UINT], lambda f: f(path.encode("utf-8"), out, len(out))),
        ([ctypes.c_char_p, wt.UINT, ctypes.c_char_p, wt.UINT], lambda f: f(path.encode("utf-8"), len(path), out, len(out))),
        ([ctypes.c_char_p, ctypes.c_char_p], lambda f: f(path.encode("utf-8"), out)),
    ]
    for argt, inv in variants:
        for maker in (make_func, make_func_cdecl):
            fn = maker(func_ptr, argt)
            if not fn:
                continue
            try:
                rc = inv(fn)
            except Exception:
                continue
        txt = out.value.decode("utf-8", errors="ignore").strip()
        if txt:
            return rc, txt
    return None, None

def try_wfile_signatures(func_ptr, path: str):
    out = ctypes.create_unicode_buffer(1024)
    variants = [
        ([ctypes.c_wchar_p, ctypes.c_wchar_p, wt.UINT], lambda f: f(path, out, len(out))),
        ([ctypes.c_wchar_p, wt.UINT, ctypes.c_wchar_p, wt.UINT], lambda f: f(path, len(path), out, len(out))),
        ([ctypes.c_wchar_p, ctypes.c_wchar_p], lambda f: f(path, out)),
    ]
    for argt, inv in variants:
        for maker in (make_func, make_func_cdecl):
            fn = maker(func_ptr, argt, restype=ctypes.c_int)
            if not fn:
                continue
            try:
                rc = inv(fn)
            except Exception:
                continue
        txt = out.value.strip()
        if txt:
            return rc, txt
    return None, None

def try_hbitmap_signatures(func_ptr, hbm: HBITMAP):
    out = ctypes.create_string_buffer(1024)
    variants = [
        ([HBITMAP, ctypes.c_char_p, wt.UINT], lambda f: f(hbm, out, len(out))),
        ([HBITMAP, ctypes.c_char_p], lambda f: f(hbm, out)),
    ]
    for argt, inv in variants:
        for maker in (make_func, make_func_cdecl):
            fn = maker(func_ptr, argt)
            if not fn:
                continue
            try:
                rc = inv(fn)
            except Exception:
                continue
        txt = out.value.decode("utf-8", errors="ignore").strip()
        if txt:
            return rc, txt
    return None, None

def enum_exports(path: str):
    try:
        with open(path, "rb") as f:
            b = f.read()
    except Exception:
        return []
    if len(b) < 0x100:
        return []
    e_lfanew = struct.unpack_from("<I", b, 0x3C)[0]
    if e_lfanew + 0x100 > len(b):
        return []
    if b[e_lfanew:e_lfanew+4] != b"PE\0\0":
        return []
    num_sections = struct.unpack_from("<H", b, e_lfanew+6)[0]
    opt_size = struct.unpack_from("<H", b, e_lfanew+20)[0]
    opt_off = e_lfanew + 24
    magic = struct.unpack_from("<H", b, opt_off)[0]
    dir_off = opt_off + (96 if magic == 0x10B else 112)
    export_rva = struct.unpack_from("<I", b, dir_off)[0]
    sections_off = opt_off + opt_size
    sections = []
    for i in range(num_sections):
        off = sections_off + 40*i
        if off + 40 > len(b):
            break
        va = struct.unpack_from("<I", b, off+12)[0]
        rs = struct.unpack_from("<I", b, off+16)[0]
        rp = struct.unpack_from("<I", b, off+20)[0]
        sections.append((va, rp, rs))
    def rva_to_off(rva):
        for va, rp, rs in sections:
            if va <= rva < va + max(rs, 0x1000):
                return rp + (rva - va)
        return None
    if not export_rva:
        return []
    exp_off = rva_to_off(export_rva)
    if exp_off is None or exp_off + 40 > len(b):
        return []
    base = struct.unpack_from("<I", b, exp_off+16)[0]
    num_funcs = struct.unpack_from("<I", b, exp_off+20)[0]
    num_names = struct.unpack_from("<I", b, exp_off+24)[0]
    funcs_rva = struct.unpack_from("<I", b, exp_off+28)[0]
    names_rva = struct.unpack_from("<I", b, exp_off+32)[0]
    ords_rva = struct.unpack_from("<I", b, exp_off+36)[0]
    funcs_off = rva_to_off(funcs_rva)
    names_off = rva_to_off(names_rva)
    ords_off = rva_to_off(ords_rva)
    if None in (funcs_off, names_off, ords_off):
        return []
    exports = []
    # named exports
    for i in range(num_names):
        name_rva = struct.unpack_from("<I", b, names_off + 4*i)[0]
        name_off = rva_to_off(name_rva)
        if not name_off:
            continue
        s = []
        j = name_off
        while j < len(b) and b[j] != 0:
            s.append(chr(b[j]))
            j += 1
        name = "".join(s)
        ord_index = struct.unpack_from("<H", b, ords_off + 2*i)[0]
        ordinal = base + ord_index
        exports.append((name, ordinal))
    # unnamed ordinals
    if funcs_off is not None:
        for i in range(num_funcs):
            ordinal = base + i
            exports.append((None, ordinal))
    # dedup
    seen = set()
    uniq = []
    for name, ordinal in exports:
        if ordinal in seen:
            continue
        seen.add(ordinal)
        uniq.append((name, ordinal))
    return uniq

def ocr_recognize(src: str, dll_path: str | None = None, attempt_ordinal: int = 2, try_mem: bool = True, try_bmp: bool = False) -> str | None:
    os.environ.setdefault("GLOG_minloglevel", "2")
    os.environ.setdefault("GLOG_logtostderr", "1")
    local_path = None
    try:
        if os.path.isfile(src):
            with open(src, "rb") as f:
                img = f.read()
            local_path = os.path.abspath(src)
        else:
            img = fetch_bytes(src)
    except Exception:
        return None
    if not dll_path:
        dll_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ocr.dll")
    try:
        lib = ctypes.WinDLL(dll_path)
    except Exception:
        return None
    hmod = lib._handle
    exps = enum_exports(dll_path)
    if attempt_ordinal is not None:
        ptr = get_proc_by_ordinal(hmod, attempt_ordinal)
        if not ptr:
            return None
        names = {name: ordv for name, ordv in exps if name}
        if "init" in names:
            iptr = get_proc_by_ordinal(hmod, names["init"])
            if iptr:
                try:
                    init_fn = make_func(iptr, [])
                    if init_fn:
                        init_fn()
                except Exception:
                    pass
        if try_mem:
            rcM, txtM = try_signatures(ptr, img)
            if txtM:
                return txtM
        if try_mem:
            try:
                buf = (ctypes.c_ubyte * len(img)).from_buffer_copy(img)
                addr = ctypes.addressof(buf)
                val1 = (ctypes.c_longlong((addr & 0xFFFFFFFF) | (len(img) << 32))).value
                val2 = (ctypes.c_longlong(((len(img) & 0xFFFFFFFF) | (addr << 32)) & 0xFFFFFFFFFFFFFFFF)).value
                fn = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_longlong)(ptr)
                ret = fn(val1)
                if ret:
                    try:
                        s = ctypes.string_at(ret).decode("utf-8", errors="ignore").strip("\x00").strip()
                    except Exception:
                        s = None
                    if not s:
                        try:
                            s = ctypes.wstring_at(ret).strip("\x00").strip()
                        except Exception:
                            s = None
                    if s:
                        return s
            except Exception:
                pass
            try:
                fn2 = ctypes.WINFUNCTYPE(ctypes.c_void_p, ctypes.c_longlong)(ptr)
                ret2 = fn2(val2)
                if ret2:
                    try:
                        s2 = ctypes.string_at(ret2).decode("utf-8", errors="ignore").strip("\x00").strip()
                    except Exception:
                        s2 = None
                    if not s2:
                        try:
                            s2 = ctypes.wstring_at(ret2).strip("\x00").strip()
                        except Exception:
                            s2 = None
                    if s2:
                        return s2
            except Exception:
                pass
            rcM, txtM = try_signatures(ptr, img)
            if txtM:
                return txtM
        if try_bmp and local_path:
            gdip_ctx, hbm = create_hbitmap_from_file(local_path)
            if hbm:
                rcB, txtB = try_hbitmap_signatures(ptr, hbm)
                delete_hbitmap(hbm)
                if gdip_ctx and gdip_ctx[0]:
                    gdiplus_shutdown(gdip_ctx[0], gdip_ctx[1])
                if txtB:
                    return txtB
        if local_path:
            rc2, txt2 = try_file_signatures(ptr, local_path)
            if txt2:
                return txt2
            rc3, txt3 = try_wfile_signatures(ptr, local_path)
            if txt3:
                return txt3
        if "un" in names:
            uptr = get_proc_by_ordinal(hmod, names["un"])
            if uptr:
                try:
                    un_fn = make_func(uptr, [])
                    if un_fn:
                        un_fn()
                except Exception:
                    pass
        return None
    candidates = ["ocr","Recognize","OCR_Recognize","RecognizeImage","DoOCR","Parse","GetText"]
    func_ptr = None
    for name in candidates:
        ptr = get_proc_by_name(hmod, name)
        if ptr:
            func_ptr = ptr
            break
    if not func_ptr:
        return None
    rc, txt = try_signatures(func_ptr, img)
    if txt:
        return txt
    return None

def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("src")
    parser.add_argument("--dll", dest="dll", default=None)
    parser.add_argument("--no-mem", dest="no_mem", action="store_true", help="disable memory buffer calling")
    parser.add_argument("--bmp", dest="use_bmp", action="store_true", help="enable HBITMAP calling variants")
    parser.add_argument("--ordinal", dest="ordinal", type=int, default=2, help="override attempt ordinal, use -1 to disable")
    args = parser.parse_args()
    ordv = None if (args.ordinal is not None and args.ordinal < 0) else args.ordinal
    txt = ocr_recognize(args.src, dll_path=args.dll, attempt_ordinal=ordv, try_mem=(not args.no_mem), try_bmp=args.use_bmp)
    if txt:
        print(txt)
        return 0
    return 5

if __name__ == "__main__":
    sys.exit(main())

