#!/usr/bin/env python3
"""
Features:
  - Accept gadget source as local path, URL, "latest", or X.Y.Z
  - Download gadget from frida/frida GitHub releases
  - Decompress .gz/.xz assets
  - Extract IPA, embed gadget dylib, optional config
  - Patch main Mach-O to load gadget (@executable_path/...)
  - Optional best-effort signing with ldid (if installed)
  - Repack IPA
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import lzma
import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path


GITHUB_LATEST_URL = "https://api.github.com/repos/frida/frida/releases/latest"
GITHUB_TAG_URL = "https://api.github.com/repos/frida/frida/releases/tags/{tag}"

FIREFOX_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"


class Logger:
    def __init__(self) -> None:
        self._is_tty = sys.stdout.isatty()
        self._color = self._is_tty and os.environ.get("NO_COLOR") is None
        self._gha = os.environ.get("GITHUB_ACTIONS", "").lower() == "true"

    def _c(self, code: str, s: str) -> str:
        if not self._color:
            return s
        return f"\033[{code}m{s}\033[0m"

    def step(self, msg: str) -> None:
        print(f"{self._c('36', '==>')} {msg}")

    def info(self, msg: str) -> None:
        print(f"    {msg}")

    def ok(self, msg: str) -> None:
        print(f"{self._c('32', 'OK')}: {msg}")

    def warn(self, msg: str) -> None:
        if self._gha:
            print(f"::warning::{msg}", file=sys.stderr)
        else:
            print(f"{self._c('33', 'WARN')}: {msg}", file=sys.stderr)

    def error(self, msg: str) -> None:
        if self._gha:
            print(f"::error::{msg}", file=sys.stderr)
        else:
            print(f"{self._c('31', 'ERROR')}: {msg}", file=sys.stderr)


LOG = Logger()


def _error(msg: str) -> None:
    LOG.error(msg)


def _warn(msg: str) -> None:
    LOG.warn(msg)


def _is_url(value: str) -> bool:
    return value.startswith("http://") or value.startswith("https://")


def _download(url: str, dst: Path, github_token: str | None) -> None:
    headers = {
        "User-Agent": FIREFOX_UA,
        "Accept": "application/vnd.github+json",
    }
    req = urllib.request.Request(url, headers=headers)
    if github_token:
        req.add_header("Authorization", f"Bearer {github_token}")
    try:
        with urllib.request.urlopen(req) as r:
            data = r.read()
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            pass
        raise RuntimeError(f"HTTP {e.code} downloading {url}: {body[:200]}") from e
    dst.write_bytes(data)


def _github_json(url: str, github_token: str | None) -> dict:
    tmp = io.BytesIO()
    headers = {
        "User-Agent": FIREFOX_UA,
        "Accept": "application/vnd.github+json",
    }
    req = urllib.request.Request(url, headers=headers)
    if github_token:
        req.add_header("Authorization", f"Bearer {github_token}")
    with urllib.request.urlopen(req) as r:
        tmp.write(r.read())
    return json.loads(tmp.getvalue().decode("utf-8"))


def _pick_gadget_asset(release: dict) -> str:
    assets = release.get("assets") or []
    patterns = [
        re.compile(r"^frida-gadget-.*-ios-universal\.dylib\.gz$"),
        re.compile(r"^frida-gadget-.*-ios-universal\.dylib\.xz$"),
        re.compile(r"^frida-gadget-.*-ios-universal\.dylib$"),
    ]
    for pat in patterns:
        for a in assets:
            name = a.get("name", "")
            if pat.match(name):
                url = a.get("browser_download_url", "")
                if url:
                    return url
    raise RuntimeError("No ios-universal Frida Gadget asset found in release")


def _decompress_if_needed(src: Path, out_dir: Path) -> Path:
    if src.name.endswith(".gz"):
        out_path = out_dir / src.name[: -len(".gz")]
        with gzip.open(src, "rb") as f_in, out_path.open("wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        return out_path
    if src.name.endswith(".xz"):
        out_path = out_dir / src.name[: -len(".xz")]
        with lzma.open(src, "rb") as f_in, out_path.open("wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        return out_path
    return src


def resolve_gadget(value: str, download_dir: Path, github_token: str | None) -> Path:
    p = Path(value)
    if p.is_file():
        resolved = p.resolve()
        LOG.step("Using local gadget dylib")
        LOG.info(str(resolved))
        return resolved

    if _is_url(value):
        LOG.step("Downloading gadget dylib")
        LOG.info(f"URL: {value}")
        dst = download_dir / Path(value.split("?", 1)[0]).name
        _download(value, dst, github_token=None)
        out = _decompress_if_needed(dst, download_dir)
        LOG.ok(f"Gadget saved to: {out}")
        return out

    if value == "latest" or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value) or re.fullmatch(
        r"v[0-9]+\.[0-9]+\.[0-9]+", value
    ):
        api_url = GITHUB_LATEST_URL if value == "latest" else GITHUB_TAG_URL.format(tag=value.lstrip("v"))
        LOG.step("Resolving Frida Gadget from GitHub Releases")
        LOG.info(f"API: {api_url}")
        release = _github_json(api_url, github_token=github_token)
        # GitHub sometimes returns {"message": "..."} on errors/rate limiting.
        if isinstance(release, dict) and release.get("message") and not release.get("assets"):
            raise RuntimeError(f"GitHub API error: {release.get('message')}")
        tag_name = release.get("tag_name") if isinstance(release, dict) else None
        if tag_name:
            if value == "latest":
                LOG.info(f"Version: {tag_name}")
            else:
                LOG.info(f"Version: {tag_name}")
        asset_url = _pick_gadget_asset(release)
        LOG.step("Downloading Gadget asset")
        LOG.info(f"URL: {asset_url}")
        dst = download_dir / Path(asset_url.split("?", 1)[0]).name
        _download(asset_url, dst, github_token=None)
        out = _decompress_if_needed(dst, download_dir)
        LOG.ok(f"Gadget saved to: {out}")
        return out

    raise RuntimeError("Gadget not found (expected local path, URL, 'latest', or VERSION)")


def find_app_dir(extracted_dir: Path) -> Path:
    payload = extracted_dir / "Payload"
    if not payload.is_dir():
        raise RuntimeError("Missing Payload/ in extracted IPA")
    apps = [p for p in payload.iterdir() if p.is_dir() and p.name.endswith(".app")]
    if not apps:
        raise RuntimeError("No .app found under Payload/")
    # Match bash behavior: first one.
    return sorted(apps)[0]


def read_cf_bundle_executable(app_dir: Path) -> str:
    info = app_dir / "Info.plist"
    if not info.is_file():
        raise RuntimeError(f"Info.plist not found: {info}")
    with info.open("rb") as f:
        pl = plistlib.load(f)
    exe = pl.get("CFBundleExecutable")
    if not exe:
        raise RuntimeError("CFBundleExecutable missing from Info.plist")
    return str(exe)


def config_filename_for_dylib(dylib_name: str) -> str:
    if "." in dylib_name:
        return dylib_name.rsplit(".", 1)[0] + ".config"
    return dylib_name + ".config"


def write_gadget_config(
    app_dir: Path,
    dylib_name: str,
    mode: str,
    listen_address: str,
    listen_port: int,
    on_port_conflict: str,
    code_signing: str | None,
) -> None:
    cfg = {
        "interaction": {
            "type": "listen",
            "address": listen_address,
            "port": listen_port,
            "on_port_conflict": on_port_conflict,
            "on_load": mode,
        }
    }
    if code_signing:
        cfg["code_signing"] = code_signing
    name = config_filename_for_dylib(dylib_name)
    (app_dir / name).write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")


def ensure_lief() -> None:
    try:
        import lief  # noqa: F401
    except Exception as e:
        raise RuntimeError("Python package 'lief' is required. Install it first, e.g.: python3 -m pip install lief") from e


def patch_load_command(main_binary: Path, dylib_load_path: str) -> None:
    import lief

    fat = lief.MachO.parse(str(main_binary))
    if fat is None:
        raise RuntimeError(f"Failed to parse Mach-O: {main_binary}")

    # lief may return a Binary or a FatBinary.
    binaries = list(fat) if hasattr(fat, "__iter__") else [fat]

    updated = False
    for b in binaries:
        has_entry = any(lib.name == dylib_load_path for lib in b.libraries)
        if not has_entry:
            b.add_library(dylib_load_path)
            updated = True

    if updated:
        fat.write(str(main_binary))
        LOG.ok(f"Patched Mach-O load command: {main_binary}")
        LOG.info(f"Load path: {dylib_load_path}")
    else:
        LOG.ok("Mach-O already contains the load command (skipped)")


MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",  # MH_MAGIC
    b"\xce\xfa\xed\xfe",  # MH_CIGAM
    b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64
    b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64
    b"\xca\xfe\xba\xbe",  # FAT_MAGIC
    b"\xbe\xba\xfe\xca",  # FAT_CIGAM
    b"\xca\xfe\xba\xbf",  # FAT_MAGIC_64
    b"\xbf\xba\xfe\xca",  # FAT_CIGAM_64 (byte-swapped)
}


def is_macho(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            head = f.read(4)
        return head in MACHO_MAGICS
    except Exception:
        return False


def ldid_sign_app(app_dir: Path) -> None:
    ldid = shutil.which("ldid")
    if not ldid:
        _warn("ldid not found; skipping signing")
        return

    LOG.step("Signing Mach-O files (ldid)")
    for root, _dirs, files in os.walk(app_dir):
        for fn in files:
            p = Path(root) / fn
            if not p.is_file():
                continue
            if not is_macho(p):
                continue

            # First try quiet; if it fails, rerun with output for debugging.
            r = subprocess.run([ldid, "-S", str(p)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if r.returncode != 0:
                subprocess.run([ldid, "-S", str(p)], check=False)


def zip_dir(src_dir: Path, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()

    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(src_dir):
            root_p = Path(root)

            # Preserve empty directories (rare but safe).
            if not files and not dirs:
                rel = root_p.relative_to(src_dir).as_posix().rstrip("/") + "/"
                zi = zipfile.ZipInfo(rel)
                zi.external_attr = (stat.S_IFDIR | 0o755) << 16
                z.writestr(zi, b"")

            for fn in files:
                p = root_p / fn
                if p.is_symlink():
                    # Zip symlink as a small file containing the link target (portable behavior).
                    target = os.readlink(p)
                    rel = p.relative_to(src_dir).as_posix()
                    zi = zipfile.ZipInfo(rel)
                    zi.external_attr = (stat.S_IFLNK | 0o777) << 16
                    z.writestr(zi, target.encode("utf-8"))
                    continue

                rel = p.relative_to(src_dir).as_posix()
                st = p.stat()
                zi = zipfile.ZipInfo(rel)
                zi.external_attr = (st.st_mode & 0xFFFF) << 16
                with p.open("rb") as f:
                    z.writestr(zi, f.read())


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inject Frida Gadget into an IPA")
    parser.add_argument("-i", "--ipa", required=True, help="Input IPA path")
    parser.add_argument(
        "-g",
        "--gadget",
        required=True,
        help="Gadget source: local path, URL, 'latest', or X.Y.Z",
    )
    parser.add_argument("-o", "--out", default="", help="Output IPA path (default: com.org.app-frida.ipa)")
    parser.add_argument("--dylib-name", default="FridaGadget.dylib", help="Dylib name inside .app")
    parser.add_argument(
        "--load-path",
        default="",
        help="LC_LOAD_DYLIB path to inject (default: @executable_path/<embedded-dylib-name>)",
    )
    parser.add_argument("--keep-downloaded-name", action="store_true", help="Keep downloaded gadget filename inside .app")
    parser.add_argument("--gadget-config", default="", help="Path to a Gadget config JSON to embed")
    parser.add_argument(
        "--generate-config",
        choices=["resume", "wait"],
        default="",
        help="Generate a Gadget config (resume/wait). If omitted, no config is generated.",
    )
    parser.add_argument("--listen-address", default="127.0.0.1", help="Config listen address (with --generate-config)")
    parser.add_argument("--listen-port", type=int, default=27042, help="Config listen port (with --generate-config)")
    parser.add_argument("--on-port-conflict", choices=["fail", "pick"], default="fail", help="Config on_port_conflict")
    parser.add_argument(
        "--code-signing",
        choices=["optional", "required"],
        default="",
        help="Config code_signing (only with --generate-config)",
    )
    parser.add_argument("--no-sign", action="store_true", help="Skip ldid signing")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    ipa_path = Path(args.ipa)
    if not ipa_path.is_file():
        _error(f"IPA not found: {ipa_path}")
        return 1

    out_path = Path(args.out) if args.out else Path(str(ipa_path.with_suffix("")) + ".frida.ipa")
    out_path = out_path.expanduser().resolve()
    if not out_path.parent.is_dir():
        _error(f"Output directory does not exist: {out_path.parent}")
        return 1

    LOG.step("Inputs")
    LOG.info(f"IPA: {ipa_path.resolve()}")
    LOG.info(f"Gadget: {args.gadget}")
    LOG.info(f"Output: {out_path}")

    gadget_config_path = Path(args.gadget_config) if args.gadget_config else None
    if gadget_config_path and not gadget_config_path.is_file():
        _error(f"Gadget config not found: {gadget_config_path}")
        return 1

    if args.code_signing and not args.generate_config:
        _error("--code-signing is only valid with --generate-config")
        return 2

    github_token = os.environ.get("GITHUB_TOKEN") or None

    with tempfile.TemporaryDirectory(prefix="frida-ipa-") as td:
        td_p = Path(td)
        download_dir = td_p / "downloads"
        extract_dir = td_p / "extracted"
        download_dir.mkdir(parents=True, exist_ok=True)
        extract_dir.mkdir(parents=True, exist_ok=True)

        try:
            gadget_src = resolve_gadget(args.gadget, download_dir, github_token=github_token)
        except Exception as e:
            _error(str(e))
            return 1

        LOG.step("Extracting IPA")
        with zipfile.ZipFile(ipa_path) as z:
            z.extractall(extract_dir)

        try:
            app_dir = find_app_dir(extract_dir)
            exe_name = read_cf_bundle_executable(app_dir)
        except Exception as e:
            _error(str(e))
            return 1

        LOG.ok(f"App bundle: {app_dir.name}")
        LOG.info(f"Executable: {exe_name}")

        main_bin = app_dir / exe_name
        if not main_bin.is_file():
            _error(f"Main executable not found: {main_bin}")
            return 1

        # Embed gadget dylib
        embed_name = gadget_src.name if args.keep_downloaded_name else args.dylib_name
        dst_dylib = app_dir / embed_name
        LOG.step("Embedding Gadget")
        LOG.info(f"Embed name: {embed_name}")
        shutil.copy2(gadget_src, dst_dylib)
        dst_dylib.chmod(0o755)
        LOG.ok(f"Dylib embedded: {dst_dylib}")

        # Embed config (provided or generated)
        if gadget_config_path:
            cfg_name = config_filename_for_dylib(embed_name)
            LOG.step("Embedding Gadget config (provided)")
            LOG.info(f"Config name: {cfg_name}")
            shutil.copy2(gadget_config_path, app_dir / cfg_name)
            LOG.ok(f"Config embedded: {app_dir / cfg_name}")
        if args.generate_config:
            LOG.step("Embedding Gadget config (generated)")
            write_gadget_config(
                app_dir=app_dir,
                dylib_name=embed_name,
                mode=args.generate_config,
                listen_address=args.listen_address,
                listen_port=args.listen_port,
                on_port_conflict=args.on_port_conflict,
                code_signing=args.code_signing or None,
            )
            LOG.ok(f"Config embedded: {app_dir / config_filename_for_dylib(embed_name)}")
            LOG.info(f"on_load: {args.generate_config}")
            LOG.info(f"listen: {args.listen_address}:{args.listen_port} ({args.on_port_conflict})")
            if args.code_signing:
                LOG.info(f"code_signing: {args.code_signing}")

        # Patch Mach-O load command
        try:
            ensure_lief()
            load_path = args.load_path or f"@executable_path/{embed_name}"
            LOG.step("Patching Mach-O")
            patch_load_command(main_bin, load_path)
        except Exception as e:
            _error(str(e))
            return 1

        # Optional signing (best-effort)
        if not args.no_sign:
            ldid_sign_app(app_dir)
            LOG.ok("Signing complete")
        else:
            LOG.info("Signing: skipped (--no-sign)")

        # Repack IPA (everything extracted)
        try:
            LOG.step("Repacking IPA")
            zip_dir(extract_dir, out_path)
        except Exception as e:
            _error(f"Failed to repack IPA: {e}")
            return 1

        LOG.ok(f"Wrote: {out_path}")
        return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
