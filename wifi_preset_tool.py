"""
Wi-Fi 事前設定ツール for Windows
- SSIDとパスワードを事前に登録
- Windows用Wi-FiプロファイルXMLを生成・エクスポート
- netsh コマンドで直接インポートも可能
"""

# ─── 起動時に不足モジュールを自動インストール ────────────────────
import sys
import subprocess
import importlib

# (パッケージ名, importで使う名前) のリスト
# 標準ライブラリはここに含めない。将来サードパーティを追加する際はここへ追記する。
REQUIRED_PACKAGES: list[tuple[str, str]] = [
    ("cryptography", "cryptography"),
]

def _ensure_packages():
    """必要パッケージをimportで確認し、なければインストール後に1回だけ再起動する。
    環境変数 _WIFI_RESTARTED=1 で再起動済みフラグを管理してループを防ぐ。"""
    import os as _os
    already_restarted = _os.environ.get("_WIFI_RESTARTED") == "1"

    missing = []
    for pkg_name, import_name in REQUIRED_PACKAGES:
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing.append(pkg_name)

    if not missing:
        return  # 全て揃っている

    if already_restarted:
        # 再起動後もまだ足りない → インストール自体の失敗
        import tkinter as _tk
        from tkinter import messagebox as _mb
        _r = _tk.Tk(); _r.withdraw()
        _mb.showerror("インストール失敗",
            f"パッケージのインストールが完了しませんでした。\n\n"
            f"コマンドプロンプトで以下を実行してください:\n\n"
            + "\n".join(f"  pip install {p}" for p in missing))
        _r.destroy()
        sys.exit(1)

    for pkg_name in missing:
        print(f"[自動インストール] {pkg_name} をインストール中...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", pkg_name],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            import tkinter as _tk
            from tkinter import messagebox as _mb
            _r = _tk.Tk(); _r.withdraw()
            _mb.showerror("インストール失敗",
                f"パッケージ「{pkg_name}」の自動インストールに失敗しました。\n\n"
                f"コマンドプロンプトで以下を実行してください:\n\n"
                f"  pip install {pkg_name}\n\n"
                f"エラー詳細:\n{result.stderr or result.stdout}")
            _r.destroy()
            sys.exit(1)
        print(f"  ✅ {pkg_name} インストール完了")

    # 再起動フラグを立てて1回だけ再起動
    env = _os.environ.copy()
    env["_WIFI_RESTARTED"] = "1"
    print("[自動インストール] 完了 → 再起動します...")
    subprocess.run([sys.executable] + sys.argv, env=env)
    sys.exit(0)

_ensure_packages()
# ────────────────────────────────────────────────────────────

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import xml.etree.ElementTree as ET
import os
import json
import re
import base64
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ─── データ保存ファイル ──────────────────────────────────────
SAVE_FILE = Path(__file__).parent / "wifi_presets.enc"

# ─── カラーパレット ──────────────────────────────────────────
BG       = "#0f1117"
SURFACE  = "#1a1d27"
CARD     = "#21253a"
ACCENT   = "#4f8ef7"
ACCENT2  = "#7c5cfc"
TEXT     = "#e8ecf4"
MUTED    = "#6b7280"
SUCCESS  = "#34d399"
WARNING  = "#fbbf24"
DANGER   = "#f87171"
BORDER   = "#2d3250"


def _get_key() -> bytes:
    """マシン固有情報からAES-256キーを導出する（ユーザーごとに異なる）"""
    import platform, getpass
    seed = f"{getpass.getuser()}:{platform.node()}:wifi-preset-tool-v1"
    return hashlib.sha256(seed.encode()).digest()  # 32バイト = AES-256


def load_presets() -> list:
    if not SAVE_FILE.exists():
        return []
    try:
        raw = SAVE_FILE.read_bytes()
        # フォーマット: [12バイト nonce][暗号文]
        nonce, ciphertext = raw[:12], raw[12:]
        key = _get_key()
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))
    except Exception:
        return []


def save_presets(presets: list) -> None:
    save_presets_to(presets, SAVE_FILE)


# バックアップファイルのマジックバイト（形式識別用）
BACKUP_MAGIC = b"WIFIBAK1"  # 8バイト


def _derive_key(password: str, salt: bytes) -> bytes:
    """パスワードとsaltからPBKDF2-HMAC-SHA256でAES-256キーを導出する"""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    return kdf.derive(password.encode("utf-8"))


def save_presets_to(presets: list, path: Path, password: str = "") -> None:
    """パスワードで暗号化してバックアップ保存する。
    フォーマット: [8 magic][16 salt][12 nonce][ciphertext]
    """
    plaintext = json.dumps(presets, ensure_ascii=False).encode("utf-8")
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    path.write_bytes(BACKUP_MAGIC + salt + nonce + ciphertext)


def load_presets_from(path: Path, password: str = "") -> list:
    """パスワードで復号してバックアップを読み込む。"""
    raw = path.read_bytes()
    if not raw.startswith(BACKUP_MAGIC):
        raise ValueError("バックアップファイルの形式が正しくありません。")
    raw = raw[len(BACKUP_MAGIC):]
    salt, nonce, ciphertext = raw[:16], raw[16:28], raw[28:]
    key = _derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("パスワードが違います。")
    return json.loads(plaintext.decode("utf-8"))


# セキュリティ種別 → (authentication, encryption, keyType, useOneX, is_enterprise)
AUTH_MAP = {
    "認証なし (オープン システム)": ("open",        "none", None,         False, False),
    "WPA2-パーソナル":              ("WPA2PSK",     "AES",  "passPhrase",  False, False),
    "WPA3-パーソナル":              ("WPA3SAE",     "AES",  "passPhrase",  False, False),
    "WPA3-エンタープライズ 192 ビット": ("WPA3ENT192", "GCMP256", None,    True,  True),
    "WPA3-エンタープライズ":        ("WPA3ENT",     "AES",  None,         True,  True),
    "WPA2-エンタープライズ":        ("WPA2ENT",     "AES",  None,         True,  True),
    "802.1X":                       ("WPA2ENT",     "AES",  None,         True,  True),
}


def generate_xml(ssid: str, password: str, auth: str, encryption: str, auto_connect: bool, hidden: bool = False) -> str:
    """Windows Wi-FiプロファイルXMLを生成する（全セキュリティ種別対応）"""
    hex_ssid = ssid.encode("utf-8").hex().upper()

    auth_str, enc_str, key_type, use_onex, is_enterprise = AUTH_MAP.get(
        auth, ("WPA2PSK", "AES", "passPhrase", False, False)
    )

    # 共有キーブロック（パーソナル系のみ）
    if key_type and password:
        key_block = f"""
        <sharedKey>
            <keyType>{key_type}</keyType>
            <protected>false</protected>
            <keyMaterial>{password}</keyMaterial>
        </sharedKey>"""
    else:
        key_block = ""

    onex_str = "true" if use_onex else "false"

    # エンタープライズ系は OneX 設定ブロックが必要
    onex_block = ""
    if is_enterprise:
        onex_block = """
    <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
        <authMode>machineOrUser</authMode>
        <EAPConfig>
            <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
                <EapMethod>
                    <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">25</Type>
                    <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
                    <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
                    <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId>
                </EapMethod>
            </EapHostConfig>
        </EAPConfig>
    </OneX>"""

    non_broadcast = "<nonBroadcast>true</nonBroadcast>" if hidden else "<nonBroadcast>false</nonBroadcast>"

    xml = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <hex>{hex_ssid}</hex>
            <name>{ssid}</name>
        </SSID>
        {non_broadcast}
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>{"auto" if auto_connect else "manual"}</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>{auth_str}</authentication>
                <encryption>{enc_str}</encryption>
                <useOneX>{onex_str}</useOneX>
            </authEncryption>{key_block}{onex_block}
        </security>
    </MSM>
    <MacRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v2">
        <enableRandomization>false</enableRandomization>
    </MacRandomization>
</WLANProfile>"""
    return xml


def import_to_windows(xml_content: str, ssid: str) -> tuple[bool, str]:
    """netsh で Windows へ直接インポートする"""
    tmp = Path(os.environ.get("TEMP", ".")) / f"wifi_{ssid}_tmp.xml"
    try:
        tmp.write_text(xml_content, encoding="utf-8")
        result = subprocess.run(
            ["netsh", "wlan", "add", "profile", f"filename={tmp}", "user=all"],
            capture_output=True  # text=True は使わず bytes で受け取る
        )
        tmp.unlink(missing_ok=True)

        # Windows の netsh は cp932 (Shift-JIS) で出力するが、
        # 環境によって utf-8 の場合もあるため順番に試みる
        def _decode(b: bytes) -> str:
            for enc in ("cp932", "utf-8", "utf-8-sig"):
                try:
                    return b.decode(enc)
                except UnicodeDecodeError:
                    continue
            return b.decode("cp932", errors="replace")

        if result.returncode == 0:
            return True, "インポート成功"
        else:
            msg = _decode(result.stderr) or _decode(result.stdout)
            return False, msg
    except Exception as e:
        tmp.unlink(missing_ok=True)
        return False, str(e)


# ────────────────────────────────────────────────────────────
class CheckSelectDialog(tk.Toplevel):
    """汎用チェックボックス選択ダイアログ"""
    def __init__(self, parent, title: str, prompt: str, ok_label: str,
                 items: list[str], tags: dict[str, str] | None = None,
                 default_checked: bool = True):
        """
        items      : 表示する項目名のリスト
        tags       : {項目名: 付加タグ文字列} 色付きタグを付ける場合に指定
        """
        super().__init__(parent)
        self.title(title)
        self.configure(bg=SURFACE)
        self.resizable(True, True)
        self.grab_set()
        self.selected: list[str] = []
        self.geometry("440x420")
        tags = tags or {}

        tk.Label(self, text=prompt, bg=SURFACE, fg=TEXT,
                 font=("Segoe UI", 10, "bold"), wraplength=400, justify="left"
                 ).pack(fill="x", padx=16, pady=(14, 6))

        # 全選択・解除ボタン
        sel_row = tk.Frame(self, bg=SURFACE)
        sel_row.pack(fill="x", padx=16, pady=(0, 4))
        tk.Button(sel_row, text="全選択", command=self._select_all,
                  bg=CARD, fg=TEXT, relief="flat", font=("Segoe UI", 8),
                  cursor="hand2", padx=8, pady=3).pack(side="left", padx=(0, 4))
        tk.Button(sel_row, text="全解除", command=self._deselect_all,
                  bg=CARD, fg=TEXT, relief="flat", font=("Segoe UI", 8),
                  cursor="hand2", padx=8, pady=3).pack(side="left")

        # スクロール可能なチェックボックス一覧
        frame = tk.Frame(self, bg=SURFACE)
        frame.pack(fill="both", expand=True, padx=16)
        canvas = tk.Canvas(frame, bg=SURFACE, highlightthickness=0)
        sb = tk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(canvas, bg=SURFACE)
        canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        self._vars: list[tuple[tk.BooleanVar, str]] = []
        for name in items:
            var = tk.BooleanVar(value=default_checked)
            tag = tags.get(name, "")
            fg_color = WARNING if tag else TEXT
            label = f"{name}  {tag}" if tag else name
            cb = tk.Checkbutton(inner, text=label, variable=var,
                                bg=SURFACE, fg=fg_color, selectcolor=CARD,
                                activebackground=SURFACE, activeforeground=fg_color,
                                font=("Segoe UI", 9), anchor="w")
            cb.pack(fill="x", pady=1)
            self._vars.append((var, name))

        # ボタン行
        btn_row = tk.Frame(self, bg=SURFACE)
        btn_row.pack(fill="x", padx=16, pady=12)
        tk.Button(btn_row, text=ok_label, command=self._ok,
                  bg=ACCENT, fg="white", relief="flat",
                  font=("Segoe UI", 10, "bold"), cursor="hand2",
                  padx=16, pady=6).pack(side="right")
        tk.Button(btn_row, text="キャンセル", command=self.destroy,
                  bg=CARD, fg=MUTED, relief="flat",
                  font=("Segoe UI", 9), cursor="hand2",
                  padx=12, pady=6).pack(side="right", padx=(0, 6))

    def _select_all(self):
        for var, _ in self._vars:
            var.set(True)

    def _deselect_all(self):
        for var, _ in self._vars:
            var.set(False)

    def _ok(self):
        self.selected = [name for var, name in self._vars if var.get()]
        if not self.selected:
            messagebox.showwarning("選択なし", "1つ以上選択してください。", parent=self)
            return
        self.destroy()


# 後方互換エイリアス（_import_from_windows が使用）
ImportSelectDialog = CheckSelectDialog


# ────────────────────────────────────────────────────────────
class PasswordDialog(tk.Toplevel):
    """パスワード入力ダイアログ"""
    def __init__(self, parent, title: str, prompt: str, confirm: bool = False):
        super().__init__(parent)
        self.title(title)
        self.configure(bg=SURFACE)
        self.resizable(False, False)
        self.grab_set()
        self.result = None
        self.geometry("360x210" if confirm else "360x165")

        tk.Label(self, text=prompt, bg=SURFACE, fg=TEXT,
                 font=("Segoe UI", 10), wraplength=320, justify="left"
                 ).pack(fill="x", padx=20, pady=(16, 4))

        self._pw = tk.StringVar()
        e1 = tk.Entry(self, textvariable=self._pw, show="*",
                      bg=CARD, fg=TEXT, insertbackground=TEXT,
                      relief="flat", font=("Segoe UI", 11),
                      highlightbackground=BORDER, highlightthickness=1,
                      highlightcolor=ACCENT)
        e1.pack(fill="x", padx=20)
        e1.focus_set()

        self._pw2 = None
        if confirm:
            tk.Label(self, text="確認のため再入力", bg=SURFACE, fg=MUTED,
                     font=("Segoe UI", 9)).pack(fill="x", padx=20, pady=(8, 2))
            self._pw2 = tk.StringVar()
            tk.Entry(self, textvariable=self._pw2, show="*",
                     bg=CARD, fg=TEXT, insertbackground=TEXT,
                     relief="flat", font=("Segoe UI", 11),
                     highlightbackground=BORDER, highlightthickness=1,
                     highlightcolor=ACCENT).pack(fill="x", padx=20)

        btn_row = tk.Frame(self, bg=SURFACE)
        btn_row.pack(fill="x", padx=20, pady=12)
        tk.Button(btn_row, text="OK", command=self._ok,
                  bg=ACCENT, fg="white", relief="flat",
                  font=("Segoe UI", 10, "bold"), cursor="hand2",
                  padx=16, pady=6).pack(side="right")
        tk.Button(btn_row, text="キャンセル", command=self.destroy,
                  bg=CARD, fg=MUTED, relief="flat",
                  font=("Segoe UI", 9), cursor="hand2",
                  padx=12, pady=6).pack(side="right", padx=(0, 6))

        self.bind("<Return>", lambda e: self._ok())
        self.bind("<Escape>", lambda e: self.destroy())

    def _ok(self):
        pw = self._pw.get()
        if not pw:
            messagebox.showwarning("入力エラー", "パスワードを入力してください。", parent=self)
            return
        if self._pw2 is not None and pw != self._pw2.get():
            messagebox.showwarning("入力エラー", "パスワードが一致しません。", parent=self)
            return
        self.result = pw
        self.destroy()


# ────────────────────────────────────────────────────────────
class WiFiPresetApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Wi-Fi 事前設定ツール")
        self.geometry("860x620")
        self.minsize(760, 540)
        self.configure(bg=BG)
        self.resizable(True, True)

        self.presets = load_presets()
        self._build_ui()
        self._refresh_list()

    # ── UI構築 ────────────────────────────────────────────
    def _build_ui(self):
        # ヘッダー
        hdr = tk.Frame(self, bg=BG, pady=16, padx=24)
        hdr.pack(fill="x")
        tk.Label(hdr, text="📶", font=("Segoe UI Emoji", 22), bg=BG, fg=ACCENT).pack(side="left")
        tk.Label(hdr, text="  Wi-Fi 事前設定ツール", font=("Segoe UI", 18, "bold"),
                 bg=BG, fg=TEXT).pack(side="left")
        tk.Label(hdr, text="Windows用プロファイルを接続前に登録",
                 font=("Segoe UI", 9), bg=BG, fg=MUTED).pack(side="left", padx=12)

        sep = tk.Frame(self, bg=BORDER, height=1)
        sep.pack(fill="x")

        # メインコンテンツ
        main = tk.Frame(self, bg=BG)
        main.pack(fill="both", expand=True, padx=16, pady=12)

        # 左：登録フォーム
        left = tk.Frame(main, bg=SURFACE, padx=20, pady=20,
                        highlightbackground=BORDER, highlightthickness=1)
        left.pack(side="left", fill="y", ipadx=4)

        self._form_title = tk.Label(left, text="新規プロファイル登録", font=("Segoe UI", 11, "bold"),
                 bg=SURFACE, fg=TEXT)
        self._form_title.grid(row=0, column=0, columnspan=2, pady=(0, 14), sticky="w")

        fields = [
            ("SSID（ネットワーク名）", "ssid"),
            ("パスワード", "pw"),
        ]
        self._vars = {}
        for i, (label, key) in enumerate(fields, start=1):
            tk.Label(left, text=label, font=("Segoe UI", 9), bg=SURFACE, fg=MUTED
                     ).grid(row=i*2-1, column=0, columnspan=2, sticky="w", pady=(8, 2))
            var = tk.StringVar()
            self._vars[key] = var
            show = "*" if key == "pw" else ""
            ent = tk.Entry(left, textvariable=var, show=show,
                           bg=CARD, fg=TEXT, insertbackground=TEXT,
                           relief="flat", font=("Segoe UI", 10), width=26,
                           highlightbackground=BORDER, highlightthickness=1,
                           highlightcolor=ACCENT)
            ent.grid(row=i*2, column=0, columnspan=2, sticky="ew", ipady=5)

        # セキュリティ種別
        tk.Label(left, text="セキュリティ", font=("Segoe UI", 9), bg=SURFACE, fg=MUTED
                 ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(8, 2))
        self._auth_var = tk.StringVar(value="WPA2-パーソナル")
        auth_cb = ttk.Combobox(left, textvariable=self._auth_var,
                               values=[
                                   "WPA2-パーソナル",
                                   "WPA3-パーソナル",
                                   "認証なし (オープン システム)",
                                   "WPA2-エンタープライズ",
                                   "WPA3-エンタープライズ",
                                   "WPA3-エンタープライズ 192 ビット",
                                   "802.1X",
                               ],
                               state="readonly", width=24, font=("Segoe UI", 10),
                               style="Bright.TCombobox")
        auth_cb.grid(row=6, column=0, columnspan=2, sticky="ew", ipady=3)
        auth_cb.bind("<<ComboboxSelected>>", self._on_auth_change)
        self._auth_cb = auth_cb  # スタイル再適用用に保持

        # 自動接続
        self._auto_var = tk.BooleanVar(value=True)
        chk = tk.Checkbutton(left, text="自動接続する", variable=self._auto_var,
                             bg=SURFACE, fg=TEXT, selectcolor=CARD,
                             activebackground=SURFACE, activeforeground=TEXT,
                             font=("Segoe UI", 9))
        chk.grid(row=7, column=0, columnspan=2, sticky="w", pady=(10, 0))

        # 隠しSSID
        self._hidden_var = tk.BooleanVar(value=False)
        chk_hidden = tk.Checkbutton(left, text="隠しSSID（ブロードキャストなし）",
                             variable=self._hidden_var,
                             bg=SURFACE, fg=TEXT, selectcolor=CARD,
                             activebackground=SURFACE, activeforeground=TEXT,
                             font=("Segoe UI", 9))
        chk_hidden.grid(row=8, column=0, columnspan=2, sticky="w", pady=(4, 0))

        # 登録／更新ボタン
        self._add_btn = tk.Button(left, text="＋ プロファイルを登録",
                            command=self._add_preset,
                            bg=ACCENT, fg="white", relief="flat",
                            font=("Segoe UI", 10, "bold"),
                            cursor="hand2", pady=8)
        self._add_btn.grid(row=9, column=0, columnspan=2, sticky="ew", pady=(16, 0))
        self._hover(self._add_btn, ACCENT, "#3a7ae0")

        # キャンセルボタン（編集中のみ表示）
        self._cancel_btn = tk.Button(left, text="✕ キャンセル",
                            command=self._cancel_edit,
                            bg=SURFACE, fg=MUTED, relief="flat",
                            font=("Segoe UI", 9),
                            cursor="hand2", pady=4,
                            highlightbackground=BORDER, highlightthickness=1)
        self._cancel_btn.grid(row=10, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        self._cancel_btn.grid_remove()  # 初期非表示

        # 編集中インデックス（None = 新規登録モード）
        self._edit_index: int | None = None

        # 右：プロファイル一覧
        right = tk.Frame(main, bg=BG)
        right.pack(side="left", fill="both", expand=True, padx=(12, 0))

        hbar = tk.Frame(right, bg=BG)
        hbar.pack(fill="x", pady=(0, 8))
        tk.Label(hbar, text="登録済みプロファイル", font=("Segoe UI", 11, "bold"),
                 bg=BG, fg=TEXT).pack(side="left")
        self._count_lbl = tk.Label(hbar, text="", font=("Segoe UI", 9),
                                   bg=BG, fg=MUTED)
        self._count_lbl.pack(side="left", padx=8)

        # リストボックス
        list_frame = tk.Frame(right, bg=BORDER, padx=1, pady=1)
        list_frame.pack(fill="both", expand=True)
        self._listbox = tk.Listbox(list_frame, bg=SURFACE, fg=TEXT,
                                   selectbackground=ACCENT, selectforeground="white",
                                   font=("Consolas", 10), relief="flat",
                                   highlightthickness=0, borderwidth=0,
                                   activestyle="none")
        sb = tk.Scrollbar(list_frame, orient="vertical",
                          command=self._listbox.yview, bg=SURFACE)
        self._listbox.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._listbox.pack(fill="both", expand=True)
        self._listbox.bind("<<ListboxSelect>>", self._on_select)

        # アクションボタン行1
        btn_row = tk.Frame(right, bg=BG)
        btn_row.pack(fill="x", pady=(8, 0))
        btns = [
            ("✏ 編集", self._start_edit, "#2d3f6b", TEXT),
            ("💾 XMLを保存", self._export_xml, SURFACE, TEXT),
            ("⚡ Windowsへ適用", self._apply_windows, ACCENT2, "white"),
            ("🗑 削除", self._delete_preset, DANGER, "white"),
        ]
        for txt, cmd, bg, fg in btns:
            b = tk.Button(btn_row, text=txt, command=cmd,
                          bg=bg, fg=fg, relief="flat",
                          font=("Segoe UI", 9, "bold"),
                          cursor="hand2", padx=10, pady=6)
            b.pack(side="left", padx=(0, 6))

        # アクションボタン行2（バックアップ／復元）
        btn_row2 = tk.Frame(right, bg=BG)
        btn_row2.pack(fill="x", pady=(4, 0))
        btns2 = [
            ("📦 バックアップ", self._backup, "#1e3a2f", SUCCESS),
            ("📂 復元", self._restore, "#1e3a2f", SUCCESS),
            ("📋 全XMLを一括保存", self._export_all_xml, SURFACE, TEXT),
            ("📥 Windowsから取り込む", self._import_from_windows, "#2d3250", TEXT),
        ]
        for txt, cmd, bg, fg in btns2:
            b = tk.Button(btn_row2, text=txt, command=cmd,
                          bg=bg, fg=fg, relief="flat",
                          font=("Segoe UI", 9, "bold"),
                          cursor="hand2", padx=10, pady=6)
            b.pack(side="left", padx=(0, 6))

        # ステータスバー
        self._status = tk.StringVar(value="準備完了")
        status_bar = tk.Label(self, textvariable=self._status,
                              bg=SURFACE, fg=MUTED, font=("Segoe UI", 8),
                              anchor="w", padx=12, pady=4)
        status_bar.pack(fill="x", side="bottom")

    # ── ヘルパー ─────────────────────────────────────────
    def _hover(self, btn, normal, hover):
        btn.bind("<Enter>", lambda e: btn.config(bg=hover))
        btn.bind("<Leave>", lambda e: btn.config(bg=normal))

    def _on_auth_change(self, _=None):
        auth = self._auth_var.get()
        # Open の場合はパスワード欄を無効化
        state = "disabled" if auth == "Open" else "normal"
        # Entryウィジェットを探して state 変更
        for w in self.winfo_children():
            pass  # Entry参照を直接持つ方が確実なので以下で対処

    def _set_status(self, msg, color=MUTED):
        self._status.set(msg)
        # ステータスラベルの色を動的に変更
        for w in self.winfo_children():
            if isinstance(w, tk.Label) and hasattr(w, '_is_status'):
                w.config(fg=color)

    def _refresh_list(self):
        self._listbox.delete(0, "end")
        for p in self.presets:
            auth_tag = {
                "WPA2-パーソナル": "WPA2",
                "WPA3-パーソナル": "WPA3",
                "認証なし (オープン システム)": "OPEN",
                "WPA2-エンタープライズ": "WPA2-ENT",
                "WPA3-エンタープライズ": "WPA3-ENT",
                "WPA3-エンタープライズ 192 ビット": "WPA3-192",
                "802.1X": "802.1X",
            }.get(p["auth"], "?")
            auto_tag = "⚡" if p.get("auto_connect", True) else "  "
            hidden_tag = "🔒" if p.get("hidden", False) else "  "
            self._listbox.insert("end",
                f"  {auto_tag} {hidden_tag} [{auth_tag}]  {p['ssid']}")
        self._count_lbl.config(text=f"{len(self.presets)} 件")

    def _selected_indices(self) -> list:
        """選択中の全インデックスを返す"""
        return list(self._listbox.curselection())

    def _selected_index(self):
        """最初の選択インデックスを返す（1件操作用）"""
        sel = self._listbox.curselection()
        return sel[0] if sel else None

    def _on_select(self, _=None):
        """リスト選択時にステータスバーへ選択件数を表示する"""
        sel = self._selected_indices()
        if not sel:
            return
        if len(sel) == 1:
            p = self.presets[sel[0]]
            self._status.set(f"選択中: {p['ssid']}  [{p['auth']}]  ─  編集するには「✏ 編集」を押してください")
        else:
            self._status.set(f"選択中: {len(sel)} 件  ─  「⚡ 一括適用」または「🗑 削除」で一括操作できます")

    # ── アクション ────────────────────────────────────────
    def _add_preset(self):
        ssid = self._vars["ssid"].get().strip()
        pw   = self._vars["pw"].get()
        auth = self._auth_var.get()
        auto = self._auto_var.get()

        if not ssid:
            messagebox.showwarning("入力エラー", "SSIDを入力してください。")
            return
        if auth not in ("認証なし (オープン システム)", "WPA2-エンタープライズ", "WPA3-エンタープライズ", "WPA3-エンタープライズ 192 ビット", "802.1X") and len(pw) < 8:
            messagebox.showwarning("入力エラー", "パスワードは8文字以上必要です。")
            return

        if self._edit_index is not None:
            # ── 編集モード：既存エントリを上書き ──
            self.presets[self._edit_index] = {
                "ssid": ssid, "password": pw,
                "auth": auth, "auto_connect": auto,
                "hidden": self._hidden_var.get()
            }
            save_presets(self.presets)
            self._refresh_list()
            self._listbox.selection_set(self._edit_index)
            self._status.set(f"✅ 「{ssid}」を更新しました")
            self._end_edit()
        else:
            # ── 新規登録モード ──
            # 重複チェック
            if any(p["ssid"] == ssid for p in self.presets):
                if not messagebox.askyesno("確認", f"SSID「{ssid}」は既に登録されています。上書きしますか？"):
                    return
                self.presets = [p for p in self.presets if p["ssid"] != ssid]
            self.presets.append({
                "ssid": ssid, "password": pw,
                "auth": auth, "auto_connect": auto,
                "hidden": self._hidden_var.get()
            })
            save_presets(self.presets)
            self._refresh_list()
            self._vars["ssid"].set("")
            self._vars["pw"].set("")
            self._status.set(f"✅ 「{ssid}」を登録しました")

    def _export_xml(self):
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo("選択してください", "エクスポートするプロファイルをリストから選択してください。")
            return
        p = self.presets[idx]
        xml = generate_xml(p["ssid"], p["password"], p["auth"],
                           "",  # encryption は AUTH_MAP から自動決定
                           p.get("auto_connect", True),
                           p.get("hidden", False))
        path = filedialog.asksaveasfilename(
            defaultextension=".xml",
            initialfile=f"wifi_{p['ssid']}.xml",
            filetypes=[("XML ファイル", "*.xml"), ("すべて", "*.*")],
            title="XMLとして保存"
        )
        if path:
            Path(path).write_text(xml, encoding="utf-8")
            self._status.set(f"💾 「{Path(path).name}」に保存しました")
            messagebox.showinfo("保存完了",
                f"XMLファイルを保存しました。\n\n適用方法：\n"
                f"  netsh wlan add profile filename=\"{path}\" user=all")

    def _apply_windows(self):
        if not self.presets:
            messagebox.showinfo("適用", "登録済みのプロファイルがありません。")
            return
        items = [p["ssid"] for p in self.presets]
        dlg = CheckSelectDialog(self,
                                "Windowsへ一括適用",
                                "Windowsに適用するプロファイルを選択してください",
                                "⚡ 適用する",
                                items=items, default_checked=False)
        self.wait_window(dlg)
        if not dlg.selected:
            return
        targets = [p for p in self.presets if p["ssid"] in set(dlg.selected)]
        if not messagebox.askyesno("確認",
                f"{len(targets)} 件をWindowsに適用します。\n（管理者権限が必要な場合があります）\n\n続行しますか？"):
            return
        ok_list, fail_list = [], []
        for p in targets:
            xml = generate_xml(p["ssid"], p["password"], p["auth"],
                               "", p.get("auto_connect", True), p.get("hidden", False))
            ok, msg = import_to_windows(xml, p["ssid"])
            if ok:
                ok_list.append(p["ssid"])
            else:
                fail_list.append((p["ssid"], msg))
        parts = []
        if ok_list:
            parts.append("✅ 適用成功 ({}) 件:\n".format(len(ok_list)) + "\n".join(f"  ・{s}" for s in ok_list))
        if fail_list:
            parts.append("❌ 適用失敗 ({}) 件:\n".format(len(fail_list)) + "\n".join(f"  ・{s}: {m}" for s, m in fail_list))
            parts.append("管理者として実行してみてください。")
        result_msg = "\n\n".join(parts)
        self._status.set(f"⚡ {len(ok_list)} 件適用完了" + (f"、{len(fail_list)} 件失敗" if fail_list else ""))
        if fail_list:
            messagebox.showwarning("適用結果", result_msg)
        else:
            messagebox.showinfo("適用完了", result_msg + "\n\nWi-Fiが圏内に入ると自動接続されます。")


    def _delete_preset(self):
        if not self.presets:
            messagebox.showinfo("削除", "登録済みのプロファイルがありません。")
            return
        items = [p["ssid"] for p in self.presets]
        dlg = CheckSelectDialog(self,
                                "プロファイルを削除",
                                "削除するプロファイルを選択してください",
                                "🗑 削除する",
                                items=items, default_checked=False)
        self.wait_window(dlg)
        if not dlg.selected:
            return
        del_set = set(dlg.selected)
        if not messagebox.askyesno("削除確認",
                f"以下 {len(del_set)} 件を削除しますか？\n\n" +
                "\n".join(f"  ・{s}" for s in dlg.selected)):
            return
        self.presets = [p for p in self.presets if p["ssid"] not in del_set]
        save_presets(self.presets)
        self._refresh_list()
        self._cancel_edit()
        self._status.set(f"🗑 {len(del_set)} 件を削除しました")


    def _start_edit(self):
        """選択中のプロファイルをフォームに読み込み編集モードへ"""
        idx = self._selected_index()
        if idx is None:
            messagebox.showinfo("選択してください", "編集するプロファイルをリストから選択してください。")
            return
        p = self.presets[idx]
        self._edit_index = idx
        # フォームに値をセット
        self._vars["ssid"].set(p["ssid"])
        self._vars["pw"].set(p["password"])
        self._auth_var.set(p["auth"])
        self._auto_var.set(p.get("auto_connect", True))
        self._hidden_var.set(p.get("hidden", False))
        # UIを編集モードに切替
        self._form_title.config(text="プロファイルを編集", fg=WARNING)
        self._add_btn.config(text="💾 変更を保存", bg="#2d6a4f")
        self._hover(self._add_btn, "#2d6a4f", "#1e4d38")
        self._cancel_btn.grid()
        self._status.set(f"編集中: 「{p['ssid']}」─  変更後「💾 変更を保存」を押してください")

    def _end_edit(self):
        """編集モードを終了してフォームをリセット"""
        self._edit_index = None
        self._vars["ssid"].set("")
        self._vars["pw"].set("")
        self._auth_var.set("WPA2-パーソナル")
        self._auto_var.set(True)
        self._hidden_var.set(False)
        self._form_title.config(text="新規プロファイル登録", fg=TEXT)
        self._add_btn.config(text="＋ プロファイルを登録", bg=ACCENT)
        self._hover(self._add_btn, ACCENT, "#3a7ae0")
        self._cancel_btn.grid_remove()

    def _cancel_edit(self):
        """編集をキャンセルしてフォームをリセット"""
        if self._edit_index is not None:
            self._status.set("編集をキャンセルしました")
        self._end_edit()


    # ── バックアップ／復元 ───────────────────────────────────
    def _backup(self):
        """全プロファイルをパスワード暗号化バックアップファイルとして書き出す"""
        if not self.presets:
            messagebox.showinfo("バックアップ", "登録済みのプロファイルがありません。")
            return
        dlg = PasswordDialog(self, "バックアップ用パスワード",
                             "バックアップを保護するパスワードを設定してください。\n（復元時に必要になります）",
                             confirm=True)
        self.wait_window(dlg)
        if dlg.result is None:
            return
        from datetime import datetime
        default_name = f"wifi_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.enc"
        path = filedialog.asksaveasfilename(
            defaultextension=".enc",
            initialfile=default_name,
            filetypes=[("暗号化バックアップ", "*.enc"), ("すべて", "*.*")],
            title="バックアップ先を選択"
        )
        if not path:
            return
        try:
            save_presets_to(self.presets, Path(path), dlg.result)
            self._status.set(f"📦 バックアップ完了: {Path(path).name}  ({len(self.presets)} 件)")
            messagebox.showinfo("バックアップ完了",
                f"{len(self.presets)} 件のプロファイルをバックアップしました。\n\n{path}\n\n設定したパスワードを忘れずに保管してください。")
        except Exception as e:
            messagebox.showerror("バックアップ失敗", str(e))

    def _restore(self):
        """バックアップファイルからプロファイルを復元する"""
        path = filedialog.askopenfilename(
            filetypes=[("暗号化バックアップ", "*.enc"), ("すべて", "*.*")],
            title="復元するバックアップファイルを選択"
        )
        if not path:
            return
        dlg = PasswordDialog(self, "バックアップのパスワード",
                             "バックアップ作成時に設定したパスワードを入力してください。",
                             confirm=False)
        self.wait_window(dlg)
        if dlg.result is None:
            return
        try:
            imported = load_presets_from(Path(path), dlg.result)
        except ValueError as e:
            messagebox.showerror("復元失敗", str(e))
            return
        except Exception as e:
            messagebox.showerror("復元失敗", f"ファイルの読み込みに失敗しました。\n\n{e}")
            return
        if not imported:
            messagebox.showwarning("復元", "バックアップファイルにデータがありません。")
            return

        # 既存データとのマージ確認
        if self.presets:
            choice = messagebox.askyesnocancel(
                "復元方法を選択",
                "既に " + str(len(self.presets)) + " 件のプロファイルが登録されています。\n\n「はい」  → 既存データに追加（重複SSIDは上書き）\n「いいえ」→ 既存データを削除してバックアップで置き換え\n「キャンセル」→ 復元をやめる"
            )
            if choice is None:
                return
            if choice:
                # マージ：重複SSIDは imported 側を優先
                existing = {p["ssid"]: p for p in self.presets}
                for p in imported:
                    existing[p["ssid"]] = p
                self.presets = list(existing.values())
            else:
                self.presets = imported
        else:
            self.presets = imported

        save_presets(self.presets)
        self._refresh_list()
        self._status.set(f"📂 復元完了: {len(imported)} 件を読み込みました")
        messagebox.showinfo("復元完了",
            f"{len(imported)} 件のプロファイルを復元しました。")

    def _export_all_xml(self):
        """全プロファイルをXMLとしてフォルダに一括保存する"""
        if not self.presets:
            messagebox.showinfo("一括保存", "登録済みのプロファイルがありません。")
            return
        folder = filedialog.askdirectory(title="保存先フォルダを選択")
        if not folder:
            return
        folder = Path(folder)
        saved = []
        for p in self.presets:
            xml = generate_xml(p["ssid"], p["password"], p["auth"],
                               "", p.get("auto_connect", True), p.get("hidden", False))
            # ファイル名に使えない文字を置換
            safe_ssid = re.sub(r'[\/:*?"<>|]', "_", p["ssid"])
            fpath = folder / f"wifi_{safe_ssid}.xml"
            fpath.write_text(xml, encoding="utf-8")
            saved.append(fpath.name)
        self._status.set(f"📋 {len(saved)} 件のXMLを保存しました → {folder}")
        msg = "\n".join(saved)
        messagebox.showinfo("一括保存完了", f"{len(saved)} 件のプロファイルをXMLとして保存しました。\n\n保存先: {folder}\n\n{msg}")

    def _import_from_windows(self):
        """Windowsに登録済みのWi-Fiプロファイルを一括取り込む"""
        # netsh で登録済みプロファイル名一覧を取得
        try:
            r = subprocess.run(
                ["netsh", "wlan", "show", "profiles"],
                capture_output=True
            )
            def _dec(b):
                for enc in ("cp932", "utf-8", "utf-8-sig"):
                    try: return b.decode(enc)
                    except: pass
                return b.decode("cp932", errors="replace")
            output = _dec(r.stdout)
        except Exception as e:
            messagebox.showerror("取り込みエラー", f"netsh の実行に失敗しました。\n\n{e}")
            return

        # プロファイル名を抽出（"すべてのユーザー プロファイル : SSID名" の形式）
        profile_names = []
        for line in output.splitlines():
            if ":" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    name = parts[1].strip()
                    if name:
                        profile_names.append(name)

        if not profile_names:
            messagebox.showinfo("取り込み", "Windowsに登録済みのWi-Fiプロファイルが見つかりませんでした。")
            return

        # 選択ダイアログを表示
        existing = {p["ssid"] for p in self.presets}
        tags = {n: "[登録済]" for n in profile_names if n in existing}
        dlg = CheckSelectDialog(self,
                                "Windowsのプロファイルを選択",
                                "取り込むプロファイルを選択してください",
                                "取り込む",
                                items=profile_names, tags=tags)
        self.wait_window(dlg)
        if not dlg.selected:
            return

        # 選択されたプロファイルのXMLを取得して解析
        imported = []
        failed = []
        for name in dlg.selected:
            try:
                r2 = subprocess.run(
                    ["netsh", "wlan", "show", "profile", f"name={name}", "key=clear"],
                    capture_output=True
                )
                xml_out = _dec(r2.stdout)
                profile = self._parse_netsh_profile(xml_out, name)
                if profile:
                    imported.append(profile)
                else:
                    failed.append(name)
            except Exception:
                failed.append(name)

        if not imported:
            messagebox.showwarning("取り込み結果", "プロファイルの解析に失敗しました。")
            return

        # 既存データにマージ（重複SSIDは上書き確認）
        existing_ssids = {p["ssid"] for p in self.presets}
        duplicates = [p["ssid"] for p in imported if p["ssid"] in existing_ssids]
        if duplicates:
            dup_list = "\n".join(f"  ・{s}" for s in duplicates)
            if not messagebox.askyesno("重複確認",
                    f"以下のSSIDはすでに登録されています。上書きしますか？\n\n{dup_list}"):
                imported = [p for p in imported if p["ssid"] not in existing_ssids]

        for p in imported:
            self.presets = [x for x in self.presets if x["ssid"] != p["ssid"]]
            self.presets.append(p)

        save_presets(self.presets)
        self._refresh_list()

        msg = f"{len(imported)} 件のプロファイルを取り込みました。"
        if failed:
            msg += f"\n\n取得できなかったプロファイル ({len(failed)} 件):\n" + "\n".join(f"  ・{n}" for n in failed)
            msg += "\n\n（管理者として実行するとパスワードも取得できる場合があります）"
        self._status.set(f"📥 {len(imported)} 件取り込み完了")
        messagebox.showinfo("取り込み完了", msg)

    def _parse_netsh_profile(self, output: str, ssid: str) -> dict | None:
        """netsh show profile の出力からプロファイル情報を解析する"""
        import re
        # 認証方式
        auth_match = re.search(r"認証\s*:\s*(.+)", output) or re.search(r"Authentication\s*:\s*(.+)", output)
        # 暗号化
        enc_match  = re.search(r"暗号化\s*:\s*(.+)", output) or re.search(r"Cipher\s*:\s*(.+)", output)
        # パスワード（key=clear で取得可能な場合）
        pw_match   = re.search(r"主要なコンテンツ\s*:\s*(.+)", output) or re.search(r"Key Content\s*:\s*(.+)", output)
        # 自動接続
        auto_match = re.search(r"接続モード\s*:\s*(.+)", output) or re.search(r"Connection mode\s*:\s*(.+)", output)
        # 非ブロードキャスト
        hidden_match = re.search(r"非ブロードキャスト\s*:\s*(.+)", output) or re.search(r"Non Broadcast\s*:\s*(.+)", output)

        # 認証方式をツール内形式に変換
        NETSH_AUTH_MAP = {
            "WPA2-パーソナル": "WPA2-パーソナル", "WPA2 Personal": "WPA2-パーソナル",
            "WPA2PSK": "WPA2-パーソナル",
            "WPA3-パーソナル": "WPA3-パーソナル", "WPA3 Personal": "WPA3-パーソナル",
            "WPA3SAE": "WPA3-パーソナル",
            "WPA2-エンタープライズ": "WPA2-エンタープライズ", "WPA2 Enterprise": "WPA2-エンタープライズ",
            "WPA3-エンタープライズ": "WPA3-エンタープライズ", "WPA3 Enterprise": "WPA3-エンタープライズ",
            "オープン": "認証なし (オープン システム)", "Open": "認証なし (オープン システム)",
        }
        raw_auth = auth_match.group(1).strip() if auth_match else ""
        auth = NETSH_AUTH_MAP.get(raw_auth, "WPA2-パーソナル")
        password = pw_match.group(1).strip() if pw_match else ""
        auto = True
        if auto_match:
            v = auto_match.group(1).strip()
            auto = "自動" in v or "Auto" in v or "auto" in v
        hidden = False
        if hidden_match:
            v = hidden_match.group(1).strip()
            hidden = "はい" in v or "Yes" in v or "yes" in v

        return {"ssid": ssid, "password": password, "auth": auth,
                "auto_connect": auto, "hidden": hidden}




# ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import traceback
    _log = Path(__file__).parent / "wifi_preset_error.log"
    try:
        # ttk スタイル調整
        app = WiFiPresetApp()
        style = ttk.Style(app)
        style.theme_use("clam")
        # Combobox 基本スタイル
        style.configure("TCombobox",
                        fieldbackground=CARD,
                        background=CARD,
                        foreground=TEXT,
                        selectbackground=CARD,
                        selectforeground=TEXT,
                        bordercolor=BORDER,
                        arrowcolor=TEXT,
                        insertcolor=TEXT)
        # 文字色を確実に明るくするカスタムスタイル
        style.configure("Bright.TCombobox",
                        fieldbackground=CARD,
                        background=CARD,
                        foreground=TEXT,
                        selectbackground=CARD,
                        selectforeground=TEXT,
                        bordercolor=BORDER,
                        arrowcolor=TEXT)
        # readonly状態でも foreground が効くようにマップ設定
        style.map("Bright.TCombobox",
                  fieldbackground=[("readonly", CARD)],
                  foreground=[("readonly", TEXT)],
                  selectbackground=[("readonly", CARD)],
                  selectforeground=[("readonly", TEXT)])
        # ドロップダウンリスト部分の文字色・背景色
        app.option_add("*TCombobox*Listbox.background", CARD)
        app.option_add("*TCombobox*Listbox.foreground", TEXT)
        app.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
        app.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")
        app.option_add("*TCombobox*Listbox.font", "{Segoe UI} 10")
        app.mainloop()
    except Exception:
        err = traceback.format_exc()
        _log.write_text(err, encoding="utf-8")
        # GUIでもエラー内容を表示
        try:
            import tkinter as _tk
            from tkinter import messagebox as _mb
            _r = _tk.Tk(); _r.withdraw()
            _mb.showerror("起動エラー",
                f"エラーが発生しました。\n\n{err}\n\n"
                f"詳細は以下に保存されました:\n{_log}")
            _r.destroy()
        except Exception:
            pass
        raise
