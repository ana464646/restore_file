import os
import shutil
import argparse
import pathlib
import datetime
import hashlib
import sys

def parse_args():
    parser = argparse.ArgumentParser(description="Windows Defender 隔離ファイル復元ツール（Windows 11対応）")
    parser.add_argument(
        "--rootdir", type=str, required=False,
        default="C:\\", help="システムのルートディレクトリ（通常は C:\\）"
    )
    parser.add_argument(
        "--restore-dir", type=str, required=False,
        default="restored_files", help="復元先フォルダ"
    )
    return parser.parse_args()

def get_file_hash(file_path: pathlib.Path) -> str:
    hasher = hashlib.sha1()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def find_windows11_quarantine_path(root_path: str) -> pathlib.Path | None:
    user = os.getenv('USERNAME')
    if not user:
        try:
            user = os.getlogin()
        except Exception:
            return None

    common_paths = [
        pathlib.Path(root_path) / "ProgramData" / "Microsoft" / "Windows Defender" / "Quarantine",
        pathlib.Path(root_path) / "ProgramData" / "Microsoft" / "Windows Defender" / "Scans" / "History" / "Store",
        pathlib.Path(root_path) / "ProgramData" / "Microsoft" / "Windows Defender Advanced Threat Protection" / "Quarantine",
        pathlib.Path(root_path) / "ProgramData" / "Microsoft" / "Microsoft Antimalware" / "Quarantine",
        pathlib.Path(root_path) / "Users" / user / "AppData" / "Local" / "Packages" / "Microsoft.SecHealthUI_cw5n1h2txyewy" / "LocalState",
    ]

    for base in common_paths:
        if base.exists():
            subdirs = ['Entries', 'Quarantine', 'Store']
            for sub in subdirs:
                candidate = base / sub
                if candidate.exists() and any(candidate.glob("*")):
                    print(f"[✓] 隔離フォルダ見つかりました: {candidate}")
                    return base
            if any(base.glob("*")):
                print(f"[✓] 隔離フォルダ見つかりました: {base}")
                return base
    return None

def restore_quarantined_files(quarantine_path: pathlib.Path, restore_dir: pathlib.Path):
    if not restore_dir.exists():
        restore_dir.mkdir(parents=True)
        print(f"[+] 復元先ディレクトリを作成: {restore_dir}")

    count = 0
    for root, _, files in os.walk(quarantine_path):
        for file in files:
            src_path = pathlib.Path(root) / file
            if not src_path.is_file():
                continue

            try:
                sha1 = get_file_hash(src_path)
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                dst_name = f"{timestamp}_{sha1[:8]}_{file}"
                dst_path = restore_dir / dst_name

                shutil.copy2(src_path, dst_path)
                print(f"[+] 復元: {src_path} → {dst_path}")
                count += 1
            except Exception as e:
                print(f"[!] エラー復元中: {src_path} → {e}")

    if count == 0:
        print("[!] 復元可能なファイルが見つかりませんでした。")
    else:
        print(f"[✓] 復元完了: {count} 個のファイル")

def main():
    args = parse_args()

    root_path = args.rootdir.rstrip('\\') + '\\'
    quarantine_base = find_windows11_quarantine_path(root_path)

    if not quarantine_base:
        print("[✗] 隔離フォルダが見つかりませんでした。")
        sys.exit(1)

    restore_path = pathlib.Path(args.restore_dir)
    restore_quarantined_files(quarantine_base, restore_path)

if __name__ == "__main__":
    main()
