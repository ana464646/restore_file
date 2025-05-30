import os
import shutil
import argparse
import pathlib
import datetime
import hashlib
import xml.etree.ElementTree as ET
import re

def parse_args():
    parser = argparse.ArgumentParser(description="Windows Defender 隔離ファイル復元ツール（拡張）")
    parser.add_argument("--rootdir", type=str, default="C:\\", help="ルートディレクトリ")
    parser.add_argument("--restore-dir", type=str, default="restored_files", help="復元先フォルダ")
    return parser.parse_args()

def extract_original_name(xml_path: pathlib.Path) -> dict:
    """
    Defender の Store フォルダ内にある xml ファイルをパースし、
    元のファイルパスとハッシュを返す
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        info = {}
        for item in root.iter():
            if item.tag.endswith("OriginalFileName"):
                info['original_name'] = item.text
            if item.tag.endswith("SHA1"):
                info['sha1'] = item.text.lower()
        return info if 'sha1' in info else {}
    except Exception as e:
        return {}

def scan_quarantine_store(quarantine_path: pathlib.Path):
    metadata = {}
    for file in quarantine_path.rglob("*.xml"):
        info = extract_original_name(file)
        if 'sha1' in info:
            metadata[info['sha1']] = info.get('original_name', '')
    return metadata

def get_file_hash(path: pathlib.Path) -> str:
    hasher = hashlib.sha1()
    with open(path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest().lower()

def restore_files(quarantine_dir: pathlib.Path, restore_dir: pathlib.Path, metadata: dict):
    restore_dir.mkdir(parents=True, exist_ok=True)
    count = 0

    for file in quarantine_dir.rglob("*"):
        if file.is_file() and not file.suffix.lower() in {'.xml', '.log'}:
            try:
                sha1 = get_file_hash(file)
                original_name = metadata.get(sha1, "")
                extension = pathlib.Path(original_name).suffix if original_name else file.suffix
                safe_name = pathlib.Path(original_name).name if original_name else f"{sha1}{extension}"

                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                dst_name = f"{timestamp}_{safe_name}"
                dst_path = restore_dir / dst_name

                shutil.copy2(file, dst_path)
                print(f"[+] 復元成功: {dst_path}")
                count += 1
            except Exception as e:
                print(f"[!] エラー: {file} → {e}")

    if count == 0:
        print("[!] 復元ファイルなし")
    else:
        print(f"[✓] {count} 個のファイルを復元しました。")

def find_quarantine_path(root: str) -> pathlib.Path | None:
    base = pathlib.Path(root)
    possible_paths = [
        base / "ProgramData" / "Microsoft" / "Windows Defender" / "Quarantine",
        base / "ProgramData" / "Microsoft" / "Windows Defender" / "Scans" / "History" / "Store",
        base / "ProgramData" / "Microsoft" / "Windows Defender Advanced Threat Protection" / "Quarantine",
        base / "ProgramData" / "Microsoft" / "Microsoft Antimalware" / "Quarantine"
    ]
    for p in possible_paths:
        if p.exists():
            print(f"[✓] 隔離フォルダ検出: {p}")
            return p
    return None

def main():
    args = parse_args()
    quarantine = find_quarantine_path(args.rootdir)
    if not quarantine:
        print("[✗] 隔離フォルダが見つかりません")
        return

    metadata = scan_quarantine_store(quarantine)
    restore_path = pathlib.Path(args.restore_dir)
    restore_files(quarantine, restore_path, metadata)

if __name__ == "__main__":
    main()
