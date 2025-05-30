#!/usr/bin/env python3

'''
Windows Defenderの隔離ファイルを復元するプログラム
作成者: Nikola Knežević - 2021
参考: https://github.com/ernw/quarantine-formats

このプログラムは、Windows Defenderによって隔離されたファイルを
復元するためのツールです。隔離ファイルの暗号化を解除し、
元のファイルとして取り出すことができます。
'''

import io
import struct
import argparse
import datetime
import pathlib
import os
import sys
import ctypes
import re
import win32security
import win32api
import win32con
import pywintypes
import msvcrt
from collections import namedtuple
from winreg import *

try:
    from mpress import XpressDecompressor
except ImportError:
    print("mpressモジュールをインストールしています...")
    os.system('pip install mpress')
    from mpress import XpressDecompressor

file_record = namedtuple("file_record", "path hash detection filetime")

def is_admin():
    """
    現在のプロセスが管理者権限で実行されているかを確認します
    
    Returns:
        bool: 管理者権限がある場合はTrue、ない場合はFalse
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def mse_ksa():
    """
    RC4暗号化のための初期化処理を行います
    mpengine.dllから取得したハードコードされたキーを使用します
    
    Returns:
        list: 初期化されたSボックス
    """
    # mpengine.dllから取得したハードコードされたキー
    key = [
        0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69,
        0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86, 0xA3, 0xF6, 0x23, 0xB7,
        0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC,
        0x54, 0xFA, 0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD, 0x0F,
        0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18, 0x27, 0x96,
        0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4,
        0x8E, 0x23, 0xD0, 0x53, 0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8,
        0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04,
        0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58,
        0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE, 0x3C, 0x8A, 0x77, 0x52,
        0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC,
        0x1B, 0xC8, 0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59,
        0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E, 0x3E, 0x19,
        0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D,
        0x2C, 0x07, 0xE2, 0x57, 0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E,
        0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29,
        0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3,
        0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A, 0xEA, 0xCD, 0x62, 0x1D,
        0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE,
        0xD7, 0xDC, 0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12,
        0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16, 0x4B, 0x11,
        0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6,
        0x26, 0x2E, 0x42, 0x9B, 0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98,
        0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
        0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD,
        0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53
    ]
    
    # Sボックスの初期化
    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + key[i]) % 256
        tmp = sbox[i]
        sbox[i] = sbox[j]
        sbox[j] = tmp
    return sbox

def rc4_decrypt(data):
    """
    RC4アルゴリズムを使用してデータを復号化します
    
    Args:
        data (bytes): 復号化する暗号化データ
        
    Returns:
        bytearray: 復号化されたデータ
    """
    sbox = mse_ksa()
    out = bytearray(len(data))
    i = 0
    j = 0
    
    for k in range(len(data)):
        i = (i + 1) % 256
        j = (j + sbox[i]) % 256
        tmp = sbox[i]
        sbox[i] = sbox[j]
        sbox[j] = tmp
        val = sbox[(sbox[i] + sbox[j]) % 256]
        out[k] = val ^ data[k]

    return out

def unpack_malware(f):
    """
    隔離ファイルを解析し、元のファイルデータを抽出します
    
    Args:
        f: ファイルオブジェクト
        
    Returns:
        tuple: (ファイルデータ, ファイルサイズ)
    """
    decrypted = rc4_decrypt(f.read())
    sd_len = struct.unpack_from('<I', decrypted, 0x8)[0]
    header_len = 0x28 + sd_len
    malfile_len = struct.unpack_from('<Q', decrypted, sd_len + 0x1C)[0]
    malfile = decrypted[header_len:header_len + malfile_len]

    return (malfile, malfile_len)

def dump_entries(basedir, entries):
    """
    隔離されたファイルをTARアーカイブにエクスポートします
    
    Args:
        basedir (Path): 隔離ファイルが格納されているベースディレクトリ
        entries (list): エクスポートする隔離ファイルのエントリリスト
    """
    if not entries:
        print("隔離されたファイルが見つかりませんでした。")
        return

    try:
        tar = tarfile.open('quarantine.tar', 'w')

        for file_rec in entries:
            quarfile = basedir / 'ResourceData' / file_rec.hash[:2] / file_rec.hash

            if not quarfile.exists():
                print(f"警告: {file_rec.path.name} の隔離ファイルが見つかりません。")
                continue

            try:
                with open(quarfile, 'rb') as f:
                    print(f'エクスポート中: {file_rec.path.name}')
                    malfile, malfile_len = unpack_malware(f)

                    tarinfo = tarfile.TarInfo(file_rec.path.name)
                    tarinfo.size = malfile_len
                    tar.addfile(tarinfo, io.BytesIO(malfile))
            except Exception as e:
                print(f"エラー: {file_rec.path.name} の処理中にエラーが発生しました: {str(e)}")

        tar.close()
        print("ファイル 'quarantine.tar' が正常に作成されました")
    except Exception as e:
        print(f"エラー: tarファイルの作成中にエラーが発生しました: {str(e)}")

def get_entry(data):
    """
    隔離ファイルのエントリ情報を解析します
    
    Args:
        data (bytes): 解析するエントリデータ
        
    Returns:
        tuple: (ファイルパス, ハッシュ値, エントリタイプ)
    """
    # UTF-16LEでエンコードされたパス文字列を抽出
    pos = data.find(b'\x00\x00\x00') + 1
    path_str = data[:pos].decode('utf-16le')

    # パスの正規化
    if path_str[2:4] == '?\\':
        path_str = path_str[4:]

    path = pathlib.PureWindowsPath(path_str)

    # エントリタイプの抽出
    pos += 4  # エントリ数フィールドをスキップ
    type_len = data[pos:].find(b'\x00')
    type = data[pos:pos + type_len].decode()  # エントリタイプ（UTF-8）を取得
    pos += type_len + 1
    pos += (4 - pos) % 4  # パディングバイトをスキップ
    pos += 4  # 追加メタデータをスキップ
    hash = data[pos:pos + 20].hex().upper()

    return (path, hash, type)

def enable_security_privilege():
    """
    セキュリティ関連の特権を有効にします
    
    Returns:
        bool: 特権の有効化に成功した場合はTrue、失敗した場合はFalse
    """
    try:
        # プロセスのトークンを取得
        flags = win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), flags)
        
        # SEBackupPrivilege（バックアップ）とSESecurityPrivilege（セキュリティ）の特権を有効化
        privileges = [
            (win32security.LookupPrivilegeValue(None, "SeBackupPrivilege"), win32con.SE_PRIVILEGE_ENABLED),
            (win32security.LookupPrivilegeValue(None, "SeSecurityPrivilege"), win32con.SE_PRIVILEGE_ENABLED)
        ]
        
        # 特権を有効化
        win32security.AdjustTokenPrivileges(token, False, privileges)
        return True
    except pywintypes.error as e:
        print(f"警告: セキュリティ特権の有効化に失敗しました: {str(e)}")
        return False

def safe_open_file(file_path, mode='rb'):
    """
    安全にファイルを開くためのラッパー関数
    
    Args:
        file_path: 開くファイルのパス
        mode: ファイルを開くモード（デフォルトは'rb'）
        
    Returns:
        tuple: (ファイルオブジェクト, エラーメッセージ)
        エラーの場合はファイルオブジェクトはNone
    """
    try:
        # まず通常の方法で試みる
        return open(file_path, mode), None
    except PermissionError:
        try:
            # セキュリティ特権を有効化
            if enable_security_privilege():
                # 再度ファイルを開く
                return open(file_path, mode), None
        except Exception as e:
            return None, f"ファイルアクセスエラー: {str(e)}"
    except Exception as e:
        return None, f"ファイルアクセスエラー: {str(e)}"

def parse_entries(basedir):
    """
    隔離ファイルのエントリ情報を解析します
    
    Args:
        basedir (Path): 隔離ファイルが格納されているベースディレクトリ
        
    Returns:
        list: 隔離ファイルのエントリ情報のリスト
    """
    results = []
    
    # セキュリティ特権を有効化
    enable_security_privilege()
    
    # 再帰的にすべてのファイルを検索
    for file_path in basedir.rglob('*'):
        if not file_path.is_file():
            continue
            
        print(f"デバッグ: ファイルを確認中: {file_path}")
        
        try:
            # ファイルを安全に開く
            f, error = safe_open_file(file_path)
            if error:
                print(f"警告: {file_path} - {error}")
                continue
                
            if not f:
                continue
                
            with f:
                # ファイルサイズを確認
                file_size = file_path.stat().st_size
                if file_size < 0x20:  # 最小ヘッダーサイズより小さいファイルはスキップ
                    continue
                    
                # ファイルの先頭バイトをチェック
                header_bytes = f.read(0x20)
                f.seek(0)
                
                # Windows 11の新しい形式のチェック
                if b'MSFT' in header_bytes or b'Windows Defender' in header_bytes or b'Quarantine' in header_bytes:
                    print(f"デバッグ: 新しい形式の可能性があるファイルを発見: {file_path}")
                    try:
                        # ファイル全体を読み込んで解析
                        content = f.read()
                        # UTF-16LEでデコード可能な部分を探す
                        for i in range(0, len(content)-2, 2):
                            try:
                                text = content[i:i+200].decode('utf-16le', errors='ignore')
                                if any(pattern in text for pattern in ['VirusDOS', 'EICAR', 'Malware', 'Threat', 'Quarantine']):
                                    print(f"デバッグ: 隔離ファイルの情報を発見: {text[:200]}")
                                    # 現在の時刻を使用（正確な時刻は新形式からは取得できない）
                                    current_time = datetime.datetime.now()
                                    results.append(file_record(
                                        pathlib.PureWindowsPath(text.split('\\')[-1]),
                                        file_path.name,
                                        "VirusDOS/EICAR",
                                        current_time
                                    ))
                                    break
                            except:
                                continue
                    except Exception as e:
                        print(f"警告: 新形式の解析中にエラー: {str(e)}")
                        continue
                
                # バイナリ内の特徴的な文字列を検索
                content = f.read()
                if any(pattern in content for pattern in [b'VirusDOS', b'EICAR', b'Malware', b'Threat', b'Quarantine']):
                    print(f"デバッグ: 特徴的な文字列を含むファイルを発見: {file_path}")
                    try:
                        # ファイル名を抽出
                        name_match = re.search(rb'[A-Za-z]:\\[^"\x00<>|]*', content)
                        if name_match:
                            file_name = name_match.group(0).decode('utf-8', errors='ignore').split('\\')[-1]
                        else:
                            file_name = file_path.name
                            
                        results.append(file_record(
                            pathlib.PureWindowsPath(file_name),
                            file_path.name,
                            "検出された脅威",
                            datetime.datetime.now()
                        ))
                    except Exception as e:
                        print(f"警告: ファイル情報の抽出中にエラー: {str(e)}")
                        continue
                        
        except Exception as e:
            print(f"警告: ファイル {file_path} の処理中にエラー: {str(e)}")
            continue
    
    return results

def analyze_log_files(base_path):
    """
    Windows Defenderのログファイルを解析して隔離ファイルの場所を特定します
    
    Args:
        base_path (str): 検索を開始するベースパス
    
    Returns:
        list: 見つかった可能性のある隔離ファイルのパスのリスト
    """
    possible_locations = set()
    
    # ログファイルのパターン
    log_patterns = [
        '**/Support/MPDetection*.log',
        '**/Support/MPLog*.log',
        '**/Scans/History/**/*',
        '**/Logs/*.etl'
    ]
    
    print("\nログファイルを解析中...")
    
    for pattern in log_patterns:
        for log_file in pathlib.Path(base_path).glob(pattern):
            if not log_file.is_file():
                continue
                
            print(f"デバッグ: ログファイルを解析中: {log_file}")
            try:
                # バイナリモードでログファイルを読み込み
                with open(log_file, 'rb') as f:
                    content = f.read()
                    
                    # 一般的な隔離ファイルのパターンを検索
                    patterns = [
                        b'Quarantine',
                        b'VirusDOS',
                        b'ECAR',
                        b'Malware',
                        b'Threat',
                        b'Detection'
                    ]
                    
                    # ログの内容をUTF-16とUTF-8の両方で試行
                    try:
                        text_content = content.decode('utf-16le', errors='ignore')
                    except:
                        try:
                            text_content = content.decode('utf-8', errors='ignore')
                        except:
                            continue
                    
                    lines = text_content.splitlines()
                    for line in lines:
                        # 隔離ファイルに関連する行を検索
                        if any(pattern.decode() in line for pattern in patterns):
                            print(f"デバッグ: 関連する行を発見: {line[:200]}...")  # 長すぎる行は省略
                            
                            # パスらしき文字列を抽出
                            path_matches = re.findall(r'[A-Za-z]:\\[^"<>|]*', line)
                            for path in path_matches:
                                if 'defender' in path.lower() or 'quarantine' in path.lower():
                                    possible_locations.add(path)
                                    print(f"デバッグ: 可能性のある隔離パスを発見: {path}")
            
            except Exception as e:
                print(f"警告: ログファイル {log_file} の解析中にエラー: {str(e)}")
                continue
    
    return list(possible_locations)

def get_original_filename(hash_value):
    """
    ハッシュ値から元のファイル名を取得します
    
    Args:
        hash_value (str): ファイルのハッシュ値
        
    Returns:
        str: 元のファイル名、見つからない場合はNone
    """
    try:
        # 検索するパス
        detection_paths = [
            pathlib.Path("C:/ProgramData/Microsoft/Windows Defender/Scans/History/Service/DetectionHistory"),
            pathlib.Path("C:/ProgramData/Microsoft/Windows Defender/Scans/History/Service"),
            pathlib.Path("C:/ProgramData/Microsoft/Windows Defender/Support")
        ]
        
        # ファイルパターン
        patterns = [
            "*.log",
            "Detections.log",
            "MPDetection*.log"
        ]
        
        for base_path in detection_paths:
            if not base_path.exists():
                continue
                
            # 再帰的にログファイルを検索
            for pattern in patterns:
                for log_file in base_path.rglob(pattern):
                    try:
                        f, error = safe_open_file(log_file)
                        if error or not f:
                            continue
                            
                        with f:
                            content = f.read()
                            # バイナリデータをデコード
                            try:
                                text = content.decode('utf-16le', errors='ignore')
                            except:
                                try:
                                    text = content.decode('utf-8', errors='ignore')
                                except:
                                    continue
                            
                            # ハッシュ値を含む行を検索
                            if hash_value in text:
                                # ファイルパスを抽出
                                matches = re.finditer(r'[A-Za-z]:\\[^"\n<>|]*', text)
                                for match in matches:
                                    path = match.group(0)
                                    if path.endswith('.exe') or path.endswith('.dll') or path.endswith('.zip'):
                                        return pathlib.PureWindowsPath(path).name
                                        
                    except Exception as e:
                        print(f"警告: ログファイル {log_file} の解析中にエラー: {str(e)}")
                        continue
    
    except Exception as e:
        print(f"警告: 元のファイル名の検索中にエラー: {str(e)}")
    
    return None

def get_defender_paths():
    """
    Windows Defenderの関連パスをレジストリから取得します
    
    Returns:
        list: 検索対象のパスのリスト
    """
    paths = set()
    try:
        # レジストリキーを開く
        with OpenKey(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender") as key:
            try:
                install_location = QueryValueEx(key, "InstallLocation")[0]
                paths.add(pathlib.Path(install_location))
            except:
                pass
            
        with OpenKey(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender\Quarantine") as key:
            try:
                quarantine_location = QueryValueEx(key, "QuarantineLocation")[0]
                paths.add(pathlib.Path(quarantine_location))
            except:
                pass
    except:
        pass
        
    # デフォルトのパスを追加
    default_paths = [
        pathlib.Path("C:/ProgramData/Microsoft/Windows Defender/Quarantine"),
        pathlib.Path("C:/ProgramData/Microsoft/Windows Defender/Scans/History/Store"),
        pathlib.Path("C:/ProgramData/Microsoft/Windows Defender/Scans/History/Service/DetectionHistory"),
        pathlib.Path("C:/ProgramData/Microsoft/Windows Defender/Support"),
        pathlib.Path("C:/ProgramData/Microsoft/Windows Defender/LocalCopy"),
        pathlib.Path("C:/Windows/ServiceState/SecurityService")
    ]
    
    paths.update(default_paths)
    return list(paths)

def find_quarantine_files():
    """
    システム内の隔離ファイルを検索します
    
    Returns:
        list: 見つかった隔離ファイルのパスのリスト
    """
    quarantine_files = []
    
    # Windows Defenderの関連パスを取得
    search_paths = get_defender_paths()
    
    for base_path in search_paths:
        if not base_path.exists():
            continue
            
        try:
            # 再帰的にファイルを検索
            for path in base_path.rglob("*"):
                if not path.is_file():
                    continue
                    
                try:
                    # ファイルサイズチェック
                    if path.stat().st_size < 0x20:
                        continue
                        
                    # ファイルの先頭をチェック
                    with open(path, "rb") as f:
                        header = f.read(8)
                        if (header.startswith(b"MPQU") or
                            any(pattern in header for pattern in [b"MPSQ", b"MSFT", b"Windows Defender"])):
                            quarantine_files.append(path)
                except (PermissionError, OSError):
                    continue
                    
        except Exception as e:
            print(f"警告: {base_path}の検索中にエラー: {str(e)}")
            
    return quarantine_files

def parse_quarantine_file(path):
    """
    隔離ファイルを解析して元のファイルを復元します
    
    Args:
        path (str): 隔離ファイルのパス
        
    Returns:
        bytes: 復元されたファイルデータ
    """
    try:
        with open(path, "rb") as f:
            data = f.read()

        # ヘッダーチェック
        if data[:4] == b"MPQU":
            # 標準的な隔離ファイル形式
            header_size = struct.unpack_from("<I", data, 4)[0]
            if header_size >= len(data):
                raise ValueError("無効なヘッダーサイズです")
                
            compressed = data[header_size:]
            if not compressed:
                raise ValueError("圧縮データが見つかりません")
                
            decompressor = XpressDecompressor()
            decompressed = decompressor.decompress(compressed, output_size=10*len(compressed))
            return decompressed
            
        else:
            # 新しい形式の隔離ファイル
            return rc4_decrypt(data)

    except FileNotFoundError:
        raise RuntimeError(f"ファイルが見つかりません: {path}")
    except PermissionError:
        raise RuntimeError(f"ファイルにアクセスする権限がありません: {path}")
    except Exception as e:
        raise RuntimeError(f"ファイルの解析中にエラーが発生しました: {str(e)}")

def main(args):
    """
    メイン処理を実行します
    
    Args:
        args: コマンドライン引数
    """
    if not is_admin():
        print("このプログラムは管理者権限で実行する必要があります。")
        if msvcrt.getch():  # キー入力待ち
            sys.exit(1)

    try:
        print("隔離ファイルを検索中...")
        print("これには数分かかる場合があります。")
        
        # 隔離ファイルの検索
        quarantine_files = find_quarantine_files()
        
        if not quarantine_files:
            print("\n隔離ファイルが見つかりませんでした。")
            print("\n考えられる原因:")
            print("1. Windows Defenderが隔離ファイルを別の場所に保存している")
            print("2. 隔離ファイルが存在しない")
            print("3. アクセス権限の問題")
            print("\n確認事項:")
            print("1. Windowsセキュリティを開き、ウイルスと脅威の防止 → 保護の履歴で")
            print("   ファイルが実際に隔離されているか確認してください")
            print("2. 隔離操作が完了してから十分な時間が経過しているか確認してください")
            print("3. Windows Defenderのサービスが実行中か確認してください")
            if msvcrt.getch():  # キー入力待ち
                return
        
        print(f"\n{len(quarantine_files)}個の隔離ファイルが見つかりました")
        
        # 最新のファイルを処理
        latest_file = max(quarantine_files, key=lambda f: f.stat().st_mtime)
        print(f"\n処理するファイル: {latest_file}")
        print(f"ファイルサイズ: {latest_file.stat().st_size:,} バイト")
        print(f"最終更新日時: {datetime.datetime.fromtimestamp(latest_file.stat().st_mtime)}")

        # 出力ディレクトリの作成
        output_dir = pathlib.Path("restored_files")
        output_dir.mkdir(exist_ok=True)

        # 出力ファイル名の生成（タイムスタンプ付き）
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = output_dir / f"restored_{timestamp}_{latest_file.name}"

        # ファイルの復元
        print("\nファイルを復元中...")
        restored_data = parse_quarantine_file(str(latest_file))
        
        # 復元したデータの保存
        with open(output_path, "wb") as f:
            f.write(restored_data)

        print(f"\nファイルを復元しました: {output_path}")
        print(f"復元したデータのサイズ: {len(restored_data):,} バイト")
        
        if msvcrt.getch():  # キー入力待ち
            return

    except Exception as e:
        print(f"エラー: プログラムの実行中にエラーが発生しました: {str(e)}")
        if msvcrt.getch():  # キー入力待ち
            sys.exit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
           description='Windows Defenderで隔離されたファイルを復元'
    )
    parser.add_argument(
            'rootdir',
            help='Windowsのルートディレクトリ（例: C:\\）'
    )
    parser.add_argument(
            '-d', '--dump', action='store_true',
            help='すべてのエントリをtarアーカイブ（quarantine.tar）にエクスポート'
    )

    main(parser.parse_args())