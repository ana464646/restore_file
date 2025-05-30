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
import tarfile
import os
import sys
import ctypes

from collections import namedtuple
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

def parse_entries(basedir):
    """
    隔離ファイルのエントリ情報を解析します
    
    Args:
        basedir (Path): 隔離ファイルが格納されているベースディレクトリ
        
    Returns:
        list: 隔離ファイルのエントリ情報のリスト
    """
    results = []
    entries_path = basedir / 'Entries'
    
    print(f"デバッグ: 検索対象のディレクトリ: {entries_path}")
    
    if not entries_path.exists():
        print(f"警告: Entriesディレクトリが見つかりません: {entries_path}")
        return results

    try:
        entry_files = list(entries_path.glob('{*}'))
        print(f"デバッグ: 見つかったエントリファイル数: {len(entry_files)}")
        
        for guid in entry_files:
            print(f"デバッグ: エントリファイルを処理中: {guid}")
            try:
                with open(guid, 'rb') as f:
                    # ヘッダーの解析
                    header = rc4_decrypt(f.read(0x3c))
                    data1_len, data2_len = struct.unpack_from('<II', header, 0x28)

                    # データ1の解析（タイムスタンプと検出名）
                    data1 = rc4_decrypt(f.read(data1_len))
                    filetime, = struct.unpack('<Q', data1[0x20:0x28])
                    filetime = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=filetime // 10 - 11644473600000000)
                    detection = data1[0x34:].decode('utf8')

                    # データ2の解析（ファイル情報）
                    data2 = rc4_decrypt(f.read(data2_len))
                    cnt = struct.unpack_from('<I', data2)[0]
                    offsets = struct.unpack_from('<' + str(cnt) + 'I', data2, 0x4)

                    for o in offsets:
                        path, hash, type = get_entry(data2[o:])
                        if type == 'file':
                            results.append(file_record(path, hash, detection, filetime))
            except Exception as e:
                print(f"警告: エントリファイル {guid} の処理中にエラーが発生しました: {str(e)}")
                continue
    except Exception as e:
        print(f"警告: エントリの検索中にエラーが発生しました: {str(e)}")
    
    return results

def main(args):
    """
    メイン処理を実行します
    
    Args:
        args: コマンドライン引数
    """
    if not is_admin():
        print("このプログラムは管理者権限で実行する必要があります。")
        sys.exit(1)

    try:
        # Windowsのパス指定を修正
        root_path = str(args.rootdir).rstrip('\\') + '\\'
        
        # Windows 11での一般的な隔離フォルダの場所をリストアップ
        possible_paths = [
            pathlib.Path(root_path) / 'ProgramData' / 'Microsoft' / 'Windows Defender' / 'Quarantine',
            pathlib.Path(root_path) / 'ProgramData' / 'Microsoft' / 'Windows Defender' / 'Scans' / 'History' / 'Store',
            pathlib.Path(root_path) / 'ProgramData' / 'Microsoft' / 'Windows Defender Advanced Threat Protection' / 'Quarantine',
            pathlib.Path(root_path) / 'Windows Defender',
            pathlib.Path(root_path) / 'Users' / os.getenv('USERNAME') / 'AppData' / 'Local' / 'Microsoft' / 'Windows Defender',
            pathlib.Path(root_path) / 'ProgramData' / 'Microsoft' / 'Microsoft Antimalware' / 'Quarantine',
        ]
        
        found_path = None
        for path in possible_paths:
            print(f"デバッグ: パスを確認中: {path}")
            if path.exists():
                print(f"デバッグ: パスが存在します: {path}")
                # 各パスの下の可能性のあるサブディレクトリを確認
                sub_paths = [
                    path,
                    path / 'Entries',
                    path / 'Quarantine',
                    path / 'Store'
                ]
                for sub_path in sub_paths:
                    if sub_path.exists() and any(sub_path.glob('*')):
                        print(f"デバッグ: 有効なディレクトリを発見: {sub_path}")
                        found_path = path
                        break
                if found_path:
                    break
        
        if not found_path:
            print("\nエラー: 隔離フォルダが見つかりませんでした。")
            print("\n以下のパスを確認しましたが、見つかりませんでした:")
            for path in possible_paths:
                print(f"- {path}")
            print("\n代替の確認方法:")
            print("1. Windowsセキュリティを開く")
            print("2. ウイルスと脅威の防止 → 保護の履歴を確認")
            print("3. 隔離されたアイテムの詳細を確認")
            print("\nまたは、以下のPowerShellコマンドで設定を確認:")
            print('Get-MpPreference | Format-List')
            sys.exit(1)

        basedir = found_path
        print(f"\nデバッグ: 選択された隔離フォルダ: {basedir}")
        
        # 隔離ファイルの詳細な場所を探索
        quarantine_files = []
        for pattern in ['**/*', '**/Entries/*', '**/Quarantine/*', '**/Store/*']:
            quarantine_files.extend(list(basedir.glob(pattern)))
        
        print("\nデバッグ: 見つかったファイル:")
        for file in quarantine_files:
            print(f"- {file}")
        
        entries = parse_entries(basedir)

        if args.dump:
            dump_entries(basedir, entries)
        else:
            if not entries:
                print("\n隔離されたファイルが見つかりませんでした。")
                print("考えられる原因:")
                print("1. Windows Defenderが隔離ファイルを別の場所に保存している")
                print("2. 隔離ファイルが存在しない")
                print("3. アクセス権限の問題")
                print("\n確認事項:")
                print("1. Windows Defenderで実際にファイルが隔離されているか")
                print("2. Windows Defenderの設定で隔離フォルダの場所を確認")
                print("3. 管理者権限で実行しているか")
                print("\nWindowsセキュリティの保護の履歴から隔離ファイルの存在を確認してください。")
                return
                
            detection_max_len = max([len(x[2]) for x in entries]) if entries else 0
            print("\n隔離されたファイルの一覧:")
            print("-" * 80)
            for entry in entries:
                print(f"{entry.filetime} | {entry.detection:<{detection_max_len}} | {entry.path}")
            print("-" * 80)
            print(f"合計: {len(entries)}個のファイル\n")

    except Exception as e:
        print(f"エラー: プログラムの実行中にエラーが発生しました: {str(e)}")
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