import os
import sys
import struct
import ctypes
import pathlib
from datetime import datetime

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

class XpressDecompressor:
    """XPRESSデータの解凍を行うクラス"""
    
    def __init__(self):
        """XPRESSライブラリの初期化"""
        try:
            self.xpress = ctypes.WinDLL("xpress.dll")
        except Exception as e:
            try:
                # フルパスで試行
                self.xpress = ctypes.WinDLL(r"C:\Windows\System32\xpress.dll")
            except Exception as e:
                raise RuntimeError(f"xpress.dllの読み込みに失敗しました: {str(e)}")
        
        # 関数定義の設定
        self.xpress.XpressDecode.argtypes = [
            ctypes.c_void_p,   # 出力バッファ
            ctypes.c_uint,     # 出力バッファサイズ
            ctypes.c_void_p,   # 入力バッファ
            ctypes.c_uint,     # 入力サイズ
        ]
        self.xpress.XpressDecode.restype = ctypes.c_uint
    
    def decompress(self, data, output_size):
        """
        XPRESSデータを解凍します
        
        Args:
            data (bytes): 圧縮されたデータ
            output_size (int): 出力バッファサイズ
            
        Returns:
            bytes: 解凍されたデータ
        """
        output = (ctypes.c_ubyte * output_size)()
        input_buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        
        try:
            result = self.xpress.XpressDecode(
                ctypes.byref(output),
                output_size,
                ctypes.byref(input_buffer),
                len(data)
            )
            
            if result == 0:
                raise RuntimeError("データの解凍に失敗しました")
                
            return bytes(output)[:result]
            
        except Exception as e:
            raise RuntimeError(f"解凍処理中にエラーが発生しました: {str(e)}")

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
        if data[:4] != b"MPQU":
            raise ValueError("無効な隔離ファイルです（MPQUヘッダーがありません）")

        # ヘッダーサイズの取得
        header_size = struct.unpack_from("<I", data, 4)[0]
        if header_size >= len(data):
            raise ValueError("無効なヘッダーサイズです")

        # 圧縮データの取得
        compressed = data[header_size:]
        if not compressed:
            raise ValueError("圧縮データが見つかりません")

        # 解凍処理
        decompressor = XpressDecompressor()
        # 出力サイズは圧縮データの10倍を確保
        decompressed = decompressor.decompress(compressed, output_size=10*len(compressed))
        
        return decompressed

    except FileNotFoundError:
        raise RuntimeError(f"ファイルが見つかりません: {path}")
    except PermissionError:
        raise RuntimeError(f"ファイルにアクセスする権限がありません: {path}")
    except Exception as e:
        raise RuntimeError(f"ファイルの解析中にエラーが発生しました: {str(e)}")

def find_quarantine_files():
    """
    Windows Defenderの隔離ファイルを検索します
    
    Returns:
        list: 見つかった隔離ファイルのパスのリスト
    """
    search_paths = [
        # 標準の隔離フォルダ
        r"C:\ProgramData\Microsoft\Windows Defender\Quarantine",
        # Windows 11の新しい場所
        r"C:\ProgramData\Microsoft\Windows Defender\Scans\History\Store",
        r"C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory",
        # 追加の可能性のある場所
        r"C:\ProgramData\Microsoft\Windows Defender\LocalCopy",
        r"C:\ProgramData\Microsoft\Windows Defender\Quarantine\Low",
        r"C:\ProgramData\Microsoft\Windows Defender\Quarantine\Resource"
    ]
    
    found_files = []
    for base_path in search_paths:
        try:
            path = pathlib.Path(base_path)
            if path.exists():
                # 直接のファイル
                found_files.extend(path.glob("*"))
                # サブディレクトリ内のファイル
                found_files.extend(path.glob("**/*"))
        except Exception as e:
            print(f"警告: {base_path} の検索中にエラー: {str(e)}")
            continue
    
    # 重複を除去
    return list(set(found_files))

def is_quarantine_file(path):
    """
    ファイルが隔離ファイルかどうかを判定します
    
    Args:
        path: チェックするファイルパス
        
    Returns:
        bool: 隔離ファイルの場合はTrue
    """
    try:
        if not path.is_file():
            return False
            
        # サイズチェック（最小サイズ以上）
        if path.stat().st_size < 0x20:
            return False
            
        # ファイルの先頭をチェック
        with open(path, "rb") as f:
            header = f.read(8)
            # MPQUヘッダーチェック
            if header.startswith(b"MPQU"):
                return True
            # その他の既知のヘッダーパターン
            known_patterns = [b"MPSQ", b"MSFT", b"Windows Defender"]
            if any(pattern in header for pattern in known_patterns):
                return True
                
        return False
        
    except Exception:
        return False

def main():
    """メイン処理"""
    
    if not is_admin():
        print("このプログラムは管理者権限で実行する必要があります。")
        sys.exit(1)

    try:
        print("隔離ファイルを検索中...")
        
        # 隔離ファイルの検索
        all_files = find_quarantine_files()
        if not all_files:
            raise RuntimeError("隔離ファイルが見つかりません")
            
        # 隔離ファイルのフィルタリング
        quarantine_files = [f for f in all_files if is_quarantine_file(f)]
        if not quarantine_files:
            raise RuntimeError("有効な隔離ファイルが見つかりません")
            
        print(f"\n{len(quarantine_files)}個の隔離ファイルが見つかりました")
        
        # 最新のファイルを処理
        latest_file = max(quarantine_files, key=lambda f: f.stat().st_mtime)
        print(f"\n処理するファイル: {latest_file}")
        print(f"ファイルサイズ: {latest_file.stat().st_size:,} バイト")
        print(f"最終更新日時: {datetime.fromtimestamp(latest_file.stat().st_mtime)}")

        # 出力ディレクトリの作成
        output_dir = pathlib.Path("restored_files")
        output_dir.mkdir(exist_ok=True)

        # 出力ファイル名の生成（タイムスタンプ付き）
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = output_dir / f"{timestamp}_{latest_file.name}"

        # ファイルの復元
        print("\nファイルを復元中...")
        restored_data = parse_quarantine_file(str(latest_file))
        
        # 復元したデータの保存
        with open(output_path, "wb") as f:
            f.write(restored_data)

        print(f"\nファイルを復元しました: {output_path}")
        print(f"復元したデータのサイズ: {len(restored_data):,} バイト")

    except Exception as e:
        print(f"エラー: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
