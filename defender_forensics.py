import os
import sys
import struct
import ctypes
import pathlib
from datetime import datetime
from io import BytesIO
from typing import BinaryIO
from dataclasses import dataclass
from enum import IntEnum

# RC4暗号化に使用する定数キー（Windows Defenderのmpengine.dllから抽出）
RC4_KEY = bytes([0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69,
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
                0xD8, 0xF6, 0xC7, 0x45, 0x79, 0xE8, 0x53, 0x03, 0x0F, 0xBC,
                0x86, 0x5D, 0x06, 0x1C, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

class FieldType(IntEnum):
    """QuarantineEntryResourceFieldのタイプ定義"""
    UNKNOWN = 0
    STRING = 1
    BINARY = 2
    DWORD = 3
    QWORD = 4

@dataclass
class QuarantineEntryFileHeader:
    """隔離ファイルのヘッダー構造"""
    magic_header: bytes  # "QUAR"
    section1_size: int
    section1_crc: int
    section2_size: int
    section2_crc: int
    magic_footer: bytes  # "QFIL"

@dataclass
class QuarantineEntrySection1:
    """隔離ファイルのセクション1構造（メタデータ）"""
    entry_id: bytes
    scan_id: bytes
    timestamp: int
    threat_id: int
    detection_name: str

@dataclass
class QuarantineEntryResource:
    """隔離されたリソースの情報"""
    detection_path: str
    detection_type: str
    fields: list

def rc4_crypt(data: bytes) -> bytes:
    """RC4暗号化/復号化を行う"""
    if not data:
        return b""
    
    # RC4の状態配列を初期化
    S = list(range(256))
    j = 0
    
    # KSA (Key Scheduling Algorithm)
    for i in range(256):
        j = (j + S[i] + RC4_KEY[i % len(RC4_KEY)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    
    # PRGA (Pseudo-Random Generation Algorithm)
    result = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) & 0xFF]
        result.append(byte ^ k)
    
    return bytes(result)

class DefenderQuarantine:
    """Windows Defender隔離ファイルの解析クラス"""
    
    def __init__(self, quarantine_path: str):
        self.quarantine_path = pathlib.Path(quarantine_path)
        
    def parse_header(self, data: bytes) -> QuarantineEntryFileHeader:
        """ヘッダーを解析"""
        if len(data) < 60:  # ヘッダーの最小サイズ
            raise ValueError("無効なヘッダーサイズです")
            
        magic_header = data[:4]
        if magic_header != b"QUAR":
            raise ValueError("無効な隔離ファイルです（QUARヘッダーがありません）")
            
        section1_size = struct.unpack("<I", data[4:8])[0]
        section1_crc = struct.unpack("<I", data[8:12])[0]
        section2_size = struct.unpack("<I", data[12:16])[0]
        section2_crc = struct.unpack("<I", data[16:20])[0]
        magic_footer = data[56:60]
        
        if magic_footer != b"QFIL":
            raise ValueError("無効な隔離ファイルです（QFILフッターがありません）")
            
        return QuarantineEntryFileHeader(
            magic_header=magic_header,
            section1_size=section1_size,
            section1_crc=section1_crc,
            section2_size=section2_size,
            section2_crc=section2_crc,
            magic_footer=magic_footer
        )
        
    def parse_section1(self, data: bytes) -> QuarantineEntrySection1:
        """セクション1（メタデータ）を解析"""
        entry_id = data[:16]
        scan_id = data[16:32]
        timestamp = struct.unpack("<Q", data[32:40])[0]
        threat_id = struct.unpack("<Q", data[40:48])[0]
        
        # 検出名の長さを取得（NULL終端文字列）
        detection_name_end = data[48:].find(b"\x00")
        if detection_name_end == -1:
            detection_name = ""
        else:
            detection_name = data[48:48+detection_name_end].decode("utf-8", errors="ignore")
            
        return QuarantineEntrySection1(
            entry_id=entry_id,
            scan_id=scan_id,
            timestamp=timestamp,
            threat_id=threat_id,
            detection_name=detection_name
        )
        
    def parse_resource(self, data: bytes) -> QuarantineEntryResource:
        """リソース情報を解析"""
        # パスの長さを取得（NULL終端のUTF-16文字列）
        path_end = 0
        while path_end < len(data):
            if data[path_end:path_end+2] == b"\x00\x00":
                break
            path_end += 2
                
        detection_path = data[:path_end].decode("utf-16-le")
        
        # フィールド数を取得
        field_count = struct.unpack("<H", data[path_end+2:path_end+4])[0]
        
        # 検出タイプを取得
        type_start = path_end + 4
        type_end = data[type_start:].find(b"\x00")
        if type_end == -1:
            detection_type = ""
        else:
            detection_type = data[type_start:type_start+type_end].decode("ascii", errors="ignore")
            
        # フィールドの解析
        fields = []
        offset = type_start + type_end + 1
        
        for _ in range(field_count):
            # 4バイトアラインメント
            offset = (offset + 3) & ~3
            
            # フィールドヘッダーの解析
            field_size = struct.unpack("<H", data[offset:offset+2])[0]
            field_type = (data[offset+2] >> 4) & 0x0F
            field_id = ((data[offset+2] & 0x0F) << 8) | data[offset+3]
            
            # フィールドデータの取得
            field_data = data[offset+4:offset+4+field_size]
            
            # フィールドタイプに応じた解析
            parsed_data = None
            if FieldType(field_type) == FieldType.STRING:
                parsed_data = field_data.decode("utf-16-le", errors="ignore").rstrip("\x00")
            elif FieldType(field_type) == FieldType.BINARY:
                parsed_data = field_data
            elif FieldType(field_type) == FieldType.DWORD:
                parsed_data = struct.unpack("<I", field_data)[0]
            elif FieldType(field_type) == FieldType.QWORD:
                parsed_data = struct.unpack("<Q", field_data)[0]
                
            fields.append({
                "id": field_id,
                "type": FieldType(field_type).name,
                "data": parsed_data
            })
            
            offset += 4 + field_size
            
        return QuarantineEntryResource(
            detection_path=detection_path,
            detection_type=detection_type,
            fields=fields
        )
        
    def analyze_file(self, file_path: str) -> dict:
        """隔離ファイルを解析"""
        try:
            with open(file_path, "rb") as f:
                # ヘッダーの解析
                header_data = rc4_crypt(f.read(60))
                header = self.parse_header(header_data)
                
                # セクション1の解析
                section1_data = rc4_crypt(f.read(header.section1_size))
                section1 = self.parse_section1(section1_data)
                
                # セクション2の解析（リソース情報）
                section2_data = rc4_crypt(f.read(header.section2_size))
                resources = []
                
                # リソース数の取得
                resource_count = struct.unpack("<I", section2_data[:4])[0]
                offsets = struct.unpack(f"<{resource_count}I", section2_data[4:4+resource_count*4])
                
                # 各リソースの解析
                for i in range(resource_count):
                    start_offset = offsets[i]
                    end_offset = offsets[i+1] if i < resource_count-1 else len(section2_data)
                    resource_data = section2_data[start_offset:end_offset]
                    resources.append(self.parse_resource(resource_data))
                
                return {
                    "metadata": {
                        "entry_id": section1.entry_id.hex(),
                        "scan_id": section1.scan_id.hex(),
                        "timestamp": datetime.fromtimestamp(section1.timestamp).isoformat(),
                        "threat_id": section1.threat_id,
                        "detection_name": section1.detection_name
                    },
                    "resources": [
                        {
                            "path": r.detection_path,
                            "type": r.detection_type,
                            "fields": r.fields
                        } for r in resources
                    ]
                }
                
        except Exception as e:
            raise RuntimeError(f"ファイルの解析中にエラーが発生しました: {str(e)}")

def main():
    """メイン処理"""
    if len(sys.argv) != 2:
        print("使用方法: python defender_forensics.py <隔離ファイルのパス>")
        sys.exit(1)
        
    quarantine_file = sys.argv[1]
    if not os.path.exists(quarantine_file):
        print(f"エラー: ファイルが見つかりません: {quarantine_file}")
        sys.exit(1)
        
    try:
        analyzer = DefenderQuarantine(quarantine_file)
        result = analyzer.analyze_file(quarantine_file)
        
        print("\n隔離ファイルの解析結果:")
        print("-" * 50)
        print(f"エントリーID: {result['metadata']['entry_id']}")
        print(f"スキャンID: {result['metadata']['scan_id']}")
        print(f"タイムスタンプ: {result['metadata']['timestamp']}")
        print(f"脅威ID: {result['metadata']['threat_id']}")
        print(f"検出名: {result['metadata']['detection_name']}")
        
        print("\n検出されたリソース:")
        for i, resource in enumerate(result['resources'], 1):
            print(f"\nリソース {i}:")
            print(f"パス: {resource['path']}")
            print(f"タイプ: {resource['type']}")
            print("\nフィールド:")
            for field in resource['fields']:
                print(f"  ID: {field['id']}")
                print(f"  タイプ: {field['type']}")
                print(f"  データ: {field['data']}")
                print()
                
    except Exception as e:
        print(f"エラー: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 