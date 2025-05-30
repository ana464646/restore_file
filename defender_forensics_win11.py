import os
import sys
import json
import struct
import pathlib
from datetime import datetime
from typing import BinaryIO, Dict, Any
from dataclasses import dataclass
from enum import IntEnum

@dataclass
class DetectionHistoryEntry:
    """Windows Defender検出履歴エントリー"""
    detection_id: str
    timestamp: datetime
    threat_status: int
    threat_id: str
    threat_name: str
    path: str
    process_name: str
    action_success: bool
    remediation_type: int
    user_name: str
    detection_type: int
    initial_category: int
    current_category: int
    file_state: int
    threat_execution_status: int
    additional_actions_failed: int

class DefenderHistory:
    """Windows Defender検出履歴の解析クラス"""
    
    def __init__(self, history_path: str):
        self.history_path = pathlib.Path(history_path)
        
    def parse_detection_history(self, data: bytes) -> DetectionHistoryEntry:
        """検出履歴エントリーを解析"""
        try:
            # JSONとしてパース
            history_data = json.loads(data.decode('utf-16-le', errors='ignore'))
            
            # 必要なフィールドを抽出
            detection = history_data.get('detection', {})
            process = history_data.get('process', {})
            remediation = history_data.get('remediation', {})
            
            return DetectionHistoryEntry(
                detection_id=detection.get('detectionId', ''),
                timestamp=datetime.fromtimestamp(detection.get('time', 0)),
                threat_status=detection.get('threatStatus', 0),
                threat_id=detection.get('threatId', ''),
                threat_name=detection.get('threatName', ''),
                path=detection.get('filePath', ''),
                process_name=process.get('name', ''),
                action_success=remediation.get('actionSuccess', False),
                remediation_type=remediation.get('remediationType', 0),
                user_name=detection.get('detectionUserId', ''),
                detection_type=detection.get('detectionType', 0),
                initial_category=detection.get('initialCategory', 0),
                current_category=detection.get('currentCategory', 0),
                file_state=detection.get('fileState', 0),
                threat_execution_status=detection.get('threatExecutionStatus', 0),
                additional_actions_failed=remediation.get('additionalActionsFailed', 0)
            )
            
        except json.JSONDecodeError as e:
            raise ValueError(f"JSONの解析に失敗しました: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"検出履歴の解析中にエラーが発生しました: {str(e)}")
            
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """検出履歴ファイルを解析"""
        try:
            with open(file_path, "rb") as f:
                data = f.read()
                entry = self.parse_detection_history(data)
                
                return {
                    "detection_id": entry.detection_id,
                    "timestamp": entry.timestamp.isoformat(),
                    "threat": {
                        "id": entry.threat_id,
                        "name": entry.threat_name,
                        "status": entry.threat_status,
                        "execution_status": entry.threat_execution_status
                    },
                    "file": {
                        "path": entry.path,
                        "state": entry.file_state
                    },
                    "process": {
                        "name": entry.process_name
                    },
                    "remediation": {
                        "success": entry.action_success,
                        "type": entry.remediation_type,
                        "additional_actions_failed": entry.additional_actions_failed
                    },
                    "detection": {
                        "type": entry.detection_type,
                        "initial_category": entry.initial_category,
                        "current_category": entry.current_category,
                        "user": entry.user_name
                    }
                }
                
        except Exception as e:
            raise RuntimeError(f"ファイルの解析中にエラーが発生しました: {str(e)}")

def format_threat_status(status: int) -> str:
    """脅威の状態を人間が読める形式に変換"""
    statuses = {
        0: "不明",
        1: "検出済み",
        2: "クリーン済み",
        3: "隔離済み",
        4: "削除済み",
        5: "許可済み",
        6: "ブロック済み"
    }
    return statuses.get(status, f"不明な状態({status})")

def format_remediation_type(rtype: int) -> str:
    """修復タイプを人間が読める形式に変換"""
    types = {
        0: "なし",
        1: "クリーン",
        2: "隔離",
        3: "削除",
        4: "ブロック",
        5: "許可"
    }
    return types.get(rtype, f"不明な修復タイプ({rtype})")

def main():
    """メイン処理"""
    if len(sys.argv) != 2:
        print("使用方法: python defender_forensics_win11.py <検出履歴ファイルのパス>")
        sys.exit(1)
        
    history_file = sys.argv[1]
    if not os.path.exists(history_file):
        print(f"エラー: ファイルが見つかりません: {history_file}")
        sys.exit(1)
        
    try:
        analyzer = DefenderHistory(history_file)
        result = analyzer.analyze_file(history_file)
        
        print("\nWindows Defender検出履歴の解析結果:")
        print("-" * 50)
        print(f"検出ID: {result['detection_id']}")
        print(f"タイムスタンプ: {result['timestamp']}")
        print("\n脅威情報:")
        print(f"  名前: {result['threat']['name']}")
        print(f"  ID: {result['threat']['id']}")
        print(f"  状態: {format_threat_status(result['threat']['status'])}")
        print(f"  実行状態: {result['threat']['execution_status']}")
        print("\nファイル情報:")
        print(f"  パス: {result['file']['path']}")
        print(f"  状態: {result['file']['state']}")
        print("\nプロセス情報:")
        print(f"  名前: {result['process']['name']}")
        print("\n修復情報:")
        print(f"  成功: {'はい' if result['remediation']['success'] else 'いいえ'}")
        print(f"  タイプ: {format_remediation_type(result['remediation']['type'])}")
        print(f"  追加アクション失敗: {result['remediation']['additional_actions_failed']}")
        print("\n検出詳細:")
        print(f"  タイプ: {result['detection']['type']}")
        print(f"  初期カテゴリ: {result['detection']['initial_category']}")
        print(f"  現在のカテゴリ: {result['detection']['current_category']}")
        print(f"  ユーザー: {result['detection']['user']}")
        
    except Exception as e:
        print(f"エラー: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 