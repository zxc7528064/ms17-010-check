#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ms17_check.py — MS17-010（EternalBlue, CVE-2017-0143）漏洞偵測腳本

原理（依 worawit 研究與 nmap smb-vuln-ms17-010 NSE 腳本）：
  1. 以 SMBv1（NT LM 0.12）與目標協商
  2. 匿名 session 連接 IPC$
  3. 送出 TRANS_PEEK_NMPIPE 交易（setup=0x23, FID=0），
     並將 MaxParameterCount / MaxDataCount 設為 0xFFFF（關鍵：預設值會誤判）
  4. 讀取回應的 NTSTATUS：
       0xC0000205 STATUS_INSUFF_SERVER_RESOURCES → 未修補（VULNERABLE）
       0xC0000022 STATUS_ACCESS_DENIED          → 已修補
       0xC0000008 STATUS_INVALID_HANDLE         → 已修補
       連線重置 / 逾時                          → 無法判定（INCONCLUSIVE）

僅發送偵測封包，不包含任何攻擊載荷，不改變目標狀態。

需求：pip install impacket
用法：python3 ms17_check.py <host> [更多 host...]
"""

import sys
from struct import pack, unpack

try:
    from impacket import smb
    from impacket.smb import (NewSMBPacket, SMBCommand, SMBTransaction_Parameters,
                              SMBTransaction_Data, SMB)
    from impacket.smbconnection import SMBConnection
except ImportError:
    sys.exit('缺少依賴：pip install impacket')

VERDICT = {
    0xC0000205: ('VULNERABLE',   'STATUS_INSUFF_SERVER_RESOURCES — 未修補 MS17-010'),
    0xC0000022: ('PATCHED',      'STATUS_ACCESS_DENIED — 已修補'),
    0xC0000008: ('PATCHED',      'STATUS_INVALID_HANDLE — 已修補'),
}


def check(host, port=445, timeout=15):
    """回傳 (verdict, detail)。任何例外視為 INCONCLUSIVE。"""
    conn = None
    try:
        conn = SMBConnection(host, host, preferredDialect=smb.SMB_DIALECT,
                             timeout=timeout)
        conn.login('', '')                      # 匿名
        os_name = conn.getServerOS()
        tid = conn.connectTree('IPC$')
        srv = conn.getSMBServer()

        # 手刻 TRANS_PEEK_NMPIPE，參數對齊 nmap smb-vuln-ms17-010.nse
        pkt = NewSMBPacket()
        pkt['Tid'] = tid
        cmd = SMBCommand(SMB.SMB_COM_TRANSACTION)
        cmd['Parameters'] = SMBTransaction_Parameters()
        cmd['Data'] = SMBTransaction_Data()
        p = cmd['Parameters']
        p['Setup'] = pack('<H', 0x23)           # TRANS_PEEK_NMPIPE
        p['TotalParameterCount'] = 0
        p['TotalDataCount'] = 0
        p['MaxParameterCount'] = 0xFFFF          # ← 關鍵：必須 0xFFFF
        p['MaxDataCount'] = 0xFFFF               # ← 關鍵：必須 0xFFFF
        p['MaxSetupCount'] = 0
        p['Flags'] = 0
        p['Timeout'] = 0
        p['ParameterCount'] = 0
        p['ParameterOffset'] = 64 + len('\\PIPE\x00')
        p['DataCount'] = 0
        p['DataOffset'] = 0
        cmd['Data']['Name'] = '\\PIPE\x00'
        cmd['Data']['Trans_Parameters'] = b''
        cmd['Data']['Trans_Data'] = b''
        pkt.addCommand(cmd)

        srv.sendSMB(pkt)
        resp = srv.recvSMB()
        raw = resp.rawData if hasattr(resp, 'rawData') else bytes(resp)
        i = raw.find(b'\xffSMB')
        if i < 0 or len(raw) < i + 9:
            return ('INCONCLUSIVE', '回應格式異常', os_name)
        status = unpack('<I', raw[i + 5:i + 9])[0]
        verdict, detail = VERDICT.get(status, ('INCONCLUSIVE',
                                               f'未預期 NTSTATUS=0x{status:08X}'))
        return (verdict, f'{detail}（NTSTATUS=0x{status:08X}）', os_name)
    except Exception as e:
        return ('INCONCLUSIVE', f'{type(e).__name__}: {e}', None)
    finally:
        try:
            if conn:
                conn.logoff()
        except Exception:
            pass


def main():
    if len(sys.argv) < 2:
        sys.exit('用法：python3 ms17_check.py <host> [host ...]')
    print(f"{'HOST':<22} {'VERDICT':<14} DETAIL")
    print('-' * 100)
    for host in sys.argv[1:]:
        verdict, detail, os_name = check(host)
        os_info = f'（OS: {os_name}）' if os_name else ''
        print(f'{host:<22} {verdict:<14} {detail}{os_info}')


if __name__ == '__main__':
    main()
