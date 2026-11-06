# ms17_check.py

MS17-010（EternalBlue / CVE-2017-0143）漏洞偵測腳本（Python 3）。

## 原理

依 worawit 研究與 nmap `smb-vuln-ms17-010` NSE 腳本的判定邏輯：

1. SMBv1（NT LM 0.12）協商
2. 匿名 session 連接 `IPC$`
3. 送出 `TRANS_PEEK_NMPIPE` 交易（setup=0x23，MaxParameterCount/MaxDataCount=0xFFFF）
4. 讀取回應 NTSTATUS：
   - `0xC0000205`（STATUS_INSUFF_SERVER_RESOURCES）→ **未修補（VULNERABLE）**
   - `0xC0000022` / `0xC0000008` → 已修補
   - 連線重置 / 逾時 → 無法判定（INCONCLUSIVE）

僅發送偵測封包，不含攻擊載荷，不改變目標狀態。

## 依賴

```bash
pip install impacket
```

## 用法

```bash
python3 ms17_check.py <host> [host ...]
```

輸出範例：

```
HOST                   VERDICT        DETAIL
----------------------------------------------------------------------------------------------------
140.118.1.137          VULNERABLE     STATUS_INSUFF_SERVER_RESOURCES — 未修補 MS17-010（NTSTATUS=0xC0000205）（OS: Windows 10 Pro 10240）
```

## 注意

- `MaxParameterCount`/`MaxDataCount` 必須為 `0xFFFF`；較小值會被誤判為已修補。
- 已修補或 SMBv1 關閉的主機常在探測時直接重置連線，屬預期行為（INCONCLUSIVE）。

僅供獲授權之安全測試使用。
