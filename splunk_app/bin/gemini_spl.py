import sys
import os
import json
import time
import urllib.request
import urllib.error
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option

@Configuration()
class GeminiSPLCommand(GeneratingCommand):
    prompt = Option(require=True)

    def generate(self):
        # ========== KIỂM TRA INPUT RỖNG ==========
        if not self.prompt or not self.prompt.strip():
            yield {
                '_time': time.time(), 
                'Yeu_Cau': self.prompt, 
                'SPL_Query': "LỖI: Vui lòng nhập câu hỏi. Ô nhập liệu không được để trống."
            }
            return
        # ========== KẾT THÚC KIỂM TRA ==========

        # 1. Cấu hình kết nối Router
        api_key = os.environ.get('API_ROUTER_KEY')
        if not api_key:
            yield {
                '_time': time.time(), 
                'Yeu_Cau': self.prompt, 
                'SPL_Query': "LỖI: Thiếu biến môi trường API_ROUTER_KEY. Vui lòng cấu hình key cho API Router."
            }
            return
        url = "http://127.0.0.1:20128/v1/chat/completions"

        # 2. Đọc Data Dictionary
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            dict_path = os.path.join(base_dir, "data_dictionary.json")
            with open(dict_path, 'r', encoding='utf-8') as f:
                data_dict = json.load(f)
            dict_str = json.dumps(data_dict, ensure_ascii=False, indent=2)
        except Exception as e:
            yield {'_time': time.time(), 'Yeu_Cau': self.prompt, 'SPL_Query': f"Loi doc Data Dictionary: {str(e)}"}
            return

        # 3. Lệnh hệ thống (System Instruction)
        system_instruction = f"""Ban la SOC Analyst va chuyen gia Splunk SPL.
Tu dien Du lieu cua he thong:
{dict_str}

NHIEM VU VA QUY TRINH TAO SPL (BAT BUOC TUAN THU ĐUNG THU TU):
1. BASE SEARCH: Chon dung index, sourcetype, EventCode tu Tu dien. Neu ket hop Windows va Sysmon, BAT BUOC gom nhom bang toan tu OR (VD: `(EventCode=4688) OR (EventCode=1)`).
2. USER CONDITION (QUAN TRONG - CHONG LACH LUAT): 
   - Phan dinh ro ParentImage (Tien trinh cha) va Image (Tien trinh con). KHONG gop chung 1 tien trinh vao 2 thu muc.
   - KHI QUET COMMAND LINE: Phai tinh den cac ky thuat obfuscation. Khong hardcode thieu cac tham so thuc thi (VD: phai bao quat /c, /k, /s, /q voi cmd hoac -enc, -ep bypass, -w hidden voi powershell). Cach tot nhat la dung wildcard rong (VD: `*cmd.exe*`) neu nguoi dung khong yeu cau tim tham so cu the.
   - TUYET DOI KHONG DUNG toan tu `!=` o Base Search de loai tru tien trinh.
3. LOC FALSE POSITIVE (Whitelist & Exclusions): 
   - Neu co truong 'whitelist' trong tu dien, hoac neu AI tu suy luan cac tien trinh can loai tru (VD: explorer.exe), BAT BUOC phai dua tat ca vao lenh pipelining `| search NOT (...)` o cuoi.
4. FORMAT: KET THUC cau lenh bang `| table _time host` va cac 'fields_quan_trong'.
5. TUYET DOI chi tra ve 1 dong lenh SPL DUY NHAT. KHONG dung markdown (```), KHONG giai thich.

VI DU MAU TOI UU:
Yeu cau: Phat hien tien trinh chay tu thu muc temp hoac appdata do cmd.exe goi ra tren Windows.
SPL: (index=os_win sourcetype="WinEventLog:Security" EventCode=4688) OR (index=os_win sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1) ParentImage="*cmd.exe*" (Image="*temp*" OR Image="*appdata*") | search NOT (Image="*\\svchost.exe" OR ParentImage="*\\SplunkUniversalForwarder\\*" OR ParentImage="*explorer.exe*") | table _time host User Image CommandLine ParentImage ProcessId
"""
        # 4. Gửi Payload chuẩn OpenAI
        payload = {
            "model": "Splunk-AI",
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": self.prompt}
            ],
            "temperature": 0.2,
            "stream": False
        }

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json"
        }

        # 5. Gửi Request và nhận lỗi
        try:
            req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers, method='POST')
            with urllib.request.urlopen(req) as response:
                response_data = response.read().decode('utf-8')

                if not response_data.strip():
                    yield {'_time': time.time(), 'Yeu_Cau': self.prompt, 'SPL_Query': "Lỗi: Router trả về dữ liệu rỗng"}
                    return
                try:
                    response_json = json.loads(response_data)
                    ai_spl = response_json['choices'][0]['message']['content']
                    ai_spl = ai_spl.replace("```spl", "").replace("```", "").strip()
                    yield {'_time': time.time(), 'Yeu_Cau': self.prompt, 'SPL_Query': ai_spl}
                except json.JSONDecodeError:
                    yield {'_time': time.time(), 'Yeu_Cau': self.prompt, 'SPL_Query': f"Lỗi format từ Router: {response_data[:200]}"}

        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8')
            yield {'_time': time.time(), 'Yeu_Cau': self.prompt, 'SPL_Query': f"Lỗi {e.code} Router: {error_body[:200]}"}
        except Exception as e:
            yield {'_time': time.time(), 'Yeu_Cau': self.prompt, 'SPL_Query': f"Lỗi kết nối: {str(e)}"}

dispatch(GeminiSPLCommand, sys.argv, sys.stdin, sys.stdout)
