import os
import sys
# Ép Python tìm thư viện ngay trong thư mục hiện tại
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import time
from datetime import datetime
import urllib.request
import json
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option
import splunklib.client as client
import splunklib.results as results

@Configuration()
class IncidentInvestigatorCommand(GeneratingCommand):
    sid = Option(require=True)
    time = Option(require=True) 

    def generate(self):
        try:
            # 1. Kết nối với lõi Splunk
            service = client.connect(token=self._metadata.searchinfo.session_key, app=self._metadata.searchinfo.app)
            
            # 2. XỬ LÝ LỖI JOB HẾT HẠN
            try:
                alert_job = service.jobs[self.sid]
            except KeyError:
                yield {
                    "Timeline": "🔴 [Lỗi Dữ Liệu] Splunk đã xóa kết quả của cảnh báo này do quá hạn (Job Expired).\n\n💡 Hướng xử lý: Vui lòng quay lại màn hình Alerts và phân tích một cảnh báo mới phát sinh.",
                    "MITRE": "[ ❓ ] Dữ liệu gốc không tồn tại",
                    "Checklist": "Không thể lập Playbook vì không có log cảnh báo.",
                    "Victim": "N/A",
                    "Earliest": 0,
                    "Latest": 0
                }
                return

            alert_results = results.ResultsReader(alert_job.results())
            
            t_goc = None
            victim_host = "*"
            
            def parse_splunk_time(time_val):
                try:
                    return float(time_val)
                except ValueError:
                    try:
                        dt = datetime.fromisoformat(str(time_val))
                        return dt.timestamp()
                    except Exception:
                        return time.time()
            
            # Trích xuất chính xác thời điểm nổ Alert từ chuỗi SID
            alert_trigger_time = time.time()
            if "_at_" in self.sid:
                try:
                    alert_trigger_time = float(self.sid.split("_at_")[1].split("_")[0])
                except:
                    pass

            for result in alert_results:
                if isinstance(result, dict):
                    # Ưu tiên _time của log, nếu mất _time thì lấy giờ nổ Alert làm tâm chấn
                    t_goc = parse_splunk_time(result.get('_time', alert_trigger_time))
                    victim_host = result.get('host', '*')
                    break 
            
            # Nếu Alert rỗng, ép hệ thống quét dựa trên giờ nổ Alert
            if not t_goc:
                t_goc = alert_trigger_time

            # 3. QUÉT DIỆN RỘNG (Đã chuyển sang cơ chế WHITELIST EVENTID chiến thuật)
            time_window_seconds = int(self.time) * 60
            # Ép kiểu số nguyên (int) để chống lỗi cú pháp XML của Splunk
            earliest_time = int(t_goc - time_window_seconds)
            latest_time = int(t_goc + time_window_seconds)
            
            search_query = f'search index=* host="{victim_host}" EventCode IN (1, 3, 11, 4104, 4688, 4624, 4625, 7045) NOT "*SplunkUniversalForwarder*" NOT "*splunkd.exe*" NOT "*splunk-*.exe*" NOT "*MicrosoftEdgeUpdate*" NOT "*taskhostw.exe*" NOT "*usoclient.exe*" NOT "*GoogleUpdater*" NOT "*TSTheme.exe*" NOT "*msedgewebview2.exe*" NOT "*wermgr.exe*" NOT "*OneDrive*" NOT "*FileCoAuth*" NOT "*M365Copilot*" NOT "*elevation_service.exe*" NOT "*Sysmon64.exe*" NOT "*TiWorker.exe*" NOT "*RUXIMICS.EXE*" NOT "*clipesu*" NOT "*wsqmcons.exe*" NOT "*devicecensus.exe*" NOT "*WUDFHost.exe*" NOT "*PcaSvc.dll*" NOT "*SecurityHealth*" NOT "*ApplicationFrameHost.exe*" NOT "*PlatformExperienceHelper*" NOT "*platform_experience_helper.exe*" NOT "*PLUGScheduler.exe*" NOT "*DesktopAppInstaller*" NOT "*WindowsPackageManagerServer.exe*" NOT "*SLUI.exe*" NOT "*TextInputHost.exe*" NOT "*pushtoinstall*" NOT "*wuauserv*" NOT "*ctfmon.exe*" NOT "*dwm.exe*" NOT "*csrss.exe*" NOT "*TrustedInstaller.exe*" NOT "*OpenWith.exe*" NOT "*userinit.exe*" NOT "*smss.exe*" NOT "*atbroker.exe*" NOT "*rdpclip*" NOT "*sihost.exe*" NOT "*wmiadap.exe*" NOT "*svchost.exe*" NOT "*svchost.exe* -k netsvcs*" NOT "*svchost.exe* -k LocalSystemNetworkRestricted*" NOT "*svchost.exe* -k UnistackSvcGroup*" NOT "*svchost.exe* -k ClipboardSvcGroup*" earliest={earliest_time} latest={latest_time} | head 400 | sort _time'
            kwargs_oneshot = {"output_mode": "json"}
            oneshot_search_results = service.jobs.oneshot(search_query, **kwargs_oneshot)
            raw_logs = oneshot_search_results.read().decode('utf-8')
            
            log_context = str(raw_logs)[:3000]

            # 4. Hàm gọi HTTP Request xuống Ollama
            def call_ollama(prompt_text):
                url = "http://localhost:11434/api/generate"
                payload = {
                    "model": "llama3.2:3b", 
                    "prompt": prompt_text,
                    "stream": False,
                    "options": {"temperature": 0.1}
                }
                req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers={'Content-Type': 'application/json'})
                try:
                    with urllib.request.urlopen(req, timeout=120) as response:
                        result = json.loads(response.read().decode('utf-8'))
                        return result.get("response", "")
                except Exception as ex:
                    return f"Lỗi AI: {str(ex)}"

            # ĐỊNH HÌNH PROMPT CHUYÊN NGHIỆP
            system_role = """Bạn là một Chuyên gia phân tích SOC cấp cao.
QUY TẮC TỐI THƯỢNG:
1. TRẢ LỜI TRỰC TIẾP VÀO NỘI DUNG. KHÔNG CHÀO HỎI. KHÔNG GIẢI THÍCH MỞ ĐẦU ("Tôi hiểu rằng...", "Dưới đây là..."). KHÔNG KẾT LUẬN.
2. TUÂN THỦ TUYỆT ĐỐI FORMAT VÀ CÁC BIỂU TƯỢNG ĐƯỢC YÊU CẦU. KHÔNG TỰ Ý THÊM KÝ TỰ BÊN NGOÀI FORMAT.
"""

            # CHAIN 1
            prompt_chain1 = f"""{system_role}
Dữ liệu Log: {log_context}

Yêu cầu: Lập Lịch trình diễn biến sự cố (Timeline) từ dữ liệu log trên.
Quy tắc BẮT BUỘC (Tuân thủ tuyệt đối để hệ thống UI hiển thị đúng):
1. Số lượng: Trích xuất từ 4 đến tối đa 8 sự kiện mang tính bước ngoặt (như: Xâm nhập đầu tiên, Leo thang đặc quyền, Đánh cắp dữ liệu, Di chuyển ngang). Bỏ qua các log nhiễu không làm thay đổi trạng thái hệ thống.
2. Trình tự: Sắp xếp thời gian TĂNG DẦN (từ sự kiện cũ nhất đến mới nhất).
3. Độ dài: Mỗi sự kiện miêu tả tối đa 25 từ. Nêu rõ: Ai/Tiến trình nào/IP nào làm gì.
4. Phân loại biểu tượng:
   - Sử dụng 🔴 cho hành vi nguy hiểm, tấn công, mã độc, kết nối mạng bất thường.
   - Sử dụng 🟡 cho tiến trình hệ thống, hành vi đáng ngờ nhưng chưa rõ ràng.
5. Xử lý ngoại lệ: Nếu log không có bất kỳ dấu hiệu rủi ro nào, trả về duy nhất 1 dòng: "🟢 [System] Không ghi nhận hành vi đáng ngờ trong khung giờ này."
6. Định dạng đầu ra: TUYỆT ĐỐI KHÔNG dùng thẻ markdown (```), KHÔNG có câu mở đầu/kết thúc (như "Dưới đây là..."). Chỉ in ra các dòng kết quả.

Ví dụ mẫu:
🔴 [10:41:00] Hệ thống ghi nhận tài khoản 'Demo LHG' bị điều khiển từ xa qua RDP (Port 3389).
🟡 [10:43:25] Tiến trình 'AnyDesk.exe' bị can thiệp sửa đổi cấu hình hệ thống.
🔴 [10:43:27] Ghi nhận tiến trình 'cmd.exe' chạy ngầm lệnh PowerShell bất thường."""
            output_timeline = call_ollama(prompt_chain1)
            if "Lỗi AI:" in output_timeline or "tôi không thể" in output_timeline.lower():
                output_timeline = "🔴 [System] Không thể trích xuất Timeline do dữ liệu log không đủ hoặc bị từ chối."

            # CHAIN 2
            prompt_chain2 = f"""{system_role}
Timeline sự cố: {output_timeline}

Yêu cầu: Ánh xạ các hành vi từ Timeline vào ma trận MITRE ATT&CK Enterprise.
Quy tắc BẮT BUỘC:
1. Ánh xạ chính xác: Mỗi Technique phải thuộc về đúng Tactic theo tài liệu MITRE.
2. Số lượng: Chọn tối đa 3 cặp Tactic/Technique quan trọng nhất dựa trên mức độ ảnh hưởng.
3. Độ tin cậy: Nếu không chắc chắn về mã Tactic/Technique, hãy chọn cái gần nhất với mô tả. KHÔNG được bịa mã (VD: Không được ghi TA9999).
4. Phân loại mức độ nguy hiểm:
   - 🟥 (Mức nguy hiểm cao): Execution, Credential Access, Lateral Movement.
   - 🟧 (Mức trung bình): Persistence, Privilege Escalation, Collection.
   - 🟨 (Mức thấp/Cảnh báo): Discovery, Initial Access, Command and Control.
5. Định dạng đầu ra: TUYỆT ĐỐI KHÔNG dùng thẻ markdown (```), KHÔNG giải thích. Chỉ in kết quả theo định dạng sau:

[ [Icon] [Mã Tactic] - [Tên Tactic] ]
 ↳ [Mã Technique]: [Tên Technique]
   [Ghi chú bằng chứng ngắn gọn 1 dòng]

Ví dụ chuẩn:
[ 🟥 TA0002 - Execution ]
 ↳ T1059: Command and Scripting Interpreter
   Thực thi lệnh PowerShell/CMD đáng ngờ để chiếm quyền điều khiển."""
            output_mitre = call_ollama(prompt_chain2)
            if "Lỗi AI:" in output_mitre:
                output_mitre = "[ ❓ ] Không thể ánh xạ ma trận MITRE ATT&CK."

            # CHAIN 3
            prompt_chain3 = f"""{system_role}
Tình huống sự cố: {output_timeline}

Yêu cầu: Lập Sổ tay Ứng phó Khẩn cấp (Playbook) sát với thực tế.
Format bắt buộc (Giữ đúng cấu trúc tiêu đề tiếng Anh/Việt IN HOA và ngoặc vuông [ ] cho hành động):
HÀNH ĐỘNG TỨC THỜI (IMMEDIATE ACTIONS):
[ ] 1. (Hành động cách ly mạng/khóa tài khoản/chặn IP)
[ ] 2. (Hành động ngăn chặn tức thời khác)

BƯỚC ĐIỀU TRA TIẾP THEO (INVESTIGATION):
[ ] 3. (Hành động rà soát log/quét mã băm toàn hệ thống)
[ ] 4. (Hành động phân tích bộ nhớ/tiến trình)

Ví dụ mẫu (Chỉ in kết quả, không giải thích mở đầu):
HÀNH ĐỘNG TỨC THỜI (IMMEDIATE ACTIONS):
[ ] 1. Cách ly Host bị nhiễm khỏi mạng nội bộ.
[ ] 2. Chặn địa chỉ IP C&C trên Tường lửa (Firewall).

BƯỚC ĐIỀU TRA TIẾP THEO (INVESTIGATION):
[ ] 3. Quét mã băm tập vị nghi ngờ trên toàn bộ hạ tầng."""
            
            output_checklist = call_ollama(prompt_chain3)

            # 5. Đổ dữ liệu về
            yield {
                "Timeline": output_timeline,
                "MITRE": output_mitre,
                "Checklist": output_checklist,
                "Victim": victim_host,
                "Earliest": earliest_time,
                "Latest": latest_time
            }
            
        except Exception as e:
            yield {"Timeline": f"Lỗi Hệ Thống: {str(e)}", "MITRE": "-", "Checklist": "-", "Victim": "N/A", "Earliest": 0, "Latest": 0}

dispatch(IncidentInvestigatorCommand, sys.argv, sys.stdin, sys.stdout, __name__)
