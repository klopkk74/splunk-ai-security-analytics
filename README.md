# 🛡️ Splunk SIEM & AI: Automated Threat Detection and Incident Response

## 📌 Giới thiệu
Dự án này là hệ thống Quản lý Sự kiện và Thông tin Bảo mật (SIEM) được xây dựng trên nền tảng Splunk Enterprise, kết hợp với Mô hình ngôn ngữ lớn (LLM) để tối ưu hóa quy trình vận hành của Trung tâm Điều hành An ninh mạng (SOC). 

Hệ thống không chỉ thu thập và chuẩn hóa dữ liệu từ nhiều nguồn (Windows, Linux, pfSense) mà còn tự động hóa việc phát hiện hành vi tấn công (mapping theo MITRE ATT&CK), phân tích ngữ cảnh log và cảnh báo thời gian thực.

**Thực hiện bởi:** Nguyễn Trung Kiên, Nguyễn Văn Khánh, Hoàng Hải Dương (Học viện Kỹ thuật Mật mã).

## ✨ Tính năng nổi bật

* **🔍 Giám sát & Tương quan sự kiện (Event Correlation):** 
  * Thu thập và chuẩn hóa dữ liệu (CIM) bằng Universal/Heavy Forwarder.
  * Thiết kế các rules phát hiện hành vi bất thường (vd: Kịch bản tấn công T1219 - Remote Access Software bằng AnyDesk).
* **🤖 Tích hợp Trợ lý AI (Local LLM):**
  * **Natural Language to SPL:** Chuyển đổi ngôn ngữ tự nhiên (Tiếng Việt) thành câu lệnh truy vấn SPL chuyên sâu.
  * **Log Analyzer:** Cô lập, giải mã (decode Base64/PowerShell) và giải nghĩa ngữ cảnh dòng log thô thành báo cáo dễ hiểu.
  * **Incident Investigator:** Multi-chain AI tự động tổng hợp timeline sự cố, ánh xạ ma trận MITRE ATT&CK và xuất Playbook ứng phó.
* **🚨 Cảnh báo tự động (Automated Alerts):**
  * Tích hợp Webhook đẩy cảnh báo tự động về Telegram Bot với độ trễ tính bằng giây.
* **📊 Trực quan hóa (Dashboards):** 
  * Các panel giám sát linh hoạt, tự động cập nhật biểu đồ phân tích tần suất (Event Spike), Top Talkers và Raw Artifacts.

## 🛠️ Kiến trúc hệ thống & Công nghệ

* **Core SIEM:** Splunk Enterprise (Search Head, Indexers, Forwarders, Deployment Server).
* **AI/Machine Learning:** Mô hình LLM Llama 3.2 (3B) chạy cục bộ qua Ollama (Air-gapped) để đảm bảo bảo mật dữ liệu log.
* **Ngôn ngữ & Cú pháp:** Python (REST API handlers), SPL (Search Processing Language), JavaScript (Splunk Web Framework), Sigma Rules.
* **Mạng & Hạ tầng:** Môi trường lab gồm Ubuntu Server, Windows 10, pfSense Firewall.

## 📂 Cấu trúc thư mục mã nguồn

Dự án này chủ yếu chia sẻ các kịch bản (scripts) và cấu hình (configs) được tích hợp vào Splunk:

```text
## 📂 Cấu trúc dự án

```text
📦 splunk-ai-security-analytics
 ┣ 📂 splunk_app/                # Splunk App
 ┃ ┣ 📂 bin/                     # Scripts xử lý chính
 ┃ ┃ ┣ 📜 gemini_spl.py          # Convert natural language to SPL
 ┃ ┃ ┣ 📜 incident_investigator.py # Multi-chain AI investigation
 ┃ ┃ ┗ 📜 log_analyzer.py        # Parse and analyze raw logs
 ┃ ┣ 📂 default/                 # Cấu hình mặc định
 ┃ ┃ ┣ 📜 app.conf               # Thông tin ứng dụng
 ┃ ┃ ┣ 📜 commands.conf          # Đăng ký custom commands
 ┃ ┃ ┣ 📜 restmap.conf           # REST API endpoints
 ┃ ┃ ┣ 📜 web.conf               # Cấu hình giao diện web
 ┃ ┃ ┗ 📜 workflow_actions.conf  # Hành động tương tác trên UI
 ┃ ┣ 📂 local/                   # Cấu hình tùy chỉnh
 ┃ ┣ 📂 metadata/                # Metadata của App
 ┃ ┃ ┗ 📜 default.meta           # Quyền truy cập
 ┃ ┗ 📂 appserver/               # Giao diện người dùng
 ┃   ┗ 📂 static/
 ┃       ┣ 📜 alert_interceptor.js    # Đánh chặn cảnh báo, lấy SID
 ┃       ┣ 📜 dashboard_modalis.js    # Xử lý giao diện Dashboard
 ┃       ┗ 📜 log_analyzer.js         # Gọi REST API, hiển thị phân tích
 ┣ 📂 configs/                   # File cấu hình chung
 ┃ ┗ 📜 data_dictionary.json     # Từ điển dữ liệu cho RAG
 ┣ 📂 docs/                      # Tài liệu
 ┃ ┗ 📜 Bao_cao_chuyen_de_Splunk_AI.pdf
 ┣ 📂 images/                    # Hình ảnh demo
 ┃ ┣ 📜 dashboard-splunk.png     # Dashboard giám sát
 ┃ ┣ 📜 ai-query1.png            # Nhập câu hỏi tiếng Việt
 ┃ ┣ 📜 ai-query2.png            # SPL được sinh ra
 ┃ ┣ 📜 ai-analysis1.png         # Click vào log
 ┃ ┣ 📜 ai-analysis2.png         # Báo cáo AI phân tích
 ┃ ┣ 📜 ai-analysis3.png         # Đánh giá rủi ro + MITRE
 ┃ ┣ 📜 incident-investigation1.png # Danh sách Alert
 ┃ ┣ 📜 incident-investigation2.png # Nhập khung thời gian điều tra mở rộng
 ┃ ┣ 📜 incident-investigation3.png # Dashboard AI điều tra sự cố
 ┃ ┗ 📜 alert-telegram.png       # Tin nhắn Telegram
 ┣ 📜 .gitignore                 # File loại trừ khi push
 ┣ 📜 LICENSE                    # Giấy phép MIT
 ┗ 📜 README.md                  # Mô tả dự án
