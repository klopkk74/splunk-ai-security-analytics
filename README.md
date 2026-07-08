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
📦 splunk-ai-soc
 ┣ 📂 configs/             # Các file cấu hình Splunk (.conf)
 ┃ ┣ 📜 inputs.conf        # Cấu hình thu thập log
 ┃ ┣ 📜 indexes.conf       # Cấu hình lưu trữ Indexer
 ┃ ┗ 📜 workflow_actions.conf # Cấu hình hành động trên giao diện
 ┣ 📂 scripts_ai/          # Các kịch bản giao tiếp giữa Splunk và LLM
 ┃ ┣ 📜 gemini_spl.py      # Sinh lệnh SPL từ Tiếng Việt
 ┃ ┣ 📜 log_analyzer.py    # Phân tích cú pháp và giải nghĩa Log
 ┃ ┗ 📜 incident_investigator.py # Multi-chain LLM điều tra sự cố
 ┣ 📂 dashboards/          # Source XML của các Dashboard giám sát
 ┣ 📜 data_dictionary.json # Từ điển dữ liệu cấp ngữ cảnh cho AI (RAG)
 ┗ 📜 README.md
