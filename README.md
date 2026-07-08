\# Splunk AI Security Analytics



Hệ thống Splunk tích hợp trí tuệ nhân tạo hỗ trợ phát hiện hành vi bất thường và cảnh báo tự động.



\---



\## 1. Giới thiệu



Đây là đồ án tốt nghiệp của nhóm sinh viên ngành An toàn thông tin, Học viện Kỹ thuật Mật mã. Mục tiêu của dự án là xây dựng một hệ thống giám sát an ninh mạng dựa trên Splunk Enterprise, tích hợp mô hình ngôn ngữ lớn (LLM) để hỗ trợ các hoạt động truy vấn log, phân tích sự kiện và điều tra sự cố.



\*\*Vấn đề được giải quyết:\*\*

\- SOC Analyst thường mất nhiều thời gian để viết câu lệnh SPL

\- Việc đọc và hiểu log từ nhiều nguồn khác nhau rất khó khăn

\- Điều tra sự cố đòi hỏi kinh nghiệm và kiến thức sâu



\*\*Giải pháp:\*\*

\- Sử dụng AI để chuyển ngôn ngữ tự nhiên thành câu lệnh SPL

\- Dùng AI giải nghĩa log và đánh giá mức độ rủi ro

\- Tự động tạo timeline và đề xuất hướng xử lý khi có sự cố



\---



\## 2. Tính năng chính



\*\*a) Truy vấn logs bằng ngôn ngữ tự nhiên\*\*



Nhập câu hỏi bằng tiếng Việt, hệ thống tự động sinh câu lệnh SPL.



Ví dụ:

> \*"Tìm các sự kiện đăng nhập thất bại từ địa chỉ IP 192.168.1.100 trong 24h qua"\*



AI sẽ tạo ra câu lệnh SPL tương ứng, giúp người dùng không cần nhớ cú pháp phức tạp.



\*\*b) Phân tích log thông minh\*\*



Click vào một dòng log bất kỳ, AI sẽ:

\- Tóm tắt nội dung sự kiện

\- Trích xuất các thông tin điều tra quan trọng

\- Đánh giá mức độ rủi ro (Benign/Low/Medium/High/Critical)

\- Ánh xạ sang khung MITRE ATT\&CK



\*\*c) Điều tra sự cố tự động\*\*



Khi một cảnh báo xuất hiện, hệ thống sẽ:

\- Tự động thu thập tất cả log liên quan

\- Tái tạo dòng thời gian của cuộc tấn công

\- Xác định các kỹ thuật tấn công theo MITRE ATT\&CK

\- Đề xuất các bước ứng phó khẩn cấp



\*\*d) Cảnh báo qua Telegram\*\*



Các cảnh báo an ninh được gửi trực tiếp đến nhóm Telegram của đội ngũ vận hành, với đầy đủ thông tin chi tiết.



\---



\## 3. Công nghệ sử dụng



| Thành phần | Công nghệ |

|------------|-----------|

| Nền tảng SIEM | Splunk Enterprise 10.4.0 |

| Mô hình AI | LLaMA 3.2 (3B) chạy qua Ollama |

| Nguồn log | Windows Event Log, Sysmon, Linux Audit, pfSense |

| Khung phát hiện | MITRE ATT\&CK, Sigma Rules |

| Ngôn ngữ truy vấn | SPL (Search Processing Language) |

| Gửi cảnh báo | Telegram Bot API |



\---



\## 4. Kiến trúc hệ thống



```

┌────────────────────────────────────────────────────────┐

│                   Splunk Enterprise                    │

│  ┌───────────┐  ┌───────────┐  ┌───────────────────┐ │

│  │Search Head│  │  Indexer  │  │   Forwarder       │ │

│  │           │  │  Cluster  │  │  (UF/HF)          │ │

│  └───────────┘  └───────────┘  └───────────────────┘ │

├────────────────────────────────────────────────────────┤

│              AI Integration Layer                      │

│  ┌────────────────────────────────────────────────┐    │

│  │  Ollama (llama3.2:3b) + Prompt Engineering    │    │

│  └────────────────────────────────────────────────┘    │

└────────────────────────────────────────────────────────┘

```



\---



\## 5. Kịch bản thực nghiệm



Nhóm đã mô phỏng cuộc tấn công T1219 - Remote Access Software theo khung MITRE ATT\&CK:



1\. Tấn công xâm nhập qua RDP

2\. Cài đặt phần mềm AnyDesk trên máy nạn nhân

3\. Thiết lập backdoor với lệnh `anydesk.exe --set-password`

4\. Truyền file và thực thi lệnh từ xa



\*\*Kết quả:\*\*



\- Hệ thống phát hiện hành vi AnyDesk chạy với tham số `--set-password`

\- Cảnh báo được gửi qua Telegram trong vòng vài giây

\- AI hỗ trợ truy vấn và phân tích log liên quan

\- Tự động tạo timeline điều tra sự cố



\---



\## 6. So sánh hiệu quả



| Tiêu chí | Thực hiện thủ công | Với AI hỗ trợ |

|----------|-------------------|---------------|

| Thời gian truy vấn | 5-10 phút | 1-2 phút |

| Thời gian điều tra | 15-30 phút | 3-5 phút |

| Yêu cầu kỹ năng | Cần thành thạo SPL | Chỉ cần đặt câu hỏi |



\---



\## 7. Cài đặt và chạy thử



\*\*Yêu cầu hệ thống:\*\*

\- Ubuntu Server 20.04+

\- RAM tối thiểu: 8GB

\- Python 3.10+



\*\*Cài Splunk:\*\*

```bash

wget -O splunk-10.4.0-linux-amd64.tgz "https://download.splunk.com/products/splunk/releases/10.4.0/linux/splunk-10.4.0-linux-amd64.tgz"

tar -xvzf splunk-\*.tgz -C /opt

/opt/splunk/bin/splunk start --accept-license

```



\*\*Cài Ollama:\*\*

```bash

curl -fsSL https://ollama.com/install.sh | sh

ollama pull llama3.2:3b

```



\---



\## 8. Tác giả



\- \*\*Nguyễn Trung Kiên\*\* - AT200432

\- \*\*Nguyễn Văn Khánh\*\* - AT200430  

\- \*\*Hoàng Hải Dương\*\* - AT200415



Giảng viên hướng dẫn: \*\*TS. Lê Anh Tiến\*\* - Khoa Công nghệ thông tin, Học viện Kỹ thuật Mật mã



Hà Nội - 2026



\---



\## 9. Giấy phép



MIT License

