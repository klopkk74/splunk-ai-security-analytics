import sys
import json
import os
import urllib.request
import urllib.parse
import logging
from splunk.persistconn.application import PersistentServerConnectionApplication

# Cấu hình logging
logger = logging.getLogger(__name__)

class LogAnalyzerHandler(PersistentServerConnectionApplication):
    # Danh sách index được phép truy cập
    ALLOWED_INDEXES = ['os_win', 'os_nix', 'pfsense', 'main']
    MAX_LOG_LENGTH = 10000
    MAX_SEARCH_RESULTS = 1

    def __init__(self, command_line, command_arg):
        super(LogAnalyzerHandler, self).__init__()
        self.system_prompt = self._load_system_prompt()

    def _load_system_prompt(self):
        """Đọc System Prompt từ file cấu hình riêng"""
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            config_path = os.path.join(base_dir, 'prompts_config.json')
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            return config.get('log_analyzer_prompt', '')
        except Exception as e:
            logger.error(f"Failed to load prompt config: {str(e)}")
            return "[LỖI] Không thể tải cấu hình prompt. Vui lòng kiểm tra file prompts_config.json."

    def _check_user_permission(self, session_key):
        """Kiểm tra quyền của user"""
        import splunk.rest
        try:
            response, content = splunk.rest.simpleRequest(
                '/services/authentication/current-context',
                sessionKey=session_key,
                method='GET'
            )
            if response.status == 200:
                user_info = json.loads(content)
                roles = user_info.get('entry', [{}])[0].get('content', {}).get('roles', [])
                if not any(role in ['admin', 'power'] for role in roles):
                    raise PermissionError("User does not have permission to analyze logs")
            else:
                raise PermissionError("Unable to authenticate user permissions")
        except Exception as e:
            logger.error(f"Permission check failed: {str(e)}")
            raise

    def _sanitize_prompt(self, prompt):
        """Làm sạch input để tránh prompt injection"""
        if not prompt:
            return ""
        # Loại bỏ các ký tự nguy hiểm
        dangerous_patterns = ["'''", '"""', "System:", "User:", "\n\n"]
        for pattern in dangerous_patterns:
            prompt = prompt.replace(pattern, "")
        # Giới hạn độ dài
        return prompt[:500]

    def _error_response(self, message, status=500):
        """Trả về lỗi an toàn cho client"""
        logger.error(f"Returning error to client: {message[:200]}")
        return {
            'payload': json.dumps({"prompt": "", "ollama_reply": "Lỗi xử lý yêu cầu. Vui lòng thử lại sau."}),
            'status': status
        }

    def handle(self, in_string):
        try:
            args = json.loads(in_string)
            query_params = dict(args.get('query', []))
            session_key = args.get('session', {}).get('authtoken', '')

            # Kiểm tra quyền
            self._check_user_permission(session_key)

            log_index = query_params.get('index', '*')
            
            # Kiểm tra index hợp lệ
            if log_index != '*' and log_index not in self.ALLOWED_INDEXES:
                return self._error_response("Index not allowed", 403)

            log_time = query_params.get('time', '')
            log_host = urllib.parse.unquote(query_params.get('host', ''))
            log_st = urllib.parse.unquote(query_params.get('st', ''))
            log_ec = urllib.parse.unquote(query_params.get('ec', ''))
            
            log_bkt = query_params.get('bkt', '')
            log_cd = query_params.get('cd', '')

            import splunk.rest
            raw_log = "Loi: Khong lay duoc Raw Log."

            # --- PHẦN SỬA: LỌC TỌA ĐỘ BẰNG LỆNH WHERE (Bypass API Permission) ---
            if log_time and session_key:
                try:
                    t = float(log_time)
                    earliest = int(t) - 2
                    latest = int(t) + 3
                except:
                    earliest = 0
                    latest = "now"
                
                # Base search lấy theo thời gian để lách quyền API
                search_query = f'search index="{log_index}" earliest={earliest} latest={latest}'

                if log_bkt and log_cd:
                    # Lọc ở cấp độ Pipeline (where) để chọn đúng 1 log duy nhất
                    search_query += f' | where _bkt="{log_bkt}" AND _cd="{log_cd}"'
                else:
                    if log_host: search_query += f' host="{log_host}"'
                    if log_st: search_query += f' sourcetype="{log_st}"'
                    if log_ec: search_query += f' "{log_ec}"'
            else:
                search_query = f'search index="{log_index}"'
            
            search_query += f' | head {self.MAX_SEARCH_RESULTS}'
            # --------------------------------------------------------------------

            post_args = {
                'search': search_query,
                'output_mode': 'json',
                'exec_mode': 'oneshot'
            }
            try:
                response, content = splunk.rest.simpleRequest(
                    '/services/search/jobs/export',
                    sessionKey=session_key,
                    postargs=post_args,
                    method='POST'
                )
                if response.status == 200 and content:
                    lines = content.decode('utf-8').split('\n')
                    found = False
                    for line in lines:
                        if not line.strip(): continue
                        try:
                            data_json = json.loads(line)
                            if 'result' in data_json and '_raw' in data_json['result']:
                                raw_log = data_json['result']['_raw']
                                found = True
                                break
                        except Exception:
                            pass
                    if not found:
                        raw_log = f"[CẢNH BÁO] Splunk trả về 0 kết quả. Lệnh đã chạy: {search_query}"
            except Exception as e:
                logger.error(f"REST API error: {str(e)}")
                raw_log = "[LỖI REST API] Không thể truy xuất log. Vui lòng kiểm tra quyền và kết nối."

            # Giới hạn độ dài raw log
            if len(raw_log) > self.MAX_LOG_LENGTH:
                raw_log = raw_log[:self.MAX_LOG_LENGTH] + "... [CẮT NGẮN DO QUÁ DÀI]"

            # Kiểm tra system_prompt đã được tải thành công
            if not self.system_prompt or self.system_prompt.startswith("[LỖI]"):
                return self._error_response("System prompt not configured", 500)

            # Sanitize user input
            sanitized_prompt = self._sanitize_prompt(raw_log)
            user_prompt = f"--- [RAW LOG DATA] ---\n{sanitized_prompt}\n"
            
            payload = {
                "model": "llama3.2:3b",
                "prompt": f"System: {self.system_prompt}\n\nUser: {user_prompt}",
                "stream": False
            }

            ollama_url = "http://127.0.0.1:11434/api/generate"
            try:
                req = urllib.request.Request(ollama_url, data=json.dumps(payload).encode('utf-8'), method='POST')
                req.add_header('Content-Type', 'application/json')
                with urllib.request.urlopen(req, timeout=120) as res:
                    res_body = res.read().decode('utf-8')
                    ai_reply = json.loads(res_body).get("response", "Ollama không trả về dữ liệu.")
            except Exception as e:
                logger.error(f"Ollama error: {str(e)}")
                ai_reply = "[LỖI OLLAMA] Không thể phân tích log. Vui lòng kiểm tra kết nối với Ollama."

            return {
                'payload': json.dumps({"prompt": user_prompt, "ollama_reply": ai_reply}),
                'status': 200
            }
        except PermissionError as e:
            logger.warning(f"Permission denied: {str(e)}")
            return self._error_response("Không có quyền truy cập.", 403)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}", exc_info=True)
            return self._error_response("Lỗi xử lý yêu cầu. Vui lòng thử lại sau.", 500)
