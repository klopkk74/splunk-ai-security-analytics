import urllib.request
import json

# Dien API Key cua ban vao day (Giu nguyen dau ngoac kep "")
api_key = "AIzaSyBEVnCC24Pm6dAPoyTgETIMmqZ3tsF3wJY"
url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"

try:
    print("Dang ket noi den may chu Google AI Studio...\n")
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as response:
        data = json.loads(response.read().decode('utf-8'))
        
        print("DANH SACH CAC MODEL BAN DUOC PHEP SU DUNG:")
        print("-" * 50)
        for model in data.get('models', []):
            # Chi in ra cac model ho tro tao van ban (generateContent)
            if 'generateContent' in model.get('supportedGenerationMethods', []):
                print(f"Ten Model: {model.get('name')}")
                print(f"Mo ta:    {model.get('description')}")
                print("-" * 50)
                
except urllib.error.HTTPError as e:
    print(f"Loi ket noi (HTTP {e.code}): {e.read().decode('utf-8')}")
except Exception as e:
    print(f"Loi he thong: {str(e)}")
