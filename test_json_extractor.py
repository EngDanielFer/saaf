import json
import subprocess
import sys

def extract_json_from_stdout(stdout: str) -> dict:
    stdout = stdout.strip()
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    last_brace = stdout.rfind('{')
    if last_brace == -1:
        raise ValueError("No '{' found")
    try:
        obj, end = decoder.raw_decode(stdout, last_brace)
        if end == len(stdout) or stdout[end:].strip() == '':
            return obj
        else:
            i = last_brace - 1
            while i >= 0:
                if stdout[i] == '{':
                    try:
                        obj2, end2 = decoder.raw_decode(stdout, i)
                        if end2 > i and isinstance(obj2, dict):
                            return obj2
                    except json.JSONDecodeError:
                        pass
                i -= 1
            raise ValueError("No valid JSON")
    except json.JSONDecodeError:
        raise ValueError("No valid JSON")

def test_with_real_scraper():
    print("=== Test #1: Real scraper simulation ===")
    result = subprocess.run(['node', 'test_real_scraper.js'], capture_output=True, text=True)
    stdout = result.stdout
    stderr = result.stderr
    print(f"stdout size: {len(stdout)} bytes")
    print(f"stdout preview: {repr(stdout[:300])}")
    print(f"stderr: {len(stderr)} bytes")
    try:
        data = extract_json_from_stdout(stdout)
        print("\n[OK] JSON extracted successfully")
        print(f"url: {data.get('url')}")
        print(f"status_code: {data.get('status_code')}")
        print(f"html length: {len(data.get('html', ''))} chars")
        expected_html = "<html><head><title>Test</title></head><body>Hello World</body></html>"
        if data.get('html') == expected_html:
            print("[OK] HTML matches exactly")
            return True
        else:
            print("[FAIL] HTML mismatch")
            return False
    except Exception as e:
        print(f"\n[FAIL] Extraction failed: {e}")
        return False
    
if __name__ == '__main__':
    success = test_with_real_scraper()
    sys.exit(0 if success else 1)