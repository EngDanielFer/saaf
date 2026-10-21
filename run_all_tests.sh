echo "========================================="
echo "SAAF Pro Validation Tests v6.7.14"
echo "========================================="

CONTRACT_URL="${1:-${CONTRACT_URL:-https://example.com}}"

echo -e "\n[Test 1] JSON extraction"
python3 test_json_extractor.py
echo -e "\n[Test 2] Chromium"
bash test_chromium.sh
echo -e "\n[Test 3] stdout contract $CONTRACT_URL"
bash test_contract.sh "$CONTRACT_URL"
echo -e "\n[Test 4] Anti-SSRF"
bash test_ssrf.sh
echo -e "\n[Test 5] SMTP env vars"
bash test_env.sh
echo -e "\n========================================="
echo "All tests completed - v6.7.14"
echo "========================================="