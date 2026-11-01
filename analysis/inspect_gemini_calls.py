import json
with open("runs/llm_calls.jsonl", "r", encoding="utf-8") as f:
    for idx, line in enumerate(f):
        r = json.loads(line)
        if r.get("provider") == "gemini":
            print(f"Index {idx+1}: ts={r.get('timestamp')} model={r.get('model')} req_id={r.get('request_id')}")
            print(f"  prompt_snippet: {r.get('prompt')[:100]}...")
            print(f"  response_snippet: {r.get('response')[:100]}...")

