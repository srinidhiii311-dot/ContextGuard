import json
import statistics

gemini_judge_calls = []
with open("runs/llm_calls.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        r = json.loads(line.strip())
        if r.get("role") == "judge" and r.get("provider") == "gemini":
            gemini_judge_calls.append(r)

print(f"Total live Gemini judge calls in llm_calls.jsonl: {len(gemini_judge_calls)}")
for idx, c in enumerate(gemini_judge_calls, 1):
    m = c["model"]
    lat = c["latency_ms"]
    tin = c["tokens_in"]
    tout = c["tokens_out"]
    cached = c.get("cached", False)
    print(f"Call {idx}: model={m} latency_ms={lat:.2f} tokens_in={tin} tokens_out={tout} cached={cached}")

lats = [c["latency_ms"] for c in gemini_judge_calls]
tins = [c["tokens_in"] for c in gemini_judge_calls]
touts = [c["tokens_out"] for c in gemini_judge_calls]

print("\n--- EXACT LIVE JUDGE TELEMETRY NUMBERS ---")
print(f"Model Name: {gemini_judge_calls[0]['model']}")
print(f"Provider: {gemini_judge_calls[0]['provider']}")
print(f"Median Latency: {statistics.median(lats):.2f} ms ({statistics.median(lats)/1000.0:.2f} s)")
print(f"Mean Latency: {statistics.mean(lats):.2f} ms ({statistics.mean(lats)/1000.0:.2f} s)")
print(f"Median tokens_in: {statistics.median(tins)}")
print(f"Mean tokens_in: {statistics.mean(tins):.1f}")
print(f"Median tokens_out: {statistics.median(touts)}")

