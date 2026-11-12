import json
import time
from organ import solve

CASES = [10, 100, 1000, 5000]

def main():
    t0 = time.perf_counter()
    ok = 0
    for n in CASES:
        expected = n * (n + 1) // 2
        got = solve(n)
        if got == expected:
            ok += 1
    validity = 1.0 if ok == len(CASES) else 0.0
    elapsed = time.perf_counter() - t0
    # Higher is better: correctness * speed proxy
    objective = validity * (1.0 / (1.0 + elapsed * 1000.0))
    print(json.dumps({"objective": objective, "validity": validity, "elapsed_ms": elapsed * 1000.0}))

if __name__ == "__main__":
    main()
