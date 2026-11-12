# Toy CLI fixture (`experiments/toy_cli`)

Small Python project for Carnot Daemon / Function Foundry experiments (E1–E4).

## Layout

- `organ.py` — computes the sum of integers `1..n`. The harness (`run_harness`) is frozen; **Carnot owns the code between `EVOLVE_START toy` and `EVOLVE_END toy`** in `solve`.
- `solve_bench.py` — runs correctness cases and prints a single JSON line with `objective`, `validity`, and `elapsed_ms`.
- `test_organ.py` — pytest checks for `solve`.

## Baseline vs better candidate

- **Baseline (current):** slow linear scan in the EVOLVE block.
- **Expected improvement:** closed form `n * (n + 1) // 2` inside the same block.

## Sanity check

```bash
cd experiments/toy_cli && python -m pytest test_organ.py -q && python solve_bench.py
```

Expect tests to pass and JSON with `"validity": 1.0` and a positive `objective`.
