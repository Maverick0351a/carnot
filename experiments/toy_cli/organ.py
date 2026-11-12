"""Toy organ: compute sum of 1..n. Outer harness is frozen."""

def solve(n: int) -> int:
    # EVOLVE_START toy
    total = 0
    i = 1
    while i <= n:
        total = total + i
        i = i + 1
    return total
    # EVOLVE_END toy


def run_harness(raw: str) -> str:
    n = int(raw.strip())
    return str(solve(n))
