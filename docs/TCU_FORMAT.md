# TCU Metadata Format

TrigFuzz release metadata should use explicit distance expressions.

## JSON

```json
[
  {
    "cond": "v < 2",
    "distance_expr": "tf_lt((double)v, 2.0)",
    "loc": "line 23 in main.c",
    "seq": 0,
    "conj": 0,
    "w": 1.0,
    "kind": "numeric"
  }
]
```

Fields:

- `distance_expr`: C expression compiled into `distance_instrument()`. It must evaluate to `0.0` when the TCU is satisfied and a positive distance otherwise.
- `cond`: readable label for humans and reports. It is not the release path for instrumentation.
- `loc`: source insertion point in the form `line N in file.c`.
- `seq`: execution-order group. `0` is first.
- `conj`: DNF conjunct id. Same `(seq, conj)` entries are ANDed; different conjuncts at the same `seq` are ORed by taking the best conjunct distance.
- `w`: positive normalization weight.
- `kind`: `numeric` or `binary`.

## Distance Helpers

Both runtime headers provide:

```c
tf_bool(condition)
tf_lt(a, b)
tf_le(a, b)
tf_gt(a, b)
tf_ge(a, b)
tf_eq(a, b)
tf_add_num(a, b)
tf_sub_num(a, b)
tf_mul_num(a, b)
tf_min2(a, b)
```

Prefer these helpers over open-coded arithmetic. The common bug pattern is an expression that overflows or underflows before it is cast:

```c
/* Risky when nstrips is unsigned and can be 0. */
tf_gt((double)(nstrips - 1), (double)limit)

/* Preferred. */
tf_gt(tf_sub_num((double)nstrips, 1.0), (double)limit)
```

## LLM Prompting Rule

Ask the model to output `distance_expr` directly. Do not ask for only `cond` and then lower it automatically.

Good:

```text
<tf_gt(tf_sub_num((double)nstrips, 1.0), (double)limit), line 5973 in tif_dirread.c, 0, 0, 1.0>
```

Avoid:

```text
<nstrips - 1 > limit, line 5973 in tif_dirread.c, 0, 0, 1.0>
```

The Python code still accepts legacy cond-only metadata as a fallback, but that path is not recommended for generated TCUs.
