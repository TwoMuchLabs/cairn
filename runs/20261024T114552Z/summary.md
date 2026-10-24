# VariantBench run

## dev

| metric | value |
|---|---|
| cases run | 30 (0 errored) |
| rule pass rate | 97% (29/30) |
| median attempts (passing) | 2 |
| lessons marked low-confidence (too broad) | 0 |
| sibling matches (raw) | 11 |
| siblings shown after review | 6 |
| precision of raw matches (labelled) | 33% (3/9) |
| precision of shown siblings (labelled) | 20% (1/5) |
| shown siblings not yet labelled | 1 |
| labelled true siblings still shown | 17% (1/6) |

| language | pass rate |
|---|---|
| go | 6/6 |
| java | 7/7 |
| javascript | 6/7 |
| python | 10/10 |

Labels are per (path, line) at the fix commit. Labels marked `by: claude-prelabel` are a model's reading of the code and still need human confirmation.
Model usage: 64 call(s), 414,971 in / 87,965 out tokens, about $1.71
