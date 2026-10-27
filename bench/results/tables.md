Machine: Intel64 Family 6 Model 170 Stepping 4, GenuineIntel | Windows-11-10.0.26200-SP0 | Python 3.13.3 | PyCryptodome 3.24.1 | 10 runs, median

### Encrypt throughput (MiB/s)

| Size | AES-256-GCM | DES-CBC + HMAC | RC4-drop3072 + HMAC | AES-256-CBC + HMAC (control) |
|---|---|---|---|---|
| 1 KiB | 11.7 | 11.4 | 13.2 | 14.0 |
| 100 KiB | 777.5 | 71.3 | 254.9 | 369.2 |
| 1 MiB | 482.0 | 60.3 | 186.9 | 196.9 |
| 10 MiB | 346.1 | 57.1 | 179.6 | 172.2 |
| 50 MiB | 293.8 | 56.3 | 158.8 | 151.5 |
| 100 MiB | 279.1 | 57.8 | 150.2 | 148.7 |

### Storage overhead (extra bytes per stored copy)

| Size | AES-256-GCM | DES-CBC + HMAC | RC4-drop3072 + HMAC | AES-256-CBC + HMAC (control) |
|---|---|---|---|---|
| 1 KiB | 45 B (4.39%) | 77 B (7.52%) | 61 B (5.96%) | 93 B (9.08%) |
| 100 KiB | 45 B (0.04%) | 77 B (0.08%) | 61 B (0.06%) | 93 B (0.09%) |
| 1 MiB | 45 B (0.00%) | 77 B (0.01%) | 61 B (0.01%) | 93 B (0.01%) |
| 10 MiB | 270 B (0.00%) | 590 B (0.01%) | 430 B (0.00%) | 750 B (0.01%) |
| 50 MiB | 1270 B (0.00%) | 2870 B (0.01%) | 2070 B (0.00%) | 3670 B (0.01%) |
| 100 MiB | 2520 B (0.00%) | 5720 B (0.01%) | 4120 B (0.00%) | 7320 B (0.01%) |

### Key cost

| Operation | Median (ms) | Min | Max | CV |
|---|---|---|---|---|
| `derive_keys` | 45.7 | 44.6 | 53.0 | 5.4% |
| `wrap_secret` | 0.039 | 0.036 | 0.040 | 4.1% |
| `unwrap_secret` | 0.046 | 0.044 | 0.050 | 5.1% |

### Upload cost (new secret + wrap + encrypt, x3 app ciphers)

| Size | Median (ms) | Min | Max | CV |
|---|---|---|---|---|
| 1 KiB | 0.399 | 0.369 | 0.409 | 3.0% |
| 100 KiB | 2.1 | 2.0 | 2.3 | 5.3% |
| 1 MiB | 23.8 | 22.1 | 26.2 | 5.0% |
| 10 MiB | 267.8 | 247.3 | 280.9 | 4.2% |
| 50 MiB | 1412.8 | 1376.0 | 1503.4 | 2.6% |
| 100 MiB | 2746.2 | 2686.8 | 2872.9 | 2.6% |

### HMAC-SHA256 alone (same 1 MiB chunks as the app)

| Size | Median (ms) | MiB/s | CV |
|---|---|---|---|
| 1 KiB | 0.003 | 340.5 | 4.5% |
| 100 KiB | 0.061 | 1611.1 | 5.1% |
| 1 MiB | 0.914 | 1094.1 | 4.9% |
| 10 MiB | 11.9 | 842.7 | 8.1% |
| 50 MiB | 59.5 | 840.1 | 3.4% |
| 100 MiB | 121.8 | 821.1 | 4.2% |

### HMAC share of encrypt time (rest = cipher + per-item setup)

| Size | DES-CBC + HMAC: HMAC share / rest MiB/s | RC4-drop3072 + HMAC: HMAC share / rest MiB/s | AES-256-CBC + HMAC (control): HMAC share / rest MiB/s |
|---|---|---|---|
| 1 KiB | 3% / 11.8 | 4% / 13.7 | 4% / 14.5 |
| 100 KiB | 4% / 74.6 | 16% / 302.8 | 23% / 478.9 |
| 1 MiB | 6% / 63.8 | 17% / 225.4 | 18% / 240.2 |
| 10 MiB | 7% / 61.3 | 21% / 228.3 | 20% / 216.4 |
| 50 MiB | 7% / 60.3 | 19% / 195.8 | 18% / 184.8 |
| 100 MiB | 7% / 62.2 | 18% / 183.8 | 18% / 181.5 |

_HMAC and cipher medians come from separate runs, so shares are estimates. 'n/a' = HMAC median was longer than the whole encrypt median (noise)._
