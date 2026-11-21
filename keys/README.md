# Demo keys — NOT for production

`ksk.pem`, `zsk1.pem`, `zsk2.pem` are pre-provisioned, **fixed** demo keys
(ECDSA P-256, DNSSEC algorithm 13):

- `ksk.pem` — the fixed KSK (flags 257); signs the DNSKEY RRset.
- `zsk1.pem` — the "old" ZSK (flags 256); signs the A record initially.
- `zsk2.pem` — the "new" ZSK (flags 256); rotation target.

They are committed to the repo on purpose so the demo is reproducible.
Never use them for a real zone. To regenerate a fresh set:

```bash
python3 scripts/gen_keys.py keys --force
```
