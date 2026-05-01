# BreachLab — Ghost Track: Level 4
**Signal in the Noise · 180 pts**

---

## Objective

Locate a hidden credential buried inside a vault of 500+ record files on the `ghost4` server.
This challenge simulates the core SOC analyst workflow: filtering log noise to find the one
entry that matters.

**Tools used:** `grep` `find`

**Real-world context:** Threat hunting. This is the core loop of every SOC analyst on the
planet — find the needle in the log haystack.

---

## Environment Access

Used the password captured from Level 3 to SSH into the ghost4 host on port 2222:

```bash
ssh ghost4@204.168.229.209 -p 2222
```

---

## Reconnaissance

Home directory contained a single folder: `vault`

```bash
ghost4@breachlab:~$ ls
vault

ghost4@breachlab:~$ cd vault/

ghost4@breachlab:~/vault$ ls -a
record_0001  record_0002  record_0003  ...  record_0500
```

500 sequentially named record files. Opening them manually wasn't an option.

---

## Step 1 — Understand the File Format

Ran a broad `grep` to see what the records looked like:

```bash
ghost4@breachlab:~/vault$ grep 'A' *record*
record_0001:[2026-03-28 02:01:01] STATUS: 9e26b6efef7d43e6881058f7746c70a3
record_0002:[2026-03-28 02:02:02] STATUS: 405ba3bed0b074933fb62fd13fa8003b
record_0003:[2026-03-28 02:03:03] STATUS: 9f9ff1efe32003650f9172f508d552ef
...
```

Pattern: every record was a timestamped `STATUS:` entry followed by a lowercase hex hash.
498 files of identical noise. The flag had to be in something that broke this format.

---

## Step 2 — Find the Anomaly

Key insight: all normal hashes are lowercase hex (`0-9`, `a-f`). Any uppercase letter would
indicate an anomalous entry. Searched for `'G'`:

```bash
ghost4@breachlab:~/vault$ grep 'G' *record*
record_0291:[2026-03-28 02:47:13] password=nv38evLGJIofob4E
record_0451:[CLASSIFIED] CREDENTIAL: Gr3p_F1nds_Truth
```

Two records broke the pattern. Record `0451` contained the flag.

---

## Flag

```
Gr3p_F1nds_Truth
```

---

## Key Takeaways

**`grep` with wildcards** — `grep 'pattern' *record*` scans all matching files in one shot.
No loops, no manual opening.

**Signal vs noise** — 498 records were identical. Two weren't. In real SOC work the anomaly
is always outnumbered by normal traffic. `grep` is how you find it.

**Case sensitivity as a filter** — Normal hex is always lowercase (`a-f`). Filtering for
uppercase letters is a fast way to surface entries that don't belong in a hex-only log.

---

*Solved on BreachLab · Ghost Track · [breachlab.org](https://breachlab.org)*
