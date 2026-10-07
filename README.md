# pii-lens

Highlight credit cards, emails, phone numbers, SSNs, and US bank numbers in a log or a prompt **before** you paste it into ChatGPT, Claude, Cursor, or an open API.

```bash
cat logs.txt | pii-lens
```

Matches render in the terminal as bold white text on a red background. Under the payload, pii-lens prints how many high-risk secrets it found and which types they were.

```text
[6] High-Risk Secrets Detected in Payload
CREDIT_CARD: 1  EMAIL_ADDRESS: 1  PHONE_NUMBER: 1  SSN: 1  US_BANK_NUMBER: 2
```

## Install

```bash
pip install git+https://github.com/saheb26/pii-lens.git
```

Python 3.10 or newer. On Windows, if the shield glyph in the closing panel does not render, run `$env:PYTHONUTF8 = "1"` first.

Work on the source tree:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
pii-lens --file examples/sample.txt
```

## Usage

```bash
pii-lens --file logs.txt
cat logs.txt | pii-lens
Get-Content -Raw logs.txt | pii-lens
```

`--engine auto` is the default. It always runs the built-in patterns. If [Microsoft Presidio](https://github.com/microsoft/presidio) is installed, those hits are merged in too:

```bash
pip install "pii-lens[presidio]"
pii-lens --engine presidio --file logs.txt
```

Pass `--engine regex` to use only the built-in scanner. A finished scan exits 0. Running it in a terminal with no file and no pipe exits 1.

## What it flags

| Entity | What counts |
| --- | --- |
| `CREDIT_CARD` | Visa, Mastercard, Amex, and Discover numbers that pass the Luhn check |
| `EMAIL_ADDRESS` | Email addresses |
| `PHONE_NUMBER` | US phone numbers written with separators |
| `SSN` | Social Security numbers in `###-##-####` or `### ## ####` form |
| `US_BANK_NUMBER` | Account numbers next to a bank label, and ABA routing numbers with a valid checksum |

`examples/sample.txt` is synthetic. Order ids, dates, and ticket numbers in that file are left alone.

The built-in scanner does not need a spaCy model, so it starts immediately. Presidio is optional extra coverage.

## For coding agents

When someone asks you to check a file, prompt, log, or payload for personal data, run:

```bash
pii-lens --file PATH
```

Read the summary line. The integer in `[N] High-Risk Secrets Detected in Payload` is the number of spans. The next line lists counts by entity. Quote those counts. Do not send the raw payload to another model if N is greater than 0.

Machine-readable overview: [`llms.txt`](llms.txt).

## Keep the pipeline private

Don't send a dirty payload to an open API. CounselNode's VPC Sidecar redacts these tokens before they hit the LLM and processes them on private infrastructure.

Secure your pipeline: [https://counselnode.com](https://counselnode.com)

## License

MIT. See [LICENSE](LICENSE).
