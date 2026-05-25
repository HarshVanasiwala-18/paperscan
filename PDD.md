# Paperscan — Product Design Document

**Version:** 0.5.0  
**Author:** Harsh  
**Status:** Active

---

## 1. Problem Statement

AI products that process user-uploaded documents (invoice automation, resume screening, contract analysis, RAG pipelines) extract text and feed it verbatim into an LLM. Attackers embed hidden instructions inside those documents that redirect the AI's behavior while the document looks completely normal to a human reader. This class of attack — **prompt injection via document** — is largely invisible to existing security tooling which focuses on network traffic, not document content.

---

## 2. Goals

| Goal | Description |
|------|-------------|
| Detect hidden injections | Catch text invisible to humans but readable by AI: white-on-white, zero-font, off-page, OCG layers, vanish runs, field codes, etc. |
| Low false-positive rate | Benign imperatives (recipes, legal docs, code docs) must not be flagged. FP rate target: < 5% on typical business documents. |
| Format coverage | Support PDF, DOCX, JPG, JPEG, PNG — the dominant formats in business AI pipelines. |
| Speed | Pattern + heuristic scan completes in < 2 s for typical documents. Full semantic scan < 3 min. |
| No required dependencies | Run without API key: pattern + heuristic layers cover the majority of attacks. Semantic layer is optional. |
| Safe deployment | The scanner itself must not be exploitable: XXE disabled, no parser network access, 50 MB upload cap, rate limiting, magic byte validation. |

## 3. Non-Goals

- Not a general-purpose antivirus or malware scanner.
- Not a DLP (data loss prevention) tool.
- Does not scan encrypted documents (password-protected PDFs, encrypted DOCX).
- Does not guarantee 100% detection — sophisticated adversaries may adapt; defense-in-depth is expected.
- Does not remediate; it flags and optionally sanitizes for downstream use.

---

## 4. Stakeholders

| Role | Concern |
|------|---------|
| AI product developers | Integrate Paperscan as a pre-processing gate before documents reach their LLM |
| Security teams | Understand attack surface, review findings, tune thresholds |
| End users (uploaders) | Documents processed fairly; legitimate files not blocked |
| Operators (DevOps) | Deploy as Docker/Render service; monitor rate limits and error rates |

---

## 5. Requirements

### 5.1 Functional Requirements

#### FR-01: Multi-format extraction
The scanner must extract all content surfaces from supported formats:
- **PDF**: visible text layer, OCG hidden layers, `/ActualText` attributes, clipped/off-page text, form field defaults, XMP/document metadata, embedded JavaScript, embedded images
- **DOCX**: body text, `w:vanish`/tiny font/white color runs, tracked deletions (`w:del`), field codes (`w:instrText`), comments XML, VBA macro detection
- **Images (JPG/PNG)**: EXIF metadata, Tesseract OCR (when available), embedded image bytes for vision analysis

#### FR-02: Three-layer detection
Every scan must run all three detection layers in parallel and combine results:
1. **Pattern layer** — regex-based detection across all content surfaces
2. **Heuristic layer** — structural anomaly detection (ratios, thresholds, format-specific rules)
3. **Semantic layer** — 6-pass LLM pipeline (requires `ANTHROPIC_API_KEY`)

#### FR-03: Confidence-weighted scoring
- Each finding carries a confidence score (0.0–1.0)
- Findings below `_CONFIDENCE_FLOOR = 0.50` are shown in the UI but excluded from scoring
- Noisy pattern categories in visible text carry reduced confidence (0.35) to prevent false positives
- OCR-only surfaces are treated like visible text for pattern confidence purposes

#### FR-04: Severity classification
| Score | Severity |
|-------|----------|
| 0–20 | `clean` |
| 21–60 | `suspicious` |
| 61–100 | `malicious` |

#### FR-05: Semantic pipeline (6 passes)
When `ANTHROPIC_API_KEY` is set:
1. **Classification** — identify document type and set type-appropriate FP norms
2. **Injection analysis** — tool-use loop to find injection findings
3. **FP review** — challenge and dismiss weak/context-inappropriate findings
4. **Risk narrative** — generate human-readable risk description and attack scenario
5. **Sanitization** — produce clean version of document text safe for downstream AI
6. **Vision** — analyze embedded images for rasterized injection (up to 10 images/doc)

#### FR-06: Streaming API
`POST /scan/stream` must emit SSE progress events during long-running scans so clients can show real-time progress. Keepalive pings every 20 s prevent proxy timeouts.

#### FR-07: CLI interface
`paperscan scan <file>` must exit with `0` (clean), `1` (suspicious), or `2` (malicious) for CI/CD pipeline integration.

#### FR-08: False-positive controls
- Benign imperative language in recipes, legal documents must not be flagged
- Educational mentions of `eval()`/`exec()` must not produce malicious verdict without semantic confirmation
- Auto-generated PDF metadata (`_xmp`, `format`, `producer`, `creationDate`, etc.) must be excluded from pattern scanning
- OCR divergence must not inflate the hidden-text-ratio heuristic

### 5.2 Non-Functional Requirements

#### NFR-01: Performance
| Operation | Target |
|-----------|--------|
| Pattern + heuristic scan | < 2 s (typical document) |
| Full semantic scan (Haiku) | < 90 s |
| Full semantic scan (deep mode / Sonnet) | < 3 min |
| Extraction timeout | 120 s (kills hung parsers) |
| Semantic timeout | 300 s |

#### NFR-02: Security
- Magic byte validation before any parsing
- Extension allowlist: `.pdf`, `.docx`, `.jpg`, `.jpeg`, `.png`
- 50 MB upload size cap enforced during streaming read (not after full buffer)
- Rate limit: 20 requests/minute per IP (sliding window, spoofing-resistant)
- No parser network access; XXE disabled
- Temp files deleted immediately after scan (success or failure)
- API key never logged, never returned in HTTP responses, never embedded in URLs
- Security headers: CSP, HSTS, X-Frame-Options, COOP, CORP, Permissions-Policy

#### NFR-03: Reliability
- Scanner must not crash on malformed documents — extraction errors are caught and reported
- SSE stream must deliver a `complete` or `error` event; it must never silently hang
- Temp file cleanup must occur even when scan raises an exception (`finally` block)

#### NFR-04: Observability
- All scan errors logged with `logger.exception` (server-side, never client-side)
- Client receives sanitized error messages only ("Scan failed — check server logs.")
- Scan duration recorded in every `ScanReport` (`scan_duration_ms`)

#### NFR-05: Deployability
- Runs without Tesseract, pyzbar, or API key (graceful degradation)
- Docker image < 1 GB
- Compatible with Render free tier (512 MB RAM minimum)
- `TRUSTED_PROXY_COUNT` env var controls XFF trust for rate limiter

---

## 6. Architecture

```
                     ┌────────────────────────────────────────┐
  User upload ──────►│           FastAPI (app.py)             │
  (50 MB limit)      │  - Magic byte validation               │
                     │  - Rate limiting (sliding window/IP)   │
                     │  - SSE streaming (/scan/stream)        │
                     └───────────────┬────────────────────────┘
                                     │
                                     ▼
                     ┌────────────────────────────────────────┐
                     │           scanner.py                   │
                     │  - Dispatch to format extractor        │
                     │  - Run 3 detector layers in parallel   │
                     │  - Aggregate → ScanReport              │
                     └───┬───────────────────┬────────────────┘
                         │                   │
             ┌───────────▼──┐         ┌──────▼────────────────┐
             │  Extractors  │         │      Detectors         │
             │  pdf.py      │         │  patterns.py  (regex)  │
             │  docx.py     │         │  heuristics.py (struct)│
             │  image.py    │         │  semantic.py  (LLM)    │
             │  ocr.py      │         │                        │
             │  qr.py       │         │  6-pass pipeline:      │
             └──────────────┘         │  classify → inject →   │
                                      │  fp_review → narrative │
                                      │  → sanitize → vision   │
                                      └────────────────────────┘
```

### Key data models
- `ExtractedDocument` — all surfaces: `visible_text`, `hidden_text[]`, `metadata{}`, `embedded_images[]`, `macro_present`
- `Finding` — single detection event: `layer`, `category`, `severity`, `confidence`, `location`, `evidence`, `reasoning`
- `ScanReport` — final output: `score`, `severity`, `findings[]`, plus all semantic narrative fields

---

## 7. Detection Coverage

| Attack Class | Detection Method | Corpus File |
|---|---|---|
| White-on-white text | Heuristic (hidden ratio) + Pattern | 02, 09, 10 |
| Zero/tiny font | Heuristic (font size < 1pt) | 03 |
| Off-page text | Heuristic (y-coord outside mediabox) | 08 |
| OCG hidden layer | Heuristic (hidden-by-default OCG) | 15 |
| `/ActualText` substitution | Heuristic (visible ≠ extracted mismatch) | 16 |
| Clip-to-zero-area | Heuristic (zero-area clip path) | 17 |
| XMP / metadata injection | Pattern (metadata surface) | 04, 06 |
| Form field default | Pattern (form field surface) | 05 |
| DOCX `w:vanish` | Heuristic (vanish run detection) | 11 |
| DOCX comments | Pattern (comment surface) | 12 |
| DOCX tracked deletions | Pattern (del-run surface) | 18 |
| DOCX field codes | Pattern (instrText surface) | 19 |
| Image/OCR injection | OCR diff (Tesseract 300 DPI) | 07, 26 |
| Vision injection (diagram) | Semantic pass 6 (Claude vision) | 27 |
| QR code injection | QR decoder (pyzbar) | 28, 29 |
| Code execution payload | Pattern (code_execution category) | 20 |
| Credential theft payload | Pattern (credential_theft category) | 21 |
| URL exfiltration payload | Pattern (url_exfiltration category) | 22 |
| Multilingual injection | Pattern (FR/ES/DE/ZH patterns) | 23 |

---

## 8. False Positive Design

| Document Class | Risk | Mitigation |
|---|---|---|
| Recipes | Imperative verbs ("fold", "bake") | FP Review pass knows doc type; `_TYPE_HINTS` for recipe type |
| Legal docs | Authority language ("you must", "you shall not") | FP Review pass knows doc type; `_TYPE_HINTS` for legal type |
| Code documentation | `eval()`, `exec()` in educational context | Pattern confidence < threshold without semantic confirmation; `code_execution` must be confirmed by semantic layer |
| PDF with logo/image | Vision analysis of non-injected PNG | Vision pass calls `note_benign` for decorative images; geometric logos have no injection text |
| Auto-generated PDF metadata | `_xmp`, `producer`, `creationDate` fields | `_SKIP_METADATA_KEYS` excludes these from all scanning |
| OCR output | Tesseract output treated as OCR surface | `_VISIBLE_LIKE_METHODS` applies lower confidence to OCR hits; excluded from hidden-text ratio |

---

## 9. Open Questions / Future Work

- [ ] Password-protected PDF support (decrypt with user-supplied password)
- [ ] Batch scanning API (`POST /scan/batch`)
- [ ] Webhook callback on scan completion (async pipeline integration)
- [ ] Per-organization tunable thresholds (confidence floor, severity bands)
- [ ] STIX/TAXII threat indicator export for SOC integration
- [ ] Fine-tune a smaller model on labeled corpus to replace Haiku (latency + cost)
