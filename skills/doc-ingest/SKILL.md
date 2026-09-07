---
name: doc-ingest
description: Convert PDF/PPTX/DOCX/HTML evidence to Markdown with markitdown_helper for LLM ingest. Use when briefing from decks, SOWs, policies, or PDF reports.
---

# Doc ingest

```bash
python3 markitdown_helper.py path/to/file.pptx -o out.md
python3 markitdown_helper.py path/to/dir --glob "*.pdf" -o markdown_out/
```

Requires `markitdown[all]` in `.venv` (see requirements.txt / setup.sh).
