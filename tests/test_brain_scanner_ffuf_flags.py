"""ffuf / nuclei rate-flag confusion fixes in brain_scanner.py.

The LLM sometimes emits ``ffuf ... --rate-limit N`` (nuclei's flag). ffuf only
accepts ``-rate N``. These tests lock the rewrite helper and keep nuclei alone.
"""
import pytest

from brain_scanner import _rewrite_confused_tool_flags


@pytest.mark.parametrize("code,expected", [
    (
        'ffuf -u "https://x.example.invalid/FUZZ" -w wordlists/common.txt --rate-limit 5 -mc 200',
        'ffuf -u "https://x.example.invalid/FUZZ" -w wordlists/common.txt -rate 5 -mc 200',
    ),
    (
        'ffuf -u "https://x.example.invalid/FUZZ" -w wordlists/common.txt -rate-limit 10',
        'ffuf -u "https://x.example.invalid/FUZZ" -w wordlists/common.txt -rate 10',
    ),
    (
        'ffuf -u "https://x.example.invalid/FUZZ" -w wordlists/common.txt -rate 10 -mc 200',
        'ffuf -u "https://x.example.invalid/FUZZ" -w wordlists/common.txt -rate 10 -mc 200',
    ),
])
def test_ffuf_rate_limit_rewritten(code, expected):
    assert _rewrite_confused_tool_flags(code) == expected


def test_nuclei_rate_limit_untouched():
    code = 'nuclei -u "https://x.example.invalid" -rate-limit 50 -silent'
    assert _rewrite_confused_tool_flags(code) == code
    code2 = 'nuclei -u "https://x.example.invalid" --rate-limit 50 -silent'
    assert _rewrite_confused_tool_flags(code2) == code2


def test_mixed_script_only_ffuf_line_rewritten():
    code = (
        'nuclei -u "https://x.example.invalid" -rate-limit 50 -silent\n'
        'ffuf -u "https://x.example.invalid/FUZZ" -w wordlists/common.txt --rate-limit 5\n'
    )
    out = _rewrite_confused_tool_flags(code)
    assert 'nuclei -u "https://x.example.invalid" -rate-limit 50 -silent' in out
    assert '--rate-limit' not in [ln for ln in out.splitlines() if 'ffuf' in ln][0]
    assert '-rate 5' in out


def test_non_tool_script_unchanged():
    code = 'curl -s https://x.example.invalid/ | head'
    assert _rewrite_confused_tool_flags(code) == code
