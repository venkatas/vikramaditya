from hunt import _shell_env_prefix


def test_shell_env_prefix_quotes_values_with_spaces_and_metacharacters():
    prefix = _shell_env_prefix({
        "RATE_LIMIT_OVERRIDE": "25",
        "CUSTOM_VALUE": "alpha beta;$HOME",
    })

    assert "RATE_LIMIT_OVERRIDE=25" in prefix
    assert "CUSTOM_VALUE='alpha beta;$HOME'" in prefix
    assert prefix.endswith(" ")
