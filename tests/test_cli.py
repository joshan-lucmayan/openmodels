"""CLI smoke tests via click's CliRunner."""

from __future__ import annotations

from click.testing import CliRunner

from opensystem import VERSION
from opensystem.cli.commands import cli


def test_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert VERSION in result.output


def test_target_list():
    runner = CliRunner()
    result = runner.invoke(cli, ["target", "list"])
    assert result.exit_code == 0
    assert "http" in result.output


def test_attack_list():
    runner = CliRunner()
    result = runner.invoke(cli, ["attack", "list"])
    assert result.exit_code == 0
    assert "http-security-headers" in result.output


def test_unknown_target_inspect_fails():
    runner = CliRunner()
    result = runner.invoke(cli, ["target", "inspect", "nonexistent"])
    assert result.exit_code == 1
    assert "Unknown target adapter" in result.output


def test_attack_list_has_no_mock_strategies():
    runner = CliRunner()
    result = runner.invoke(cli, ["attack", "list"])
    assert result.exit_code == 0
    assert "auth-bypass" not in result.output