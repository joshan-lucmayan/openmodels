"""CLI smoke tests via click's CliRunner."""

from __future__ import annotations

from click.testing import CliRunner

from openmodels.cli.commands import cli


def test_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_target_list():
    runner = CliRunner()
    result = runner.invoke(cli, ["target", "list"])
    assert result.exit_code == 0
    assert "mock" in result.output


def test_target_inspect():
    runner = CliRunner()
    result = runner.invoke(cli, ["target", "inspect", "mock"])
    assert result.exit_code == 0
    assert "mock-service" in result.output


def test_attack_list():
    runner = CliRunner()
    result = runner.invoke(cli, ["attack", "list"])
    assert result.exit_code == 0
    assert "auth-bypass" in result.output


def test_unknown_target_inspect_fails():
    runner = CliRunner()
    result = runner.invoke(cli, ["target", "inspect", "nonexistent"])
    assert result.exit_code == 1
    assert "Unknown target adapter" in result.output
