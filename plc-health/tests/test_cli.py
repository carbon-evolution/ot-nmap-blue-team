import json

from plchealth import cli


def test_cli_healthy_exit_zero(modbus_healthy, capsys):
    code = cli.main(["poll", "127.0.0.1", "--proto", "modbus",
                     "--port", str(modbus_healthy)])
    assert code == 0
    assert "modbus" in capsys.readouterr().out.lower()


def test_cli_fault_exit_one(modbus_exception):
    code = cli.main(["poll", "127.0.0.1", "--proto", "modbus",
                     "--port", str(modbus_exception)])
    assert code == 1


def test_cli_unreachable_exit_two():
    code = cli.main(["poll", "127.0.0.1", "--proto", "modbus", "--port", "1",
                     "--timeout", "0.3"])
    assert code == 2


def test_cli_json_output(modbus_healthy, tmp_path):
    out = tmp_path / "h.json"
    cli.main(["poll", "127.0.0.1", "--proto", "modbus",
              "--port", str(modbus_healthy), "--json", str(out)])
    data = json.loads(out.read_text())
    assert data["proto"] == "modbus" and data["state"] == "RUN"
