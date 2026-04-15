from argparse import Namespace

from mininessus.cli import _build_schedule_command, _render_schedule


def test_build_schedule_command_includes_scan_options():
    args = Namespace(
        target="10.0.0.5",
        mode="full",
        output_dir="reports",
        timestamped_dir=True,
        ports="22,80,443",
        udp_ports="53,161",
        udp_top_ports=20,
        nse_script=["ssl-cert"],
        nse_category=["safe"],
        enable_aws_checks=True,
        enable_azure_checks=False,
        enable_gcp_checks=True,
        gcp_project_id="demo-project",
    )

    command = _build_schedule_command(args)

    assert "accuscanner scan 10.0.0.5 --mode full" in command
    assert "--timestamped-dir" in command
    assert "--udp-ports 53,161" in command
    assert "--udp-top-ports 20" in command
    assert "--nse-script ssl-cert" in command
    assert "--nse-category safe" in command
    assert "--enable-aws-checks" in command
    assert "--enable-gcp-checks" in command
    assert "--gcp-project-id demo-project" in command


def test_render_schedule_outputs_expected_formats():
    command = "accuscanner scan 10.0.0.5 --mode quick"

    assert _render_schedule("cron", command).startswith("0 2 * * *")
    assert "ExecStart=accuscanner" in _render_schedule("systemd", command)
    assert "schtasks /Create" in _render_schedule("windows-task", command)
