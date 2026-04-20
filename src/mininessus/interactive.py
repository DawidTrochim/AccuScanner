from __future__ import annotations

import getpass
import shlex


def run_interactive_menu() -> list[str] | None:
    print("=" * 72)
    print("AccuScanner Interactive Launcher")
    print("=" * 72)
    print("AccuScanner is a defensive assessment power tool.")
    print("Use it only against systems, applications, cloud assets, and networks")
    print("that you own or are explicitly authorized to test.")
    print()
    print("Notes:")
    print("- Cloud posture scans require valid cloud credentials.")
    print("- Authenticated Linux and Windows scans require SSH or WinRM access.")
    print("- Direct CLI usage still works if you prefer manual command control.")
    print("=" * 72)
    print("1. Simple mode")
    print("2. Advanced mode")
    print("3. Custom mode")
    print("4. Code scan")
    print("5. Database scan")
    print("6. Exit")
    selection = _prompt_choice("Select an option", 6)
    if selection == 1:
        return _simple_mode_args()
    if selection == 2:
        return _advanced_mode_args()
    if selection == 3:
        return _custom_mode_args()
    if selection == 4:
        return _code_scan_args()
    if selection == 5:
        return _db_scan_args()
    return None


def _simple_mode_args() -> list[str]:
    print("\nSimple mode offers guided presets for common AccuScanner workflows.")
    options = [
        ("Quick perimeter scan", ["--mode", "quick"]),
        ("Full TCP scan", ["--mode", "full"]),
        ("Web application scan", ["--mode", "web"]),
        ("GCP cloud posture scan", ["--mode", "gcp", "--enable-gcp-checks"]),
        ("Linux authenticated scan", ["--mode", "full", "--profile", "linux"]),
        ("Windows authenticated scan", ["--mode", "full", "--profile", "windows"]),
    ]
    for index, (label, _) in enumerate(options, start=1):
        print(f"{index}. {label}")
    selection = _prompt_choice("Choose a scan type", len(options))
    label, base_args = options[selection - 1]
    print(f"\nSelected: {label}")

    args = ["scan", _prompt_required("Target IP, hostname, CIDR, or URL")]
    args.extend(base_args)
    args.extend(_common_scan_args())

    if "--enable-gcp-checks" in args or _mode_from_args(args) == "gcp":
        project_id = _prompt_optional("GCP project ID (press Enter to skip)")
        if project_id:
            args.extend(["--gcp-project-id", project_id])
    if _mode_from_args(args) == "web" and _prompt_yes_no("Enable browser-assisted rendered discovery", default=False):
        args.append("--browser-assisted")
        browser_max_pages = _prompt_optional("Browser max pages (press Enter for default)")
        if browser_max_pages:
            args.extend(["--browser-max-pages", browser_max_pages])
        browser_timeout_ms = _prompt_optional("Browser timeout in ms (press Enter for default)")
        if browser_timeout_ms:
            args.extend(["--browser-timeout-ms", browser_timeout_ms])
    if _mode_from_args(args) == "web":
        args.extend(_prompt_web_session_args())
    if "--profile" in args and "linux" in args:
        args.extend(_prompt_ssh_args())
    if "--profile" in args and "windows" in args:
        args.extend(_prompt_winrm_args())
    return args


def _advanced_mode_args() -> list[str]:
    print("\nAdvanced mode walks through the full scan configuration.")
    args = ["scan", _prompt_required("Target IP, hostname, CIDR, or URL")]

    mode_options = ["quick", "full", "web", "gcp"]
    mode = _prompt_menu("Select scan mode", mode_options)
    args.extend(["--mode", mode])

    profile_options = ["none", "external", "internal", "cloud", "k8s", "windows", "linux"]
    profile = _prompt_menu("Select profile preset", profile_options)
    if profile != "none":
        args.extend(["--profile", profile])

    output_dir = _prompt_optional("Output directory (default: reports)")
    if output_dir:
        args.extend(["--output-dir", output_dir])
    if _prompt_yes_no("Create a timestamped report directory", default=True):
        args.append("--timestamped-dir")
    if _prompt_yes_no("Save raw nmap XML", default=False):
        args.append("--save-raw-xml")
    if _prompt_yes_no("Save a history copy for dashboards", default=True):
        args.append("--save-history")
        history_dir = _prompt_optional("History directory override (press Enter for default)")
        if history_dir:
            args.extend(["--history-dir", history_dir])

    ports = _prompt_optional("TCP ports expression (for example 22,80,443 or 1-1024)")
    if ports:
        args.extend(["--ports", ports])
    udp_ports = _prompt_optional("UDP ports expression (for example 53,123,161)")
    if udp_ports:
        args.extend(["--udp-ports", udp_ports])
    udp_top_ports = _prompt_optional("Top UDP ports count (press Enter to skip)")
    if udp_top_ports:
        args.extend(["--udp-top-ports", udp_top_ports])
    if _prompt_yes_no("Skip host discovery (-Pn)", default=False):
        args.append("--skip-host-discovery")
    if mode == "web" and _prompt_yes_no("Enable browser-assisted rendered discovery", default=False):
        args.append("--browser-assisted")
        browser_max_pages = _prompt_optional("Browser max pages (press Enter for default)")
        if browser_max_pages:
            args.extend(["--browser-max-pages", browser_max_pages])
        browser_timeout_ms = _prompt_optional("Browser timeout in ms (press Enter for default)")
        if browser_timeout_ms:
            args.extend(["--browser-timeout-ms", browser_timeout_ms])
    if mode == "web":
        args.extend(_prompt_web_session_args())

    nse_categories = _prompt_optional("NSE categories, comma-separated (safe,default,vuln)")
    args.extend(_split_csv_option("--nse-category", nse_categories))
    nse_scripts = _prompt_optional("Specific NSE scripts, comma-separated")
    args.extend(_split_csv_option("--nse-script", nse_scripts))

    parallelism = _prompt_optional("Minimum nmap parallelism (press Enter to skip)")
    if parallelism:
        args.extend(["--parallelism", parallelism])
    suppressions = _prompt_optional("Suppression rules file path (press Enter to skip)")
    if suppressions:
        args.extend(["--suppressions", suppressions])
    plugin_dir = _prompt_optional("Plugin directory path (press Enter to skip)")
    if plugin_dir:
        args.extend(["--plugin-dir", plugin_dir])
    ignore_ids = _prompt_optional("Finding IDs to suppress, comma-separated")
    args.extend(_split_csv_option("--ignore-id", ignore_ids))

    if mode in {"gcp", "quick", "full", "web"} and _prompt_yes_no("Run GCP cloud posture checks too", default=mode == "gcp"):
        args.append("--enable-gcp-checks")
        project_id = _prompt_optional("GCP project ID (press Enter to skip)")
        if project_id:
            args.extend(["--gcp-project-id", project_id])

    if _prompt_yes_no("Run authenticated Linux SSH checks", default=False):
        args.extend(_prompt_ssh_args())
    if _prompt_yes_no("Run authenticated Windows WinRM checks", default=False):
        args.extend(_prompt_winrm_args())
    return args


def _custom_mode_args() -> list[str]:
    print("\nCustom mode lets you enter any AccuScanner command exactly how you want it.")
    print("Examples:")
    print("  scan 10.0.0.5 --mode full --ports 22,80,443 --timestamped-dir")
    print("  dashboard history/*.json --html-output reports/dashboard.html")
    while True:
        raw_command = input("Enter arguments after `accuscanner`: ").strip()
        if raw_command:
            return shlex.split(raw_command)
        print("Please enter a command or choose Exit from the main menu.")


def _code_scan_args() -> list[str]:
    print("\nCode scan reviews a local source tree for secrets, risky code patterns, and insecure configuration signals.")
    args = ["code-scan", _prompt_required("Local path to source code or repository")]
    output_dir = _prompt_optional("Output directory (default: reports)")
    if output_dir:
        args.extend(["--output-dir", output_dir])
    if _prompt_yes_no("Create a timestamped report directory", default=True):
        args.append("--timestamped-dir")
    if _prompt_yes_no("Save a history copy for dashboards", default=True):
        args.append("--save-history")
        history_dir = _prompt_optional("History directory override (press Enter for default)")
        if history_dir:
            args.extend(["--history-dir", history_dir])
    exclude_patterns = _prompt_optional("Exclude path substrings, comma-separated (default: tests/)")
    merged_excludes = ["tests/"]
    merged_excludes.extend([value.strip() for value in exclude_patterns.split(",") if value.strip()])
    for value in merged_excludes:
        args.extend(["--exclude", value])
    include_patterns = _prompt_optional("Include path substrings, comma-separated (press Enter to skip)")
    args.extend(_split_csv_option("--include", include_patterns))
    max_size = _prompt_optional("Maximum file size in KB (default: 256)")
    if max_size:
        args.extend(["--max-file-size-kb", max_size])
    language = _prompt_optional("Language filter such as python, javascript, php, or config (press Enter to skip)")
    if language:
        args.extend(["--language", language])
    return args


def _db_scan_args() -> list[str]:
    print("\nDatabase scan uses user-supplied read-only credentials to inspect PostgreSQL or MySQL posture.")
    args = ["db-scan"]
    db_type = _prompt_menu("Select database type", ["postgres", "mysql"])
    args.extend(["--db-type", db_type])
    if _prompt_yes_no("Use a connection string instead of separate fields", default=False):
        args.extend(["--connection-string", _prompt_required("Connection string")])
    else:
        args.extend(["--host", _prompt_required("Database host")])
        port = _prompt_optional(f"Database port (default: {'5432' if db_type == 'postgres' else '3306'})")
        if port:
            args.extend(["--port", port])
        args.extend(["--database", _prompt_required("Database name")])
        args.extend(["--user", _prompt_required("Database username")])
        password = getpass.getpass("Database password: ").strip()
        if password:
            args.extend(["--password", password])
    ssl_mode = _prompt_optional("SSL mode or secure transport label (press Enter to skip)")
    if ssl_mode:
        args.extend(["--ssl-mode", ssl_mode])
    output_dir = _prompt_optional("Output directory (default: reports)")
    if output_dir:
        args.extend(["--output-dir", output_dir])
    if _prompt_yes_no("Create a timestamped report directory", default=True):
        args.append("--timestamped-dir")
    if _prompt_yes_no("Save a history copy for dashboards", default=True):
        args.append("--save-history")
        history_dir = _prompt_optional("History directory override (press Enter for default)")
        if history_dir:
            args.extend(["--history-dir", history_dir])
    return args


def _common_scan_args() -> list[str]:
    args: list[str] = []
    if _prompt_yes_no("Create a timestamped report directory", default=True):
        args.append("--timestamped-dir")
    if _prompt_yes_no("Save raw nmap XML", default=False):
        args.append("--save-raw-xml")
    if _prompt_yes_no("Save a history copy for dashboards", default=True):
        args.append("--save-history")
        history_dir = _prompt_optional("History directory override (press Enter for default)")
        if history_dir:
            args.extend(["--history-dir", history_dir])
    return args


def _prompt_ssh_args() -> list[str]:
    args: list[str] = []
    ssh_user = _prompt_required("SSH username")
    args.extend(["--ssh-user", ssh_user])
    ssh_key_path = _prompt_optional("SSH private key path (press Enter to skip)")
    if ssh_key_path:
        args.extend(["--ssh-key-path", ssh_key_path])
    if not ssh_key_path or _prompt_yes_no("Also provide an SSH password", default=False):
        ssh_password = getpass.getpass("SSH password (press Enter to skip): ").strip()
        if ssh_password:
            args.extend(["--ssh-password", ssh_password])
    return args


def _prompt_winrm_args() -> list[str]:
    args: list[str] = []
    winrm_user = _prompt_required("WinRM username")
    winrm_password = getpass.getpass("WinRM password: ").strip()
    args.extend(["--winrm-user", winrm_user, "--winrm-password", winrm_password])
    winrm_port = _prompt_optional("WinRM port (default: 5985)")
    if winrm_port:
        args.extend(["--winrm-port", winrm_port])
    transport = _prompt_optional("WinRM transport (default: ntlm)")
    if transport:
        args.extend(["--winrm-transport", transport])
    if _prompt_yes_no("Use HTTPS for WinRM", default=False):
        args.append("--winrm-ssl")
    return args


def _prompt_web_session_args() -> list[str]:
    args: list[str] = []
    web_cookie = _prompt_optional("Session cookie header for authenticated web scanning (press Enter to skip)")
    if web_cookie:
        args.extend(["--web-cookie", web_cookie])
    web_headers = _prompt_optional("Extra web headers as comma-separated 'Name: Value' entries (press Enter to skip)")
    for header in [value.strip() for value in web_headers.split(",") if value.strip()]:
        args.extend(["--web-header", header])
    return args


def _prompt_required(label: str) -> str:
    while True:
        value = input(f"{label}: ").strip()
        if value:
            return value
        print(f"{label} is required.")


def _prompt_optional(label: str) -> str:
    return input(f"{label}: ").strip()


def _prompt_yes_no(label: str, default: bool) -> bool:
    default_label = "Y/n" if default else "y/N"
    while True:
        response = input(f"{label} [{default_label}]: ").strip().lower()
        if not response:
            return default
        if response in {"y", "yes"}:
            return True
        if response in {"n", "no"}:
            return False
        print("Please answer yes or no.")


def _prompt_choice(label: str, option_count: int) -> int:
    while True:
        raw_value = input(f"{label} [1-{option_count}]: ").strip()
        if raw_value.isdigit():
            choice = int(raw_value)
            if 1 <= choice <= option_count:
                return choice
        print(f"Please enter a number between 1 and {option_count}.")


def _prompt_menu(label: str, options: list[str]) -> str:
    for index, option in enumerate(options, start=1):
        print(f"{index}. {option}")
    return options[_prompt_choice(label, len(options)) - 1]


def _split_csv_option(flag: str, raw_value: str) -> list[str]:
    values = [value.strip() for value in raw_value.split(",") if value.strip()]
    args: list[str] = []
    for value in values:
        args.extend([flag, value])
    return args


def _mode_from_args(args: list[str]) -> str | None:
    try:
        mode_index = args.index("--mode")
    except ValueError:
        return None
    return args[mode_index + 1] if mode_index + 1 < len(args) else None
