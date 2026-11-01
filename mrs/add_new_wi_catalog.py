from pathlib import Path
import sys

CATALOG_ENTRIES = (
    "   'samsung_ddr5': {'label':'Samsung DDR5 OSV','folder':root/'wi_samsung_ddr5','endpoint':'wi_samsung_ddr5.index'},\n"
    "   'delta_psu': {'label':'Delta PSU Tester','folder':root/'wi_delta_psu','endpoint':'wi_delta_psu.index'},\n"
    "   'liteon_psu': {'label':'Liteon PSU Tester','folder':root/'wi_liteon_psu','endpoint':'wi_liteon_psu.index'},\n"
)

MICRON_ENTRY = (
    "   'micron': {'label':'Micron DDR4 Tester','folder':root/'wi_micron_ddr4',"
    "'endpoint':'wi_micron_ddr4.index'},\n"
)


def locate_routes_file() -> Path:
    """Find tools_portal/routes.py regardless of where this updater is run."""
    script_dir = Path(__file__).resolve().parent
    cwd = Path.cwd().resolve()

    candidates = [
        script_dir / "routes.py",
        cwd / "routes.py",
        script_dir / "mrs_app" / "features" / "tools_portal" / "routes.py",
        cwd / "mrs_app" / "features" / "tools_portal" / "routes.py",
    ]

    for parent in [script_dir, *script_dir.parents, cwd, *cwd.parents]:
        candidates.append(parent / "mrs_app" / "features" / "tools_portal" / "routes.py")

    checked = set()
    for candidate in candidates:
        candidate = candidate.resolve()
        if candidate in checked:
            continue
        checked.add(candidate)
        if candidate.is_file() and candidate.parent.name == "tools_portal":
            return candidate

    locations = "\n".join(f"  - {path}" for path in checked)
    raise FileNotFoundError(
        "Could not locate tools_portal/routes.py. Checked:\n" + locations
    )


def main() -> int:
    try:
        routes_path = locate_routes_file()
        source = routes_path.read_text(encoding="utf-8")

        if all(key in source for key in ("'samsung_ddr5':", "'delta_psu':", "'liteon_psu':")):
            print(f"No update needed. All three Work Instructions are already registered.\nFile: {routes_path}")
            return 0

        if MICRON_ENTRY not in source:
            print(
                "ERROR: Found routes.py, but could not find the Micron catalog entry used as the insertion point.\n"
                f"File: {routes_path}\n"
                "The file was not changed.",
                file=sys.stderr,
            )
            return 1

        backup_path = routes_path.with_name("routes.py.before_new_wi_catalog.bak")
        if not backup_path.exists():
            backup_path.write_text(source, encoding="utf-8")

        updated = source.replace(MICRON_ENTRY, MICRON_ENTRY + CATALOG_ENTRIES, 1)
        routes_path.write_text(updated, encoding="utf-8")

        print("Work Instruction editor catalog updated successfully.")
        print(f"Updated: {routes_path}")
        print(f"Backup:  {backup_path}")
        print("Added: Samsung DDR5, Delta PSU, and Liteon PSU")
        return 0

    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
