"""
fix_amp_and_cleanup.py
------------------------
Três mudanças:
  1. cli/main.py — mover cleanup() do Docker para DEPOIS da geração dos
     relatórios (senão o ficheiro temporário é apagado antes do snippet HTML).
  2. core/report_html.py — esconder o multiplicador ×1.6, manter o score.
  3. cli/main.py — esconder o ×1.6 no terminal, manter o score.

Uso:
    python3 fix_amp_and_cleanup.py
"""

from __future__ import annotations
import sys
from pathlib import Path

# ════════════════════════════════════════════════════════════════════
# 1. cli/main.py — adiar cleanup para depois dos relatórios
# ════════════════════════════════════════════════════════════════════

main_path = Path("cli/main.py")
if not main_path.exists():
    print("ERROR: cli/main.py not found. Run from ~/ccss_scan.")
    sys.exit(1)

main = main_path.read_text(encoding="utf-8")
main_orig = main

# Approach: keep the existing try/finally structure intact, but change the
# finally so it does NOT clean up immediately. Instead, defer cleanup to the
# very end of the function. We do this by:
#   1. Replacing the `finally:` cleanup with a no-op pass (keeping try valid).
#   2. Appending the actual cleanup, wrapped in try/finally, around the rest.
#
# Simplest robust version that doesn't touch indentation of the report block:
# move the cleanup call to run right before each return/exit path AND at the
# normal end. Since there's one normal end and one sys.exit, we register the
# cleanup with atexit-like behaviour via a local try/finally that wraps only
# the scan() call result usage.
#
# Cleanest of all: replace the early-cleanup finally with deferred cleanup
# by introducing a `_cleanup = resolved.cleanup` saved reference, nulling the
# immediate call, and calling it at the very end.

old_finally = """    try:
        with Database(db_path) as db:
            result = runtime.scan(resolved.path, db)
    finally:
        if resolved.cleanup:
            resolved.cleanup()

    _print_result(result, resolved=resolved)"""

new_deferred = """    _deferred_cleanup = resolved.cleanup if resolved.cleanup else None
    try:
        with Database(db_path) as db:
            result = runtime.scan(resolved.path, db)
    except Exception:
        if _deferred_cleanup:
            _deferred_cleanup()
        raise

    _print_result(result, resolved=resolved)"""

if old_finally in main:
    main = main.replace(old_finally, new_deferred, 1)
    print("\u2713 1a: deferred cleanup (saved reference, removed early cleanup)")
elif "_deferred_cleanup" in main:
    print("\u2713 1a: cleanup already deferred — skipping")
else:
    print("\u26a0 1a: could not find the try/finally block — check manually")

# Add the actual cleanup call right before the threshold check (the end)
threshold_marker = "    if threshold > 0.0 and result.global_temporal_score > threshold:"
cleanup_call = """    # Cleanup temp files (e.g. Docker extraction dir) AFTER reports are written,
    # so the HTML snippet feature can still read the config file.
    if _deferred_cleanup:
        _deferred_cleanup()

"""

if "_deferred_cleanup()" not in main.split("_print_result")[-1].split("if threshold")[0] and threshold_marker in main:
    # Only add if not already added in the report region
    if main.count("_deferred_cleanup()") < 2:
        main = main.replace(threshold_marker, cleanup_call + threshold_marker, 1)
        print("\u2713 1b: added deferred cleanup call after reports")
    else:
        print("\u2713 1b: cleanup call already present")
elif threshold_marker not in main:
    print("\u26a0 1b: could not find threshold marker — check manually")
else:
    print("\u2713 1b: cleanup call already present")

main_path.write_text(main, encoding="utf-8")

# ════════════════════════════════════════════════════════════════════
# 2. cli/main.py — hide ×N in terminal
# ════════════════════════════════════════════════════════════════════

main = main_path.read_text(encoding="utf-8")

# Line 217: amp = click.style(f"×{chain.amplification}", fg="yellow", bold=True)
# We want to remove the amp display. The amp variable is used in the echo
# on line ~219-221. Let's find where amp is echoed and remove it.

old_amp_def = '    amp = click.style(f"×{chain.amplification}", fg="yellow", bold=True)'
if old_amp_def in main:
    main = main.replace(old_amp_def, '    # amp multiplier hidden by design — score already reflects amplification', 1)
    print("✓ 2a: removed amp variable definition in terminal")

# Now remove any usage of `amp` in the echo lines
import re as _re
# Find lines that reference {amp} or  amp  in click.echo and strip them
for pat, repl in [
    ('  {amp}', ''),
    (' {amp}', ''),
    ('{amp}', ''),
]:
    if pat in main:
        main = main.replace(pat, repl)
        print(f"✓ 2b: removed '{pat}' usage in terminal echo")
        break

main_path.write_text(main, encoding="utf-8")

# ════════════════════════════════════════════════════════════════════
# 3. core/report_html.py — hide ×N in HTML
# ════════════════════════════════════════════════════════════════════

report_path = Path("core/report_html.py")
report = report_path.read_text(encoding="utf-8")
report_orig = report

# Line 278: f'<span class="amp">&#215;{chain.amplification}</span>{_badge(chain.amplified_score)}</div>' +
old_amp_html = "f'<span class=\"amp\">&#215;{chain.amplification}</span>{_badge(chain.amplified_score)}</div>' +"
new_amp_html = "f'{_badge(chain.amplified_score)}</div>' +"

if old_amp_html in report:
    report = report.replace(old_amp_html, new_amp_html, 1)
    print("✓ 3: removed ×N multiplier badge from HTML (score badge kept)")
elif '<span class="amp">' not in report:
    print("✓ 3: amp badge already removed from HTML")
else:
    print("⚠ 3: could not find the exact amp span in HTML — check line 278 manually")

report_path.write_text(report, encoding="utf-8")

# ════════════════════════════════════════════════════════════════════
# Verify both files
# ════════════════════════════════════════════════════════════════════

import ast
ok = True
for p in [main_path, report_path]:
    try:
        ast.parse(p.read_text(encoding="utf-8"))
    except SyntaxError as e:
        ok = False
        print(f"\n✗ SYNTAX ERROR in {p} line {e.lineno}: {e.msg}")
        print("  Restoring originals...")
        main_path.write_text(main_orig, encoding="utf-8")
        report_path.write_text(report_orig, encoding="utf-8")
        print("  Both files restored. Paste this error.")
        break

if ok:
    print("\nSyntax OK on both files. Re-run the scan:")
    print("  ccss scan docker://ccss-test-apache:vulnerable --report --output ~/relatorios/")
