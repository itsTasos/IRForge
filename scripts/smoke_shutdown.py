"""Optional developer test: send Ctrl+C to a private hidden console, without host mutation."""
import ctypes
import json
from pathlib import Path
import subprocess
import time
import uuid

root = Path(__file__).resolve().parent.parent
base = root / "build" / ("shutdown-" + uuid.uuid4().hex)
startup = subprocess.STARTUPINFO()
startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
startup.wShowWindow = 0
with base.with_suffix(".stdout.txt").open("w", encoding="utf-8") as stdout, base.with_suffix(".stderr.txt").open("w", encoding="utf-8") as stderr:
    process = subprocess.Popen(
        [str(root / "build/mingw/irforge.exe"), "monitor", "--allow-degraded", "--quiet",
         "--duration-seconds", "30", "--output", str(base)],
        cwd=root, stdout=stdout, stderr=stderr, startupinfo=startup,
        creationflags=subprocess.CREATE_NEW_CONSOLE,
    )
    time.sleep(2)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.FreeConsole()
    if not kernel.AttachConsole(process.pid):
        raise ctypes.WinError(ctypes.get_last_error())
    kernel.SetConsoleCtrlHandler(None, True)
    if not kernel.GenerateConsoleCtrlEvent(0, 0):
        raise ctypes.WinError(ctypes.get_last_error())
    kernel.FreeConsole()
    code = process.wait(timeout=10)
    assert code == 0, code
metadata = json.loads((base / "session-metadata.json").read_text(encoding="utf-8"))
assert metadata["stop_utc"] is not None
print(json.dumps({"output_directory": str(base), "exit_code": code, "ctrl_c_shutdown": "passed", "result": metadata["result"]}, indent=2))
