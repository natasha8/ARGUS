import importlib.util
import socket
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

ROOT = Path(__file__).resolve().parents[2]
BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _serve(app, port: int):
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 15
    url = f"http://127.0.0.1:{port}/health"
    while time.time() < deadline:
        try:
            response = httpx.get(url, timeout=0.3)
            if response.status_code == 200:
                return server, thread
        except httpx.HTTPError:
            time.sleep(0.1)
    raise RuntimeError(f"Test server on {port} did not start.")


@pytest.fixture(scope="module")
def lab_servers():
    lab = _load("argus_lab_app", ROOT / "targets" / "vulnerable-api" / "lab_app.py")
    collaborator = _load(
        "argus_collaborator_app", ROOT / "targets" / "collaborator" / "collaborator_app.py"
    )
    lab_port = _free_port()
    collaborator_port = _free_port()
    lab_server, lab_thread = _serve(lab.app, lab_port)
    collaborator_server, collaborator_thread = _serve(collaborator.app, collaborator_port)
    yield {
        "lab": f"http://127.0.0.1:{lab_port}",
        "collaborator": f"http://127.0.0.1:{collaborator_port}",
    }
    lab_server.should_exit = True
    collaborator_server.should_exit = True
    lab_thread.join(timeout=5)
    collaborator_thread.join(timeout=5)
