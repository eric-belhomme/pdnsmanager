from pathlib import Path
BASE_DIR = Path(__file__).parent

from .main import app, __version__

__all__ = [
    "__version__"
    "__tittle__",
]

__tittle__ = "PowerDNS Manager"
