"""Launch the EgressIQ web UI: `python app.py [--port 8000] [--open]`."""

import sys

from web.server import run

if __name__ == "__main__":
    sys.exit(run())
