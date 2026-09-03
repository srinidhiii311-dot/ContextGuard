"""
ContextGuard attack simulation package.

Usage
-----
from attack_sim.mock_page import create_app
app = create_app()
app.run(port=5000)
"""

from attack_sim.mock_page import create_app

__all__ = ["create_app"]
