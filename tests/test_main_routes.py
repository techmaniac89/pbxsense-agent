from __future__ import annotations

import ast
import unittest
from pathlib import Path


class MainRouteStructureTest(unittest.TestCase):
    def test_pair_route_has_a_direct_html_return(self) -> None:
        """Keep later route declarations from accidentally splitting pair()."""
        source = Path("pbxsense_agent/main.py").read_text(encoding="utf-8")
        module = ast.parse(source)
        pair_function = next(
            node
            for node in module.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "pair"
        )

        direct_returns = [node for node in pair_function.body if isinstance(node, ast.Return)]

        self.assertTrue(direct_returns, "The /pair route must directly return its rendered page")

    def test_pair_page_keeps_copy_control_for_pairing_text(self) -> None:
        source = Path("pbxsense_agent/main.py").read_text(encoding="utf-8")

        self.assertIn('id="copy-pairing-text"', source)
        self.assertIn("navigator.clipboard.writeText", source)


if __name__ == "__main__":
    unittest.main()
