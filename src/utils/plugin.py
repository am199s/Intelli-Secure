import json
import os
from aiogram import Router
from typing import Optional

class Plugin:
    def __init__(self, name: str, path: str):
        self.name = name
        self.path = path
        self.router = Router()
        self.metadata = self._load_metadata()
        self.module = None

    def _load_metadata(self) -> dict:
        """Load metadata from config.json."""
        config_path = os.path.join(self.path, "config.json")
        try:
            with open(config_path, "r") as f:
                return json.load(f)
        except Exception as e:
            raise ValueError(f"Failed to load config.json for plugin {self.name}: {e}")

    def plug(self, bot) -> None:
        """Load and register the plugin."""
        if not self.module:
            module_name = f"src.plugins.{self.name}.main"
            import importlib
            self.module = importlib.import_module(module_name)
            if hasattr(self.module, "setup"):
                self.module.setup(self.router)
        bot.register_plugin(self)

    def unplug(self, bot) -> None:
        """Unregister the plugin."""
        bot.unregister_plugin(self)
        self.module = None  # Reset module to allow reloading if needed