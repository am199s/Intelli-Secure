import asyncio
import os
import logging
from src.bot import VirusCheckBot
from src.handlers.start import start_factory
from src.utils.plugin import Plugin
from src.config import Config

# Logging setup
if Config.DEV_MODE:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_plugins(bot: VirusCheckBot):
    plugins_dir = os.path.join(os.path.dirname(__file__), "src", "plugins")
    plugins = []
    plugin_buttons = []

    for plugin_name in os.listdir(plugins_dir):
        plugin_path = os.path.join(plugins_dir, plugin_name)
        if os.path.isdir(plugin_path) and not plugin_name.startswith("__"):
            try:
                plugin = Plugin(plugin_name, plugin_path)
                plugin.plug(bot)
                plugins.append(plugin)
                plugin_buttons.append(plugin.metadata["button_text"])
                logger.info(
                    f"Loaded plugin: {plugin.metadata['name']} (v{plugin.metadata['version']}) by {plugin.metadata['author']}")
            except Exception as e:
                logger.error(f"Failed to load plugin {plugin_name}: {e}")

    return plugins, plugin_buttons


async def main():
    bot = VirusCheckBot()

    # Load plugins dynamically
    plugins, plugin_buttons = load_plugins(bot)

    # Register the start handler with dynamic plugin buttons
    start_router = start_factory(plugin_buttons)
    bot.router.include_router(start_router)

    await bot.start()


if __name__ == "__main__":
    asyncio.run(main())