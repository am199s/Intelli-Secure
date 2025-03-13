import logging
from aiogram import Bot, Dispatcher, Router, types
from src.config import Config
import traceback

# Logging setup
logger = logging.getLogger(__name__)

class VirusCheckBot(Bot):  # Inherit directly from aiogram.Bot
    def __init__(self):
        super().__init__(token=Config.TELEGRAM_BOT_TOKEN)
        self.dp = Dispatcher()
        self.router = Router()
        self.dp.include_router(self.router)
        self.plugins = []

    def register_plugin(self, plugin):
        """Register a plugin's router with the bot."""
        self.router.include_router(plugin.router)
        self.plugins.append(plugin)
        logger.info(f"Registered plugin: {plugin.metadata['name']}")

    def unregister_plugin(self, plugin):
        """Unregister a plugin (placeholder for future use)."""
        if plugin in self.plugins:
            self.plugins.remove(plugin)
            logger.info(f"Unregistered plugin: {plugin.metadata['name']}")
        else:
            logger.warning(f"Plugin {plugin.metadata['name']} not found in registered plugins.")

    async def reply(self, message: types.Message, text: str, error: Exception = None):
        """Custom reply method that handles DEV_MODE logic."""
        if error and Config.DEV_MODE:
            error_details = f"\nError: {str(error)}"
            if hasattr(error, '__traceback__'):
                error_details += f"\nStack trace: {''.join(traceback.format_exception(type(error), error, error.__traceback__))}"
            await message.answer(f"{text}{error_details}")
        else:
            await message.answer(text)

    async def start(self):
        await self.dp.start_polling(self)