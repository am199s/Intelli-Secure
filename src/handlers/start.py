import logging
from aiogram import Router, types
from aiogram.filters import Command
from src.utils.keyboard import get_main_keyboard
from src.config import Config

router = Router()
logger = logging.getLogger(__name__)

def start_factory(plugin_buttons: list):
    @router.message(Command("start"))
    async def start(message: types.Message):
        logger.info(f"Start command received from user {message.from_user.id}")

        lines = [
            "🛡️ Welcome to Intelli Secure Bot!",
            "Choose a scan type from the menu:"
        ]

        if Config.DEV_MODE:
            lines.insert(0, "🚧 Developer mode is enabled.\n")

        await message.answer('\n'.join(lines),
            reply_markup=get_main_keyboard(plugin_buttons)
        )
    return router