from aiogram.types import ReplyKeyboardMarkup, KeyboardButton
from typing import List

def get_main_keyboard(plugin_buttons: List[str]) -> ReplyKeyboardMarkup:
    keyboard = [[KeyboardButton(text=button)] for button in plugin_buttons]
    return ReplyKeyboardMarkup(keyboard=keyboard, resize_keyboard=True)