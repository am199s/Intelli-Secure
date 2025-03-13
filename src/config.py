from dotenv import load_dotenv
import os

load_dotenv()

class Config:
    VIRUSTOTAL_API_KEY:str = str(os.getenv("VIRUSTOTAL_API_KEY"))
    TELEGRAM_BOT_TOKEN:str = str(os.getenv("TELEGRAM_TOKEN"))
    MAX_FILE_SIZE:int = int(os.getenv("MAX_FILE_SIZE", 32)) * 1024 * 1024
    API_RATE_LIMIT_DELAY:int = int(os.getenv("API_RATE_LIMIT_DELAY", 15))
    DEV_MODE:bool = str(os.getenv("DEV_MODE", "false")).lower() == "true"