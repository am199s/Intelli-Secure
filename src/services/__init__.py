from dotenv import load_dotenv
import os

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
API_RATE_LIMIT_DELAY = os.getenv("API_RATE_LIMIT_DELAY")