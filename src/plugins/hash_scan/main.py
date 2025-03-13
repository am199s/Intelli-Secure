import logging
import os
from aiogram import Router, types, F
from aiogram.types import FSInputFile
from src.services.virustotal import VirusTotalService
from src.services.report import Report

logger = logging.getLogger(__name__)
vt_service = VirusTotalService()

def setup(router: Router):
    @router.message(F.text == "🔎 Verify Hash")
    async def handle_hash_check_request(message: types.Message):
        logger.info(f"Hash check requested by user {message.from_user.id}")
        await message.bot.reply(message, "🔍 Please enter the file hash (MD5/SHA1/SHA256):")

    @router.message(F.text.regexp(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'))
    async def process_hash_check(message: types.Message):
        file_hash = message.text
        try:
            # Make the VirusTotal API request
            response = await vt_service.check_hash(file_hash)
            logger.debug(f"VirusTotal response for hash {file_hash}: {response}")

            # Handle error responses explicitly
            if "error" in response:
                error_code = response["error"].get("code", "Unknown")
                error_msg = response["error"].get("message", "Unknown error")
                logger.error(f"API error for hash {file_hash}: {error_code} - {error_msg}")
                await message.bot.reply(message, "🔴 Failed to process hash. Please try again.", Exception(f"{error_code} - {error_msg}"))
                return

            # Try accessing 'data' key
            try:
                data = response["data"]
            except KeyError as e:
                logger.error(f"KeyError accessing 'data': {response}")
                await message.bot.reply(message, "🔴 No data returned from VirusTotal. Please try again later.", e)
                return

            # Try accessing 'attributes' and 'last_analysis_stats'
            try:
                attributes = data["attributes"]
                stats = attributes["last_analysis_stats"]
            except KeyError as e:
                logger.error(f"KeyError accessing nested keys: {response}")
                await message.bot.reply(message, "🔴 Invalid response structure from VirusTotal. Please try again later.", e)
                return

            # Generate and send report
            report_path = Report.create_report("File Hash", file_hash, stats, attributes)
            await message.answer_document(
                document=FSInputFile(report_path, filename="hash_report.pdf"),
                caption="📄 Hash Analysis Report"
            )
            os.remove(report_path)

        except Exception as e:
            logger.error(f"Unexpected error processing hash check for {file_hash}: {str(e)}", exc_info=True)
            await message.bot.reply(message, "🔴 An unexpected error occurred while processing your request. Please try again.", e)