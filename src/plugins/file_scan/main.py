import logging
import os
import tempfile
from aiogram import Router, types, F
from aiogram.types import FSInputFile
from src.config import Config
from src.services.virustotal import VirusTotalService
from src.services.report import Report

logger = logging.getLogger(__name__)
vt_service = VirusTotalService()

def setup(router: Router):
    @router.message(F.text == "📂 Scan File")
    async def handle_file_scan_request(message: types.Message):
        logger.info(f"File scan requested by user {message.from_user.id}")
        await message.bot.reply(message, "📁 Please upload the file you want to scan:")

    @router.message(F.document)
    async def process_file_scan(message: types.Message):
        try:
            file_size = message.document.file_size
            if file_size > Config.MAX_FILE_SIZE:
                await message.bot.reply(message, "🔴 File size exceeds the limit (32 MB). Please upload a smaller file.")
                return

            file = await message.bot.get_file(message.document.file_id)
            downloaded_file = await message.bot.download_file(file.file_path)
            temp_file = tempfile.NamedTemporaryFile(delete=False)
            temp_file.write(downloaded_file.read())
            temp_file.close()

            analysis = await vt_service.scan_file(temp_file.name)
            logger.debug(f"VirusTotal response for file {message.document.file_name}: {analysis}")

            if "error" in analysis:
                error_code = analysis["error"].get("code", "Unknown")
                error_msg = analysis["error"].get("message", "Unknown error")
                logger.error(f"API error for file {message.document.file_name}: {error_code} - {error_msg}")
                await message.bot.reply(message, "🔴 Failed to process file. Please try again.", Exception(f"{error_code} - {error_msg}"))
                os.remove(temp_file.name)
                return

            try:
                data = analysis["data"]
            except KeyError as e:
                logger.error(f"KeyError accessing 'data': {analysis}")
                await message.bot.reply(message, "🔴 No data returned from VirusTotal. Please try again later.", e)
                os.remove(temp_file.name)
                return

            try:
                attributes = data["attributes"]
                stats = attributes["stats"]  # Note: For files, it's "stats", not "last_analysis_stats"
            except KeyError as e:
                logger.error(f"KeyError accessing nested keys: {analysis}")
                await message.bot.reply(message, "🔴 Invalid response structure from VirusTotal. Please try again later.", e)
                os.remove(temp_file.name)
                return

            report_path = Report.create_report("File", message.document.file_name, stats, attributes)
            await message.answer_document(
                document=FSInputFile(report_path, filename="file_scan_report.pdf"),
                caption="📄 File Scan Report"
            )
            os.remove(temp_file.name)
            os.remove(report_path)

        except Exception as e:
            logger.error(f"Unexpected error processing file scan: {str(e)}", exc_info=True)
            await message.bot.reply(message, "🔴 An unexpected error occurred while processing your request. Please try again.", e)
            if os.path.exists(temp_file.name):
                os.remove(temp_file.name)