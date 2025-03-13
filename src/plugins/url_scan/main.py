import logging
import os
from aiogram import Router, types, F
from aiogram.types import FSInputFile
from src.services.virustotal import VirusTotalService
from src.services.report import Report

logger = logging.getLogger(__name__)
vt_service = VirusTotalService()

def setup(router: Router):
    @router.message(F.text == "🔗 Scan URL")
    async def handle_url_scan_request(message: types.Message):
        logger.info(f"URL scan requested by user {message.from_user.id}")
        await message.bot.reply(message, "🔍 Please enter the URL you want to scan:")

    @router.message(F.text.startswith("http"))
    async def process_url_scan(message: types.Message):
        url = message.text
        try:
            analysis = await vt_service.scan_url(url)
            logger.debug(f"VirusTotal response for URL {url}: {analysis}")

            if "error" in analysis:
                error_msg = analysis["error"].get("message", "Unknown error")
                logger.error(f"API error for URL {url}: {error_msg}")
                await message.bot.reply(message, "🔴 Failed to process URL. Please try again.", Exception(error_msg))
                return

            stats = analysis["data"]["attributes"]["stats"]
            report_path = Report.create_report("URL", url, stats)

            await message.answer_document(
                document=FSInputFile(report_path, filename="url_scan_report.pdf"),
                caption="📄 URL Scan Report"
            )
            os.remove(report_path)
        except Exception as e:
            logger.error(f"Error processing URL scan: {str(e)}", exc_info=True)
            await message.bot.reply(message, "🔴 An error occurred while processing your request. Please try again.", e)