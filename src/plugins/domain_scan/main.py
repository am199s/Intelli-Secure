import logging
import os
from aiogram import Router, types, F
from aiogram.types import FSInputFile
from src.services.virustotal import VirusTotalService
from src.services.report import Report

logger = logging.getLogger(__name__)
vt_service = VirusTotalService()

def setup(router: Router):
    @router.message(F.text == "🖥️ Check Domain")
    async def handle_domain_scan_request(message: types.Message):
        logger.info(f"Domain scan requested by user {message.from_user.id}")
        await message.answer("🔍 Please enter the domain to scan:")

    @router.message(F.text.regexp(r'^(?!-)(?!.*--)(?:[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,}$'))
    async def process_domain_scan(message: types.Message):
        domain = message.text
        try:
            response = await vt_service.check_domain(domain)
            stats = response["data"]["attributes"]["last_analysis_stats"]
            report_path = Report.create_report("Domain", domain, stats)

            await message.answer_document(
                document=FSInputFile(report_path, filename="domain_report.pdf"),
                caption="📄 Domain Analysis Report"
            )
            os.remove(report_path)
        except Exception as e:
            logger.error(f"Error processing domain scan: {e}")
            await message.answer("🔴 An error occurred while processing your request. Please try again.")