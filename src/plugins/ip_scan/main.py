import logging
import os
import ipaddress
from aiogram import Router, types, F
from aiogram.types import FSInputFile

from src.services.virustotal import VirusTotalService
from src.services.report import Report

logger = logging.getLogger(__name__)
vt_service = VirusTotalService()

def setup(router: Router):
    @router.message(F.text == "🌍 Check IP")
    async def handle_ip_scan_request(message: types.Message):
        logger.info(f"IP scan requested by user {message.from_user.id}")
        await message.answer("🔍 Please enter the IP address to scan:")

    @router.message(F.text.regexp(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'))
    async def process_ip_scan(message: types.Message):
        ip = message.text
        try:
            ipaddress.ip_address(ip)
            response = await vt_service.check_ip(ip)
            attributes = response["data"]["attributes"]
            stats = attributes["last_analysis_stats"]
            report_path = Report.create_report("IP Address", ip, stats, attributes)

            await message.answer_document(
                document=FSInputFile(report_path, filename="ip_scan_report.pdf"),
                caption="📄 IP Scan Report"
            )
            os.remove(report_path)
        except ValueError:
            await message.answer("🔴 Invalid IP address. Please enter a valid IP.")
        except Exception as e:
            logger.error(f"Error processing IP scan: {e}")
            await message.answer("🔴 An error occurred while processing your request. Please try again.")