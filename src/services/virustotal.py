import aiohttp
import asyncio
import time
from src.config import Config


class VirusTotalService:
    def __init__(self):
        self.api_key = Config.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}
        self.last_request_time = 0

    async def _rate_limit(self):
        current_time = int(time.time())
        if current_time - self.last_request_time < Config.API_RATE_LIMIT_DELAY:
            await asyncio.sleep(Config.API_RATE_LIMIT_DELAY - (current_time - self.last_request_time))
        self.last_request_time = int(time.time())

    async def make_request(self, endpoint: str, method: str = "GET", data=None, files=None):
        await self._rate_limit()
        url = f"{self.base_url}/{endpoint}"

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(10)) as session:
            if method == "POST" and files:
                async with session.post(url, headers=self.headers, data=files) as response:
                    return await response.json()
            elif method == "POST" and data:
                async with session.post(url, headers=self.headers, data=data) as response:
                    return await response.json()
            else:
                async with session.get(url, headers=self.headers) as response:
                    return await response.json()

    async def scan_url(self, url: str):
        response = await self.make_request("urls", "POST", data={"url": url})
        scan_id = response["data"]["id"]
        await asyncio.sleep(20)
        return await self.make_request(f"analyses/{scan_id}")

    async def scan_file(self, file_path: str):
        with open(file_path, 'rb') as f:
            files = {"file": f}
            response = await self.make_request("files", "POST", files=files)
        analysis_id = response["data"]["id"]
        await asyncio.sleep(25)
        return await self.make_request(f"analyses/{analysis_id}")

    async def check_ip(self, ip: str):
        return await self.make_request(f"ip_addresses/{ip}")

    async def check_hash(self, file_hash: str):
        return await self.make_request(f"files/{file_hash}")

    async def check_domain(self, domain: str):
        return await self.make_request(f"domains/{domain}")