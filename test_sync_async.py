import maxhttp
import asyncio

resp = maxhttp.get("https://httpbin.org/get")
print(resp.json())


async def main():
    resp = await maxhttp.get("https://httpbin.org/get")
    print(resp.json())


asyncio.run(main())