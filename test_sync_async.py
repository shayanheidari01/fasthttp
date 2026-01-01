import fasthttp
import asyncio

resp = fasthttp.get("https://httpbin.org/get")
print(resp.json())


async def main():
    resp = await fasthttp.get("https://httpbin.org/get")
    print(resp.json())


asyncio.run(main())