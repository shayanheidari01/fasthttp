import asyncio

from fasthttp import WebSocket


async def websocket_client():
    url = "wss://echo.websocket.org"
    async with WebSocket.connect(url) as ws:
        # Send text message
        message = "Hello from fasthttp 👋"
        await ws.send_text(message)
        print("Sent:", message)

        # Receive text response
        reply = await ws.recv()
        print("Received text:", reply)

        # Send binary payload
        payload = b"\x00\x01binary-data"
        await ws.send_bytes(payload)
        print("Sent binary:", payload)

        received = await ws.recv()
        print("Received binary:", received)

        # Send JSON payload
        json_payload = {"type": "ping", "message": "hello"}
        await ws.send_json(json_payload)
        print("Sent JSON:", json_payload)

        reply_json = await ws.recv_json()
        print("Received JSON:", reply_json)


if __name__ == "__main__":
    asyncio.run(websocket_client())
