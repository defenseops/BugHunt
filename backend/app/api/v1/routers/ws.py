import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.redis import get_redis

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/scans/{scan_id}/progress")
async def scan_progress(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    redis = await get_redis()
    channel = f"scan:{scan_id}:logs"

    pubsub = redis.pubsub()
    await pubsub.subscribe(channel)

    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                await websocket.send_text(message["data"])
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.aclose()
