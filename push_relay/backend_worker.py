"""Run blocking Firebase-backed endpoints without blocking ASGI's event loop."""
import asyncio
import inspect
from functools import wraps

import anyio
from starlette.requests import Request

_backend_limiter = anyio.CapacityLimiter(16)


def backend_worker(endpoint):
    @wraps(endpoint)
    async def run(*args, **kwargs):
        # ASGI receive belongs to the main loop; only move cached request bytes
        # into the worker. Never read the live request stream from another loop.
        for value in (*args, *kwargs.values()):
            if isinstance(value, Request):
                await value.body()
        return await anyio.to_thread.run_sync(
            lambda: asyncio.run(endpoint(*args, **kwargs)),
            limiter=_backend_limiter,
        )

    # Resolve postponed annotations in the endpoint's original module, not here.
    run.__signature__ = inspect.signature(endpoint, eval_str=True)
    return run
