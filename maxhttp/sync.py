"""
Synchronous wrapper utilities for converting async methods to sync.
"""
import asyncio
import functools
import inspect
import threading

from .client import Client
from .response import Response
from .pool import ConnectionPool
from .connection import Connection


def async_to_sync(obj, name):
    """
    Wrap an asynchronous function or asynchronous generator method
    to make it synchronous.

    Parameters:
    - obj: Object containing the method.
    - name: Name of the method to wrap.

    Returns:
    Wrapped synchronous function or generator.
    """
    function = getattr(obj, name)
    is_coroutine_function = inspect.iscoroutinefunction(function)
    is_asyncgen_function = inspect.isasyncgenfunction(function)

    if not (is_coroutine_function or is_asyncgen_function):
        return

    try:
        main_loop = asyncio.get_event_loop()
    except RuntimeError:
        # Create and register a loop if none exists for the current thread.
        main_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(main_loop)

    def async_to_sync_gen(agen, loop, is_main_thread):
        async def anext(agen):
            try:
                return await agen.__anext__(), False
            except StopAsyncIteration:
                return None, True

        while True:
            if is_main_thread:
                item, done = loop.run_until_complete(anext(agen))
            else:
                item, done = asyncio.run_coroutine_threadsafe(
                    anext(agen), loop
                ).result()

            if done:
                break

            yield item

    @functools.wraps(function)
    def resolve_coroutine(coroutine, loop, run_inline):
        if coroutine is None or not inspect.iscoroutine(coroutine):
            return coroutine

        if run_inline:
            if loop.is_running():
                return coroutine
            return loop.run_until_complete(coroutine)

        if loop.is_running():

            async def coro_wrapper():
                return await asyncio.wrap_future(
                    asyncio.run_coroutine_threadsafe(coroutine, main_loop)
                )

            return coro_wrapper()

        return asyncio.run_coroutine_threadsafe(coroutine, main_loop).result()

    def resolve_asyncgen(generator, loop, run_inline):
        if generator is None or not inspect.isasyncgen(generator):
            return generator

        if loop.is_running():
            return generator

        return async_to_sync_gen(generator, loop if run_inline else main_loop, run_inline)

    def async_to_sync_wrap(*args, **kwargs):
        result = function(*args, **kwargs)

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        run_inline = (
            threading.current_thread() is threading.main_thread()
            or not main_loop.is_running()
        )

        if is_coroutine_function:
            return resolve_coroutine(result, loop, run_inline)

        if is_asyncgen_function:
            return resolve_asyncgen(result, loop, run_inline)

        return result

    setattr(obj, name, async_to_sync_wrap)


def wrap_methods(source):
    """
    Wrap asynchronous methods in a class to make them synchronous.

    Parameters:
    - source: Class containing asynchronous methods.
    """
    for name in dir(source):
        method = getattr(source, name)

        if not name.startswith("_") and (
            inspect.iscoroutinefunction(method) or inspect.isasyncgenfunction(method)
        ):
            async_to_sync(source, name)


wrap_methods(Client)
wrap_methods(Response)
wrap_methods(ConnectionPool)
wrap_methods(Connection)