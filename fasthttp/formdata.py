import asyncio
import functools
import mimetypes
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, BinaryIO, Iterable, Mapping, Optional, Sequence, Tuple, Union

BytesLike = Union[bytes, bytearray, memoryview]
FileContent = Union[BytesLike, str, os.PathLike[str], BinaryIO, AsyncIterator[bytes]]
FileTuple = Union[
    Tuple[str, FileContent],
    Tuple[str, FileContent, str],
]
FilesType = Union[
    Mapping[str, Union[FileContent, FileTuple]],
    Sequence[Tuple[str, Union[FileContent, FileTuple]]],
]

_DEFAULT_FILE_CONTENT_TYPE = "application/octet-stream"
_TEXT_CONTENT_TYPE = "text/plain; charset=utf-8"
_DEFAULT_CHUNK_SIZE = 64 * 1024


@dataclass
class FilePart:
    field_name: str
    file_name: str
    content_type: str
    data: Any
    is_stream: bool
    close_after: bool = False


class MultipartEncoder:
    """Stream-friendly multipart/form-data encoder."""

    def __init__(
        self,
        fields: Optional[Union[Mapping[str, Any], Sequence[Tuple[str, Any]]]] = None,
        files: Optional[FilesType] = None,
        *,
        boundary: Optional[str] = None,
        chunk_size: int = _DEFAULT_CHUNK_SIZE,
    ) -> None:
        self.boundary = boundary or self._generate_boundary()
        self._boundary_line = f"--{self.boundary}\r\n".encode("ascii")
        self._closing_boundary = f"--{self.boundary}--\r\n".encode("ascii")
        self.fields = self._normalize_fields(fields)
        self.file_parts = self._normalize_files(files)
        self.chunk_size = max(chunk_size, 1024)
        self.content_type = f"multipart/form-data; boundary={self.boundary}"

    def iter_bytes(self) -> AsyncIterator[bytes]:
        async def generator() -> AsyncIterator[bytes]:
            for name, value in self.fields:
                yield self._boundary_line
                header = self._render_field_headers(name)
                yield header
                yield self._coerce_bytes(value)
                yield b"\r\n"

            for part in self.file_parts:
                yield self._boundary_line
                yield self._render_file_headers(part)
                async for chunk in self._yield_file_data(part):
                    if chunk:
                        yield chunk
                yield b"\r\n"

            yield self._closing_boundary

        return generator()

    def _render_field_headers(self, name: str) -> bytes:
        return (
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
        ).encode("utf-8")

    def _render_file_headers(self, part: FilePart) -> bytes:
        disposition = (
            f'Content-Disposition: form-data; name="{part.field_name}"; '
            f'filename="{part.file_name}"\r\n'
        )
        headers = (
            disposition
            + f"Content-Type: {part.content_type}\r\n\r\n"
        )
        return headers.encode("utf-8")

    async def _yield_file_data(self, part: FilePart) -> AsyncIterator[bytes]:
        data = part.data
        if not part.is_stream:
            yield self._coerce_bytes(data)
            return

        if hasattr(data, "__aiter__"):
            async for chunk in data:  # type: ignore[async-for]
                yield self._coerce_bytes(chunk)
            return

        reader: BinaryIO = data
        try:
            while True:
                chunk = await _to_thread(reader.read, self.chunk_size)
                if not chunk:
                    break
                yield self._coerce_bytes(chunk)
        finally:
            if part.close_after:
                await _to_thread(reader.close)

    def _normalize_fields(
        self,
        fields: Optional[Union[Mapping[str, Any], Sequence[Tuple[str, Any]]]],
    ) -> Iterable[Tuple[str, Any]]:
        if not fields:
            return []
        if isinstance(fields, Mapping):
            items = fields.items()
        else:
            items = fields
        normalized = []
        for name, value in items:
            field_name = str(name)
            normalized.append((field_name, "" if value is None else value))
        return normalized

    def _normalize_files(self, files: Optional[FilesType]) -> Iterable[FilePart]:
        if not files:
            return []
        if isinstance(files, Mapping):
            items = files.items()
        else:
            items = files

        parts = []
        for field_name, value in items:
            parts.append(self._coerce_file_part(str(field_name), value))
        return parts

    def _coerce_file_part(self, field_name: str, value: Union[FileContent, FileTuple]) -> FilePart:
        file_name: Optional[str] = None
        content_type: Optional[str] = None
        data: Any = value

        if isinstance(value, (tuple, list)):
            if len(value) < 2 or len(value) > 3:
                raise ValueError("file tuples must be (filename, data[, content_type])")
            file_name = str(value[0])
            data = value[1]
            if len(value) == 3 and value[2]:
                content_type = str(value[2])

        close_after = False
        is_stream = False

        if isinstance(data, Path):
            data = data.open("rb")
            is_stream = True
            close_after = True
        elif hasattr(data, "__aiter__"):
            is_stream = True
        elif hasattr(data, "read"):
            is_stream = True
        elif isinstance(data, (bytes, bytearray)):
            data = bytes(data)
        elif isinstance(data, memoryview):
            data = data.tobytes()
        elif isinstance(data, str):
            data = data.encode("utf-8")
        else:
            data = str(data).encode("utf-8")

        inferred_name = None
        if hasattr(data, "name"):
            inferred = getattr(data, "name")
            if isinstance(inferred, str):
                inferred_name = os.path.basename(inferred)

        final_name = file_name or inferred_name or f"{field_name}.bin"

        if content_type is None:
            content_type = mimetypes.guess_type(final_name)[0] or _DEFAULT_FILE_CONTENT_TYPE
        if not is_stream and isinstance(data, bytes):
            # Treat plain text specially for better defaults
            if content_type == _DEFAULT_FILE_CONTENT_TYPE and _looks_like_text(data):
                content_type = _TEXT_CONTENT_TYPE

        return FilePart(
            field_name=field_name,
            file_name=final_name,
            content_type=content_type,
            data=data,
            is_stream=is_stream,
            close_after=close_after,
        )

    def _coerce_bytes(self, value: Any) -> bytes:
        if value is None:
            return b""
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, memoryview):
            return value.tobytes()
        if isinstance(value, str):
            return value.encode("utf-8")
        return str(value).encode("utf-8")

    @staticmethod
    def _generate_boundary() -> str:
        return uuid.uuid4().hex


def _looks_like_text(data: bytes) -> bool:
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


async def _to_thread(func, *args):
    if hasattr(asyncio, "to_thread"):
        return await asyncio.to_thread(func, *args)
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, functools.partial(func, *args))


__all__ = ["FilesType", "MultipartEncoder"]
