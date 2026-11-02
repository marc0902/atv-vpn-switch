"""Minimaler multipart/form-data-Parser (nur Standardbibliothek)."""

from __future__ import annotations

from email.parser import BytesParser
from email.policy import HTTP


class FormPart:
    def __init__(self, name: str, filename: str | None, data: bytes):
        self.name = name
        self.filename = filename
        self.data = data

    def text(self) -> str:
        return self.data.decode("utf-8", errors="replace")


def parse_multipart(content_type: str, body: bytes) -> dict[str, FormPart]:
    if "multipart/form-data" not in content_type.lower() or "boundary=" not in content_type.lower():
        raise ValueError("multipart/form-data mit boundary erwartet")
    msg = BytesParser(policy=HTTP).parsebytes(
        b"Content-Type: " + content_type.encode("latin-1") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    )
    if not msg.is_multipart():
        raise ValueError("Ungültiger multipart-Inhalt")
    parts: dict[str, FormPart] = {}
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        filename = part.get_filename()
        data = part.get_payload(decode=True) or b""
        parts[name] = FormPart(name, filename, data)
    return parts
