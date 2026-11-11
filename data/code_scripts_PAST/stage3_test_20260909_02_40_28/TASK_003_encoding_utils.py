"""Base64 encoding/decoding utilities for payload preparation.

ATT&CK technique: T1132.001 (Standard Encoding - Base64)

Provides:
    - Base64Encoder: wrapper class handling str/bytes input with error handling.
    - encode_to_base64: convenience function for encoding.
    - decode_from_base64: convenience function for decoding.
    - encode_json_to_base64: encode JSON-serializable data structures.
"""

import base64
import json
from typing import Any, Union


class Base64Encoder:
    """Wrapper class for base64 encoding and decoding.

    Handles both string and bytes input with appropriate error handling.

    Examples:
        >>> encoder = Base64Encoder()
        >>> encoder.encode("Hello, World!")
        'SGVsbG8sIFdvcmxkIQ=='
        >>> encoder.encode(b"\\x00\\x01\\x02")
        'AAEC'
    """

    def encode(self, data: Union[str, bytes, bytearray]) -> str:
        """Encode data to a base64 string.

        Args:
            data: The input data as a string, bytes, or bytearray.

        Returns:
            A base64-encoded string.

        Raises:
            TypeError: If data is not a string, bytes, or bytearray.
            UnicodeEncodeError: If a string cannot be encoded to UTF-8.
        """
        if isinstance(data, str):
            raw = data.encode("utf-8")
        elif isinstance(data, (bytes, bytearray)):
            raw = bytes(data)
        else:
            raise TypeError(
                f"Expected str, bytes, or bytearray, got {type(data).__name__}"
            )

        return base64.b64encode(raw).decode("ascii")

    def decode(self, data: Union[str, bytes]) -> bytes:
        """Decode a base64-encoded string or bytes to raw bytes.

        Args:
            data: The base64-encoded data as a string or bytes.

        Returns:
            The decoded bytes.

        Raises:
            TypeError: If data is not a string or bytes.
            ValueError: If the input is not valid base64.
        """
        if isinstance(data, str):
            encoded_bytes = data.encode("ascii")
        elif isinstance(data, (bytes, bytearray)):
            encoded_bytes = bytes(data)
        else:
            raise TypeError(
                f"Expected str or bytes, got {type(data).__name__}"
            )

        try:
            return base64.b64decode(encoded_bytes, validate=True)
        except (base64.binascii.Error, ValueError) as exc:
            raise ValueError(f"Invalid base64 input: {exc}") from exc

    def decode_to_str(self, data: Union[str, bytes], encoding: str = "utf-8") -> str:
        """Decode a base64 string and return the result as a string.

        Args:
            data: The base64-encoded data.
            encoding: The target string encoding (default: UTF-8).

        Returns:
            The decoded string.

        Raises:
            TypeError: If data is not a string or bytes.
            ValueError: If the input is not valid base64.
            UnicodeDecodeError: If decoded bytes are not valid in the target encoding.
        """
        return self.decode(data).decode(encoding)

    def encode_json(self, obj: Any) -> str:
        """Encode a JSON-serializable object to a base64 string.

        Args:
            obj: A JSON-serializable Python object.

        Returns:
            A base64-encoded string representing the JSON serialization.

        Raises:
            TypeError: If obj is not JSON-serializable.
        """
        try:
            json_bytes = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise TypeError(f"Object is not JSON-serializable: {exc}") from exc

        return base64.b64encode(json_bytes).decode("ascii")

    def decode_json(self, data: Union[str, bytes]) -> Any:
        """Decode a base64 string and parse the result as JSON.

        Args:
            data: A base64-encoded JSON string.

        Returns:
            The deserialized Python object.

        Raises:
            ValueError: If the input is not valid base64 or valid JSON.
        """
        raw = self.decode(data)
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"Decoded data is not valid JSON: {exc}") from exc


def encode_to_base64(data: Union[str, bytes, bytearray]) -> str:
    """Encode data to a base64 string.

    Convenience wrapper around Base64Encoder.encode.

    Args:
        data: The input data as a string, bytes, or bytearray.

    Returns:
        A base64-encoded string.

    Raises:
        TypeError: If data is not a string, bytes, or bytearray.

    Examples:
        >>> encode_to_base64("secret payload")
        'c2VjcmV0IHBheWxvYWQ='
        >>> encode_to_base64(b'\\xde\\xad\\xbe\\xef')
        '3q2+7w=='
    """
    return Base64Encoder().encode(data)


def decode_from_base64(data: Union[str, bytes]) -> bytes:
    """Decode a base64-encoded string or bytes to raw bytes.

    Convenience wrapper around Base64Encoder.decode.

    Args:
        data: The base64-encoded data as a string or bytes.

    Returns:
            The decoded bytes.

    Raises:
        TypeError: If data is not a string or bytes.
        ValueError: If the input is not valid base64.

    Examples:
        >>> decode_from_base64('SGVsbG8=')
        b'Hello'
    """
    return Base64Encoder().decode(data)


def encode_json_to_base64(obj: Any) -> str:
    """Encode a JSON-serializable data structure to a base64 string.

    Args:
        obj: A JSON-serializable Python object (dict, list, str, int, etc.).

    Returns:
        A base64-encoded string of the JSON representation.

    Raises:
        TypeError: If obj is not JSON-serializable.

    Examples:
        >>> encode_json_to_base64({"key": "value", "num": 42})
        'eyJudW0iOjQyLCJrZXkiOiJ2YWx1ZSJ9'
    """
    return Base64Encoder().encode_json(obj)
