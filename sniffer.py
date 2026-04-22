"""Packet capture interface built on top of Scapy."""

from typing import Any, Callable, Optional

try:
    from scapy.all import AsyncSniffer
except Exception:  # pragma: no cover - runtime dependency check
    AsyncSniffer = None  # type: ignore[assignment]


class PacketSniffer:
    """Capture packets and forward them to a handler callback."""

    def __init__(
        self,
        packet_handler: Callable[[Any], None],
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
    ) -> None:
        self.packet_handler = packet_handler
        self.interface = interface
        self.bpf_filter = bpf_filter
        self._sniffer = None

    def start(self) -> None:
        """Start asynchronous packet capture."""
        if AsyncSniffer is None:
            raise RuntimeError(
                "Scapy is required for packet capture. Install with: pip install scapy"
            )
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=self._safe_handler,
            store=False,
        )
        self._sniffer.start()

    def stop(self) -> None:
        """Stop packet capture if running."""
        if self._sniffer is None:
            return
        try:
            self._sniffer.stop()
        except Exception:
            pass
        finally:
            self._sniffer = None

    def _safe_handler(self, packet: Any) -> None:
        try:
            self.packet_handler(packet)
        except Exception as exc:
            print(f"[SNIFFER_ERROR] packet handling failed: {exc}")
