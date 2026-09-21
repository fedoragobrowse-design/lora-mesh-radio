"""meshctl: USB terminal interface for three-node Pico LoRa mesh.

Host only transports opaque pairing records and plaintext UI text.
No key agreement or message encryption happens in Python; all
cryptography lives in firmware (Rust). See three-pico-lora-plan.md.
"""

__version__ = "0.1.0"
