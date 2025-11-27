"""
Gateway adapter for payments.
Supports a sandbox implementation for PIX and cards.
Designed so a production gateway implementation can be plugged in.
"""
from typing import Dict
import uuid
import time
import io
import base64
import hmac
import hashlib
import requests
import qrcode


class BaseGateway:
    def create_pix(self, amount, payer_id=None) -> Dict:
        raise NotImplementedError()

    def charge_card(self, amount, card_number, card_holder, expiry, cvv) -> Dict:
        raise NotImplementedError()


class SandboxGateway(BaseGateway):
    """Simple sandbox that generates a QR code for PIX and simulates card processing.
    This is only for development and tests.
    """

    def create_pix(self, amount, payer_id=None) -> Dict:
        if amount <= 0:
            return {"status": "error", "message": "O valor da doação deve ser positivo."}

        tx_id = str(uuid.uuid4())
        qr_payload = f"PIX:{tx_id}|AMOUNT:{amount}|PAYER:{payer_id}"
        qr = qrcode.QRCode(box_size=10, border=4)
        qr.add_data(qr_payload)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_bytes = buffered.getvalue()
        qr_b64 = base64.b64encode(img_bytes).decode('ascii')
        qr_code = f"data:image/png;base64,{qr_b64}"

        # Simulate a small delay
        time.sleep(0.05)

        return {
            "status": "success",
            "method": "pix",
            "tx_id": tx_id,
            "amount": amount,
            "qr_code": qr_code,
            "message": "PIX gerado (sandbox)."
        }

    def charge_card(self, amount, card_number, card_holder, expiry, cvv) -> Dict:
        if amount <= 0:
            return {"status": "error", "message": "O valor da doação deve ser positivo."}

        tx_id = str(uuid.uuid4())
        time.sleep(0.05)

        if cvv == '000':
            return {"status": "error", "message": "Pagamento recusado (sandbox)."}

        return {"status": "success", "method": "card", "tx_id": tx_id, "amount": amount, "message": "Cartão aprovado (sandbox)."}


# Simple factory to select gateway by env var or default to sandbox
def get_gateway(name: str = None) -> BaseGateway:
    # Select gateway by environment variable or function argument.
    name = name or None
    # If environment-based selection is needed, import os to read GATEWAY_PROVIDER.
    import os
    provider = name or os.getenv('GATEWAY_PROVIDER', 'sandbox').lower()
    if provider == 'sandbox':
        return SandboxGateway()
    elif provider == 'gerencianet':
        return GerencianetGateway()
    elif provider == 'mercadopago':
        return MercadoPagoGateway()
    else:
        return SandboxGateway()


def verify_hmac_signature(payload_body: bytes, signature_header: str, secret: str) -> bool:
    """Verify HMAC SHA256 signature of payload body (hex or base64 compatible).
    signature_header: value from header, expected as hex string.
    secret: shared secret string
    """
    if not signature_header or not secret:
        return False
    computed_hmac = hmac.new(secret.encode('utf-8'), payload_body, hashlib.sha256).hexdigest()
    # Use compare_digest to avoid timing attacks
    try:
        return hmac.compare_digest(computed_hmac, signature_header)
    except Exception:
        return False


class GerencianetGateway(BaseGateway):
    """Example provider adapter (Gerencianet-like). This is a stub for demonstration
    and shows how to implement real provider logic.
    In production, implement API calls to Gerencianet or MercadoPago sandbox here.
    """
    def __init__(self):
        self.api_key = None
        self.api_secret = None
        import os
        self.api_key = os.getenv('GATEWAY_API_KEY')
        self.api_secret = os.getenv('GATEWAY_API_SECRET')

    def create_pix(self, amount, payer_id=None) -> Dict:
        # For real implementation, call the provider API and return the payload including
        # tx_id and qr_code. Here we just return not implemented.
        return {"status": "error", "message": "Gerencianet adapter not implemented (use sandbox or implement API)."}

    def charge_card(self, amount, card_number, card_holder, expiry, cvv) -> Dict:
        return {"status": "error", "message": "Gerencianet adapter not implemented (use sandbox or implement API)."}


class MercadoPagoGateway(BaseGateway):
    def __init__(self):
        self.api_key = None
        import os
        self.api_key = os.getenv('GATEWAY_API_KEY')

    def create_pix(self, amount, payer_id=None) -> Dict:
        return {"status": "error", "message": "Mercado Pago adapter not implemented (use sandbox or implement API)."}

    def charge_card(self, amount, card_number, card_holder, expiry, cvv) -> Dict:
        return {"status": "error", "message": "Mercado Pago adapter not implemented (use sandbox or implement API)."}
