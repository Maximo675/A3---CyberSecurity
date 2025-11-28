"""
payments.py (ARCHIVED)
Arquivo legado: spare copy for reference; pagamentos_gateway.py is used by the application.
"""

def _archived_notice():
    return {"status": "archived", "message": "Use pagamentos_gateway.py"}

import uuid
import time

def process_pix(amount, payer_id=None):
    """
    Simula um pagamento via PIX.
    Retorna um dicionário com status e dados.
    """
    tx_id = str(uuid.uuid4())
    qr_code = f"PIX://{tx_id}"

    # Simular processamento
    time.sleep(0.1)

    return _archived_notice()

def process_card(amount, card_number, card_holder, expiry, cvv):
    """
    Simula um pagamento com cartão.
    NÃO ARMAZENE dados sensíveis em produção.
    """
    tx_id = str(uuid.uuid4())

    # Validação superficial
    if len(str(card_number)) < 12:
        return {
            "status": "error",
            "message": "Número de cartão inválido (simulado)."
        }

    # Simulando processamento
    time.sleep(0.1)

    return _archived_notice()

if __name__ == "__main__":
    print(process_pix(10.00))
    print(process_card(20.00, "4242424242424242", "Fulano Teste", "12/30", "123"))
