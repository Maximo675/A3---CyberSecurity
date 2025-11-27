"""
Módulo de pagamentos (exemplo).
Contém funções simples para demonstrar integração de pagamentos via PIX e cartão.
Estas implementações são placeholders — substitua pela integração real com gateway.
"""

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

    return {
        "status": "success",
        "method": "pix",
        "tx_id": tx_id,
        "amount": amount,
        "qr_code": qr_code,
        "message": "Pagamento via PIX gerado com sucesso (simulado)."
    }

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

    return {
        "status": "success",
        "method": "card",
        "tx_id": tx_id,
        "amount": amount,
        "card_holder": card_holder,
        "message": "Pagamento com cartão aprovado (simulado)."
    }

if __name__ == "__main__":
    print(process_pix(10.00))
    print(process_card(20.00, "4242424242424242", "Fulano Teste", "12/30", "123"))
