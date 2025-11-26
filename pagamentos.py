# pagamentos.py

import uuid
import time

def process_pix(amount, payer_id=None):
    """
    Simula um pagamento via PIX.
    Retorna um dicionário com status e dados.
    Esta é uma implementação placeholder — substitua pela integração real com gateway PIX.
    """
    if amount <= 0:
        return {
            "status": "error",
            "message": "O valor da doação deve ser positivo."
        }
        
    tx_id = str(uuid.uuid4())
    # Em uma implementação real, esta seria a chave PIX ou URL para o QR Code.
    qr_code = f"PIX_SIMULADO://{tx_id}" 

    # Simular processamento
    time.sleep(0.1)

    return {
        "status": "success",
        "method": "pix",
        "tx_id": tx_id,
        "amount": amount,
        "qr_code": qr_code,
        "message": "Pagamento via PIX gerado com sucesso (simulado). Aguardando confirmação."
    }

def process_card(amount, card_number, card_holder, expiry, cvv):
    """
    Simula um pagamento com cartão.
    NÃO ARMAZENE dados sensíveis em produção. Use tokens fornecidos pelo gateway de pagamento.
    """
    if amount <= 0:
        return {
            "status": "error",
            "message": "O valor da doação deve ser positivo."
        }
    
    tx_id = str(uuid.uuid4())

    # Validação superficial (somente para simulação)
    if len(str(card_number).replace(' ', '')) < 12:
        return {
            "status": "error",
            "message": "Número de cartão inválido (simulado - deve ter pelo menos 12 dígitos)."
        }
    
    # Simula falha para CVV "000"
    if cvv == "000":
        return {
            "status": "error",
            "message": "Pagamento recusado pela operadora (CVV inválido, simulado)."
        }

    # Simulando processamento
    time.sleep(0.1)

    # Nota: Em um ambiente real, a bandeira do cartão não seria retornada, 
    # mas sim um token seguro e o status de aprovação.
    return {
        "status": "success",
        "method": "card",
        "tx_id": tx_id,
        "amount": amount,
        "message": "Pagamento com cartão aprovado (simulado)."
    }

if __name__ == "__main__":
    print(process_pix(10.00))
    print(process_card(20.00, "4242424242424242", "Fulano Teste", "12/30", "123"))