import hmac
import hashlib
import json
from app import db, Transaction


def sign_payload(payload_dict, secret):
    payload = json.dumps(payload_dict).encode('utf-8')
    return hmac.new(secret.encode('utf-8'), payload, hashlib.sha256).hexdigest(), payload


def test_webhook_rejects_unsigned(client):
    # Create tx as pending
    with client.application.app_context():
        tx = Transaction(tx_id='test-hmac-1', method='pix', amount=10.0, status='pending')
        db.session.add(tx)
        db.session.commit()

    resp = client.post('/webhook/payment', json={'tx_id': 'test-hmac-1', 'status': 'confirmed'})
    assert resp.status_code in (403, 400)


def test_webhook_hmac_accepts_signed(client, monkeypatch):
    secret = 'test-secret-webhook'
    monkeypatch.setenv('PAYMENT_WEBHOOK_SECRET', secret)
    # Create tx
    with client.application.app_context():
        tx = Transaction(tx_id='test-hmac-2', method='pix', amount=10.0, status='pending')
        db.session.add(tx)
        db.session.commit()

    sig, payload = sign_payload({'tx_id': 'test-hmac-2', 'status': 'confirmed'}, secret)
    resp = client.post('/webhook/payment', data=payload, headers={'Content-Type': 'application/json', 'X-GATEWAY-SIGNATURE': sig})
    assert resp.status_code == 200

    with client.application.app_context():
        tx = Transaction.query.filter_by(tx_id='test-hmac-2').first()
        assert tx.status == 'confirmed'
