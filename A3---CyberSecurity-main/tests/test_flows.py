import json
from app import db, User, Transaction


def login(client, username, password):
    return client.post('/login', data={'username': username, 'password': password}, follow_redirects=True)


def test_doar_pix_and_webhook(client):
    # login as volunteer
    with client.application.app_context():
        vol = User.query.filter_by(username='vol').first()

    # Login (form bypass using placeholder password)
    login_resp = login(client, 'vol', 'volpass')
    assert login_resp.status_code in (302, 200)

    # Create PIX donation
    resp = client.post('/doar', data={'method': 'pix', 'amount': '15.50', 'payer_id': 'tester'}, follow_redirects=False)
    assert resp.status_code in (302, 302)  # redirect to transaction view

    # Find tx id in DB
    with client.application.app_context():
        tx = Transaction.query.order_by(Transaction.created_at.desc()).first()
        assert tx is not None
        tx_id = tx.tx_id
        assert tx.status == 'pending'

    # Simulate webhook confirmation
    webhook_resp = client.post('/webhook/payment', json={'tx_id': tx_id, 'status': 'confirmed'})
    assert webhook_resp.status_code == 200

    with client.application.app_context():
        tx = Transaction.query.filter_by(tx_id=tx_id).first()
        assert tx.status == 'confirmed'
