from pagamentos_gateway import SandboxGateway


def test_sandbox_create_pix_returns_qr_and_txid():
    gw = SandboxGateway()
    res = gw.create_pix(10.50, payer_id='testpayer')
    assert res['status'] == 'success'
    assert 'tx_id' in res
    assert 'qr_code' in res and res['qr_code'].startswith('data:image/png;base64,')


def test_sandbox_charge_card_success():
    gw = SandboxGateway()
    res = gw.charge_card(20.00, '4242424242424242', 'Fulano', '12/30', '123')
    assert res['status'] == 'success'
    assert 'tx_id' in res


def test_sandbox_charge_card_reject():
    gw = SandboxGateway()
    res = gw.charge_card(20.00, '4242424242424242', 'Fulano', '12/30', '000')
    assert res['status'] == 'error'
