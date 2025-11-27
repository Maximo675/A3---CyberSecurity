// Inicializa AOS (Animate On Scroll)
document.addEventListener('DOMContentLoaded', function () {
  if (window.AOS) {
    AOS.init({
      duration: 700,
      easing: 'ease-out-cubic',
      once: true,
      offset: 60
    });
  }
  // Handler for "Simular Pagamento (Dev)" button (moved here to comply with CSP)
  try {
    const simBtn = document.getElementById('simulatePayBtn');
    if (simBtn) {
      simBtn.addEventListener('click', async function (e) {
        e.preventDefault();
        simBtn.disabled = true;
        const originalTxt = simBtn.textContent;
        simBtn.textContent = 'Simulando...';
        try {
          // read tx id from data attribute
          const txId = simBtn.dataset && simBtn.dataset.txId ? simBtn.dataset.txId : (document.querySelector('[data-tx-id]')?.getAttribute('data-tx-id'));
          const resp = await fetch('/webhook/payment', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tx_id: txId, status: 'confirmed' })
          });
          if (resp.ok) {
            window.location.reload();
          } else {
            const txt = await resp.text();
            console.error('Simulate failed', resp.status, txt);
            alert('Falha ao simular pagamento. Veja logs do servidor.');
            simBtn.disabled = false;
            simBtn.textContent = originalTxt;
          }
        } catch (err) {
          console.error(err);
          alert('Erro ao simular pagamento. Veja o console do navegador.');
          simBtn.disabled = false;
          simBtn.textContent = originalTxt;
        }
      });
    }
  } catch (e) {
    console.error('simulatePayBtn handler error', e);
  }
});
