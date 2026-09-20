// ============================================
// SERVER ORDINI — La Casa di Carta
// Riceve gli ordini dal sito, li gira in tempo reale
// al pannello di stampa, e manda l'email alla pizzeria.
// ============================================

const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// ---------- Configurazione (da variabili d'ambiente su Render) ----------
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const ORDER_EMAIL = process.env.ORDER_EMAIL || "Marconanfarodj@gmail.com";
const FROM_EMAIL = process.env.FROM_EMAIL || "onboarding@resend.dev"; // dominio di test di Resend, funziona subito

async function sendOrderEmail(subject, text) {
  if (!RESEND_API_KEY) return;
  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: FROM_EMAIL,
        to: ORDER_EMAIL,
        subject,
        text
      })
    });
  } catch (err) {
    console.error('Errore invio email:', err);
  }
}

// ---------- Elenco dei "client" del pannello di stampa in ascolto (SSE) ----------
let printClients = [];

function broadcastOrder(order) {
  const payload = `data: ${JSON.stringify(order)}\n\n`;
  printClients.forEach(res => res.write(payload));
}

// ---------- Storico ordini in memoria (si azzera se il server si riavvia) ----------
let orderHistory = [];
const MAX_HISTORY = 100;

// ---------- Endpoint: il sito manda qui i nuovi ordini ----------
app.post('/api/orders', async (req, res) => {
  const order = req.body;
  if (!order || !order.testoStampa) {
    return res.status(400).json({ ok: false, error: 'Ordine non valido' });
  }

  order.ricevutoAlle = new Date().toISOString();
  orderHistory.unshift(order);
  if (orderHistory.length > MAX_HISTORY) orderHistory.pop();

  // 1) gira l'ordine subito al pannello di stampa
  broadcastOrder(order);

  // 2) manda l'email alla pizzeria (non blocca la risposta se fallisce)
  sendOrderEmail(order.oggettoEmail || 'Nuovo ordine — La Casa di Carta', order.testoStampa);

  res.json({ ok: true });
});

// ---------- Endpoint: il pannello di stampa si mette in ascolto qui ----------
app.get('/api/orders/stream', (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });
  res.flushHeaders();
  res.write('retry: 3000\n\n');

  printClients.push(res);

  req.on('close', () => {
    printClients = printClients.filter(c => c !== res);
  });
});

// ---------- Endpoint: storico ordini (utile per controlli/debug) ----------
app.get('/api/orders', (req, res) => {
  res.json(orderHistory);
});

// ---------- Pagina di controllo semplice ----------
app.get('/', (req, res) => {
  res.send(`
    <h2>Server ordini La Casa di Carta — attivo ✅</h2>
    <p>Ordini ricevuti in totale: ${orderHistory.length}</p>
    <p>Pannelli di stampa collegati ora: ${printClients.length}</p>
  `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server ordini in ascolto sulla porta ${PORT}`);
});
