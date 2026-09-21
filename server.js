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
const FROM_EMAIL = process.env.FROM_EMAIL || "onboarding@resend.dev";

async function sendEmail(to, subject, text) {
  if (!RESEND_API_KEY) return;
  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ from: FROM_EMAIL, to, subject, text })
    });
  } catch (err) {
    console.error('Errore invio email:', err);
  }
}

function buildCustomerConfirmationText(order) {
  return `Ciao ${order.name || ''},\n\nAbbiamo ricevuto il tuo ordine da La Casa di Carta! Ecco il riepilogo:\n\n${order.testoStampa}\n\nGrazie e a presto!\nLa Casa di Carta`;
}

// ---------- Slot di consegna: max 3 ordini ogni 15 minuti ----------
const SLOT_MINUTES = 15;
const MAX_PER_SLOT = 3;
const OPEN_FROM_HOUR = 19;
const OPEN_TO_HOUR = 23;

let slotCounts = {};

function dateKey(d){
  return d.toISOString().slice(0,10);
}

function slotLabel(d){
  const h = d.getHours();
  const m = Math.floor(d.getMinutes() / SLOT_MINUTES) * SLOT_MINUTES;
  return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}`;
}

function allSlotsForDay(){
  const slots = [];
  for(let h = OPEN_FROM_HOUR; h < OPEN_TO_HOUR; h++){
    for(let m = 0; m < 60; m += SLOT_MINUTES){
      slots.push(`${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}`);
    }
  }
  return slots;
}

function findAvailableSlot(fromDate){
  const key = dateKey(fromDate);
  const slots = allSlotsForDay();
  const requestedLabel = slotLabel(fromDate);
  const startIndex = Math.max(0, slots.indexOf(requestedLabel) === -1
    ? slots.findIndex(s => s >= requestedLabel)
    : slots.indexOf(requestedLabel));
  for(let i = (startIndex === -1 ? 0 : startIndex); i < slots.length; i++){
    const count = slotCounts[`${key}|${slots[i]}`] || 0;
    if(count < MAX_PER_SLOT) return slots[i];
  }
  return null;
}

function reserveSlot(dateStr, slot){
  const key = `${dateStr}|${slot}`;
  slotCounts[key] = (slotCounts[key] || 0) + 1;
}

let printClients = [];

function broadcastOrder(order) {
  const payload = `data: ${JSON.stringify(order)}\n\n`;
  printClients.forEach(res => res.write(payload));
}

let orderHistory = [];
const MAX_HISTORY = 100;
let orderCounter = 1000;

app.get('/api/delivery-slots', (req, res) => {
  const dateStr = req.query.date || dateKey(new Date());
  const slots = allSlotsForDay();
  const result = slots.map(s => ({
    slot: s,
    prenotati: slotCounts[`${dateStr}|${s}`] || 0,
    disponibile: (slotCounts[`${dateStr}|${s}`] || 0) < MAX_PER_SLOT
  }));
  res.json({ date: dateStr, slots: result });
});

app.post('/api/orders', async (req, res) => {
  const order = req.body;
  if (!order || !order.testoStampa) {
    return res.status(400).json({ ok: false, error: 'Ordine non valido' });
  }

  if (order.modalita === 'consegna') {
    const now = new Date();
    let requestedDate = now;
    if (order.timing === 'orario' && order.orarioRichiesto) {
      const [h, m] = order.orarioRichiesto.split(':').map(Number);
      requestedDate = new Date(now);
      requestedDate.setHours(h, m, 0, 0);
    } else if (order.timing === '30min') {
      requestedDate = new Date(now.getTime() + 30 * 60000);
    }

    const dKey = dateKey(requestedDate);
    const slot = findAvailableSlot(requestedDate);
    if (!slot) {
      return res.status(409).json({ ok: false, error: 'slot_pieno_giornata', message: 'Tutto pieno per oggi, riprova domani.' });
    }
    reserveSlot(dKey, slot);
    order.slotAssegnato = slot;
  }

  order.numeroOrdine = ++orderCounter;
  order.ricevutoAlle = new Date().toISOString();
  orderHistory.unshift(order);
  if (orderHistory.length > MAX_HISTORY) orderHistory.pop();

  broadcastOrder(order);

  sendEmail(ORDER_EMAIL, order.oggettoEmail || 'Nuovo ordine — La Casa di Carta', order.testoStampa);

  if (order.email) {
    sendEmail(order.email, 'Conferma ordine — La Casa di Carta', buildCustomerConfirmationText(order));
  }

  res.json({ ok: true });
});

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

app.get('/api/orders', (req, res) => {
  res.json(orderHistory);
});

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
