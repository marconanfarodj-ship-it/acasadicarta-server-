// ============================================
// SERVER ORDINI — La Casa di Carta
// Riceve gli ordini dal sito, li gira in tempo reale
// al pannello di stampa, e manda l'email alla pizzeria.
// ============================================

const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// ---------- Configurazione (da variabili d'ambiente su Render) ----------
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const ORDER_EMAIL = process.env.ORDER_EMAIL || "Marconanfarodj@gmail.com";
const FROM_EMAIL = process.env.FROM_EMAIL || "onboarding@resend.dev";
const MONGODB_URI = process.env.MONGODB_URI || "";
const JWT_SECRET = process.env.JWT_SECRET || "cambia-questa-chiave-segreta";

// ---------- Connessione al database (account clienti) ----------
let db = null;
let customersCollection = null;
let ordersCollection = null;

async function connectDB(){
  if(!MONGODB_URI){
    console.log('MONGODB_URI non impostata: gli account cliente non funzioneranno.');
    return;
  }
  try{
    const client = new MongoClient(MONGODB_URI);
    await client.connect();
    db = client.db('lacasadicarta');
    customersCollection = db.collection('customers');
    ordersCollection = db.collection('orders');
    await customersCollection.createIndex({ email: 1 }, { unique: true });
    await ordersCollection.createIndex({ customerId: 1, ricevutoAlle: -1 });
    console.log('Connesso a MongoDB Atlas.');
  }catch(err){
    console.error('Errore connessione MongoDB:', err);
  }
}
connectDB();

function generateToken(customer){
  return jwt.sign({ id: customer._id.toString(), email: customer.email }, JWT_SECRET, { expiresIn: '180d' });
}

function authMiddleware(req, res, next){
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if(!token) return res.status(401).json({ ok: false, error: 'Non autenticato' });
  try{
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  }catch(e){
    return res.status(401).json({ ok: false, error: 'Sessione scaduta, accedi di nuovo' });
  }
}

// come authMiddleware, ma non blocca la richiesta se manca/è invalido il token
// (usata per gli ordini, che si possono fare anche senza account)
function tryGetUserFromToken(req){
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if(!token) return null;
  try{
    return jwt.verify(token, JWT_SECRET);
  }catch(e){
    return null;
  }
}

async function sendEmail(to, subject, text) {
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
        to,
        subject,
        text
      })
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

// conteggio in memoria: { "2026-09-22|19:15": 2, ... } — si azzera se il server si riavvia
let slotCounts = {};

function dateKey(d){
  return d.toISOString().slice(0,10); // YYYY-MM-DD (UTC, va bene per un conteggio interno)
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

// dato un orario "richiesto" (Date), trova il primo slot da quel momento in poi
// che non sia ancora pieno, nello stesso giorno. Torna null se la giornata è piena.
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

function isSlotAvailable(dateStr, slot){
  return (slotCounts[`${dateStr}|${slot}`] || 0) < MAX_PER_SLOT;
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
let orderCounter = 1000;

// ---------- Endpoint: disponibilità slot di consegna per una data ----------
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

// ---------- Endpoint: registrazione nuovo account cliente ----------
app.post('/api/auth/register', async (req, res) => {
  if(!customersCollection) return res.status(503).json({ ok: false, error: 'Database non disponibile' });
  const { nome, cognome, email, telefono, password, indirizzo } = req.body || {};
  if(!nome || !email || !telefono || !password){
    return res.status(400).json({ ok: false, error: 'Compila tutti i campi obbligatori.' });
  }
  if(password.length < 6){
    return res.status(400).json({ ok: false, error: 'La password deve avere almeno 6 caratteri.' });
  }
  try{
    const existing = await customersCollection.findOne({ email: email.toLowerCase() });
    if(existing){
      return res.status(409).json({ ok: false, error: 'Esiste già un account con questa email.' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const customer = {
      nome, cognome: cognome || '', email: email.toLowerCase(), telefono, indirizzo: indirizzo || '',
      passwordHash, creatoIl: new Date().toISOString()
    };
    const result = await customersCollection.insertOne(customer);
    customer._id = result.insertedId;
    const token = generateToken(customer);
    res.json({ ok: true, token, profilo: { nome, cognome, email: customer.email, telefono, indirizzo: customer.indirizzo } });
  }catch(err){
    console.error('Errore registrazione:', err);
    res.status(500).json({ ok: false, error: 'Errore del server, riprova.' });
  }
});

// ---------- Endpoint: login ----------
app.post('/api/auth/login', async (req, res) => {
  if(!customersCollection) return res.status(503).json({ ok: false, error: 'Database non disponibile' });
  const { email, password } = req.body || {};
  if(!email || !password){
    return res.status(400).json({ ok: false, error: 'Inserisci email e password.' });
  }
  try{
    const customer = await customersCollection.findOne({ email: email.toLowerCase() });
    if(!customer){
      return res.status(401).json({ ok: false, error: 'Email o password errati.' });
    }
    const valid = await bcrypt.compare(password, customer.passwordHash);
    if(!valid){
      return res.status(401).json({ ok: false, error: 'Email o password errati.' });
    }
    const token = generateToken(customer);
    res.json({ ok: true, token, profilo: { nome: customer.nome, cognome: customer.cognome, email: customer.email, telefono: customer.telefono, indirizzo: customer.indirizzo } });
  }catch(err){
    console.error('Errore login:', err);
    res.status(500).json({ ok: false, error: 'Errore del server, riprova.' });
  }
});

// ---------- Endpoint: profilo cliente autenticato ----------
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  if(!customersCollection) return res.status(503).json({ ok: false, error: 'Database non disponibile' });
  try{
    const { ObjectId } = require('mongodb');
    const customer = await customersCollection.findOne({ _id: new ObjectId(req.user.id) });
    if(!customer) return res.status(404).json({ ok: false, error: 'Account non trovato' });
    res.json({ ok: true, profilo: { nome: customer.nome, cognome: customer.cognome, email: customer.email, telefono: customer.telefono, indirizzo: customer.indirizzo } });
  }catch(err){
    res.status(500).json({ ok: false, error: 'Errore del server' });
  }
});

// ---------- Endpoint: aggiorna indirizzo/telefono salvato ----------
app.put('/api/auth/me', authMiddleware, async (req, res) => {
  if(!customersCollection) return res.status(503).json({ ok: false, error: 'Database non disponibile' });
  const { nome, cognome, telefono, indirizzo } = req.body || {};
  try{
    const { ObjectId } = require('mongodb');
    await customersCollection.updateOne(
      { _id: new ObjectId(req.user.id) },
      { $set: { nome, cognome, telefono, indirizzo } }
    );
    res.json({ ok: true });
  }catch(err){
    res.status(500).json({ ok: false, error: 'Errore del server' });
  }
});

// ---------- Endpoint: il sito manda qui i nuovi ordini ----------
app.post('/api/orders', async (req, res) => {
  const order = req.body;
  if (!order || !order.testoStampa) {
    return res.status(400).json({ ok: false, error: 'Ordine non valido' });
  }

  // gestione slot: si applica solo alle consegne a domicilio
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
    // "prima" (il prima possibile) usa direttamente l'orario attuale

    const dKey = dateKey(requestedDate);
    const slot = slotLabel(requestedDate);
    if (!isSlotAvailable(dKey, slot)) {
      return res.status(409).json({
        ok: false,
        error: 'slot_pieno',
        message: `L'orario delle ${slot} è al completo per le consegne. Scegli un altro orario tra quelli disponibili.`
      });
    }
    reserveSlot(dKey, slot);
    order.slotAssegnato = slot;
    // l'orario mostrato in comanda/email riflette lo slot vero assegnato
    order.orarioLabel = `Alle ${slot}`;
    order.testoStampa = (order.testoStampa || '').replace(/Orario richiesto:.*$/m, `Orario richiesto: Alle ${slot}`);
  }

  order.numeroOrdine = ++orderCounter;
  order.ricevutoAlle = new Date().toISOString();
  orderHistory.unshift(order);
  if (orderHistory.length > MAX_HISTORY) orderHistory.pop();

  // se il cliente ha effettuato il login, colleghiamo l'ordine al suo account
  // per lo storico permanente (visibile solo a lui)
  const user = tryGetUserFromToken(req);
  if (user && ordersCollection) {
    const { customerId, ...orderToSave } = order;
    ordersCollection.insertOne({ ...orderToSave, customerId: user.id }).catch(err => {
      console.error('Errore salvataggio storico ordine:', err);
    });
  }

  // 1) gira l'ordine subito al pannello di stampa
  broadcastOrder(order);

  // 2) manda l'email alla pizzeria (non blocca la risposta se fallisce)
  sendEmail(ORDER_EMAIL, order.oggettoEmail || 'Nuovo ordine — La Casa di Carta', order.testoStampa);

  // 3) manda l'email di conferma al cliente, se ha lasciato un indirizzo valido
  if (order.email) {
    sendEmail(order.email, 'Conferma ordine — La Casa di Carta', buildCustomerConfirmationText(order));
  }

  res.json({ ok: true });
});

// ---------- Endpoint: storico ordini personale del cliente collegato ----------
app.get('/api/orders/mine', authMiddleware, async (req, res) => {
  if(!ordersCollection) return res.status(503).json({ ok: false, error: 'Database non disponibile' });
  try{
    const orders = await ordersCollection
      .find({ customerId: req.user.id })
      .sort({ ricevutoAlle: -1 })
      .limit(50)
      .toArray();
    res.json({ ok: true, ordini: orders });
  }catch(err){
    res.status(500).json({ ok: false, error: 'Errore del server' });
  }
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
