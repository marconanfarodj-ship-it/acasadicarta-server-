// ============================================
// SERVER ORDINI — La Casa di Carta
// Riceve gli ordini dal sito, li gira in tempo reale
// al pannello di stampa, e manda l'email alla pizzeria.
// ============================================

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');

const app = express();

// Origini autorizzate a fare richieste con i cookie (il sito ordini, sul dominio vero
// e, per compatibilità durante il passaggio, anche il vecchio indirizzo netlify.app)
const ALLOWED_ORIGINS = [
  'https://ordini.pizzerialacasadicarta.it',
  'https://cheerful-melomakarona-cc557e.netlify.app'
];
app.use(cors({
  origin: function(origin, callback){
    if(!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(null, true); // per ora permissivo anche verso altre origini (es. claude.ai in fase di test)
  },
  credentials: true
}));
app.use(cookieParser());
app.use((req, res, next) => {
  if (req.originalUrl === '/api/stripe-webhook') {
    next(); // qui serve il corpo "grezzo", non json già interpretato
  } else {
    express.json()(req, res, next);
  }
});

// dominio su cui il cookie di sessione è condiviso (sito e server sono su sottodomini diversi
// dello stesso dominio vero, quindi il cookie può essere condiviso tra i due)
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || '.pizzerialacasadicarta.it';

// ---------- Configurazione (da variabili d'ambiente su Render) ----------
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const ORDER_EMAIL = process.env.ORDER_EMAIL || "Marconanfarodj@gmail.com";
const FROM_EMAIL = process.env.FROM_EMAIL || "onboarding@resend.dev";
const MONGODB_URI = process.env.MONGODB_URI || "";
const JWT_SECRET = process.env.JWT_SECRET || "cambia-questa-chiave-segreta";
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";
const SITE_URL = process.env.SITE_URL || "https://ordini.pizzerialacasadicarta.it";
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

// ordini creati dal cliente ma in attesa dell'esito del pagamento online,
// salvati su MongoDB (con scadenza automatica dopo 24 ore) così sopravvivono
// anche se il server si riavvia mentre il cliente sta pagando su Stripe.
let pendingOnlineOrders = {}; // riserva in memoria, usata solo se il database non è disponibile

// ---------- Connessione al database (account clienti) ----------
let db = null;
let customersCollection = null;
let ordersCollection = null;
let pendingOrdersCollection = null;

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
    pendingOrdersCollection = db.collection('pendingOnlineOrders');
    await customersCollection.createIndex({ email: 1 }, { unique: true });
    await ordersCollection.createIndex({ customerId: 1, ricevutoAlle: -1 });
    await pendingOrdersCollection.createIndex({ createdAt: 1 }, { expireAfterSeconds: 60 * 60 * 24 });
    console.log('Connesso a MongoDB Atlas.');
  }catch(err){
    console.error('Errore connessione MongoDB:', err);
  }
}
connectDB();

function generateToken(customer){
  return jwt.sign({ id: customer._id.toString(), email: customer.email }, JWT_SECRET, { expiresIn: '180d' });
}

function setAuthCookie(res, token){
  res.cookie('lcdc_session', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    domain: COOKIE_DOMAIN,
    maxAge: 180 * 24 * 60 * 60 * 1000, // 180 giorni
    path: '/'
  });
}

function clearAuthCookie(res){
  res.clearCookie('lcdc_session', { domain: COOKIE_DOMAIN, path: '/' });
}

function extractToken(req){
  if(req.cookies && req.cookies.lcdc_session) return req.cookies.lcdc_session;
  const header = req.headers.authorization || '';
  return header.startsWith('Bearer ') ? header.slice(7) : null; // retrocompatibilità
}

function authMiddleware(req, res, next){
  const token = extractToken(req);
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
  const token = extractToken(req);
  if(!token) return null;
  try{
    return jwt.verify(token, JWT_SECRET);
  }catch(e){
    return null;
  }
}

async function sendEmail(to, subject, text, html) {
  if (!RESEND_API_KEY) return;
  try {
    const payload = { from: FROM_EMAIL, to, subject, text };
    if (html) payload.html = html;
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });
  } catch (err) {
    console.error('Errore invio email:', err);
  }
}

function buildCustomerConfirmationText(order) {
  return `Ciao ${order.name || ''},\n\nAbbiamo ricevuto il tuo ordine da La Casa di Carta! Ecco il riepilogo:\n\n${order.testoStampa}\n\nGrazie e a presto!\nLa Casa di Carta`;
}

function esc(s){
  return String(s || '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
}
function money(n){ return '€' + (Number(n) || 0).toFixed(2).replace('.', ','); }

function buildCustomerConfirmationHtml(order) {
  const logoUrl = `${SITE_URL}/icon-512.png`;

  const righeArticoli = (order.articoli || []).map(a => {
    const dettagli = (a.dettagli || []).map(d => `<div style="font-size:12px;color:#8a8a8a;margin-top:2px;">${esc(d)}</div>`).join('');
    return `
      <tr>
        <td style="padding:10px 0;border-bottom:1px solid #eee;vertical-align:top;">
          <div style="font-weight:600;color:#222;">${a.qty}× ${esc(a.nome)}</div>
          ${dettagli}
        </td>
        <td style="padding:10px 0;border-bottom:1px solid #eee;text-align:right;white-space:nowrap;color:#222;vertical-align:top;">${money(a.prezzo)}</td>
      </tr>`;
  }).join('');

  const modalitaLabel = order.modalita === 'consegna' ? 'Consegna a domicilio' : 'Ritiro in sede';
  const rigaIndirizzo = order.modalita === 'consegna' && order.address
    ? `<tr><td style="padding:4px 0;color:#8a8a8a;">Indirizzo</td><td style="padding:4px 0;text-align:right;color:#222;">${esc(order.address)}</td></tr>`
    : '';
  const rigaConsegna = order.speseConsegna
    ? `<tr><td style="padding:8px 0 0;color:#8a8a8a;">Spese di consegna</td><td style="padding:8px 0 0;text-align:right;color:#222;">${money(order.speseConsegna)}</td></tr>`
    : '';

  return `
<!DOCTYPE html>
<html lang="it">
<body style="margin:0;padding:0;background:#f4f1ee;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f1ee;padding:24px 0;">
    <tr><td align="center">
      <table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:18px;overflow:hidden;box-shadow:0 4px 18px rgba(0,0,0,0.08);">

        <tr><td style="background:linear-gradient(135deg,#c1382b,#7a1f16);padding:28px 24px;text-align:center;">
          <img src="${logoUrl}" alt="La Casa di Carta" width="72" height="72" style="border-radius:20px;display:block;margin:0 auto 12px;">
          <div style="color:#ffffff;font-size:20px;font-weight:700;letter-spacing:0.02em;">La Casa di Carta</div>
          <div style="color:rgba(255,255,255,0.85);font-size:13px;margin-top:2px;">Pizzeria · Panineria · Griglieria — Niscemi</div>
        </td></tr>

        <tr><td style="padding:26px 24px 6px;">
          <div style="font-size:17px;font-weight:700;color:#222;">Ciao ${esc(order.name || '')}! 🍕</div>
          <div style="font-size:14px;color:#555;margin-top:6px;line-height:1.5;">Abbiamo ricevuto il tuo ordine numero <strong>#${order.numeroOrdine || ''}</strong>. Ecco il riepilogo:</div>
        </td></tr>

        <tr><td style="padding:10px 24px 0;">
          <table width="100%" cellpadding="0" cellspacing="0">
            ${righeArticoli}
          </table>
        </td></tr>

        <tr><td style="padding:14px 24px 0;">
          <table width="100%" cellpadding="0" cellspacing="0" style="font-size:14px;">
            <tr><td style="padding:4px 0;color:#8a8a8a;">Subtotale</td><td style="padding:4px 0;text-align:right;color:#222;">${money(order.subtotale)}</td></tr>
            ${rigaConsegna}
            <tr><td style="padding:10px 0 0;font-weight:700;color:#222;border-top:1px solid #eee;">Totale</td><td style="padding:10px 0 0;text-align:right;font-weight:700;color:#c1382b;border-top:1px solid #eee;">${money(order.grandTotal)}</td></tr>
          </table>
        </td></tr>

        <tr><td style="padding:20px 24px 0;">
          <table width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;background:#f8f5f2;border-radius:12px;padding:14px;">
            <tr><td colspan="2" style="padding:0 0 8px;font-weight:700;color:#222;">${modalitaLabel}</td></tr>
            <tr><td style="padding:2px 0;color:#8a8a8a;">Orario</td><td style="padding:2px 0;text-align:right;color:#222;">${esc(order.orarioLabel || '')}</td></tr>
            ${rigaIndirizzo}
          </table>
        </td></tr>

        <tr><td style="padding:22px 24px 28px;text-align:center;">
          <div style="font-size:13px;color:#8a8a8a;">Grazie per il tuo ordine — a presto! 🔥</div>
          <div style="font-size:12px;color:#b5b5b5;margin-top:14px;">La Casa di Carta · Via XX Settembre 192, Niscemi CL · +39 327 101 8160</div>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>`;
}

// ---------- Slot di consegna: max 3 ordini ogni 15 minuti ----------
const SLOT_MINUTES = 15;
const MAX_PER_SLOT = 3;
const MIN_DELIVERY_ORDER = 10.00;
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
    setAuthCookie(res, token);
    res.json({ ok: true, profilo: { nome, cognome, email: customer.email, telefono, indirizzo: customer.indirizzo } });
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
    setAuthCookie(res, token);
    res.json({ ok: true, profilo: { nome: customer.nome, cognome: customer.cognome, email: customer.email, telefono: customer.telefono, indirizzo: customer.indirizzo } });
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

// ---------- Endpoint: logout ----------
app.post('/api/auth/logout', (req, res) => {
  clearAuthCookie(res);
  res.json({ ok: true });
});

// ---------- Endpoint: il sito manda qui i nuovi ordini (pagamento a consegna) ----------
async function assignDeliverySlotIfNeeded(order){
  if (order.modalita !== 'consegna') return { ok: true };
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
  const slot = slotLabel(requestedDate);
  if (!isSlotAvailable(dKey, slot)) {
    return {
      ok: false,
      error: 'slot_pieno',
      message: `L'orario delle ${slot} è al completo per le consegne. Scegli un altro orario tra quelli disponibili.`
    };
  }
  reserveSlot(dKey, slot);
  order.slotAssegnato = slot;
  order.orarioLabel = `Alle ${slot}`;
  order.testoStampa = (order.testoStampa || '').replace(/Orario richiesto:.*$/m, `Orario richiesto: Alle ${slot}`);
  return { ok: true };
}

// Prende un ordine già "pronto" (slot assegnato se serve) e lo finalizza:
// numero ordine, storico, stampa in cucina, email. Usata sia dal checkout
// diretto (pagamento a consegna) sia dal webhook Stripe (pagamento online).
async function finalizeOrder(order, customerId){
  order.numeroOrdine = ++orderCounter;
  order.ricevutoAlle = new Date().toISOString();
  orderHistory.unshift(order);
  if (orderHistory.length > MAX_HISTORY) orderHistory.pop();

  if (customerId && ordersCollection) {
    ordersCollection.insertOne({ ...order, customerId }).catch(err => {
      console.error('Errore salvataggio storico ordine:', err);
    });
  }

  broadcastOrder(order);
  sendEmail(ORDER_EMAIL, order.oggettoEmail || 'Nuovo ordine — La Casa di Carta', order.testoStampa);
  if (order.email) {
    sendEmail(order.email, 'Conferma ordine — La Casa di Carta', buildCustomerConfirmationText(order), buildCustomerConfirmationHtml(order));
  }
}

// ---------- Endpoint: richieste di prenotazione tavolo ----------
let reservationCounter = 0;

app.post('/api/reservations', async (req, res) => {
  const { nome, telefono, data, ora, persone, note } = req.body || {};
  if (!nome || !telefono || !data || !ora || !persone) {
    return res.status(400).json({ ok: false, error: 'Compila tutti i campi obbligatori.' });
  }

  reservationCounter++;
  const ricevutoAlle = new Date().toISOString();
  const dataLeggibile = new Date(data + 'T00:00:00').toLocaleDateString('it-IT', { weekday: 'long', day: 'numeric', month: 'long' });

  const sep = '------------------------------';
  let testoStampa = `PRENOTAZIONE TAVOLO — LA CASA DI CARTA\n`;
  testoStampa += `Richiesta #${reservationCounter}\n${sep}\n\n`;
  testoStampa += `Nome: ${nome}\n`;
  testoStampa += `Telefono: ${telefono}\n`;
  testoStampa += `Data: ${dataLeggibile}\n`;
  testoStampa += `Ora: ${ora}\n`;
  testoStampa += `Persone: ${persone}\n`;
  if (note) testoStampa += `Note: ${note}\n`;
  testoStampa += `\n${sep}\nRicevuta il ${new Date(ricevutoAlle).toLocaleString('it-IT')}\n`;

  const reservation = {
    tipo: 'prenotazione',
    numeroPrenotazione: reservationCounter,
    nome, telefono, data, ora, persone, note,
    testoStampa,
    ricevutoAlle
  };

  broadcastOrder(reservation);
  sendEmail(
    ORDER_EMAIL,
    `Nuova prenotazione tavolo — ${nome} (${persone} persone, ${dataLeggibile} ore ${ora})`,
    testoStampa
  );

  res.json({ ok: true });
});

app.post('/api/orders', async (req, res) => {
  const order = req.body;
  if (!order || !order.testoStampa) {
    return res.status(400).json({ ok: false, error: 'Ordine non valido' });
  }

  if (order.modalita === 'consegna' && (order.subtotale || 0) < MIN_DELIVERY_ORDER) {
    return res.status(400).json({
      ok: false,
      error: 'ordine_minimo',
      message: `L'ordine minimo per la consegna a domicilio è di €${MIN_DELIVERY_ORDER.toFixed(2).replace('.', ',')}.`
    });
  }

  const slotResult = await assignDeliverySlotIfNeeded(order);
  if (!slotResult.ok) {
    return res.status(409).json(slotResult);
  }

  order.pagatoOnline = false; // pagamento a consegna/ritiro
  const user = tryGetUserFromToken(req);
  await finalizeOrder(order, user ? user.id : null);

  res.json({ ok: true });
});

// ---------- Endpoint: crea una sessione di pagamento online (Stripe) ----------
app.post('/api/checkout/create-session', async (req, res) => {
  if (!stripe) return res.status(503).json({ ok: false, error: 'Pagamento online non configurato.' });
  const order = req.body;
  if (!order || !order.testoStampa || !order.grandTotal) {
    return res.status(400).json({ ok: false, error: 'Ordine non valido' });
  }

  if (order.modalita === 'consegna' && (order.subtotale || 0) < MIN_DELIVERY_ORDER) {
    return res.status(400).json({
      ok: false,
      error: 'ordine_minimo',
      message: `L'ordine minimo per la consegna a domicilio è di €${MIN_DELIVERY_ORDER.toFixed(2).replace('.', ',')}.`
    });
  }

  // controllo preventivo: se lo slot è già pieno, non ha senso far pagare il cliente
  const now = new Date();
  let requestedDate = now;
  if (order.timing === 'orario' && order.orarioRichiesto) {
    const [h, m] = order.orarioRichiesto.split(':').map(Number);
    requestedDate = new Date(now);
    requestedDate.setHours(h, m, 0, 0);
  } else if (order.timing === '30min') {
    requestedDate = new Date(now.getTime() + 30 * 60000);
  }
  if (order.modalita === 'consegna' && !isSlotAvailable(dateKey(requestedDate), slotLabel(requestedDate))) {
    return res.status(409).json({
      ok: false,
      error: 'slot_pieno',
      message: `L'orario delle ${slotLabel(requestedDate)} è al completo per le consegne. Scegli un altro orario tra quelli disponibili.`
    });
  }

  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'eur',
          product_data: { name: `Ordine La Casa di Carta — ${order.name || 'Cliente'}` },
          unit_amount: Math.round(order.grandTotal * 100)
        },
        quantity: 1
      }],
      customer_email: order.email || undefined,
      success_url: `${SITE_URL}/?pagamento=riuscito`,
      cancel_url: `${SITE_URL}/?pagamento=annullato`
    });

    order.pagamento = 'carta_online';
    order.pagatoOnline = true;
    const user = tryGetUserFromToken(req);
    const pendingData = { order, customerId: user ? user.id : null };

    if (pendingOrdersCollection) {
      await pendingOrdersCollection.insertOne({ _id: session.id, ...pendingData, createdAt: new Date() });
    } else {
      pendingOnlineOrders[session.id] = pendingData; // riserva se il database non è raggiungibile
    }
    console.log('Sessione di pagamento creata:', session.id);

    res.json({ ok: true, url: session.url });
  } catch (err) {
    console.error('Errore creazione sessione Stripe:', err);
    res.status(500).json({ ok: false, error: 'Errore nella creazione del pagamento. Riprova.' });
  }
});

// ---------- Endpoint: Stripe avvisa qui quando un pagamento va a buon fine ----------
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  console.log('Webhook Stripe ricevuto');
  if (!stripe || !STRIPE_WEBHOOK_SECRET) return res.status(503).send('Webhook non configurato');
  let event;
  try {
    const signature = req.headers['stripe-signature'];
    event = stripe.webhooks.constructEvent(req.body, signature, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Firma webhook Stripe non valida:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  console.log('Evento Stripe valido:', event.type);

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    let pending = null;
    if (pendingOrdersCollection) {
      pending = await pendingOrdersCollection.findOne({ _id: session.id });
    } else {
      pending = pendingOnlineOrders[session.id];
    }
    if (pending) {
      const { order, customerId } = pending;
      const slotResult = await assignDeliverySlotIfNeeded(order);
      if (!slotResult.ok) {
        console.error('Slot pieno al momento della conferma pagamento — ordine comunque accettato:', slotResult.message);
      }
      await finalizeOrder(order, customerId);
      console.log('Ordine finalizzato dopo pagamento online, numero:', order.numeroOrdine);
      if (pendingOrdersCollection) {
        await pendingOrdersCollection.deleteOne({ _id: session.id });
      } else {
        delete pendingOnlineOrders[session.id];
      }
    } else {
      console.error('Ricevuta conferma di pagamento per una sessione sconosciuta:', session.id);
    }
  }

  res.json({ received: true });
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
