// ============================================
// SERVER ORDINI — La Casa di Carta
// Riceve gli ordini dal sito, li gira in tempo reale
// al pannello di stampa, e manda l'email alla pizzeria.
// ============================================

// IMPORTANTISSIMO: il server (Render) gira in orario UTC, non italiano.
// Senza questa riga, tutti i calcoli di orario (slot, apertura/chiusura)
// sarebbero sfasati di 1-2 ore rispetto all'ora reale in Italia.
process.env.TZ = 'Europe/Rome';

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');

const app = express();
app.set('trust proxy', true); // Render fa da proxy: serve per leggere il vero IP del cliente, non quello di Render

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
    express.json({ limit: '3mb' })(req, res, next);
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
// cambia ogni volta che il server si riavvia: serve per far capire alle app di posta
// (soprattutto Mail su iPhone) che il logo è "nuovo" quando lo aggiorniamo
const ASSET_VERSION = Date.now();
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
let soldOutCollection = null;
let soldOutCache = new Set();
let blacklistCollection = null;
let blockedPhonesCache = new Set(); // riserva in memoria, usata se il database non è raggiungibile
let ordersPaused = false; // interruttore manuale: se true, il sito rifiuta ogni nuovo ordine
// calendario deciso dal titolare dal pannello: giorni di chiusura in più e martedì eccezionalmente aperti
let calendario = { chiusi: [], aperti: [] }; // date "YYYY-MM-DD"
let settingsCollection = null;
let comandeCollection = null;   // comande dell'app staff (sala, banco, telefono)
let comandeMemoria = {};        // riserva in memoria se il database non è disponibile

// prezzi di partenza di ogni voce del menu (chiave uguale a quella usata per gli esauriti);
// quando il titolare modifica un prezzo dal pannello, il nuovo valore viene salvato in
// priceOverridesCache e ha sempre la precedenza su questi valori di base.
const DEFAULT_PRICES = {"Pizza|Faccia Di Vecchia": 3, "Pizza|Rossa": 4, "Pizza|Biancaneve": 5, "Pizza|Marinara": 4.5, "Pizza|Margherita": 5, "Pizza|Patapizza": 6.5, "Pizza|Bufala": 7, "Pizza|Diavola": 6, "Pizza|Pizza Regina": 7, "Pizza|Tonno & Cipolla": 7, "Pizza|Napoli": 6.5, "Pizza|Oslo": 6.5, "Pizza|Norma": 6.5, "Pizza|Berlino": 7, "Pizza|Tropea": 8.5, "Pizza|Helsinki": 9, "Pizza|Sfiziosa": 9, "Pizza|Nairobi": 9, "Pizza|Mosca": 9, "Pizza|Rio": 8.5, "Pizza|Tutti I Gusti": 9, "Pizza|Ripiegata": 8.5, "Pizza|4 Formaggi": 8, "Pizza|007": 8, "Pizza|La Casa Di Carta": 8.5, "Pizza|Parmigiana": 8, "Pizza|4 Stagioni": 8, "Pizza|Bella Ciao": 8, "Pizza|Marsiglia": 8.5, "Pizza|Ai Porcini": 9, "Pizza|Vegetariana": 8, "Pizza|Pizza Kebab": 9, "Pizza|Gustosa": 9, "Pizza|Tokio": 8.5, "Pizza|Bogotà": 11, "Pizza|Frutti Di Mare": 11, "Pizza|Cincinnati": 10, "Pizza|Suprema": 13, "Pizza|Denver": 8, "Pizza|Capricciosa": 8, "Pizza Dolce|Nutella": 5, "Pizza Dolce|Kinder Bueno": 7, "Pizza Dolce|Dubai": 7, "Panini|Panino Patatine, Wurstel": 3, "Panini|Panino con Patatine": 2.5, "Panini|Panino Crocchette di Patate & Patatine": 3, "Panini|Panino Patatine, Wurstel in Salsa Rosa": 3.5, "Panini|Panino Pollo al Curry & Patatine": 5, "Panini|Panino Pollo ai Funghi & Patatine": 5.5, "Panini|Panino Pollo Impanato & Patatine": 5, "Panini|Panino Pollo Messicano & Patatine": 5, "Panini|Panino Pollo al Barbecue & Patatine": 5, "Panini|Panino Petto di Pollo alla Griglia & Patatine": 5, "Panini|Panino Arrosto di Pollo & Patatine": 5, "Panini|Panino Petto di Pollo Sfilettato & Patatine": 5, "Panini|Panino Porchettata & Patatine": 4, "Panini|Panino Salame Piccante e Mozzarella & Patatine": 4, "Panini|Panino Salame Piccante e Svizzero & Patatine": 4, "Panini|Panino Bella Ciao & Patatine": 5.5, "Panini|Panino 4 Formaggi & Patatine": 4.5, "Panini|Panino Prosciutto Mozzarella & Patatine": 4, "Panini|Cocktail Di Tonno & Patatine": 5, "Panini|Panino Kebab & Patatine": 5, "Panini|Panino Polpette di Cavallo & Patatine": 6, "Panini|Panino Cavallo & Patatine": 6, "Panini|Panino Salsiccia & Patatine": 5, "Panini|Panino in Cocktail di Gamberi in Salsa Rosa & Patatine": 6.5, "Panini|Hamburger di Scottona & Patatine": 6, "Panini|Hamburger di Angus & Patatine": 6, "Panini|Panino Porchetta Artigianale e Patatine": 6, "Panini|Panino con Salsiccia di Cavallo & Patatine": 6, "Hamburger|Brooklyn": 5, "Hamburger|Bronx": 8, "Hamburger|Spicy": 8, "Hamburger|Manathan": 9, "Hamburger|Queens": 5, "Focacce|Focaccia Vuota Da Condire": 3, "Focacce|Casareccia": 4.5, "Focacce|Focaccia Prosciutto": 6.5, "Focacce|Focaccia Caprese": 6.5, "Focacce|Focaccia Del Pirata": 6.5, "Focacce|Focaccia Mista": 7, "Focacce|Deliziosa": 7, "Focacce|Focaccia 4 Formaggi": 7.5, "Focacce|Bella Ciao": 8, "Focacce|Focaccia Nairobi": 9, "Fritture|Vaschetta Piccola — Patatine": 2, "Fritture|Vaschetta Media — Patatine": 3, "Fritture|Patatine con Buccia": 3, "Fritture|Vaschetta Piccola — 4 Würstel & Patatine": 2, "Fritture|Vaschetta — 8 Würstel": 2, "Fritture|Vaschetta — Crocchette di Patate": 2, "Fritture|Vaschetta di Kebab": 3, "Fritture|Anelli di Cipolla": 3, "Fritture|Panzerotti Fritti Mignon Pomodoro e Mozzarella": 3, "Fritture|Mozzarelline Impanate": 3.5, "Fritture|Bocconcini Pollo Amadori Impanato Piccante": 3.5, "Fritture|Arancini Mignon al Ragù": 3, "Fritture|Nuggets 10 Pezzi": 5, "Bevande|Gassosa": 1, "Bevande|Acqua Naturale Piccola": 1, "Bevande|Acqua Frizzante": 1, "Bevande|Coca Cola 33": 2, "Bevande|Coca Cola Zero": 2, "Bevande|Birra Moretti": 2, "Bevande|Birra Peroni": 2, "Bevande|Coca Cola Vetro cl 33": 2.5, "Bevande|Estathe Pesca": 2.5, "Bevande|Estathe Limone": 2.5, "Bevande|Nastro Azzurro": 3, "Bevande|Ceres": 3.5, "Bevande|Coca Cola Bottiglia Grande": 4, "Bevande|Birra Messina Grande": 5, "Bevande|Birra Nastro Azzurro Grande": 5, "Bevande|Peroni Chill Lemon": 2.5, "Extra|Bustina Maionese": 0.25, "Extra|Bustina Ketchup": 0.25, "EXTRA_PIZZA|Extra Mozzarella": 1.5, "EXTRA_PIZZA|Scaglie di Grana Padano DOP": 1, "EXTRA_PIZZA|Patatine": 1.5, "EXTRA_PIZZA|Gorgonzola": 1, "EXTRA_PIZZA|Formaggio Svizzero": 0.5, "EXTRA_PIZZA|Prosciutto Crudo Ferrarini": 1.5, "EXTRA_PIZZA|Olive": 0.5, "EXTRA_PIZZA|Rucola": 0.5, "EXTRA_PIZZA|Ciliegino": 0.5, "EXTRA_PIZZA|Piselli": 0.5, "EXTRA_PIZZA|Funghi": 1, "EXTRA_PIZZA|Speck": 1, "EXTRA_PIZZA|Funghi Porcini": 2.5, "EXTRA_PIZZA|Lattuga": 0.5, "EXTRA_PIZZA|Spinaci": 0.5, "EXTRA_PIZZA|Cipolla": 0.5, "EXTRA_PIZZA|Carciofi in Spicchi": 1, "EXTRA_PIZZA|Prosciutto Cotto": 1, "EXTRA_PIZZA|Uovo": 0.5, "EXTRA_PIZZA|Wurstel": 0.5, "EXTRA_PIZZA|Granella di Pistacchio": 2, "EXTRA_PIZZA|Crocchette Patate": 1, "EXTRA_PIZZA|Crema di Pistacchio": 2, "EXTRA_PIZZA|Acciughe": 1, "EXTRA_PIZZA|Tonno": 1.5, "EXTRA_PIZZA|Salame Piccante": 1, "EXTRA_PIZZA|Bresaola": 2.5, "EXTRA_PIZZA|Polpette di Cavallo": 3, "EXTRA_PIZZA|Bacon": 1, "EXTRA_PIZZA|Mozzarella di Bufala": 2, "EXTRA_PIZZA|Salmone": 2.5, "EXTRA_PIZZA|Patate della Nonna": 1, "EXTRA_PIZZA|Salsiccia di Maiale": 1.5, "EXTRA_PIZZA|Fettina di Pollo alla Griglia": 3.5, "EXTRA_PIZZA|Pollo Sfilettato": 3.5, "EXTRA_PIZZA|Pollo al Curry": 3.5, "EXTRA_PIZZA|Fettina di Cavallo": 4, "EXTRA_PIZZA|Melanzana Fritta": 1, "EXTRA_PIZZA|Stracciatella di Bufala": 2, "EXTRA_PIZZA|Capuliato": 0.5, "EXTRA_PIZZA|Kebab": 3.5, "EXTRA_PIZZA|Pollo Impanato": 4, "EXTRA_PIZZA|Cipolla Croccante": 0.5, "EXTRA_PANINO|Lattuga": 0.5, "EXTRA_PANINO|Ciliegino": 0.5, "EXTRA_PANINO|Cipolla": 0.5, "EXTRA_PANINO|Mozzarella": 0.5, "EXTRA_PANINO|Gorgonzola": 0.5, "EXTRA_PANINO|Würstel": 0.5, "EXTRA_PANINO|Grana Padano DOP": 0.5, "EXTRA_PANINO|Formaggio Svizzero": 0.5, "EXTRA_PANINO|Prosciutto Crudo": 1.5, "EXTRA_PANINO|Speck": 0.5, "EXTRA_PANINO|Prosciutto Cotto": 1, "EXTRA_PANINO|Crocchette di Patate": 1, "EXTRA_PANINO|Salame Piccante": 1, "EXTRA_PANINO|Funghi Freschi": 1, "EXTRA_PANINO|Mozzarella di Bufala": 2, "EXTRA_PANINO|Granella di Pistacchio": 1, "EXTRA_PANINO|Crema di Pistacchio": 1, "EXTRA_PANINO|Würstel in Salsa Rosa": 1.5, "EXTRA_PANINO|Bresaola": 2, "EXTRA_PANINO|Rucola": 0.5, "EXTRA_PANINO|Salmone 50g": 3, "EXTRA_PANINO|Funghi Piccanti": 1, "EXTRA_PANINO|Cipolla Croccante": 0.5};
let priceOverridesCollection = null;

function getCurrentPrice(chiave){
  if (priceOverridesCache[chiave] !== undefined) return priceOverridesCache[chiave];
  if (DEFAULT_PRICES[chiave] !== undefined) return DEFAULT_PRICES[chiave];
  return null;
}

// Foto dei singoli piatti caricate dal titolare dal pannello di stampa.
// Salvate come immagine (base64) dentro MongoDB, chiave uguale a quella usata per prezzi/esauriti.
let productPhotosCache = {}; // chiave -> { data: "data:image/jpeg;base64,...", updatedAt }
let productPhotosCollection = null;

// Piatti nuovi aggiunti dal titolare dal pannello di stampa (in più rispetto al menu di base).
let customMenuItemsCache = []; // [{ cat, nome, descrizione, prezzo }]
let customMenuItemsCollection = null;


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
    soldOutCollection = db.collection('soldOutItems');
    blacklistCollection = db.collection('blockedPhones');
    await customersCollection.createIndex({ email: 1 }, { unique: true });
    await ordersCollection.createIndex({ customerId: 1, ricevutoAlle: -1 });
    await pendingOrdersCollection.createIndex({ createdAt: 1 }, { expireAfterSeconds: 60 * 60 * 24 });
    const soldOutDocs = await soldOutCollection.find({}).toArray();
    soldOutCache = new Set(soldOutDocs.map(d => d._id));
    const blockedDocs = await blacklistCollection.find({}).toArray();
    blockedPhonesCache = new Set(blockedDocs.map(d => d._id));
    priceOverridesCollection = db.collection('priceOverrides');
    const priceDocs = await priceOverridesCollection.find({}).toArray();
    priceOverridesCache = {};
    priceDocs.forEach(d => { priceOverridesCache[d._id] = d.prezzo; });
    settingsCollection = db.collection('settings');
    const pausedDoc = await settingsCollection.findOne({ _id: 'ordersPaused' });
    ordersPaused = !!(pausedDoc && pausedDoc.value);
    const calDoc = await settingsCollection.findOne({ _id: 'calendario' });
    if (calDoc && calDoc.value) calendario = { chiusi: calDoc.value.chiusi || [], aperti: calDoc.value.aperti || [] };
    productPhotosCollection = db.collection('productPhotos');
    const photoDocs = await productPhotosCollection.find({}, { projection: { data: 0 } }).toArray();
    // all'avvio carichiamo solo l'elenco delle chiavi con foto (leggero); l'immagine vera si scarica
    // una alla volta quando serve, tramite /api/product-photos/img/:chiave
    photoDocs.forEach(d => { productPhotosCache[d._id] = true; });
    comandeCollection = db.collection('comandeStaff');
    await comandeCollection.createIndex({ stato: 1, aggiornataAlle: -1 });
    customMenuItemsCollection = db.collection('customMenuItems');
    customMenuItemsCache = await customMenuItemsCollection.find({}).toArray();
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

function buildOrderReadyText(order) {
  const azione = order.modalita === 'consegna'
    ? 'Il tuo ordine è pronto ed è in partenza per la consegna! 🛵'
    : 'Il tuo ordine è pronto per il ritiro! 🍕';
  const link = order.modalita === 'consegna'
    ? `\n\nSegui la consegna in tempo reale: ${SITE_URL}/traccia.html?ordine=${order.numeroOrdine}`
    : '';
  return `Ciao ${order.name || ''},\n\n${azione}\n\nOrdine #${order.numeroOrdine}${link}\n\nA presto!\nLa Casa di Carta`;
}

function buildOrderReadyHtml(order) {
  const logoUrl = `${SITE_URL}/icon-512.png?v=${ASSET_VERSION}`;
  const azione = order.modalita === 'consegna'
    ? 'Il tuo ordine è pronto ed è in partenza per la consegna! 🛵'
    : 'Il tuo ordine è pronto per il ritiro! 🍕';
  return `
<!DOCTYPE html>
<html lang="it">
<body style="margin:0;padding:0;background:#f4f1ee;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f1ee;padding:24px 0;">
    <tr><td align="center">
      <table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:18px;overflow:hidden;box-shadow:0 4px 18px rgba(0,0,0,0.08);">
        <tr><td style="background:linear-gradient(135deg,#1a9c4a,#127034);padding:28px 24px;text-align:center;">
          <img src="${logoUrl}" alt="La Casa di Carta" width="72" height="72" style="border-radius:20px;display:block;margin:0 auto 12px;">
          <div style="color:#ffffff;font-size:20px;font-weight:700;letter-spacing:0.02em;">La Casa di Carta</div>
        </td></tr>
        <tr><td style="padding:30px 24px;text-align:center;">
          <div style="font-size:19px;font-weight:700;color:#222;margin-bottom:10px;">Ciao ${esc(order.name || '')}!</div>
          <div style="font-size:17px;color:#333;line-height:1.5;">${azione}</div>
          <div style="font-size:14px;color:#8a8a8a;margin-top:16px;">Ordine #${order.numeroOrdine}</div>
          ${order.modalita === 'consegna' ? `
          <a href="${SITE_URL}/traccia.html?ordine=${order.numeroOrdine}" style="display:inline-block;margin-top:20px;background:linear-gradient(135deg,#1a9c4a,#127034);color:#fff;text-decoration:none;font-weight:700;font-size:15px;padding:13px 28px;border-radius:999px;">🛵 Segui la consegna in tempo reale</a>
          ` : ''}
        </td></tr>
        <tr><td style="padding:0 24px 26px;text-align:center;">
          <div style="font-size:13px;color:#8a8a8a;">La Casa di Carta · Via XX Settembre 192, Niscemi CL · +39 327 101 8160</div>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`;
}

function esc(s){
  return String(s || '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
}
function money(n){ return '€' + (Number(n) || 0).toFixed(2).replace('.', ','); }

function buildOwnerOrderHtml(order) {
  const logoUrl = `${SITE_URL}/icon-512.png?v=${ASSET_VERSION}`;

  const righeArticoli = (order.articoli || []).map(a => {
    const dettagli = (a.dettagli || []).map(d => {
      const isSenza = /^Senza:/i.test(d);
      const stile = isSenza ? 'font-size:12px;color:#c1382b;margin-top:2px;font-weight:700;text-decoration:underline;' : 'font-size:12px;color:#8a8a8a;margin-top:2px;';
      return `<div style="${stile}">${esc(d)}</div>`;
    }).join('');
    return `
      <tr>
        <td style="padding:10px 0;border-bottom:1px solid #eee;vertical-align:top;">
          <div style="font-weight:600;color:#222;">${a.qty}× ${esc(a.nome)}</div>
          ${dettagli}
        </td>
        <td style="padding:10px 0;border-bottom:1px solid #eee;text-align:right;white-space:nowrap;color:#222;vertical-align:top;">${money(a.prezzo)}</td>
      </tr>`;
  }).join('');

  const modalitaLabel = order.modalita === 'consegna' ? '🛵 Consegna a domicilio' : '🏠 Ritiro in sede';
  const rigaIndirizzo = order.modalita === 'consegna' && order.address
    ? `<tr><td style="padding:4px 0;color:#8a8a8a;">Indirizzo</td><td style="padding:4px 0;text-align:right;color:#222;">${esc(order.address)}</td></tr>`
    : '';
  const rigaConsegna = order.speseConsegna
    ? `<tr><td style="padding:8px 0 0;color:#8a8a8a;">Spese di consegna</td><td style="padding:8px 0 0;text-align:right;color:#222;">${money(order.speseConsegna)}</td></tr>`
    : '';
  const rigaSconto = order.scontoPrimoOrdine
    ? `<tr><td style="padding:4px 0;color:#1a9c4a;">🎉 Sconto primo ordine</td><td style="padding:4px 0;text-align:right;color:#1a9c4a;font-weight:700;">-${money(order.scontoPrimoOrdine)}</td></tr>`
    : '';
  const pagamentoLabel = order.pagatoOnline ? '✅ Pagato online' : '⏳ Da riscuotere alla consegna/ritiro';
  const rigaPagamento = `<tr><td style="padding:2px 0;color:#8a8a8a;">Pagamento</td><td style="padding:2px 0;text-align:right;color:${order.pagatoOnline ? '#1a9c4a' : '#c1382b'};font-weight:700;">${pagamentoLabel}</td></tr>`;
  const rigaTelefono = order.phone
    ? `<tr><td style="padding:2px 0;color:#8a8a8a;">Telefono</td><td style="padding:2px 0;text-align:right;color:#222;">${esc(order.phone)}</td></tr>`
    : '';

  return `
<!DOCTYPE html>
<html lang="it">
<body style="margin:0;padding:0;background:#f4f1ee;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f1ee;padding:24px 0;">
    <tr><td align="center">
      <table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:18px;overflow:hidden;box-shadow:0 4px 18px rgba(0,0,0,0.08);">

        <tr><td style="background:linear-gradient(135deg,#c1382b,#7a1f16);padding:28px 24px;text-align:center;">
          <img src="${logoUrl}" alt="La Casa di Carta" width="64" height="64" style="border-radius:18px;display:block;margin:0 auto 10px;">
          <div style="color:#ffffff;font-size:20px;font-weight:700;letter-spacing:0.02em;">🔥 Nuovo ordine ricevuto!</div>
          <div style="color:rgba(255,255,255,0.9);font-size:15px;margin-top:4px;font-weight:700;">Ordine #${order.numeroOrdine || ''}</div>
        </td></tr>

        <tr><td style="padding:22px 24px 6px;">
          <div style="font-size:17px;font-weight:700;color:#222;">${esc(order.name || order.nome || 'Cliente')}</div>
          <div style="font-size:14px;color:#555;margin-top:2px;">${modalitaLabel} · ${esc(order.orarioLabel || '')}</div>
        </td></tr>

        <tr><td style="padding:10px 24px 0;">
          <table width="100%" cellpadding="0" cellspacing="0">
            ${righeArticoli}
          </table>
        </td></tr>

        <tr><td style="padding:14px 24px 0;">
          <table width="100%" cellpadding="0" cellspacing="0" style="font-size:14px;">
            <tr><td style="padding:4px 0;color:#8a8a8a;">Subtotale</td><td style="padding:4px 0;text-align:right;color:#222;">${money(order.subtotaleBase != null ? order.subtotaleBase : order.subtotale)}</td></tr>
            ${rigaSconto}
            ${rigaConsegna}
            <tr><td style="padding:10px 0 0;font-weight:700;color:#222;border-top:1px solid #eee;">Totale</td><td style="padding:10px 0 0;text-align:right;font-weight:700;color:#c1382b;border-top:1px solid #eee;">${money(order.grandTotal)}</td></tr>
          </table>
        </td></tr>

        <tr><td style="padding:20px 24px 0;">
          <table width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;background:#f8f5f2;border-radius:12px;padding:14px;">
            ${rigaTelefono}
            ${rigaIndirizzo}
            ${rigaPagamento}
          </table>
        </td></tr>

        <tr><td style="padding:22px 24px 28px;text-align:center;">
          <div style="font-size:12px;color:#b5b5b5;">La Casa di Carta · Via XX Settembre 192, Niscemi CL · +39 327 101 8160</div>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>`;
}

function buildCustomerConfirmationHtml(order) {
  const logoUrl = `${SITE_URL}/icon-512.png?v=${ASSET_VERSION}`;

  const righeArticoli = (order.articoli || []).map(a => {
    const dettagli = (a.dettagli || []).map(d => {
      const isSenza = /^Senza:/i.test(d);
      const stile = isSenza ? 'font-size:12px;color:#c1382b;margin-top:2px;font-weight:700;text-decoration:underline;' : 'font-size:12px;color:#8a8a8a;margin-top:2px;';
      return `<div style="${stile}">${esc(d)}</div>`;
    }).join('');
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
  const rigaSconto = order.scontoPrimoOrdine
    ? `<tr><td style="padding:4px 0;color:#1a9c4a;">🎉 Sconto primo ordine</td><td style="padding:4px 0;text-align:right;color:#1a9c4a;font-weight:700;">-${money(order.scontoPrimoOrdine)}</td></tr>`
    : '';
  const pagamentoLabel = order.pagatoOnline
    ? '✅ Pagato online'
    : (order.pagamento === 'contanti' ? 'Contanti alla consegna/ritiro' : 'Bancomat/Carta alla consegna/ritiro');
  const rigaPagamento = `<tr><td style="padding:2px 0;color:#8a8a8a;">Pagamento</td><td style="padding:2px 0;text-align:right;color:${order.pagatoOnline ? '#1a9c4a' : '#222'};font-weight:${order.pagatoOnline ? '700' : '400'};">${pagamentoLabel}</td></tr>`;

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
            <tr><td style="padding:4px 0;color:#8a8a8a;">Subtotale</td><td style="padding:4px 0;text-align:right;color:#222;">${money(order.subtotaleBase != null ? order.subtotaleBase : order.subtotale)}</td></tr>
            ${rigaSconto}
            ${rigaConsegna}
            <tr><td style="padding:10px 0 0;font-weight:700;color:#222;border-top:1px solid #eee;">Totale</td><td style="padding:10px 0 0;text-align:right;font-weight:700;color:#c1382b;border-top:1px solid #eee;">${money(order.grandTotal)}</td></tr>
          </table>
        </td></tr>

        <tr><td style="padding:20px 24px 0;">
          <table width="100%" cellpadding="0" cellspacing="0" style="font-size:13px;background:#f8f5f2;border-radius:12px;padding:14px;">
            <tr><td colspan="2" style="padding:0 0 8px;font-weight:700;color:#222;">${modalitaLabel}</td></tr>
            <tr><td style="padding:2px 0;color:#8a8a8a;">Orario</td><td style="padding:2px 0;text-align:right;color:#222;">${esc(order.orarioLabel || '')}</td></tr>
            ${rigaIndirizzo}
            ${rigaPagamento}
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
const CLOSED_WEEKDAY = 2; // 0=domenica, 1=lunedì, 2=martedì...
const MAX_DAYS_AHEAD = 3; // si può ordinare/prenotare da oggi fino a 3 giorni dopo
const ASAP_DISABLED_WEEKDAYS_CONSEGNA = [0, 6]; // 0=domenica, 6=sabato: niente "il prima possibile" per le consegne

// catalogo di categorie e nomi articoli (usato dal pannello di stampa per segnare i prodotti esauriti)
const MENU_CATALOG = [{"cat": "Pizza", "items": ["Faccia Di Vecchia", "Rossa", "Biancaneve", "Marinara", "Margherita", "Patapizza", "Bufala", "Diavola", "Pizza Regina", "Tonno & Cipolla", "Napoli", "Oslo", "Norma", "Berlino", "Tropea", "Helsinki", "Sfiziosa", "Nairobi", "Mosca", "Rio", "Tutti I Gusti", "Ripiegata", "4 Formaggi", "007", "La Casa Di Carta", "Parmigiana", "4 Stagioni", "Bella Ciao", "Marsiglia", "Ai Porcini", "Vegetariana", "Pizza Kebab", "Gustosa", "Tokio", "Bogotà", "Frutti Di Mare", "Cincinnati", "Suprema", "Denver", "Capricciosa"], "keyPrefix": "Pizza"}, {"cat": "Pizza Dolce", "items": ["Nutella", "Kinder Bueno", "Dubai"], "keyPrefix": "Pizza Dolce"}, {"cat": "Panini", "items": ["Panino Patatine, Wurstel", "Panino con Patatine", "Panino Crocchette di Patate & Patatine", "Panino Patatine, Wurstel in Salsa Rosa", "Panino Pollo al Curry & Patatine", "Panino Pollo ai Funghi & Patatine", "Panino Pollo Impanato & Patatine", "Panino Pollo Messicano & Patatine", "Panino Pollo al Barbecue & Patatine", "Panino Petto di Pollo alla Griglia & Patatine", "Panino Arrosto di Pollo & Patatine", "Panino Petto di Pollo Sfilettato & Patatine", "Panino Porchettata & Patatine", "Panino Salame Piccante e Mozzarella & Patatine", "Panino Salame Piccante e Svizzero & Patatine", "Panino Bella Ciao & Patatine", "Panino 4 Formaggi & Patatine", "Panino Prosciutto Mozzarella & Patatine", "Cocktail Di Tonno & Patatine", "Panino Kebab & Patatine", "Panino Polpette di Cavallo & Patatine", "Panino Cavallo & Patatine", "Panino Salsiccia & Patatine", "Panino in Cocktail di Gamberi in Salsa Rosa & Patatine", "Hamburger di Scottona & Patatine", "Hamburger di Angus & Patatine", "Panino Porchetta Artigianale e Patatine", "Panino con Salsiccia di Cavallo & Patatine"], "keyPrefix": "Panini"}, {"cat": "Hamburger", "items": ["Brooklyn", "Bronx", "Spicy", "Manathan", "Queens"], "keyPrefix": "Hamburger"}, {"cat": "Focacce", "items": ["Focaccia Vuota Da Condire", "Casareccia", "Focaccia Prosciutto", "Focaccia Caprese", "Focaccia Del Pirata", "Focaccia Mista", "Deliziosa", "Focaccia 4 Formaggi", "Bella Ciao", "Focaccia Nairobi"], "keyPrefix": "Focacce"}, {"cat": "Fritture", "items": ["Vaschetta Piccola — Patatine", "Vaschetta Media — Patatine", "Patatine con Buccia", "Vaschetta Piccola — 4 Würstel & Patatine", "Vaschetta — 8 Würstel", "Vaschetta — Crocchette di Patate", "Vaschetta di Kebab", "Anelli di Cipolla", "Panzerotti Fritti Mignon Pomodoro e Mozzarella", "Mozzarelline Impanate", "Bocconcini Pollo Amadori Impanato Piccante", "Arancini Mignon al Ragù", "Nuggets 10 Pezzi"], "keyPrefix": "Fritture"}, {"cat": "Bevande", "items": ["Gassosa", "Acqua Naturale Piccola", "Acqua Frizzante", "Coca Cola 33", "Coca Cola Zero", "Birra Moretti", "Birra Peroni", "Coca Cola Vetro cl 33", "Estathe Pesca", "Estathe Limone", "Nastro Azzurro", "Ceres", "Coca Cola Bottiglia Grande", "Birra Messina Grande", "Birra Nastro Azzurro Grande", "Peroni Chill Lemon"], "keyPrefix": "Bevande"}, {"cat": "Extra", "items": ["Bustina Maionese", "Bustina Ketchup"], "keyPrefix": "Extra"}, {"cat": "🧀 Extra ingredienti — Pizza/Focacce", "items": ["Extra Mozzarella", "Scaglie di Grana Padano DOP", "Patatine", "Gorgonzola", "Formaggio Svizzero", "Prosciutto Crudo Ferrarini", "Olive", "Rucola", "Ciliegino", "Piselli", "Funghi", "Speck", "Funghi Porcini", "Lattuga", "Spinaci", "Cipolla", "Carciofi in Spicchi", "Prosciutto Cotto", "Uovo", "Wurstel", "Granella di Pistacchio", "Crocchette Patate", "Crema di Pistacchio", "Acciughe", "Tonno", "Salame Piccante", "Bresaola", "Polpette di Cavallo", "Bacon", "Mozzarella di Bufala", "Salmone", "Patate della Nonna", "Salsiccia di Maiale", "Fettina di Pollo alla Griglia", "Pollo Sfilettato", "Pollo al Curry", "Fettina di Cavallo", "Melanzana Fritta", "Stracciatella di Bufala", "Capuliato", "Kebab", "Pollo Impanato", "Cipolla Croccante"], "keyPrefix": "EXTRA_PIZZA"}, {"cat": "🧀 Extra ingredienti — Panini/Hamburger/Fritture", "items": ["Lattuga", "Ciliegino", "Cipolla", "Mozzarella", "Gorgonzola", "Würstel", "Grana Padano DOP", "Formaggio Svizzero", "Prosciutto Crudo", "Speck", "Prosciutto Cotto", "Crocchette di Patate", "Salame Piccante", "Funghi Freschi", "Mozzarella di Bufala", "Granella di Pistacchio", "Crema di Pistacchio", "Würstel in Salsa Rosa", "Bresaola", "Rucola", "Salmone 50g", "Funghi Piccanti", "Cipolla Croccante"], "keyPrefix": "EXTRA_PANINO"}];

// conteggio in memoria: { "2026-09-22|19:15": 2, ... } — si azzera se il server si riavvia
let slotCounts = {};

// normalizza un numero di telefono per il confronto (toglie spazi, trattini, prefisso +39/0039)
function normalizePhone(phone){
  if(!phone) return '';
  let p = String(phone).replace(/[\s\-().]/g, '');
  p = p.replace(/^\+39/, '').replace(/^0039/, '');
  return p;
}

// normalizza un indirizzo di consegna per un confronto affidabile (minuscolo, spazi ridotti,
// niente punteggiatura): serve a riconoscere lo stesso indirizzo anche scritto in modo leggermente diverso
function normalizeAddress(address){
  if(!address) return '';
  return String(address)
    .toLowerCase()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '') // toglie gli accenti
    .replace(/[.,]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

const SCONTO_PRIMO_ORDINE = 0.10; // 10%, solo sui piatti (mai sulle spese di consegna)

async function isFirstOrderForPhone(phone, address){
  if(!ordersCollection) return false;
  const normPhone = normalizePhone(phone);
  const normAddress = normalizeAddress(address);
  if(!normPhone) return false;
  try{
    // niente sconto se questo numero HA GIA' ordinato, oppure se questo indirizzo di consegna
    // è già comparso in un ordine passato (anche con un numero di telefono diverso)
    const query = normAddress
      ? { $or: [{ phoneNormalized: normPhone }, { addressNormalized: normAddress }] }
      : { phoneNormalized: normPhone };
    const esistente = await ordersCollection.findOne(query);
    return !esistente;
  }catch(err){
    console.error('Errore controllo primo ordine:', err);
    return false; // in caso di dubbio, niente sconto: evitiamo di regalarlo per un errore tecnico
  }
}

function round2(n){ return Math.round(n * 100) / 100; }

// ---------- Zona di consegna: prezzo in base alla distanza dalla pizzeria ----------
// Fino a 2,5 km (tutto il paese) spese normali; da 2,5 a 8 km (contrade/campagna) +3€;
// oltre 8 km niente consegna. Distanza calcolata "in linea d'aria" dalla pizzeria.
const PIZZERIA_POS = { lat: 37.1484812, lng: 14.3868172 }; // Via XX Settembre 192, Niscemi
const SPESE_CONSEGNA_BASE = 1.50;
const RAGGIO_PAESE_KM = 2.5;
const SOVRAPPREZZO_FUORI_PAESE = 3.00;
const RAGGIO_MAX_KM = 8;

function distanzaKm(a, b){
  const R = 6371;
  const toRad = x => x * Math.PI / 180;
  const dLat = toRad(b.lat - a.lat);
  const dLng = toRad(b.lng - a.lng);
  const h = Math.sin(dLat/2) ** 2 + Math.cos(toRad(a.lat)) * Math.cos(toRad(b.lat)) * Math.sin(dLng/2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
}

// trova le coordinate di un indirizzo (solo nella zona di Niscemi), con cache in memoria
const geocodeCache = new Map();
async function geocodeAddress(address){
  const key = normalizeAddress(address);
  if (!key) return null;
  if (geocodeCache.has(key)) return geocodeCache.get(key);
  const q = /niscemi/i.test(address) ? address : `${address}, Niscemi`;
  const url = 'https://nominatim.openstreetmap.org/search?' + new URLSearchParams({
    q, format: 'json', limit: '1', countrycodes: 'it',
    viewbox: '14.237,37.268,14.537,37.028', bounded: '1' // ~12 km attorno a Niscemi
  });
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5000);
    const r = await fetch(url, {
      headers: { 'User-Agent': 'LaCasaDiCarta-Ordini/1.0 (ordini.pizzerialacasadicarta.it)', 'Accept-Language': 'it' },
      signal: ctrl.signal
    });
    clearTimeout(timer);
    if (!r.ok) return null; // errore temporaneo: non lo salviamo in cache
    const arr = await r.json();
    const pos = Array.isArray(arr) && arr[0] ? { lat: parseFloat(arr[0].lat), lng: parseFloat(arr[0].lon) } : null;
    geocodeCache.set(key, pos);
    return pos;
  } catch (err) {
    console.error('Errore ricerca indirizzo:', err.message);
    return null;
  }
}

// calcola spese e zona. Se l'indirizzo non si trova sulla mappa usa la posizione GPS del cliente
// (se l'ha condivisa), altrimenti la zona dichiarata dal cliente, segnata "da verificare".
async function calcolaZonaConsegna({ address, lat, lng, zonaDichiarata }){
  let pos = await geocodeAddress(address);
  let fonte = 'indirizzo';
  if (!pos && Number.isFinite(lat) && Number.isFinite(lng)) { pos = { lat, lng }; fonte = 'gps'; }

  if (!pos) {
    const fuori = zonaDichiarata === 'fuori';
    return {
      ok: true, trovato: false, chiediZona: !zonaDichiarata, daVerificare: true,
      fuoriPaese: fuori, distanzaKm: null,
      spese: round2(SPESE_CONSEGNA_BASE + (fuori ? SOVRAPPREZZO_FUORI_PAESE : 0))
    };
  }

  const km = Math.round(distanzaKm(PIZZERIA_POS, pos) * 10) / 10;
  if (km > RAGGIO_MAX_KM) {
    return {
      ok: false, error: 'fuori_zona', distanzaKm: km,
      message: `Ci dispiace, l'indirizzo è a circa ${String(km).replace('.', ',')} km dalla pizzeria: consegniamo fino a ${RAGGIO_MAX_KM} km. Puoi scegliere il ritiro in sede.`
    };
  }
  const fuori = km > RAGGIO_PAESE_KM;
  return {
    ok: true, trovato: true, fonte, daVerificare: false,
    fuoriPaese: fuori, distanzaKm: km,
    spese: round2(SPESE_CONSEGNA_BASE + (fuori ? SOVRAPPREZZO_FUORI_PAESE : 0))
  };
}

// imposta in modo autorevole le spese di consegna dell'ordine (mai fidarsi del valore del sito)
async function applyDeliveryZone(order){
  if (order.modalita !== 'consegna') { order.speseConsegna = 0; return { ok: true }; }
  const z = await calcolaZonaConsegna({
    address: order.address,
    lat: Number(order.lat), lng: Number(order.lng),
    zonaDichiarata: order.zonaDichiarata
  });
  if (!z.ok) return z;

  order.speseConsegna = z.spese;
  order.distanzaKm = z.distanzaKm;
  order.fuoriPaese = !!z.fuoriPaese;
  order.zonaDaVerificare = !!z.daVerificare;

  if (order.testoStampa) {
    let riga = `Consegna a domicilio: +${money(z.spese)}`;
    if (z.fuoriPaese) riga += ' (fuori paese)';
    if (z.distanzaKm != null) riga += ` — ${String(z.distanzaKm).replace('.', ',')} km`;
    if (z.daVerificare) riga += `\n⚠️ ZONA DA VERIFICARE: indirizzo non trovato, il cliente dice "${z.fuoriPaese ? 'fuori paese' : 'in paese'}"`;
    order.testoStampa = order.testoStampa.replace(/Consegna a domicilio: \+[^\n]*/, riga);
  }
  return { ok: true };
}

// Ricalcola sconto/subtotale/totale in modo autorevole: non ci fidiamo mai dei valori
// mandati dal sito, li ricalcoliamo sempre qui prima di stampare/salvare/far pagare.
async function applyFirstOrderDiscount(order){
  const subtotaleBase = round2(Number(order.subtotaleBase != null ? order.subtotaleBase : order.subtotale) || 0);
  const eligible = await isFirstOrderForPhone(order.phone, order.address);
  const sconto = eligible ? round2(subtotaleBase * SCONTO_PRIMO_ORDINE) : 0;

  order.subtotaleBase = subtotaleBase;
  order.scontoPrimoOrdine = sconto;
  order.subtotale = round2(subtotaleBase - sconto);
  order.grandTotal = round2(order.subtotale + (Number(order.speseConsegna) || 0));

  if (order.testoStampa) {
    // togliamo un'eventuale riga sconto scritta dal sito (potrebbe essere sbagliata/vecchia) e la
    // riscriviamo noi, insieme al totale finale, in base al calcolo vero appena fatto qui sopra
    order.testoStampa = order.testoStampa.replace(/\n🎉 Sconto primo ordine \([^)]*\): -[^\n]*\n/, '\n');
    if (sconto > 0) {
      order.testoStampa = order.testoStampa.replace(
        /\n(-{5,}\nTOTALE:)/,
        `\n🎉 Sconto primo ordine (20%): -${money(sconto)}\n$1`
      );
    }
    order.testoStampa = order.testoStampa.replace(/TOTALE: [^\n]*/, `TOTALE: ${money(order.grandTotal)}`);
  }
}

function dateKey(d){
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`; // YYYY-MM-DD, ora in ora italiana grazie a process.env.TZ
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

const MIN_LEAD_MINUTES = 15; // non si può scegliere un orario a meno di 15 minuti da adesso

// vero se lo slot (data + orario) è già passato, o troppo vicino ad ora per essere preparato in tempo
function isSlotInPast(dateStr, slot){
  const [h, m] = slot.split(':').map(Number);
  const slotDate = new Date(dateStr + 'T00:00:00');
  slotDate.setHours(h, m, 0, 0);
  const now = new Date();
  const minAllowed = new Date(now.getTime() + MIN_LEAD_MINUTES * 60000);
  return slotDate < minAllowed;
}

// giorno chiuso? Prima conta il calendario del titolare, poi il martedì di chiusura fisso
function isClosedDate(dateStr){
  if (calendario.chiusi.includes(dateStr)) return true;
  if (calendario.aperti.includes(dateStr)) return false;
  return new Date(dateStr + 'T00:00:00').getDay() === CLOSED_WEEKDAY;
}

// controlla che una data (stringa "YYYY-MM-DD") sia tra oggi e i prossimi
// MAX_DAYS_AHEAD giorni, e che non sia un giorno di chiusura
function isValidRequestDate(dateStr){
  if(!dateStr || !/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return false;
  const today = new Date();
  today.setHours(0,0,0,0);
  const requested = new Date(dateStr + 'T00:00:00');
  const diffDays = Math.round((requested - today) / 86400000);
  if(diffDays < 0 || diffDays > MAX_DAYS_AHEAD) return false;
  if(isClosedDate(dateStr)) return false;
  return true;
}

// ---------- Elenco dei "client" del pannello di stampa in ascolto (SSE) ----------
let printClients = [];

function broadcastOrder(order) {
  const payload = `data: ${JSON.stringify(order)}\n\n`;
  printClients.forEach(res => {
    try { res.write(payload); } catch (e) { /* il client verrà rimosso al prossimo "close" */ }
  });
}

// Un "battito" ogni 25 secondi: tiene viva la connessione attraverso eventuali proxy/timeout
// di rete, ed evita che il pannello resti "appeso" senza accorgersi che la linea è caduta.
setInterval(() => {
  printClients = printClients.filter(res => {
    try { res.write(': ping\n\n'); return true; }
    catch (e) { return false; }
  });
}, 25000);

// ---------- Storico ordini in memoria (si azzera se il server si riavvia) ----------
let orderHistory = [];
const MAX_HISTORY = 100;
let orderCounter = 1000;

// ---------- Endpoint: disponibilità slot di consegna per una data ----------
app.get('/api/delivery-slots', (req, res) => {
  const dateStr = req.query.date || dateKey(new Date());
  if (!isValidRequestDate(dateStr)) {
    return res.json({ date: dateStr, chiuso: true, slots: [] });
  }
  const slots = allSlotsForDay();
  const result = slots.map(s => ({
    slot: s,
    prenotati: slotCounts[`${dateStr}|${s}`] || 0,
    disponibile: (slotCounts[`${dateStr}|${s}`] || 0) < MAX_PER_SLOT && !isSlotInPast(dateStr, s)
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

  if (order.timing === 'prima' && ASAP_DISABLED_WEEKDAYS_CONSEGNA.includes(new Date().getDay())) {
    return {
      ok: false,
      error: 'asap_non_disponibile',
      message: 'Nel weekend le consegne a domicilio sono solo su prenotazione. Scegli un orario specifico.'
    };
  }
  const now = new Date();
  const TEMPO_PREPARAZIONE_ASAP_MIN = 30; // per "il prima possibile": tempo realistico di preparazione + consegna
  let requestedDate = now;
  let dKey = dateKey(now);

  if (order.timing === 'orario' && order.orarioRichiesto) {
    // se il cliente ha scelto un giorno futuro (fino a MAX_DAYS_AHEAD), lo validiamo
    if (order.dataRichiesta) {
      if (!isValidRequestDate(order.dataRichiesta)) {
        return {
          ok: false,
          error: 'data_non_valida',
          message: 'Il giorno scelto non è disponibile per gli ordini. Scegline un altro tra quelli mostrati.'
        };
      }
      dKey = order.dataRichiesta;
    }
    const [h, m] = order.orarioRichiesto.split(':').map(Number);
    requestedDate = new Date(dKey + 'T00:00:00');
    requestedDate.setHours(h, m, 0, 0);
  } else {
    // "il prima possibile": non è realistico che arrivi nello stesso istante,
    // quindi contiamo il posto in cucina e stimiamo l'orario 30 minuti da adesso
    requestedDate = new Date(now.getTime() + TEMPO_PREPARAZIONE_ASAP_MIN * 60000);
    dKey = dateKey(requestedDate);
  }

  const slot = slotLabel(requestedDate);
  if (order.timing === 'orario' && isSlotInPast(dKey, slot)) {
    return {
      ok: false,
      error: 'orario_scaduto',
      message: `L'orario delle ${slot} è già passato (o troppo vicino). Scegli un altro orario tra quelli disponibili.`
    };
  }
  if (!isSlotAvailable(dKey, slot)) {
    return {
      ok: false,
      error: 'slot_pieno',
      message: `L'orario delle ${slot} è al completo per le consegne. Scegli un altro orario tra quelli disponibili.`
    };
  }
  reserveSlot(dKey, slot);
  order.slotAssegnato = slot;
  if (order.timing === 'orario') {
    const giornoLabel = dKey !== dateKey(now) ? ` del ${new Date(dKey + 'T00:00:00').toLocaleDateString('it-IT', { weekday: 'long', day: 'numeric', month: 'long' })}` : '';
    order.orarioLabel = `Alle ${slot}${giornoLabel}`;
    order.testoStampa = (order.testoStampa || '').replace(/Orario richiesto:.*$/m, `Orario richiesto: Alle ${slot}${giornoLabel}`);
  } else {
    // "il prima possibile": mostriamo una stima realistica (30 minuti), non l'ora esatta di invio
    order.orarioLabel = `Il prima possibile (circa alle ${slot})`;
    order.testoStampa = (order.testoStampa || '').replace(/Orario richiesto:.*$/m, `Orario richiesto: Il prima possibile (circa alle ${slot})`);
  }
  return { ok: true };
}

// Prende un ordine già "pronto" (slot assegnato se serve) e lo finalizza:
// numero ordine, storico, stampa in cucina, email. Usata sia dal checkout
// diretto (pagamento a consegna) sia dal webhook Stripe (pagamento online).
async function finalizeOrder(order, customerId){
  order.numeroOrdine = ++orderCounter;
  order.ricevutoAlle = new Date().toISOString();
  order.stato = 'da_preparare';
  order.metodoPagamento = order.pagatoOnline ? 'online' : null; // 'online' | 'contanti' | 'bancomat' | null (da registrare)
  order.stampato = false; // diventa true quando un pannello lo stampa (anche in differita, vedi /api/orders/non-stampati)
  order.phoneNormalized = normalizePhone(order.phone);
  order.addressNormalized = normalizeAddress(order.address);
  orderHistory.unshift(order);
  if (orderHistory.length > MAX_HISTORY) orderHistory.pop();

  if (ordersCollection) {
    ordersCollection.insertOne({ ...order, customerId: customerId || null }).catch(err => {
      console.error('Errore salvataggio storico ordine:', err);
    });
  }

  broadcastOrder(order);
  sendEmail(ORDER_EMAIL, order.oggettoEmail || 'Nuovo ordine — La Casa di Carta', order.testoStampa, buildOwnerOrderHtml(order));
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
  if (!isValidRequestDate(data)) {
    return res.status(409).json({ ok: false, error: 'Il giorno scelto non è disponibile. Scegline un altro tra quelli mostrati.' });
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

  if (ordersPaused) {
    return res.status(403).json({
      ok: false,
      error: 'ordini_sospesi',
      message: 'Siamo momentaneamente pieni e non possiamo accettare altri ordini. Riprova tra qualche minuto!'
    });
  }

  {
    const giornoOrdine = (order.timing === 'orario' && order.dataRichiesta) ? order.dataRichiesta : dateKey(new Date());
    if (isClosedDate(giornoOrdine)) {
      return res.status(409).json({
        ok: false,
        error: 'giorno_chiuso',
        message: 'Quel giorno siamo chiusi. Scegli un altro giorno tra quelli disponibili.'
      });
    }
  }

  if (blockedPhonesCache.has(normalizePhone(order.phone))) {
    return res.status(403).json({
      ok: false,
      error: 'numero_bloccato',
      message: 'Non è stato possibile completare l\'ordine. Contatta la pizzeria telefonicamente.'
    });
  }

  order.ipCliente = req.ip || null;

  const subtotaleForMinimo = Number(order.subtotaleBase != null ? order.subtotaleBase : order.subtotale) || 0;
  if (order.modalita === 'consegna' && subtotaleForMinimo < MIN_DELIVERY_ORDER) {
    return res.status(400).json({
      ok: false,
      error: 'ordine_minimo',
      message: `L'ordine minimo per la consegna a domicilio è di €${MIN_DELIVERY_ORDER.toFixed(2).replace('.', ',')}.`
    });
  }

  const zona = await applyDeliveryZone(order); // spese di consegna in base alla distanza
  if (!zona.ok) return res.status(400).json(zona);

  await applyFirstOrderDiscount(order); // ricalcola sconto/subtotale/totale in modo autorevole

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

  if (ordersPaused) {
    return res.status(403).json({
      ok: false,
      error: 'ordini_sospesi',
      message: 'Siamo momentaneamente pieni e non possiamo accettare altri ordini. Riprova tra qualche minuto!'
    });
  }

  {
    const giornoOrdine = (order.timing === 'orario' && order.dataRichiesta) ? order.dataRichiesta : dateKey(new Date());
    if (isClosedDate(giornoOrdine)) {
      return res.status(409).json({
        ok: false,
        error: 'giorno_chiuso',
        message: 'Quel giorno siamo chiusi. Scegli un altro giorno tra quelli disponibili.'
      });
    }
  }

  if (blockedPhonesCache.has(normalizePhone(order.phone))) {
    return res.status(403).json({
      ok: false,
      error: 'numero_bloccato',
      message: 'Non è stato possibile completare l\'ordine. Contatta la pizzeria telefonicamente.'
    });
  }

  order.ipCliente = req.ip || null;

  const subtotaleForMinimo = Number(order.subtotaleBase != null ? order.subtotaleBase : order.subtotale) || 0;
  if (order.modalita === 'consegna' && subtotaleForMinimo < MIN_DELIVERY_ORDER) {
    return res.status(400).json({
      ok: false,
      error: 'ordine_minimo',
      message: `L'ordine minimo per la consegna a domicilio è di €${MIN_DELIVERY_ORDER.toFixed(2).replace('.', ',')}.`
    });
  }

  const zona = await applyDeliveryZone(order); // spese di consegna in base alla distanza
  if (!zona.ok) return res.status(400).json(zona);

  await applyFirstOrderDiscount(order); // ricalcola sconto/subtotale/totale in modo autorevole

  // controllo preventivo: se lo slot è già pieno (o la data non valida), non ha senso far pagare il cliente
  if (order.modalita === 'consegna' && order.timing === 'prima' && ASAP_DISABLED_WEEKDAYS_CONSEGNA.includes(new Date().getDay())) {
    return res.status(409).json({
      ok: false,
      error: 'asap_non_disponibile',
      message: 'Nel weekend le consegne a domicilio sono solo su prenotazione. Scegli un orario specifico.'
    });
  }
  const now = new Date();
  let dKeyCheck = dateKey(now);
  let requestedDate = now;
  if (order.timing === 'orario' && order.orarioRichiesto) {
    if (order.dataRichiesta) {
      if (!isValidRequestDate(order.dataRichiesta)) {
        return res.status(409).json({
          ok: false,
          error: 'data_non_valida',
          message: 'Il giorno scelto non è disponibile per gli ordini. Scegline un altro tra quelli mostrati.'
        });
      }
      dKeyCheck = order.dataRichiesta;
    }
    const [h, m] = order.orarioRichiesto.split(':').map(Number);
    requestedDate = new Date(dKeyCheck + 'T00:00:00');
    requestedDate.setHours(h, m, 0, 0);
  }
  if (order.modalita === 'consegna' && order.timing === 'orario' && isSlotInPast(dKeyCheck, slotLabel(requestedDate))) {
    return res.status(409).json({
      ok: false,
      error: 'orario_scaduto',
      message: `L'orario delle ${slotLabel(requestedDate)} è già passato (o troppo vicino). Scegli un altro orario tra quelli disponibili.`
    });
  }
  if (order.modalita === 'consegna' && !isSlotAvailable(dKeyCheck, slotLabel(requestedDate))) {
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

// ---------- Tracciamento consegna in tempo reale ----------
// posizione del fattorino: una sola, condivisa (un mezzo alla volta consegna)
let driverLocation = null; // { lat, lng, aggiornataAlle }

app.post('/api/driver-location', (req, res) => {
  const { lat, lng } = req.body || {};
  if (typeof lat !== 'number' || typeof lng !== 'number') {
    return res.status(400).json({ ok: false, error: 'Coordinate non valide' });
  }
  driverLocation = { lat, lng, aggiornataAlle: new Date().toISOString() };
  res.json({ ok: true });
});

app.get('/api/driver-location', (req, res) => {
  if (!driverLocation) return res.json({ disponibile: false });
  // se la posizione non si aggiorna da più di 5 minuti, consideriamola scaduta
  const eta = Date.now() - new Date(driverLocation.aggiornataAlle).getTime();
  if (eta > 5 * 60 * 1000) return res.json({ disponibile: false });
  res.json({ disponibile: true, ...driverLocation });
});

// info minime e pubbliche su un ordine, usate dalla pagina di tracciamento del cliente
// (nessun dato sensibile: solo ciò che serve per mostrare la mappa)
app.get('/api/orders/:numeroOrdine/pubblico', (req, res) => {
  const numeroOrdine = Number(req.params.numeroOrdine);
  const order = orderHistory.find(o => o.numeroOrdine === numeroOrdine);
  if (!order) return res.status(404).json({ ok: false, error: 'Ordine non trovato' });
  res.json({
    ok: true,
    numeroOrdine: order.numeroOrdine,
    modalita: order.modalita,
    address: order.modalita === 'consegna' ? order.address : null,
    stato: order.stato || 'da_preparare'
  });
});

// ---------- Endpoint: il pannello di stampa segna qui un ordine come pronto ----------
app.post('/api/orders/:numeroOrdine/pronto', (req, res) => {
  const numeroOrdine = Number(req.params.numeroOrdine);
  const order = orderHistory.find(o => o.numeroOrdine === numeroOrdine);
  if (!order) return res.status(404).json({ ok: false, error: 'Ordine non trovato' });

  order.stato = 'pronto';
  order.prontoAlle = new Date().toISOString();

  if (ordersCollection) {
    ordersCollection.updateOne({ numeroOrdine }, { $set: { stato: 'pronto', prontoAlle: order.prontoAlle } }).catch(err => {
      console.error('Errore aggiornamento stato ordine nel database:', err);
    });
  }

  broadcastOrder({ evento: 'stato_aggiornato', numeroOrdine, stato: 'pronto' });

  // per il ritiro in sede l'email va mandata subito (il cliente può già venire a ritirare);
  // per la consegna aspettiamo che il fattorino carichi davvero l'ordine (endpoint /in-consegna)
  if (order.email && order.modalita !== 'consegna') {
    sendEmail(
      order.email,
      'Il tuo ordine è pronto! — La Casa di Carta',
      buildOrderReadyText(order),
      buildOrderReadyHtml(order)
    );
  }

  res.json({ ok: true });
});

// ---------- Endpoint: il pannello di stampa registra qui come ha pagato il cliente (contanti/bancomat) ----------
app.post('/api/orders/:numeroOrdine/pagamento', (req, res) => {
  const numeroOrdine = Number(req.params.numeroOrdine);
  const { metodo } = req.body || {};
  if (metodo !== 'contanti' && metodo !== 'bancomat') {
    return res.status(400).json({ ok: false, error: 'Metodo non valido' });
  }
  const order = orderHistory.find(o => o.numeroOrdine === numeroOrdine);
  if (!order) return res.status(404).json({ ok: false, error: 'Ordine non trovato' });
  if (order.pagatoOnline) return res.status(400).json({ ok: false, error: 'Questo ordine è già pagato online' });

  order.metodoPagamento = metodo;

  if (ordersCollection) {
    ordersCollection.updateOne({ numeroOrdine }, { $set: { metodoPagamento: metodo } }).catch(err => {
      console.error('Errore salvataggio metodo di pagamento:', err);
    });
  }

  broadcastOrder({ evento: 'pagamento_registrato', numeroOrdine, metodoPagamento: metodo });
  res.json({ ok: true });
});

// ---------- Endpoint: elenco ordini pronti da caricare in consegna (per la pagina del fattorino) ----------
// ---------- Endpoint: catalogo prodotti (per la lista da spuntare nel pannello di stampa) ----------
// tipi di pane per i panini (deve combaciare con BREAD_OPTIONS nel sito)
const BREAD_TYPES = ["Panino Classico", "Pan Pizza", "Tortilla"];

app.get('/api/menu-catalog', (req, res) => {
  // uniamo il catalogo di base con i piatti nuovi aggiunti dal titolare, categoria per categoria
  const categorie = MENU_CATALOG.map(g => ({ ...g, items: [...g.items] }));
  customMenuItemsCache.forEach(item => {
    let gruppo = categorie.find(g => g.cat === item.cat && !g.keyPrefix?.startsWith('EXTRA_'));
    if (!gruppo) {
      gruppo = { cat: item.cat, items: [], keyPrefix: item.cat };
      categorie.push(gruppo);
    }
    if (!gruppo.items.includes(item.nome)) gruppo.items.push(item.nome);
  });
  res.json({ categorie, tipiPane: BREAD_TYPES });
});

// ---------- Endpoint: piatti nuovi aggiunti dal titolare dal pannello di stampa ----------
app.get('/api/custom-menu-items', (req, res) => {
  res.json(customMenuItemsCache);
});

app.post('/api/custom-menu-items/add', async (req, res) => {
  const { cat, nome, descrizione, prezzo } = req.body || {};
  const nuovoPrezzo = Number(prezzo);
  if (!cat || !nome || typeof cat !== 'string' || typeof nome !== 'string' || !Number.isFinite(nuovoPrezzo) || nuovoPrezzo < 0) {
    return res.status(400).json({ ok: false, error: 'Dati non validi' });
  }
  const chiave = `${cat}|${nome}`;
  const item = { _id: chiave, cat, nome, descrizione: descrizione || '', prezzo: nuovoPrezzo, createdAt: new Date().toISOString() };

  customMenuItemsCache = customMenuItemsCache.filter(i => i.cat !== cat || i.nome !== nome);
  customMenuItemsCache.push(item);
  priceOverridesCache[chiave] = nuovoPrezzo; // così è subito modificabile anche da "Modifica prezzi"

  if (customMenuItemsCollection) {
    try {
      await customMenuItemsCollection.updateOne({ _id: chiave }, { $set: item }, { upsert: true });
      if (priceOverridesCollection) {
        await priceOverridesCollection.updateOne({ _id: chiave }, { $set: { prezzo: nuovoPrezzo } }, { upsert: true });
      }
    } catch (err) {
      console.error('Errore salvataggio piatto nuovo:', err);
      return res.status(500).json({ ok: false, error: 'Errore di salvataggio' });
    }
  }
  res.json({ ok: true, item });
});

app.post('/api/custom-menu-items/delete', async (req, res) => {
  const { cat, nome } = req.body || {};
  if (!cat || !nome) return res.status(400).json({ ok: false, error: 'Dati mancanti' });
  const chiave = `${cat}|${nome}`;
  customMenuItemsCache = customMenuItemsCache.filter(i => i.cat !== cat || i.nome !== nome);
  if (customMenuItemsCollection) {
    customMenuItemsCollection.deleteOne({ _id: chiave }).catch(err => {
      console.error('Errore rimozione piatto:', err);
    });
  }
  res.json({ ok: true });
});

// ---------- Endpoint: elenco prodotti attualmente esauriti ----------
app.get('/api/sold-out', (req, res) => {
  res.json([...soldOutCache]);
});

// ---------- Endpoint: interruttore "sospendi ordini" (usato dal pannello di stampa) ----------
app.get('/api/orders-status', (req, res) => {
  res.json({ paused: ordersPaused });
});

app.post('/api/orders-status/toggle', async (req, res) => {
  ordersPaused = !ordersPaused;
  if (settingsCollection) {
    settingsCollection.updateOne(
      { _id: 'ordersPaused' },
      { $set: { value: ordersPaused } },
      { upsert: true }
    ).catch(err => console.error('Errore salvataggio stato ordini:', err));
  }
  broadcastOrder({ evento: 'ordini_sospesi_aggiornato', paused: ordersPaused });
  res.json({ ok: true, paused: ordersPaused });
});

// ---------- Endpoint: calendario aperture/chiusure (deciso dal titolare dal pannello) ----------
function pulisciCalendario(){
  const oggi = dateKey(new Date());
  calendario.chiusi = [...new Set(calendario.chiusi)].filter(d => d >= oggi).sort();
  calendario.aperti = [...new Set(calendario.aperti)].filter(d => d >= oggi).sort();
}

app.get('/api/calendario', (req, res) => {
  pulisciCalendario();
  res.json({ ...calendario, giornoChiusuraSettimanale: CLOSED_WEEKDAY });
});

// body: { data: "YYYY-MM-DD", chiuso: true|false }
app.post('/api/calendario/giorno', async (req, res) => {
  const { data, chiuso } = req.body || {};
  if (!data || !/^\d{4}-\d{2}-\d{2}$/.test(data)) return res.status(400).json({ ok: false, error: 'Data non valida' });
  calendario.chiusi = calendario.chiusi.filter(d => d !== data);
  calendario.aperti = calendario.aperti.filter(d => d !== data);
  const eMartedi = new Date(data + 'T00:00:00').getDay() === CLOSED_WEEKDAY;
  if (chiuso && !eMartedi) calendario.chiusi.push(data);   // giorno di chiusura in più
  if (!chiuso && eMartedi) calendario.aperti.push(data);   // martedì aperto eccezionalmente
  pulisciCalendario();
  if (settingsCollection) {
    settingsCollection.updateOne({ _id: 'calendario' }, { $set: { value: calendario } }, { upsert: true })
      .catch(err => console.error('Errore salvataggio calendario:', err));
  }
  res.json({ ok: true, ...calendario });
});

// ---------- Endpoint: statistiche per la dashboard (incassi e numero ordini) ----------
// Costo ingredienti noto solo per questi piatti (vedi food-cost.md): finché non censiamo gli
// altri piatti, il "guadagno netto" nella dashboard resta calcolato solo su questi.
const COSTO_INGREDIENTI = {
  'Capricciosa': 2.24,
};

function nuovoAggregato(){
  return {
    incasso: 0, ordini: 0,
    topItems: {}, // nome -> { qty, incasso }
    pagamenti: { online: 0, contanti: 0, bancomat: 0, nonRegistrato: 0 },
    pagamentiIncasso: { online: 0, contanti: 0, bancomat: 0, nonRegistrato: 0 },
    modalita: { consegna: 0, ritiro: 0 },
    modalitaIncasso: { consegna: 0, ritiro: 0 },
    scontoTotale: 0,
    guadagnoNetto: 0,
    qtyGuadagnoNetto: 0, // quante unità dei piatti censiti sono state vendute (per trasparenza)
    phones: new Set(),
  };
}

function accumula(agg, o){
  const importo = Number(o.grandTotal != null ? o.grandTotal : o.subtotale) || 0;
  agg.incasso += importo; agg.ordini++;

  const metodo = o.metodoPagamento && agg.pagamenti[o.metodoPagamento] !== undefined ? o.metodoPagamento : 'nonRegistrato';
  agg.pagamenti[metodo]++; agg.pagamentiIncasso[metodo] += importo;

  const modo = o.modalita === 'consegna' ? 'consegna' : 'ritiro';
  agg.modalita[modo]++; agg.modalitaIncasso[modo] += importo;

  agg.scontoTotale += Number(o.scontoPrimoOrdine) || 0;
  if (o.phoneNormalized) agg.phones.add(o.phoneNormalized);

  (o.articoli || []).forEach(a => {
    const nome = a.nome;
    const qty = Number(a.qty) || 0;
    const incassoRiga = Number(a.prezzo) || 0;
    if (!agg.topItems[nome]) agg.topItems[nome] = { qty: 0, incasso: 0 };
    agg.topItems[nome].qty += qty;
    agg.topItems[nome].incasso += incassoRiga;

    if (COSTO_INGREDIENTI[nome] != null) {
      agg.guadagnoNetto += incassoRiga - (COSTO_INGREDIENTI[nome] * qty);
      agg.qtyGuadagnoNetto += qty;
    }
  });
}

function finalizzaAggregato(agg, clientiNuovi){
  const topItems = Object.entries(agg.topItems)
    .map(([nome, v]) => ({ nome, qty: v.qty, incasso: round2(v.incasso) }))
    .sort((a, b) => b.qty - a.qty)
    .slice(0, 8);
  return {
    incasso: round2(agg.incasso),
    ordini: agg.ordini,
    scontrinoMedio: agg.ordini ? round2(agg.incasso / agg.ordini) : 0,
    topItems,
    pagamenti: agg.pagamenti,
    pagamentiIncasso: Object.fromEntries(Object.entries(agg.pagamentiIncasso).map(([k, v]) => [k, round2(v)])),
    modalita: agg.modalita,
    modalitaIncasso: Object.fromEntries(Object.entries(agg.modalitaIncasso).map(([k, v]) => [k, round2(v)])),
    scontoTotale: round2(agg.scontoTotale),
    guadagnoNetto: round2(agg.guadagnoNetto),
    qtyGuadagnoNetto: agg.qtyGuadagnoNetto,
    clientiNuovi,
    clientiAbituali: Math.max(0, agg.phones.size - clientiNuovi),
  };
}

// ---------- Endpoint: ordini arrivati ma non ancora stampati da nessun pannello ----------
// Serve a recuperare gli ordini ricevuti mentre il pannello era chiuso/disconnesso: appena
// il pannello si (ri)apre, li chiede qui e li stampa come se arrivassero ora.
app.get('/api/orders/non-stampati', async (req, res) => {
  if (!ordersCollection) return res.json([]);
  try {
    // solo ultime 6 ore: evita di recuperare ordini vecchi/storici (es. quelli di prima
    // che esistesse questo controllo, che non hanno mai avuto il campo "stampato" impostato)
    const limiteOrario = new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString();
    const ordini = await ordersCollection.find(
      { stampato: { $ne: true }, ricevutoAlle: { $gte: limiteOrario } },
      { sort: { ricevutoAlle: 1 }, limit: 50 }
    ).toArray();
    res.json(ordini);
  } catch (err) {
    console.error('Errore recupero ordini non stampati:', err);
    res.json([]);
  }
});

app.post('/api/orders/segna-stampato', async (req, res) => {
  const numeroOrdine = Number(req.body && req.body.numeroOrdine);
  if (!numeroOrdine) return res.status(400).json({ ok: false, error: 'Numero ordine mancante' });

  const inMemoria = orderHistory.find(o => o.numeroOrdine === numeroOrdine);
  if (inMemoria) inMemoria.stampato = true;

  if (ordersCollection) {
    try { await ordersCollection.updateOne({ numeroOrdine }, { $set: { stampato: true } }); }
    catch (err) { console.error('Errore salvataggio stampato:', err); }
  }
  res.json({ ok: true });
});

app.get('/api/dashboard-stats', async (req, res) => {
  const vuoto = { incasso: 0, ordini: 0 };
  if (!ordersCollection) {
    return res.json({ today: vuoto, week: vuoto, month: vuoto, daily: [], periods: {}, peakHours: [] });
  }
  try {
    const now = new Date(); // ora italiana, grazie a TZ=Europe/Rome impostato a inizio file
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 0, 0, 0, 0);
    const dayOfWeek = now.getDay(); // 0=domenica, 1=lunedì, ...
    const diffToMonday = (dayOfWeek === 0 ? 6 : dayOfWeek - 1);
    const startOfWeek = new Date(now.getFullYear(), now.getMonth(), now.getDate() - diffToMonday, 0, 0, 0, 0);
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1, 0, 0, 0, 0);
    const startOfPrevWeek = new Date(startOfWeek.getTime() - 7 * 24 * 60 * 60 * 1000);
    const startOfPrevMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1, 0, 0, 0, 0);
    // margine di sicurezza: partiamo da qui per essere certi di avere anche settimana/mese precedenti
    const queryStart = new Date(Math.min(startOfPrevMonth.getTime(), startOfPrevWeek.getTime()) - 24 * 60 * 60 * 1000);

    const orders = await ordersCollection.find(
      { ricevutoAlle: { $gte: queryStart.toISOString() } },
      { projection: { ricevutoAlle: 1, grandTotal: 1, subtotale: 1, articoli: 1, metodoPagamento: 1, modalita: 1, scontoPrimoOrdine: 1, phoneNormalized: 1 } }
    ).toArray();

    // per "clienti nuovi vs abituali": chi aveva già un numero di telefono visto PRIMA dell'inizio di ciascun periodo
    const phoneVistiPrima = { today: new Set(), week: new Set(), month: new Set() };
    orders.forEach(o => {
      if (!o.phoneNormalized) return;
      const t = new Date(o.ricevutoAlle);
      if (t < startOfToday) phoneVistiPrima.today.add(o.phoneNormalized);
      if (t < startOfWeek) phoneVistiPrima.week.add(o.phoneNormalized);
      if (t < startOfMonth) phoneVistiPrima.month.add(o.phoneNormalized);
    });

    const todayAgg = nuovoAggregato(), weekAgg = nuovoAggregato(), monthAgg = nuovoAggregato();
    const prevWeekTot = { incasso: 0, ordini: 0 }, prevMonthTot = { incasso: 0, ordini: 0 };
    const dailyMap = {};
    const oreMap = {}; // 0-23 -> numero ordini, calcolato sul mese in corso

    const nuoviToday = new Set(), nuoviWeek = new Set(), nuoviMonth = new Set();

    orders.forEach(o => {
      const importo = Number(o.grandTotal != null ? o.grandTotal : o.subtotale) || 0;
      const t = new Date(o.ricevutoAlle);
      const key = dateKey(t);

      if (t >= startOfMonth) {
        accumula(monthAgg, o);
        if (o.phoneNormalized && !phoneVistiPrima.month.has(o.phoneNormalized)) nuoviMonth.add(o.phoneNormalized);
        const ora = t.getHours();
        oreMap[ora] = (oreMap[ora] || 0) + 1;
        if (!dailyMap[key]) dailyMap[key] = { incasso: 0, ordini: 0 };
        dailyMap[key].incasso += importo; dailyMap[key].ordini++;
      } else if (t >= startOfPrevMonth) {
        prevMonthTot.incasso += importo; prevMonthTot.ordini++;
      }

      if (t >= startOfWeek) {
        accumula(weekAgg, o);
        if (o.phoneNormalized && !phoneVistiPrima.week.has(o.phoneNormalized)) nuoviWeek.add(o.phoneNormalized);
      } else if (t >= startOfPrevWeek && t < startOfWeek) {
        prevWeekTot.incasso += importo; prevWeekTot.ordini++;
      }

      if (t >= startOfToday) {
        accumula(todayAgg, o);
        if (o.phoneNormalized && !phoneVistiPrima.today.has(o.phoneNormalized)) nuoviToday.add(o.phoneNormalized);
      }
    });

    const daily = Object.keys(dailyMap).sort().map(k => ({
      data: k, incasso: round2(dailyMap[k].incasso), ordini: dailyMap[k].ordini
    }));
    const peakHours = Array.from({ length: 24 }, (_, ora) => ({ ora, ordini: oreMap[ora] || 0 }));

    res.json({
      today: { incasso: round2(todayAgg.incasso), ordini: todayAgg.ordini },
      week: { incasso: round2(weekAgg.incasso), ordini: weekAgg.ordini },
      month: { incasso: round2(monthAgg.incasso), ordini: monthAgg.ordini },
      weekPrev: { incasso: round2(prevWeekTot.incasso), ordini: prevWeekTot.ordini },
      monthPrev: { incasso: round2(prevMonthTot.incasso), ordini: prevMonthTot.ordini },
      daily,
      peakHours,
      periods: {
        today: finalizzaAggregato(todayAgg, nuoviToday.size),
        week: finalizzaAggregato(weekAgg, nuoviWeek.size),
        month: finalizzaAggregato(monthAgg, nuoviMonth.size),
      },
      costiCensiti: Object.keys(COSTO_INGREDIENTI),
    });
  } catch (err) {
    console.error('Errore calcolo statistiche dashboard:', err);
    res.status(500).json({ today: vuoto, week: vuoto, month: vuoto, daily: [], periods: {}, peakHours: [] });
  }
});

// ---------- Endpoint: prezzi correnti di tutte le voci del menu (di base + eventuali modifiche) ----------
app.get('/api/menu-prices', (req, res) => {
  const prezzi = {};
  Object.keys(DEFAULT_PRICES).forEach(chiave => {
    prezzi[chiave] = getCurrentPrice(chiave);
  });
  res.json(prezzi);
});

// ---------- Endpoint: il titolare modifica il prezzo di una voce dal pannello di stampa ----------
app.post('/api/menu-prices/update', async (req, res) => {
  const { chiave, prezzo } = req.body || {};
  const nuovoPrezzo = Number(prezzo);
  if (!chiave || typeof chiave !== 'string' || !Number.isFinite(nuovoPrezzo) || nuovoPrezzo < 0) {
    return res.status(400).json({ ok: false, error: 'Dati non validi' });
  }
  priceOverridesCache[chiave] = nuovoPrezzo;
  if (priceOverridesCollection) {
    priceOverridesCollection.updateOne(
      { _id: chiave },
      { $set: { prezzo: nuovoPrezzo } },
      { upsert: true }
    ).catch(err => console.error('Errore salvataggio prezzo:', err));
  }
  res.json({ ok: true, chiave, prezzo: nuovoPrezzo });
});

// ---------- Endpoint: foto dei piatti (caricate dal titolare dal pannello di stampa) ----------
// Elenco leggero delle chiavi che hanno già una foto: usato dal sito per sapere quali
// piatti mostrare con l'immagine, senza scaricare tutte le foto in un colpo solo.
app.get('/api/product-photos/keys', (req, res) => {
  res.json(Object.keys(productPhotosCache));
});

// Serve la singola immagine (scaricata dal database solo quando serve davvero, e tenuta
// in cache dal browser per una settimana: non pesa sul caricamento iniziale del sito).
app.get('/api/product-photos/img/:chiave', async (req, res) => {
  const chiave = decodeURIComponent(req.params.chiave);
  if (!productPhotosCache[chiave] || !productPhotosCollection) {
    return res.status(404).send('Foto non trovata');
  }
  try {
    const doc = await productPhotosCollection.findOne({ _id: chiave });
    if (!doc || !doc.data) return res.status(404).send('Foto non trovata');
    const match = doc.data.match(/^data:(image\/\w+);base64,(.+)$/);
    if (!match) return res.status(500).send('Formato immagine non valido');
    const buffer = Buffer.from(match[2], 'base64');
    res.set('Content-Type', match[1]);
    res.set('Cache-Control', 'public, max-age=604800');
    res.send(buffer);
  } catch (err) {
    console.error('Errore lettura foto piatto:', err);
    res.status(500).send('Errore del server');
  }
});

// Il titolare carica/sostituisce la foto di un piatto dal pannello di stampa.
// imageDataUrl arriva già ridimensionata e compressa dal browser (niente foto enormi salvate).
app.post('/api/product-photos/upload', async (req, res) => {
  const { chiave, imageDataUrl } = req.body || {};
  if (!chiave || typeof chiave !== 'string' || !imageDataUrl || !/^data:image\/(jpeg|png|webp);base64,/.test(imageDataUrl)) {
    return res.status(400).json({ ok: false, error: 'Dati non validi' });
  }
  if (imageDataUrl.length > 2_000_000) {
    return res.status(400).json({ ok: false, error: 'Immagine troppo pesante' });
  }
  productPhotosCache[chiave] = true;
  if (productPhotosCollection) {
    try {
      await productPhotosCollection.updateOne(
        { _id: chiave },
        { $set: { data: imageDataUrl, updatedAt: new Date().toISOString() } },
        { upsert: true }
      );
    } catch (err) {
      console.error('Errore salvataggio foto piatto:', err);
      return res.status(500).json({ ok: false, error: 'Errore di salvataggio' });
    }
  }
  res.json({ ok: true, chiave });
});

app.post('/api/product-photos/delete', async (req, res) => {
  const { chiave } = req.body || {};
  if (!chiave) return res.status(400).json({ ok: false, error: 'Chiave mancante' });
  delete productPhotosCache[chiave];
  if (productPhotosCollection) {
    productPhotosCollection.deleteOne({ _id: chiave }).catch(err => {
      console.error('Errore rimozione foto piatto:', err);
    });
  }
  res.json({ ok: true });
});

// ---------- Endpoint: controlla se questo numero ha diritto allo sconto primo ordine ----------
app.get('/api/check-first-order-discount', async (req, res) => {
  const eligible = await isFirstOrderForPhone(req.query.phone, req.query.address);
  res.json({ eligible, percentuale: eligible ? Math.round(SCONTO_PRIMO_ORDINE * 100) : 0 });
});

// ---------- Endpoint: preventivo spese di consegna per un indirizzo (usato dal sito) ----------
app.get('/api/delivery-quote', async (req, res) => {
  const z = await calcolaZonaConsegna({
    address: String(req.query.address || ''),
    lat: parseFloat(req.query.lat), lng: parseFloat(req.query.lng),
    zonaDichiarata: req.query.zona || null
  });
  res.json({ ...z, raggioPaeseKm: RAGGIO_PAESE_KM, raggioMaxKm: RAGGIO_MAX_KM, speseBase: SPESE_CONSEGNA_BASE, sovrapprezzo: SOVRAPPREZZO_FUORI_PAESE });
});

// =====================================================================
// ---------- APP STAFF: comande salvate, modificabili, conto ----------
// =====================================================================
const crypto = require('crypto');

async function comandaGet(id){
  if (comandeCollection) return await comandeCollection.findOne({ _id: id });
  return comandeMemoria[id] || null;
}
async function comandaSave(c){
  c.aggiornataAlle = new Date().toISOString();
  if (comandeCollection) await comandeCollection.replaceOne({ _id: c._id }, c, { upsert: true });
  else comandeMemoria[c._id] = c;
  return c;
}
async function comandeList(filtro){
  if (comandeCollection) return await comandeCollection.find(filtro).sort({ creataAlle: -1 }).limit(200).toArray();
  return Object.values(comandeMemoria).filter(c => Object.entries(filtro).every(([k, v]) => {
    if (v && typeof v === 'object' && v.$gte) return c[k] >= v.$gte;
    return c[k] === v;
  })).sort((a, b) => b.creataAlle.localeCompare(a.creataAlle));
}

function oraIT(d = new Date()){
  return d.toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit', timeZone: 'Europe/Rome' });
}
function etichettaComanda(c){
  if (c.tipo === 'tavolo') return `TAVOLO ${c.tavolo}`;
  if (c.tipo === 'consegna') return `CONSEGNA S${c.numero}`;
  return `ASPORTO S${c.numero}`;
}

// pulisce le righe mandate dall'app e mette il prezzo giusto preso dal listino del server
function normalizzaRighe(righe){
  if (!Array.isArray(righe)) return [];
  return righe.slice(0, 300).map(r => {
    const chiave = String(r.chiave || '');
    const listino = getCurrentPrice(chiave);
    const prezzo = listino != null ? listino : Math.max(0, Number(r.prezzo) || 0); // voci libere: prezzo scritto dallo staff
    return {
      rid: String(r.rid || crypto.randomUUID()),
      chiave,
      nome: String(r.nome || '').slice(0, 120),
      cat: String(r.cat || '').slice(0, 80),
      qty: Math.max(0, Math.min(99, parseInt(r.qty, 10) || 0)),
      note: String(r.note || '').slice(0, 200),
      prezzo: round2(prezzo)
    };
  }).filter(r => r.nome && r.qty > 0);
}

function totaleComanda(c){
  return round2((c.righe || []).reduce((t, r) => t + r.prezzo * r.qty, 0));
}

// differenze tra quanto già mandato in cucina e la comanda attuale
function diffComanda(inviate, righe){
  const prima = new Map((inviate || []).map(r => [r.rid, r]));
  const dopo = new Map((righe || []).map(r => [r.rid, r]));
  const aggiunte = [], tolte = [], note = [];
  dopo.forEach((r, rid) => {
    const p = prima.get(rid);
    if (!p) aggiunte.push({ ...r });
    else {
      if (r.qty > p.qty) aggiunte.push({ ...r, qty: r.qty - p.qty });
      if (r.qty < p.qty) tolte.push({ ...r, qty: p.qty - r.qty });
      if ((r.note || '') !== (p.note || '')) note.push(r);
    }
  });
  prima.forEach((p, rid) => { if (!dopo.has(rid)) tolte.push({ ...p }); });
  return { aggiunte, tolte, note };
}

function testoComandaCucina(c, diff, primaVolta){
  const L = [];
  L.push('================================');
  L.push(etichettaComanda(c));
  if (c.nome) L.push(`Cliente: ${c.nome}`);
  if (c.tipo === 'consegna' && c.indirizzo) L.push(`Indirizzo: ${c.indirizzo}`);
  if (c.telefono && c.tipo !== 'tavolo') L.push(`Tel: ${c.telefono}`);
  if (c.orario) L.push(`Per le ore: ${c.orario}`);
  L.push(primaVolta ? `NUOVA COMANDA - ore ${oraIT()}` : `*** MODIFICA n.${c.invii} - ore ${oraIT()} ***`);
  L.push('================================');
  if (diff.aggiunte.length){
    if (!primaVolta) L.push('AGGIUNGERE:');
    diff.aggiunte.forEach(r => {
      L.push(`${primaVolta ? '' : '+ '}${r.qty}x ${r.nome}`);
      if (r.note) L.push(`   >> ${r.note}`);
    });
  }
  if (diff.tolte.length){
    if (diff.aggiunte.length) L.push('');
    L.push('TOGLIERE:');
    diff.tolte.forEach(r => L.push(`- ${r.qty}x ${r.nome}`));
  }
  if (diff.note.length){
    if (diff.aggiunte.length || diff.tolte.length) L.push('');
    L.push('NOTE CAMBIATE:');
    diff.note.forEach(r => L.push(`* ${r.nome}: ${r.note || '(nessuna nota)'}`));
  }
  if (primaVolta && c.noteComanda) { L.push(''); L.push(`NOTE: ${c.noteComanda}`); }
  L.push('================================');
  return L.join('\n');
}

function testoConto(c){
  const L = [];
  L.push('PIZZERIA LA CASA DI CARTA');
  L.push('Via XX Settembre 192 - Niscemi');
  L.push('--------------------------------');
  L.push(`${etichettaComanda(c)} - ${oraIT()}`);
  L.push('PRECONTO (non fiscale)');
  L.push('--------------------------------');
  (c.righe || []).forEach(r => L.push(`${r.qty}x ${r.nome}  ${money(r.prezzo * r.qty)}`));
  L.push('--------------------------------');
  if (c.spese) L.push(`Consegna: ${money(c.spese)}`);
  L.push(`TOTALE: ${money(totaleComanda(c) + (c.spese || 0))}`);
  return L.join('\n');
}

function stampaStaff(testo, rif){
  broadcastOrder({ evento: 'stampa_staff', testoStampa: testo, rif });
}

function infoComandaDaBody(b, c){
  const tipo = ['tavolo', 'asporto', 'consegna'].includes(b.tipo) ? b.tipo : (c && c.tipo) || 'tavolo';
  return {
    tipo,
    tavolo: tipo === 'tavolo' ? String(b.tavolo || '').slice(0, 10) : '',
    nome: String(b.nome || '').slice(0, 80),
    telefono: String(b.telefono || '').slice(0, 30),
    indirizzo: tipo === 'consegna' ? String(b.indirizzo || '').slice(0, 200) : '',
    orario: String(b.orario || '').slice(0, 10),
    noteComanda: String(b.noteComanda || '').slice(0, 300),
    spese: tipo === 'consegna' ? Math.max(0, Number(b.spese) || 0) : 0
  };
}

// elenco: aperte, oppure chiuse di oggi
app.get('/api/staff/comande', async (req, res) => {
  try {
    const stato = req.query.stato === 'chiusa' ? 'chiusa' : 'aperta';
    const filtro = stato === 'aperta' ? { stato: 'aperta' } : { stato: 'chiusa', giorno: dateKey(new Date()) };
    const lista = await comandeList(filtro);
    res.json(lista.map(c => ({ ...c, totale: totaleComanda(c) })));
  } catch (err) { console.error(err); res.status(500).json({ ok: false, error: 'Errore server' }); }
});

app.get('/api/staff/comande/:id', async (req, res) => {
  const c = await comandaGet(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Comanda non trovata' });
  res.json({ ...c, totale: totaleComanda(c) });
});

// nuova comanda
app.post('/api/staff/comande', async (req, res) => {
  try {
    const info = infoComandaDaBody(req.body || {});
    if (info.tipo === 'tavolo' && !info.tavolo) return res.status(400).json({ ok: false, error: 'Scrivi il numero del tavolo' });
    const giorno = dateKey(new Date());
    const diOggi = await comandeList({ giorno });
    const numero = diOggi.reduce((m, c) => Math.max(m, c.numero || 0), 0) + 1;
    const c = {
      _id: crypto.randomUUID(), numero, giorno, ...info,
      righe: [], inviate: [], invii: 0, stato: 'aperta',
      creataAlle: new Date().toISOString()
    };
    await comandaSave(c);
    res.json({ ok: true, comanda: { ...c, totale: 0 } });
  } catch (err) { console.error(err); res.status(500).json({ ok: false, error: 'Errore server' }); }
});

// salva (senza stampare) righe e/o dati della comanda
app.put('/api/staff/comande/:id', async (req, res) => {
  const c = await comandaGet(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Comanda non trovata' });
  const b = req.body || {};
  if (Array.isArray(b.righe)) c.righe = normalizzaRighe(b.righe);
  if (b.info) Object.assign(c, infoComandaDaBody(b.info, c));
  await comandaSave(c);
  res.json({ ok: true, comanda: { ...c, totale: totaleComanda(c) } });
});

// manda in cucina: stampa solo le differenze rispetto all'ultimo invio
app.post('/api/staff/comande/:id/invia', async (req, res) => {
  const c = await comandaGet(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Comanda non trovata' });
  if (Array.isArray((req.body || {}).righe)) c.righe = normalizzaRighe(req.body.righe);
  const diff = diffComanda(c.inviate, c.righe);
  if (!diff.aggiunte.length && !diff.tolte.length && !diff.note.length) {
    return res.json({ ok: true, nienteDaInviare: true, comanda: { ...c, totale: totaleComanda(c) } });
  }
  const primaVolta = c.invii === 0;
  c.invii += 1;
  stampaStaff(testoComandaCucina(c, diff, primaVolta), `${etichettaComanda(c)} #${c.invii}`);
  c.inviate = c.righe.map(r => ({ ...r }));
  c.ultimoInvio = new Date().toISOString();
  await comandaSave(c);
  res.json({ ok: true, comanda: { ...c, totale: totaleComanda(c) } });
});

app.post('/api/staff/comande/:id/ristampa', async (req, res) => {
  const c = await comandaGet(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Comanda non trovata' });
  if (!c.invii) return res.status(400).json({ ok: false, error: 'Non è ancora stata mandata in cucina' });
  const testo = testoComandaCucina(c, { aggiunte: c.inviate || [], tolte: [], note: [] }, true)
    .replace(/NUOVA COMANDA - ore/, 'RISTAMPA COMPLETA - ore');
  stampaStaff(testo, `Ristampa ${etichettaComanda(c)}`);
  res.json({ ok: true });
});

app.post('/api/staff/comande/:id/conto', async (req, res) => {
  const c = await comandaGet(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Comanda non trovata' });
  stampaStaff(testoConto(c), `Conto ${etichettaComanda(c)}`);
  res.json({ ok: true });
});

app.post('/api/staff/comande/:id/chiudi', async (req, res) => {
  const c = await comandaGet(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Comanda non trovata' });
  const pagamento = ['contanti', 'carta'].includes((req.body || {}).pagamento) ? req.body.pagamento : 'contanti';
  c.stato = 'chiusa';
  c.pagamento = pagamento;
  c.totaleIncassato = round2(totaleComanda(c) + (c.spese || 0));
  c.chiusaAlle = new Date().toISOString();
  await comandaSave(c);
  res.json({ ok: true });
});

app.post('/api/staff/comande/:id/riapri', async (req, res) => {
  const c = await comandaGet(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Comanda non trovata' });
  c.stato = 'aperta';
  delete c.pagamento; delete c.totaleIncassato; delete c.chiusaAlle;
  await comandaSave(c);
  res.json({ ok: true, comanda: { ...c, totale: totaleComanda(c) } });
});

// annulla: se qualcosa era già in cucina, stampa l'avviso di annullamento
app.post('/api/staff/comande/:id/annulla', async (req, res) => {
  const c = await comandaGet(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Comanda non trovata' });
  if (c.invii > 0) {
    stampaStaff(['================================', etichettaComanda(c), `*** COMANDA ANNULLATA - ore ${oraIT()} ***`, 'Non preparare nulla di questa comanda', '================================'].join('\n'), `Annullata ${etichettaComanda(c)}`);
  }
  c.stato = 'annullata';
  await comandaSave(c);
  res.json({ ok: true });
});

// listino per l'app staff: categorie, voci con prezzo attuale ed esauriti
app.get('/api/staff/menu', (req, res) => {
  const categorie = MENU_CATALOG.map(g => ({ cat: g.cat, keyPrefix: g.keyPrefix, items: [...g.items] }));
  customMenuItemsCache.forEach(item => {
    let g = categorie.find(x => x.cat === item.cat && !String(x.keyPrefix).startsWith('EXTRA_'));
    if (!g) { g = { cat: item.cat, keyPrefix: item.cat, items: [] }; categorie.push(g); }
    if (!g.items.includes(item.nome)) g.items.push(item.nome);
  });
  res.json(categorie.map(g => ({
    cat: g.cat,
    extra: String(g.keyPrefix).startsWith('EXTRA_'),
    items: g.items.map(nome => {
      const chiave = `${g.keyPrefix}|${nome}`;
      return { nome, chiave, prezzo: getCurrentPrice(chiave), esaurito: soldOutCache.has(chiave) };
    })
  })));
});

// ---------- Endpoint: lista nera numeri di telefono ----------
app.get('/api/blacklist', (req, res) => {
  res.json([...blockedPhonesCache]);
});

app.post('/api/blacklist/add', async (req, res) => {
  const numero = normalizePhone(req.body && req.body.numero);
  if (!numero) return res.status(400).json({ ok: false, error: 'Numero non valido' });
  blockedPhonesCache.add(numero);
  if (blacklistCollection) {
    await blacklistCollection.updateOne({ _id: numero }, { $set: { _id: numero } }, { upsert: true }).catch(err => {
      console.error('Errore salvataggio numero bloccato:', err);
    });
  }
  res.json({ ok: true, bloccati: [...blockedPhonesCache] });
});

app.post('/api/blacklist/remove', async (req, res) => {
  const numero = normalizePhone(req.body && req.body.numero);
  if (!numero) return res.status(400).json({ ok: false, error: 'Numero non valido' });
  blockedPhonesCache.delete(numero);
  if (blacklistCollection) {
    await blacklistCollection.deleteOne({ _id: numero }).catch(err => {
      console.error('Errore rimozione numero bloccato:', err);
    });
  }
  res.json({ ok: true, bloccati: [...blockedPhonesCache] });
});

// ---------- Endpoint: segna tutti i prodotti come disponibili (azzera l'elenco esauriti) ----------
app.post('/api/sold-out/reset-all', async (req, res) => {
  soldOutCache = new Set();
  if (soldOutCollection) {
    await soldOutCollection.deleteMany({}).catch(err => {
      console.error('Errore azzeramento esauriti:', err);
    });
  }
  broadcastOrder({ evento: 'esauriti_aggiornati', esauriti: [] });
  res.json({ ok: true });
});

// ---------- Endpoint: segna/togli un prodotto come esaurito ----------
app.post('/api/sold-out/toggle', async (req, res) => {
  const { chiave, esaurito } = req.body || {};
  if (!chiave) return res.status(400).json({ ok: false, error: 'Manca la chiave del prodotto' });

  if (esaurito) {
    soldOutCache.add(chiave);
    if (soldOutCollection) {
      await soldOutCollection.updateOne({ _id: chiave }, { $set: { _id: chiave } }, { upsert: true }).catch(err => {
        console.error('Errore salvataggio esaurito:', err);
      });
    }
  } else {
    soldOutCache.delete(chiave);
    if (soldOutCollection) {
      await soldOutCollection.deleteOne({ _id: chiave }).catch(err => {
        console.error('Errore rimozione esaurito:', err);
      });
    }
  }

  broadcastOrder({ evento: 'esauriti_aggiornati', esauriti: [...soldOutCache] });
  res.json({ ok: true, esauriti: [...soldOutCache] });
});

app.get('/api/orders/pronti-consegna', (req, res) => {
  const ordini = orderHistory
    .filter(o => o.modalita === 'consegna' && (o.stato === 'pronto' || o.stato === 'in_consegna'))
    .map(o => ({
      numeroOrdine: o.numeroOrdine,
      name: o.name || o.nome || 'Cliente',
      address: o.address || '',
      stato: o.stato
    }));
  res.json(ordini);
});

// ---------- Endpoint: il fattorino segna qui un ordine come caricato/in consegna ----------
app.post('/api/orders/:numeroOrdine/in-consegna', (req, res) => {
  const numeroOrdine = Number(req.params.numeroOrdine);
  const order = orderHistory.find(o => o.numeroOrdine === numeroOrdine);
  if (!order) return res.status(404).json({ ok: false, error: 'Ordine non trovato' });

  order.stato = 'in_consegna';
  order.inConsegnaAlle = new Date().toISOString();

  if (ordersCollection) {
    ordersCollection.updateOne({ numeroOrdine }, { $set: { stato: 'in_consegna', inConsegnaAlle: order.inConsegnaAlle } }).catch(err => {
      console.error('Errore aggiornamento stato ordine nel database:', err);
    });
  }

  broadcastOrder({ evento: 'stato_aggiornato', numeroOrdine, stato: 'in_consegna' });

  if (order.email) {
    sendEmail(
      order.email,
      'Il tuo ordine è in partenza! — La Casa di Carta',
      buildOrderReadyText(order),
      buildOrderReadyHtml(order)
    );
  }

  res.json({ ok: true });
});

// ---------- Resoconto giornaliero via email (ogni giorno alle 23:30, ora italiana) ----------
function getTodayRangeISO(){
  const now = new Date(); // il processo gira con TZ=Europe/Rome
  const y = now.getFullYear(), m = now.getMonth(), d = now.getDate();
  const start = new Date(y, m, d, 0, 0, 0, 0);
  const end = new Date(y, m, d, 23, 59, 59, 999);
  return { startISO: start.toISOString(), endISO: end.toISOString() };
}

async function buildDailyReport(){
  const { startISO, endISO } = getTodayRangeISO();
  const orders = ordersCollection
    ? await ordersCollection.find({ ricevutoAlle: { $gte: startISO, $lte: endISO } }).toArray()
    : orderHistory.filter(o => o.ricevutoAlle >= startISO && o.ricevutoAlle <= endISO);

  const perMetodo = {
    online:    { label: '💳 Pagati online',      count: 0, tot: 0 },
    bancomat:  { label: '💳 Bancomat',            count: 0, tot: 0 },
    contanti:  { label: '💵 Contanti',            count: 0, tot: 0 },
    daRegistrare: { label: '⚠️ Non registrato',   count: 0, tot: 0 },
  };
  const perModalita = {
    consegna: { label: '🛵 Consegna a domicilio', count: 0, tot: 0 },
    ritiro:   { label: '🏠 Ritiro in sede',        count: 0, tot: 0 },
  };
  let totaleGiorno = 0;

  orders.forEach(o => {
    const importo = Number(o.grandTotal || o.subtotale || 0);
    totaleGiorno += importo;

    const metodo = o.pagatoOnline ? 'online' : ((o.metodoPagamento && perMetodo[o.metodoPagamento]) ? o.metodoPagamento : 'daRegistrare');
    perMetodo[metodo].count++;
    perMetodo[metodo].tot += importo;

    const modalita = o.modalita === 'consegna' ? 'consegna' : 'ritiro';
    perModalita[modalita].count++;
    perModalita[modalita].tot += importo;
  });

  const oggi = new Date().toLocaleDateString('it-IT', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });

  let testo = `RESOCONTO GIORNALIERO — LA CASA DI CARTA\n${oggi}\n${'-'.repeat(40)}\n\n`;
  testo += `Ordini totali: ${orders.length}\nIncasso totale: ${money(totaleGiorno)}\n\n`;
  testo += `PAGAMENTI\n`;
  Object.values(perMetodo).forEach(v => { testo += `${v.label}: ${v.count} ordini — ${money(v.tot)}\n`; });
  testo += `\nCONSEGNA / RITIRO\n`;
  Object.values(perModalita).forEach(v => { testo += `${v.label}: ${v.count} ordini — ${money(v.tot)}\n`; });

  const logoUrl = `${SITE_URL}/icon-512.png?v=${ASSET_VERSION}`;
  const riga = (v) => `<tr><td style="padding:8px 0;border-bottom:1px solid #eee;color:#333;">${v.label}</td><td style="padding:8px 0;border-bottom:1px solid #eee;text-align:right;color:#8a8a8a;white-space:nowrap;">${v.count} ordini</td><td style="padding:8px 0;border-bottom:1px solid #eee;text-align:right;font-weight:700;color:#222;white-space:nowrap;">${money(v.tot)}</td></tr>`;
  const rigaFinale = (v) => `<tr><td style="padding:8px 0;color:#333;">${v.label}</td><td style="padding:8px 0;text-align:right;color:#8a8a8a;white-space:nowrap;">${v.count} ordini</td><td style="padding:8px 0;text-align:right;font-weight:700;color:#222;white-space:nowrap;">${money(v.tot)}</td></tr>`;
  const tabella = (obj) => {
    const rows = Object.values(obj);
    return rows.map((v,i) => i === rows.length-1 ? rigaFinale(v) : riga(v)).join('');
  };

  const html = `
<!DOCTYPE html>
<html lang="it">
<body style="margin:0;padding:0;background:#f4f1ee;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f1ee;padding:24px 0;">
    <tr><td align="center">
      <table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:18px;overflow:hidden;box-shadow:0 4px 18px rgba(0,0,0,0.08);">

        <tr><td style="background:linear-gradient(135deg,#c1382b,#7a1f16);padding:28px 24px;text-align:center;">
          <img src="${logoUrl}" alt="La Casa di Carta" width="72" height="72" style="border-radius:20px;display:block;margin:0 auto 12px;">
          <div style="color:#ffffff;font-size:20px;font-weight:700;letter-spacing:0.02em;">Resoconto giornaliero</div>
          <div style="color:rgba(255,255,255,0.85);font-size:13px;margin-top:2px;text-transform:capitalize;">${oggi}</div>
        </td></tr>

        <tr><td style="padding:26px 24px 6px;text-align:center;">
          <div style="font-size:13px;color:#8a8a8a;text-transform:uppercase;letter-spacing:0.06em;">Incasso totale</div>
          <div style="font-size:36px;font-weight:800;color:#c1382b;margin-top:4px;">${money(totaleGiorno)}</div>
          <div style="font-size:13px;color:#8a8a8a;margin-top:2px;">${orders.length} ordini ricevuti oggi</div>
        </td></tr>

        <tr><td style="padding:22px 24px 0;">
          <table width="100%" cellpadding="0" cellspacing="0" style="font-size:14px;background:#f8f5f2;border-radius:12px;padding:16px;">
            <tr><td colspan="3" style="padding:0 0 8px;font-weight:700;color:#222;">💰 Pagamenti</td></tr>
            ${tabella(perMetodo)}
          </table>
        </td></tr>

        <tr><td style="padding:16px 24px 0;">
          <table width="100%" cellpadding="0" cellspacing="0" style="font-size:14px;background:#f8f5f2;border-radius:12px;padding:16px;">
            <tr><td colspan="3" style="padding:0 0 8px;font-weight:700;color:#222;">📦 Consegna / Ritiro</td></tr>
            ${tabella(perModalita)}
          </table>
        </td></tr>

        <tr><td style="padding:22px 24px 28px;text-align:center;">
          <div style="font-size:13px;color:#8a8a8a;">Buon riposo — a domani! 🔥</div>
          <div style="font-size:12px;color:#b5b5b5;margin-top:14px;">La Casa di Carta · Via XX Settembre 192, Niscemi CL · +39 327 101 8160</div>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>`;

  return { testo, html, oggi };
}

async function sendDailyReport(){
  try {
    const { testo, html, oggi } = await buildDailyReport();
    await sendEmail(ORDER_EMAIL, `Resoconto giornaliero — ${oggi}`, testo, html);
    console.log('Resoconto giornaliero inviato.');
  } catch (err) {
    console.error('Errore invio resoconto giornaliero:', err);
  }
}

// Endpoint per testare subito il resoconto (utile prima di fidarsi dell'invio automatico delle 23:30)
app.get('/api/daily-report/test', async (req, res) => {
  await sendDailyReport();
  res.json({ ok: true, message: 'Resoconto inviato (controlla la mail).' });
});

let ultimoResocontoInviatoIl = null; // evita invii doppi nello stesso minuto/giorno
setInterval(() => {
  const now = new Date(); // ora italiana grazie a TZ=Europe/Rome
  const oggiKey = dateKey(now);
  if (now.getHours() === 23 && now.getMinutes() === 30 && ultimoResocontoInviatoIl !== oggiKey) {
    ultimoResocontoInviatoIl = oggiKey;
    sendDailyReport();
  }
}, 60 * 1000);

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
