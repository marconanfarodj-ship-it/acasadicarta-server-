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
  'https://pizzerialacasadicarta.it',
  'https://www.pizzerialacasadicarta.it',
  'https://cheerful-melomakarona-cc557e.netlify.app'
].concat((process.env.CORS_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean));
// Le app staff mandano un token nell'intestazione e non usano cookie, quindi possono chiamare
// da qualunque indirizzo. I cookie di login dei clienti, invece, vengono accettati SOLO dai nostri
// siti: prima venivano accettati da qualsiasi sito, e una pagina estranea poteva leggere i dati di un cliente loggato.
app.use(cors((req, callback) => {
  const origin = req.get('Origin');
  callback(null, { origin: true, credentials: !!origin && ALLOWED_ORIGINS.includes(origin) });
}));
app.use(cookieParser());
app.use((req, res, next) => {
  if (req.originalUrl === '/api/stripe-webhook') {
    next(); // qui serve il corpo "grezzo", non json già interpretato
  } else {
    express.json({ limit: '3mb' })(req, res, next);
  }
});

// =====================================================================
//  ACCESSO STAFF — protegge le rotte che modificano dati o mostrano dati dei clienti
//  (ordini, comande, clienti, prenotazioni, scorte, prezzi, blacklist...).
//  Si attiva impostando STAFF_CODE su Render (il codice che si scrive una volta sola
//  su ogni telefono/tablet dello staff). Senza STAFF_CODE tutto resta aperto come prima.
//  Chi può entrare: l'app Titolare (token titolare), lo staff (token staff dopo il codice)
//  e Jarvis (intestazione x-staff-key uguale a STAFF_KEY).
// =====================================================================
const STAFF_CODE = process.env.STAFF_CODE || '';
const cryptoGuardia = require('crypto');
function tokenStaff(){ return cryptoGuardia.createHmac('sha256', JWT_SECRET).update('staff:' + STAFF_CODE).digest('hex'); }
const ROTTE_STAFF = [
  ['GET',  /^\/api\/orders\/?$/],
  ['GET',  /^\/api\/orders\/(cerca|stream|non-stampati|pronti-consegna)\/?$/],
  ['POST', /^\/api\/orders\/(segna-stampato|interno)\/?$/],
  ['POST', /^\/api\/orders\/[^/]+\/(pronto|pagamento|in-consegna|ristampa)\/?$/],
  ['POST', /^\/api\/driver-location\/?$/],
  ['POST', /^\/api\/(custom-menu-items\/(add|delete)|orders-status\/toggle|solo-sala\/toggle|stampa\/dimensione|calendario\/giorno|menu-prices\/update|product-photos\/(upload|delete)|blacklist\/(add|remove)|sold-out\/(reset-all|bulk|toggle)|fedelta\/riscatta)\/?$/],
  ['GET',  /^\/api\/blacklist\/?$/],
  ['*',    /^\/api\/stampe(\/|$)/],
  ['*',    /^\/api\/staff\/comande(\/|$)/],
  ['*',    /^\/api\/(prenotazioni|clienti|scorte)(\/|$)/],
  ['GET',  /^\/api\/tavolo\/richieste\/?$/],
  ['POST', /^\/api\/tavolo\/richieste\/[^/]+\/[^/]+\/?$/],
  ['GET',  /^\/api\/tavolo\/chiamate\/?$/],
  ['POST', /^\/api\/tavolo\/chiamate\/[^/]+\/presa\/?$/],
  ['GET',  /^\/api\/daily-report\/test\/?$/],
  ['POST', /^\/api\/push\/(iscrivi|prova)\/?$/],
  ['GET',  /^\/api\/push\/recenti\/?$/],
  ['*',    /^\/api\/(consegne|cucina)(\/|$)/]
];
function haAccessoStaff(req){
  const q = String(req.query.t || '');
  const tit = req.get('x-titolare-token') || q;
  const sta = req.get('x-staff-token') || q;
  const chiave = req.get('x-staff-key') || '';
  if (passwordAttiva() && tit && uguali(tit, tokenTitolare())) return true;
  if (STAFF_CODE && sta && uguali(sta, tokenStaff())) return true;
  if (STAFF_KEY && chiave && uguali(chiave, STAFF_KEY)) return true;
  return false;
}
app.use('/api', (req, res, next) => {
  if (!STAFF_CODE || req.method === 'OPTIONS') return next();
  const percorso = req.originalUrl.split('?')[0];
  const metodo = req.method === 'HEAD' ? 'GET' : req.method;
  const protetta = ROTTE_STAFF.some(([m, rx]) => (m === '*' || m === metodo) && rx.test(percorso));
  if (!protetta || haAccessoStaff(req)) return next();
  // 'accesso_negato' = è l'app Titolare e il suo token è scaduto; 'accesso_staff' = serve il codice dello staff
  return res.status(401).json({ ok: false, error: req.get('x-titolare-token') ? 'accesso_negato' : 'accesso_staff' });
});
const tentativiStaffCode = new Map(); // ip -> { n, dal }
app.post('/api/staff/accesso', (req, res) => {
  if (!STAFF_CODE) return res.json({ ok: true, aperto: true, token: '' });
  const ip = req.ip || 'x';
  const t = tentativiStaffCode.get(ip) || { n: 0, dal: Date.now() };
  if (Date.now() - t.dal > 10 * 60 * 1000) { t.n = 0; t.dal = Date.now(); }
  if (t.n >= 10) return res.status(429).json({ ok: false, error: 'Troppi tentativi, riprova tra qualche minuto' });
  if (!uguali(String((req.body || {}).codice || ''), STAFF_CODE)) { t.n++; tentativiStaffCode.set(ip, t); return res.status(401).json({ ok: false, error: 'Codice sbagliato' }); }
  tentativiStaffCode.delete(ip);
  res.json({ ok: true, token: tokenStaff() });
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
if (!process.env.JWT_SECRET) console.warn('ATTENZIONE: JWT_SECRET non impostata su Render. Si sta usando la chiave di riserva, che è pubblica: imposta una chiave lunga e casuale.');
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";
const SITE_URL = process.env.SITE_URL || "https://ordini.pizzerialacasadicarta.it";
// password dell'app Titolare (incassi): si imposta SOLO su Render, mai scritta nel codice
const TITOLARE_PASSWORD = process.env.TITOLARE_PASSWORD || "";
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
// fino a quale giorno (compreso) un prodotto resta esaurito: 'YYYY-MM-DD', oppure null = finché non lo riattivo
let soldOutFino = new Map();
let blacklistCollection = null;
let blockedPhonesCache = new Set(); // riserva in memoria, usata se il database non è raggiungibile
let ordersPaused = false; // interruttore manuale: se true, il sito rifiuta ogni nuovo ordine
// calendario deciso dal titolare dal pannello: giorni di chiusura in più e martedì eccezionalmente aperti
let calendario = { chiusi: [], aperti: [] }; // date "YYYY-MM-DD"
// grandezza dei caratteri in stampa, scelta dal titolare: 'piccola' | 'media' | 'grande'
const DIMENSIONI_STAMPA = ['piccola', 'media', 'grande'];
let dimensioneStampa = 'media';
let settingsCollection = null;
let soloSalaCache = new Set();  // piatti ordinabili solo in sala (nascosti nel sito clienti)
let soloOnlineCache = new Set(); // piatti ordinabili solo online (nascosti in sala: app staff, QR tavolo e banco)
let comandeCollection = null;
let stampeCollection = null;    // stampe dello staff in attesa di conferma dal tablet che stampa   // comande dell'app staff (sala, banco, telefono)
let comandeMemoria = {};        // riserva in memoria se il database non è disponibile

// prezzi di partenza di ogni voce del menu (chiave uguale a quella usata per gli esauriti);
// quando il titolare modifica un prezzo dal pannello, il nuovo valore viene salvato in
// priceOverridesCache e ha sempre la precedenza su questi valori di base.
const DEFAULT_PRICES = {"Pizza|Faccia Di Vecchia": 3, "Pizza|Rossa": 4, "Pizza|Biancaneve": 5, "Pizza|Marinara": 4.5, "Pizza|Margherita": 5, "Pizza|Patapizza": 6.5, "Pizza|Bufala": 7, "Pizza|Diavola": 6, "Pizza|Pizza Regina": 7, "Pizza|Tonno & Cipolla": 7, "Pizza|Napoli": 6.5, "Pizza|Oslo": 6.5, "Pizza|Norma": 6.5, "Pizza|Berlino": 7, "Pizza|Tropea": 8.5, "Pizza|Helsinki": 9, "Pizza|Sfiziosa": 9, "Pizza|Nairobi": 9, "Pizza|Mosca": 9, "Pizza|Rio": 8.5, "Pizza|Tutti I Gusti": 9, "Pizza|Ripiegata": 8.5, "Pizza|4 Formaggi": 8, "Pizza|007": 8, "Pizza|La Casa Di Carta": 8.5, "Pizza|Parmigiana": 8, "Pizza|4 Stagioni": 8, "Pizza|Bella Ciao": 8, "Pizza|Marsiglia": 8.5, "Pizza|Ai Porcini": 9, "Pizza|Vegetariana": 8, "Pizza|Pizza Kebab": 9, "Pizza|Gustosa": 9, "Pizza|Tokio": 8.5, "Pizza|Bogotà": 11, "Pizza|Frutti Di Mare": 11, "Pizza|Cincinnati": 10, "Pizza|Suprema": 13, "Pizza|Denver": 8, "Pizza|Capricciosa": 8, "Pizza Dolce|Nutella": 5, "Pizza Dolce|Kinder Bueno": 7, "Pizza Dolce|Dubai": 7, "Panini|Panino Patatine, Wurstel": 3, "Panini|Panino con Patatine": 2.5, "Panini|Panino Crocchette di Patate & Patatine": 3, "Panini|Panino Patatine, Wurstel in Salsa Rosa": 3.5, "Panini|Panino Pollo al Curry & Patatine": 5, "Panini|Panino Pollo ai Funghi & Patatine": 5.5, "Panini|Panino Pollo Impanato & Patatine": 5, "Panini|Panino Pollo Messicano & Patatine": 5, "Panini|Panino Pollo al Barbecue & Patatine": 5, "Panini|Panino Petto di Pollo alla Griglia & Patatine": 5, "Panini|Panino Arrosto di Pollo & Patatine": 5, "Panini|Panino Petto di Pollo Sfilettato & Patatine": 5, "Panini|Panino Porchettata & Patatine": 4, "Panini|Panino Salame Piccante e Mozzarella & Patatine": 4, "Panini|Panino Salame Piccante e Svizzero & Patatine": 4, "Panini|Panino Bella Ciao & Patatine": 5.5, "Panini|Panino 4 Formaggi & Patatine": 4.5, "Panini|Panino Prosciutto Mozzarella & Patatine": 4, "Panini|Cocktail Di Tonno & Patatine": 5, "Panini|Panino Kebab & Patatine": 5, "Panini|Panino Polpette di Cavallo & Patatine": 6, "Panini|Panino Cavallo & Patatine": 6, "Panini|Panino Salsiccia & Patatine": 5, "Panini|Panino in Cocktail di Gamberi in Salsa Rosa & Patatine": 6.5, "Panini|Hamburger di Scottona & Patatine": 6, "Panini|Hamburger di Angus & Patatine": 6, "Panini|Panino Porchetta Artigianale e Patatine": 6, "Panini|Panino con Salsiccia di Cavallo & Patatine": 6, "Hamburger|Brooklyn": 5, "Hamburger|Bronx": 8, "Hamburger|Spicy": 8, "Hamburger|Manathan": 9, "Hamburger|Queens": 5, "Focacce|Focaccia Vuota Da Condire": 3, "Focacce|Casareccia": 4.5, "Focacce|Focaccia Prosciutto": 6.5, "Focacce|Focaccia Caprese": 6.5, "Focacce|Focaccia Del Pirata": 6.5, "Focacce|Focaccia Mista": 7, "Focacce|Deliziosa": 7, "Focacce|Focaccia 4 Formaggi": 7.5, "Focacce|Bella Ciao": 8, "Focacce|Focaccia Nairobi": 9, "Fritture|Vaschetta Piccola — Patatine": 2, "Fritture|Vaschetta Media — Patatine": 3, "Fritture|Patatine con Buccia": 3, "Fritture|Vaschetta Piccola — 4 Würstel & Patatine": 2, "Fritture|Vaschetta — 8 Würstel": 2, "Fritture|Vaschetta — Crocchette di Patate": 2, "Fritture|Vaschetta di Kebab": 3, "Fritture|Anelli di Cipolla": 3, "Fritture|Panzerotti Fritti Mignon Pomodoro e Mozzarella": 3, "Fritture|Mozzarelline Impanate": 3.5, "Fritture|Bocconcini Pollo Amadori Impanato Piccante": 3.5, "Fritture|Arancini Mignon al Ragù": 3, "Fritture|Nuggets 10 Pezzi": 5, "Bevande|Gassosa": 1, "Bevande|Acqua Naturale Piccola": 1, "Bevande|Acqua Frizzante": 1, "Bevande|Coca Cola 33": 2, "Bevande|Coca Cola Zero": 2, "Bevande|Birra Moretti": 2, "Bevande|Birra Peroni": 2, "Bevande|Coca Cola Vetro cl 33": 2.5, "Bevande|Estathe Pesca": 2.5, "Bevande|Estathe Limone": 2.5, "Bevande|Nastro Azzurro": 3, "Bevande|Ceres": 3.5, "Bevande|Coca Cola Bottiglia Grande": 4, "Bevande|Birra Messina Grande": 5, "Bevande|Birra Nastro Azzurro Grande": 5, "Bevande|Peroni Chill Lemon": 2.5, "Extra|Bustina Maionese": 0.25, "Extra|Bustina Ketchup": 0.25, "EXTRA_PIZZA|Extra Mozzarella": 1.5, "EXTRA_PIZZA|Scaglie di Grana Padano DOP": 1, "EXTRA_PIZZA|Patatine": 1.5, "EXTRA_PIZZA|Gorgonzola": 1, "EXTRA_PIZZA|Formaggio Svizzero": 0.5, "EXTRA_PIZZA|Prosciutto Crudo Ferrarini": 1.5, "EXTRA_PIZZA|Olive": 0.5, "EXTRA_PIZZA|Rucola": 0.5, "EXTRA_PIZZA|Ciliegino": 0.5, "EXTRA_PIZZA|Piselli": 0.5, "EXTRA_PIZZA|Funghi": 1, "EXTRA_PIZZA|Speck": 1, "EXTRA_PIZZA|Funghi Porcini": 2.5, "EXTRA_PIZZA|Lattuga": 0.5, "EXTRA_PIZZA|Spinaci": 0.5, "EXTRA_PIZZA|Cipolla": 0.5, "EXTRA_PIZZA|Carciofi in Spicchi": 1, "EXTRA_PIZZA|Prosciutto Cotto": 1, "EXTRA_PIZZA|Uovo": 0.5, "EXTRA_PIZZA|Wurstel": 0.5, "EXTRA_PIZZA|Granella di Pistacchio": 2, "EXTRA_PIZZA|Crocchette Patate": 1, "EXTRA_PIZZA|Crema di Pistacchio": 2, "EXTRA_PIZZA|Acciughe": 1, "EXTRA_PIZZA|Tonno": 1.5, "EXTRA_PIZZA|Salame Piccante": 1, "EXTRA_PIZZA|Bresaola": 2.5, "EXTRA_PIZZA|Polpette di Cavallo": 3, "EXTRA_PIZZA|Bacon": 1, "EXTRA_PIZZA|Mozzarella di Bufala": 2, "EXTRA_PIZZA|Salmone": 2.5, "EXTRA_PIZZA|Patate della Nonna": 1, "EXTRA_PIZZA|Salsiccia di Maiale": 1.5, "EXTRA_PIZZA|Fettina di Pollo alla Griglia": 3.5, "EXTRA_PIZZA|Pollo Sfilettato": 3.5, "EXTRA_PIZZA|Pollo al Curry": 3.5, "EXTRA_PIZZA|Fettina di Cavallo": 4, "EXTRA_PIZZA|Melanzana Fritta": 1, "EXTRA_PIZZA|Stracciatella di Bufala": 2, "EXTRA_PIZZA|Capuliato": 0.5, "EXTRA_PIZZA|Kebab": 3.5, "EXTRA_PIZZA|Pollo Impanato": 4, "EXTRA_PIZZA|Cipolla Croccante": 0.5, "EXTRA_PANINO|Lattuga": 0.5, "EXTRA_PANINO|Ciliegino": 0.5, "EXTRA_PANINO|Cipolla": 0.5, "EXTRA_PANINO|Mozzarella": 0.5, "EXTRA_PANINO|Gorgonzola": 0.5, "EXTRA_PANINO|Würstel": 0.5, "EXTRA_PANINO|Grana Padano DOP": 0.5, "EXTRA_PANINO|Formaggio Svizzero": 0.5, "EXTRA_PANINO|Prosciutto Crudo": 1.5, "EXTRA_PANINO|Speck": 0.5, "EXTRA_PANINO|Prosciutto Cotto": 1, "EXTRA_PANINO|Crocchette di Patate": 1, "EXTRA_PANINO|Salame Piccante": 1, "EXTRA_PANINO|Funghi Freschi": 1, "EXTRA_PANINO|Mozzarella di Bufala": 2, "EXTRA_PANINO|Granella di Pistacchio": 1, "EXTRA_PANINO|Crema di Pistacchio": 1, "EXTRA_PANINO|Würstel in Salsa Rosa": 1.5, "EXTRA_PANINO|Bresaola": 2, "EXTRA_PANINO|Rucola": 0.5, "EXTRA_PANINO|Salmone 50g": 3, "EXTRA_PANINO|Funghi Piccanti": 1, "EXTRA_PANINO|Cipolla Croccante": 0.5};
let priceOverridesCollection = null;
let priceOverridesCache = {}; // prezzi cambiati dal titolare (riempito dal database all'avvio)

function getCurrentPrice(chiave){
  if (priceOverridesCache[chiave] !== undefined) return priceOverridesCache[chiave];
  if (DEFAULT_PRICES[chiave] !== undefined) return DEFAULT_PRICES[chiave];
  return null;
}

// Foto dei singoli piatti caricate dal titolare dal pannello di stampa.
// Salvate come immagine (base64) dentro MongoDB, chiave uguale a quella usata per prezzi/esauriti.
let productPhotosVer = {}; // chiave -> data ultimo cambio (ms), serve a rinfrescare la cache delle foto
let productPhotosCache = {}; // chiave -> { data: "data:image/jpeg;base64,...", updatedAt }
let productPhotosCollection = null;

// Piatti nuovi aggiunti dal titolare dal pannello di stampa (in più rispetto al menu di base).
let menuTestiCache = {}; // nome e descrizione mostrati per i piatti di base: { 'Pizza|Margherita': { nome, desc } }
let menuTestiCollection = null;
let customMenuItemsCache = []; // [{ cat, nome, descrizione, prezzo }]
let customMenuItemsCollection = null;


async function connectDB(){
  if(!MONGODB_URI){
    console.log('MONGODB_URI non impostata: gli account cliente non funzioneranno.');
    setTimeout(() => segnaStoricoPronto(), 0);   // senza database non c'è storico da aspettare
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
    // quelli segnati prima di questa funzione non avevano una scadenza: valgono per la giornata di oggi
    soldOutFino = new Map(soldOutDocs.map(d => [d._id, d.fino === undefined ? giornoServizio() : d.fino]));
    scadenzaEsauriti();
    const blockedDocs = await blacklistCollection.find({}).toArray();
    blockedPhonesCache = new Set(blockedDocs.map(d => d._id));
    priceOverridesCollection = db.collection('priceOverrides');
    const priceDocs = await priceOverridesCollection.find({}).toArray();
    priceOverridesCache = {};
    priceDocs.forEach(d => { priceOverridesCache[d._id] = d.prezzo; });
    settingsCollection = db.collection('settings');
    const pausedDoc = await settingsCollection.findOne({ _id: 'ordersPaused' });
    ordersPaused = !!(pausedDoc && pausedDoc.value);
    const salaDoc = await settingsCollection.findOne({ _id: 'soloSala' });
    if (salaDoc && Array.isArray(salaDoc.value)) soloSalaCache = new Set(salaDoc.value);
    const onlineDoc = await settingsCollection.findOne({ _id: 'soloOnline' });
    if (onlineDoc && Array.isArray(onlineDoc.value)) soloOnlineCache = new Set(onlineDoc.value);
    const costiDoc = await settingsCollection.findOne({ _id: 'costi' });
    if (costiDoc && costiDoc.value) COSTO_INGREDIENTI = costiDoc.value;
    const cfgDoc = await settingsCollection.findOne({ _id: 'config' });
    if (cfgDoc && cfgDoc.value) impostaConfig(cfgDoc.value);
    const pwDoc = await settingsCollection.findOne({ _id: 'titolarePassword' });
    if (pwDoc && pwDoc.hash) titolarePwHash = pwDoc.hash;
    const calDoc = await settingsCollection.findOne({ _id: 'calendario' });
    if (calDoc && calDoc.value) calendario = { chiusi: calDoc.value.chiusi || [], aperti: calDoc.value.aperti || [] };
    try {
      const vDoc = await settingsCollection.findOne({ _id: 'vapid' });
      if (vDoc && vDoc.value && vDoc.value.pub) vapid = vDoc.value;
      else { vapid = nuoveChiaviVapid(); await settingsCollection.updateOne({ _id: 'vapid' }, { $set: { value: vapid } }, { upsert: true }); }
      pushCollection = db.collection('pushIscrizioni');
      (await pushCollection.find({}).toArray()).forEach(d => pushIscritti.set(d._id, d));
    } catch (e) { console.error('Notifiche push: avvio non riuscito', e.message); }
    const faDoc = await settingsCollection.findOne({ _id: 'fattorini' });
    if (faDoc && Array.isArray(faDoc.value) && faDoc.value.length) fattorini = faDoc.value;
    const vieDoc = await settingsCollection.findOne({ _id: 'vieNiscemi' });
    if (vieDoc && vieDoc.value && Array.isArray(vieDoc.value.vie)) vieNiscemi = vieDoc.value;
    setTimeout(() => aggiornaVie().catch(() => {}), 15000);
    const piDoc = await settingsCollection.findOne({ _id: 'piantina' });
    if (piDoc && piDoc.value && Array.isArray(piDoc.value.oggetti)) piantinaSala = piDoc.value;
    const dimDoc = await settingsCollection.findOne({ _id: 'dimensioneStampa' });
    if (dimDoc && DIMENSIONI_STAMPA.includes(dimDoc.value)) dimensioneStampa = dimDoc.value;
    productPhotosCollection = db.collection('productPhotos');
    const photoDocs = await productPhotosCollection.find({}, { projection: { data: 0 } }).toArray();
    // all'avvio carichiamo solo l'elenco delle chiavi con foto (leggero); l'immagine vera si scarica
    // una alla volta quando serve, tramite /api/product-photos/img/:chiave
    photoDocs.forEach(d => { productPhotosCache[d._id] = true; productPhotosVer[d._id] = Date.parse(d.updatedAt) || 1; });
    comandeCollection = db.collection('comandeStaff');
    stampeCollection = db.collection('stampeStaff');
    await stampeCollection.createIndex({ fatta: 1, creata: 1 });
    await comandeCollection.createIndex({ stato: 1, aggiornataAlle: -1 });
    customMenuItemsCollection = db.collection('customMenuItems');
    customMenuItemsCache = await customMenuItemsCollection.find({}).toArray();
    menuTestiCollection = db.collection('menuTesti');
    menuTestiCache = {};
    (await menuTestiCollection.find({}).toArray()).forEach(d => { menuTestiCache[d._id] = { nome: d.nome || '', desc: d.desc || '' }; });
    console.log('Connesso a MongoDB Atlas.');
    riprendiStorico();
  }catch(err){
    console.error('Errore connessione MongoDB:', err);
    setTimeout(() => segnaStoricoPronto(), 0);
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
let MAX_PER_SLOT = 3;
let MIN_DELIVERY_ORDER = 10.00;
let OPEN_FROM_HOUR = 19;
let OPEN_TO_HOUR = 23;
let CLOSED_WEEKDAY = 2; // 0=domenica, 1=lunedì, 2=martedì...
let MAX_DAYS_AHEAD = 3; // si può ordinare/prenotare da oggi fino a 3 giorni dopo
let ASAP_DISABLED_WEEKDAYS_CONSEGNA = [0, 6]; // 0=domenica, 6=sabato: niente "il prima possibile" per le consegne

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

let SCONTO_PRIMO_ORDINE = 0.10; // 10%, solo sui piatti (mai sulle spese di consegna)

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
let SPESE_CONSEGNA_BASE = 1.50;
let RAGGIO_PAESE_KM = 2.5;
let SOVRAPPREZZO_FUORI_PAESE = 3.00;
let RAGGIO_MAX_KM = 8;

// =====================================================================
//  IMPOSTAZIONI DEL TITOLARE (scheda ⚙️ dell'app Titolare)
//  Salvate nel database (settings _id 'config'); questi sono i valori di partenza.
// =====================================================================
const CONFIG_BASE = {
  consegna: { speseBase: 1.50, raggioPaeseKm: 2.5, sovrapprezzoFuori: 3.00, raggioMaxKm: 8, ordineMinimo: 10 },
  orari: { dalle: 19, alle: 23, giornoChiusura: 2, ordiniPerQuarto: 3, giorniAnticipo: 3, noSubitoConsegna: [0, 6] },
  sito: { avvisoAttivo: false, avvisoTesto: '', scontoPrimoOrdine: 10, pagamenti: { contanti: true, carta: true, online: true } },
  sala: { sale: [{ nome: 'Sala', tavoli: 40 }], qrAttivo: true },
  camerieri: [],   // [{ nome, pin }] — il pin non esce mai dal server
  avvisi: { attivi: true, ritardoMinuti: 10, tavoloMinuti: 120, nonMandatiMinuti: 5, ordineGrande: 60 },
  offerte: [],     // [{ id, nome, attiva, tipo: 'percento'|'euro', valore, codice, giorni: [], minimo, scadenza }]
  fedelta: { attiva: false, ogni: 10, premio: 'Una pizza Margherita in omaggio' },
  recensioni: { attiva: false, link: '', dopoOre: 18 },
  // salse gratuite di panini, hamburger e fritture: le gestisce il titolare
  salse: ['Ketchup', 'Maionese', 'Salsa Cheddar', 'Salsa Barbecue', 'Salsa Chili', 'Salsa Curry', 'Salsa Rosa', 'Salsa Hamburger', 'Salsa Yogurt', 'Tabasco'],
  stampa: { prezziComanda: true, totaleComanda: true, spazioTraProdotti: true, logo: true,
    intestazioneConto: 'PIZZERIA LA CASA DI CARTA\nVia XX Settembre 192 - Niscemi', piedeConto: 'Grazie e arrivederci!',
    // due stampanti: dove va ogni tipo di stampa (1 = prima, 2 = seconda, 3 = tutte e due)
    nome1: 'Cucina', nome2: 'Stampante 2', instrada: { sito: 1, noi: 1, banco: 1, conti: 1, cassa: 1, pizze: 1, panini: 2 }, stile: {},
    // comanda con pizze e panini: due scontrini (pizze/focacce e panini/hamburger/fritture/bevande)
    dividi: true }
};
let CONFIG = JSON.parse(JSON.stringify(CONFIG_BASE));
function cfgNum(v, min, max, def, intero){
  const n = Number(String(v ?? '').replace(',', '.'));
  if (v === '' || v === null || v === undefined || !Number.isFinite(n)) return def;
  const x = Math.min(max, Math.max(min, n));
  return intero ? Math.round(x) : Math.round(x * 100) / 100;
}
function cfgBool(v, def){ return typeof v === 'boolean' ? v : def; }
function cfgTesto(v, max, def){ return typeof v === 'string' ? v.replace(/\r/g, '').slice(0, max) : def; }
// unisce le modifiche arrivate dall'app ai valori attuali, controllando che siano sensate
function pulisciConfig(inp, attuale){
  const c = JSON.parse(JSON.stringify(attuale));
  const i = inp || {};
  if (i.consegna) {
    const x = i.consegna, d = c.consegna;
    d.speseBase = cfgNum(x.speseBase, 0, 30, d.speseBase);
    d.raggioPaeseKm = cfgNum(x.raggioPaeseKm, 0.5, 30, d.raggioPaeseKm);
    d.sovrapprezzoFuori = cfgNum(x.sovrapprezzoFuori, 0, 30, d.sovrapprezzoFuori);
    d.raggioMaxKm = Math.max(d.raggioPaeseKm, cfgNum(x.raggioMaxKm, 0.5, 60, d.raggioMaxKm));
    d.ordineMinimo = cfgNum(x.ordineMinimo, 0, 300, d.ordineMinimo);
  }
  if (i.orari) {
    const x = i.orari, d = c.orari;
    d.dalle = cfgNum(x.dalle, 0, 23, d.dalle, true);
    d.alle = cfgNum(x.alle, 1, 24, d.alle, true);
    if (d.alle <= d.dalle) d.alle = Math.min(24, d.dalle + 1);
    d.giornoChiusura = cfgNum(x.giornoChiusura, -1, 6, d.giornoChiusura, true);
    d.ordiniPerQuarto = cfgNum(x.ordiniPerQuarto, 1, 50, d.ordiniPerQuarto, true);
    d.giorniAnticipo = cfgNum(x.giorniAnticipo, 0, 14, d.giorniAnticipo, true);
    if (Array.isArray(x.noSubitoConsegna)) d.noSubitoConsegna = [...new Set(x.noSubitoConsegna.map(Number).filter(n => Number.isInteger(n) && n >= 0 && n <= 6))].sort();
  }
  if (i.sito) {
    const x = i.sito, d = c.sito;
    d.avvisoAttivo = cfgBool(x.avvisoAttivo, d.avvisoAttivo);
    d.avvisoTesto = cfgTesto(x.avvisoTesto, 300, d.avvisoTesto);
    d.scontoPrimoOrdine = cfgNum(x.scontoPrimoOrdine, 0, 50, d.scontoPrimoOrdine, true);
    if (x.pagamenti) ['contanti', 'carta', 'online'].forEach(k => { d.pagamenti[k] = cfgBool(x.pagamenti[k], d.pagamenti[k]); });
    if (!d.pagamenti.contanti && !d.pagamenti.carta && !d.pagamenti.online) d.pagamenti.contanti = true; // almeno un modo di pagare
  }
  if (i.sala && typeof i.sala.qrAttivo === 'boolean') c.sala.qrAttivo = i.sala.qrAttivo;
  if (Array.isArray(i.salse)) {
    const viste = new Set();
    c.salse = i.salse.slice(0, 40).map(x => cfgTesto(x, 40, '').replace(/[<>"'`\\]/g, '').trim()).filter(x => x && !viste.has(x.toLowerCase()) && viste.add(x.toLowerCase()));
  }
  if (Array.isArray(i.camerieri)) {
    const visti = new Set();
    c.camerieri = i.camerieri.slice(0, 30).map(x => {
      const nome = cfgTesto(x && x.nome, 30, '').trim();
      // pin: 4 cifre; se arriva "***" teniamo quello già salvato
      const vecchio = (attuale.camerieri || []).find(v => v.nome === nome);
      let pin = String((x && x.pin) || '').trim();
      if (pin === '***') pin = vecchio ? vecchio.pin : '';
      if (pin && !/^\d{4}$/.test(pin)) pin = vecchio ? vecchio.pin : '';
      return { nome, pin };
    }).filter(x => x.nome && !visti.has(x.nome.toLowerCase()) && visti.add(x.nome.toLowerCase()));
  }
  if (Array.isArray(i.offerte)) {
    c.offerte = i.offerte.slice(0, 20).map((x, k) => {
      x = x || {};
      const vecchia = (attuale.offerte || []).find(v => v.id === x.id);
      let codice = cfgTesto(x.codice, 20, '').trim().toUpperCase().replace(/[^A-Z0-9_-]/g, '');
      if (x.codice === '***' && vecchia) codice = vecchia.codice;
      return {
        id: cfgTesto(x.id, 20, '') || Math.random().toString(36).slice(2, 10),
        nome: cfgTesto(x.nome, 60, '').trim() || `Offerta ${k + 1}`,
        attiva: cfgBool(x.attiva, true),
        tipo: x.tipo === 'euro' ? 'euro' : 'percento',
        valore: cfgNum(x.valore, 0, x.tipo === 'euro' ? 200 : 90, 10),
        codice,
        giorni: Array.isArray(x.giorni) ? [...new Set(x.giorni.map(Number).filter(n => Number.isInteger(n) && n >= 0 && n <= 6))].sort() : [],
        minimo: cfgNum(x.minimo, 0, 500, 0),
        scadenza: /^\d{4}-\d{2}-\d{2}$/.test(x.scadenza || '') ? x.scadenza : ''
      };
    });
  }
  if (i.fedelta) {
    const x = i.fedelta, d = c.fedelta;
    d.attiva = cfgBool(x.attiva, d.attiva);
    d.ogni = cfgNum(x.ogni, 2, 100, d.ogni, true);
    d.premio = cfgTesto(x.premio, 80, d.premio);
  }
  if (i.recensioni) {
    const x = i.recensioni, d = c.recensioni;
    d.attiva = cfgBool(x.attiva, d.attiva);
    d.link = /^https:\/\/[^\s"<>]{6,300}$/.test(String(x.link || '').trim()) ? String(x.link).trim() : (x.link === '' ? '' : d.link);
    d.dopoOre = cfgNum(x.dopoOre, 1, 72, d.dopoOre, true);
  }
  if (i.avvisi) {
    const x = i.avvisi, d = c.avvisi;
    d.attivi = cfgBool(x.attivi, d.attivi);
    d.ritardoMinuti = cfgNum(x.ritardoMinuti, 1, 120, d.ritardoMinuti, true);
    d.tavoloMinuti = cfgNum(x.tavoloMinuti, 10, 600, d.tavoloMinuti, true);
    d.nonMandatiMinuti = cfgNum(x.nonMandatiMinuti, 1, 60, d.nonMandatiMinuti, true);
    d.ordineGrande = cfgNum(x.ordineGrande, 0, 1000, d.ordineGrande);
  }
  if (i.sala && Array.isArray(i.sala.sale)) {
    const sale = i.sala.sale.slice(0, 8).map((x, k) => ({
      nome: cfgTesto(x && x.nome, 30, '').trim() || `Sala ${k + 1}`,
      tavoli: cfgNum(x && x.tavoli, 1, 150, 10, true)
    }));
    if (sale.length) c.sala.sale = sale;
  }
  if (i.stampa) {
    const x = i.stampa, d = c.stampa;
    ['prezziComanda', 'totaleComanda', 'spazioTraProdotti', 'logo'].forEach(k => { d[k] = cfgBool(x[k], d[k]); });
    d.intestazioneConto = cfgTesto(x.intestazioneConto, 200, d.intestazioneConto);
    d.piedeConto = cfgTesto(x.piedeConto, 200, d.piedeConto);
    d.nome1 = cfgTesto(x.nome1, 20, d.nome1 || 'Cucina') || 'Cucina';
    d.nome2 = cfgTesto(x.nome2, 20, d.nome2 || 'Stampante 2') || 'Stampante 2';
    const ins = { sito: 1, noi: 1, banco: 1, conti: 1, cassa: 1, pizze: 1, panini: 2, ...(d.instrada || {}) };
    d.dividi = cfgBool(x.dividi, d.dividi !== false);
    if (x.instrada && typeof x.instrada === 'object') Object.keys(ins).forEach(k => { const v = Number(x.instrada[k]); if ([1, 2, 3].includes(v)) ins[k] = v; });
    d.instrada = ins;
    if (x.stile && typeof x.stile === 'object') {
      const SEZ = ['numero', 'fascia', 'orario', 'indirizzo', 'cliente', 'telefono', 'pagamento', 'piatto', 'dettagli', 'senza', 'note', 'totale'];
      const st = {};
      SEZ.forEach(id => {
        const o = x.stile[id]; if (!o || typeof o !== 'object') return;
        const r = {};
        if (['normale', 'alto', 'largo', 'grande', 'enorme'].includes(o.dim)) r.dim = o.dim;
        ['bold', 'ul', 'inv'].forEach(b => { if (typeof o[b] === 'boolean') r[b] = o[b]; });
        if (Object.keys(r).length) st[id] = r;
      });
      d.stile = st;
    }
  }
  return c;
}
function impostaConfig(inp){
  CONFIG = pulisciConfig(inp, CONFIG);
  const k = CONFIG.consegna, o = CONFIG.orari;
  SPESE_CONSEGNA_BASE = k.speseBase; RAGGIO_PAESE_KM = k.raggioPaeseKm; SOVRAPPREZZO_FUORI_PAESE = k.sovrapprezzoFuori;
  RAGGIO_MAX_KM = k.raggioMaxKm; MIN_DELIVERY_ORDER = k.ordineMinimo;
  OPEN_FROM_HOUR = o.dalle; OPEN_TO_HOUR = o.alle; CLOSED_WEEKDAY = o.giornoChiusura;
  MAX_PER_SLOT = o.ordiniPerQuarto; MAX_DAYS_AHEAD = o.giorniAnticipo; ASAP_DISABLED_WEEKDAYS_CONSEGNA = o.noSubitoConsegna;
  SCONTO_PRIMO_ORDINE = CONFIG.sito.scontoPrimoOrdine / 100;
}

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
// offerte del titolare: automatiche (senza codice) o con codice sconto. Torna la migliore valida adesso.
function offertaMigliore(subtotale, codice){
  const oggi = giornoServizio(), dow = new Date(oggi + 'T12:00:00').getDay();
  const cod = String(codice || '').trim().toUpperCase();
  let migliore = null;
  (CONFIG.offerte || []).forEach(o => {
    if (!o.attiva) return;
    if (o.codice && o.codice !== cod) return;
    if (o.giorni && o.giorni.length && !o.giorni.includes(dow)) return;
    if (o.scadenza && o.scadenza < oggi) return;
    if (subtotale < (o.minimo || 0)) return;
    const sconto = round2(o.tipo === 'euro' ? Math.min(o.valore, subtotale) : subtotale * o.valore / 100);
    if (sconto > 0 && (!migliore || sconto > migliore.sconto)) migliore = { nome: o.nome, sconto, conCodice: !!o.codice };
  });
  return migliore;
}
async function applyFirstOrderDiscount(order){
  const subtotaleBase = round2(Number(order.subtotaleBase != null ? order.subtotaleBase : order.subtotale) || 0);
  const eligible = SCONTO_PRIMO_ORDINE > 0 && await isFirstOrderForPhone(order.phone, order.address);
  const scontoPrimo = eligible ? round2(subtotaleBase * SCONTO_PRIMO_ORDINE) : 0;
  // vale lo sconto più alto tra primo ordine e offerta (non si sommano)
  const off = offertaMigliore(subtotaleBase, order.codiceSconto);
  let sconto = scontoPrimo, riga = `🎉 Sconto primo ordine (${Math.round(SCONTO_PRIMO_ORDINE * 100)}%)`;
  order.scontoPrimoOrdine = scontoPrimo; order.scontoOfferta = 0; order.offerta = null;
  if (off && off.sconto > scontoPrimo) {
    sconto = off.sconto; riga = `🎁 ${off.nome}`;
    order.scontoPrimoOrdine = 0; order.scontoOfferta = off.sconto; order.offerta = off.nome;
  }

  order.subtotaleBase = subtotaleBase;
  order.subtotale = round2(subtotaleBase - sconto);
  order.grandTotal = round2(order.subtotale + (Number(order.speseConsegna) || 0));

  if (order.testoStampa) {
    // togliamo le righe sconto scritte dal sito (potrebbero essere sbagliate/vecchie) e le
    // riscriviamo noi, insieme al totale finale, in base al calcolo vero appena fatto qui sopra
    order.testoStampa = order.testoStampa.replace(/\n(?:🎉 Sconto primo ordine|🎁 )[^\n]*\n/g, '\n');
    if (sconto > 0) {
      order.testoStampa = order.testoStampa.replace(
        /\n(-{5,}\nTOTALE:)/,
        `\n${riga}: -${money(sconto)}\n$1`
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
// Chi ascolta solo per avvisare (Jarvis, con ?solo_avvisi=1) riceve gli ordini ma NON conta come pannello di stampa:
// altrimenti con Jarvis aperto e la cucina spenta un ordine verrebbe segnato "stampato" senza esserlo.
const pannelliStampa = () => printClients.filter(r => !r.soloAvvisi).length;

function broadcastOrder(order) {
  const payload = `data: ${JSON.stringify(order)}\n\n`;
  printClients.forEach(res => {
    try { res.write(payload); } catch (e) { /* il client verrà rimosso al prossimo "close" */ }
  });
}

// Un "battito" ogni 25 secondi: tiene viva la connessione attraverso eventuali proxy/timeout
// di rete, ed evita che il pannello resti "appeso" senza accorgersi che la linea è caduta.
// Al pannello di stampa il battito arriva come messaggio vero ({"evento":"ping"}): così si accorge se la linea
// è morta anche quando il browser la crede aperta, e si ricollega da solo. A Jarvis resta il battito "muto".
setInterval(() => {
  printClients = printClients.filter(res => {
    try { res.write(res.soloAvvisi ? ': ping\n\n' : 'data: {"evento":"ping"}\n\n'); return true; }
    catch (e) { return false; }
  });
}, 25000);

// ---------- Storico ordini in memoria (si azzera se il server si riavvia) ----------
let orderHistory = [];
const MAX_HISTORY = 100;
// cerca un ordine: prima in memoria, poi nel database (dopo un riavvio del server la memoria è vuota)
// filtro per aggiornare nel database proprio QUESTO ordine: i numeri vecchi si ripetevano
// (prima la numerazione ripartiva da 1001 a ogni riavvio), quindi conta anche l'ora di arrivo
function filtroOrdine(order){
  return order && order.ricevutoAlle ? { numeroOrdine: order.numeroOrdine, ricevutoAlle: order.ricevutoAlle } : { numeroOrdine: order.numeroOrdine };
}
async function trovaOrdine(numeroOrdine){
  let order = orderHistory.find(o => o.numeroOrdine === numeroOrdine);
  if (order || !ordersCollection || !numeroOrdine) return order || null;
  try {
    const doc = await ordersCollection.findOne({ numeroOrdine }, { sort: { ricevutoAlle: -1 } }); // il più recente con quel numero
    if (!doc) return null;
    delete doc._id;
    order = orderHistory.find(o => o.numeroOrdine === numeroOrdine); // nel frattempo potrebbe essere arrivato
    if (order) return order;
    orderHistory.push(doc);
    if (orderHistory.length > MAX_HISTORY * 2) orderHistory.splice(MAX_HISTORY * 2);
    return doc;
  } catch (err) {
    console.error('Errore ricerca ordine nel database:', err);
    return null;
  }
}
let orderCounter = 1000;
// all'avvio (anche dopo che Render ha "addormentato" il server) si riprendono dal database
// la numerazione degli ordini e gli ultimi ordini: niente più numeri ripetuti né elenco vuoto
let segnaStoricoPronto; const storicoPronto = new Promise(r => { segnaStoricoPronto = r; });
setTimeout(() => segnaStoricoPronto(), 20000);   // se il database non risponde, non si blocca tutto
async function riprendiStorico(){
  try {
    if (!ordersCollection) return;
    const maxDoc = await ordersCollection.find({ numeroOrdine: { $type: 'number' } }, { projection: { numeroOrdine: 1 } })
      .sort({ numeroOrdine: -1 }).limit(1).toArray();
    if (maxDoc[0] && maxDoc[0].numeroOrdine > orderCounter) orderCounter = maxDoc[0].numeroOrdine;
    const ultimi = await ordersCollection.find({ numeroOrdine: { $type: 'number' } }, { projection: { _id: 0 } })
      .sort({ ricevutoAlle: -1 }).limit(MAX_HISTORY).toArray();
    const visti = new Set(orderHistory.map(o => o.numeroOrdine + '|' + o.ricevutoAlle));
    for (const o of ultimi) if (!visti.has(o.numeroOrdine + '|' + o.ricevutoAlle)) orderHistory.push(o);
    orderHistory.sort((a, b) => String(b.ricevutoAlle || '').localeCompare(String(a.ricevutoAlle || '')));
    if (orderHistory.length > MAX_HISTORY) orderHistory.length = MAX_HISTORY;
    console.log(`Storico ripreso: ${orderHistory.length} ordini, prossimo numero ${orderCounter + 1}`);
  } catch (err) {
    console.error('Errore ripresa storico ordini:', err);
  } finally {
    segnaStoricoPronto();
  }
}

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
// ===== ORDINI PROGRAMMATI: la comanda completa esce 20 minuti prima dell'orario scelto =====
function orarioProgrammato(order){
  if (!order || order.timing !== 'orario' || !/^\d{1,2}:\d{2}$/.test(order.orarioRichiesto || '')) return null;
  const giorno = /^\d{4}-\d{2}-\d{2}$/.test(order.dataRichiesta || '') ? order.dataRichiesta : dateKey(new Date());
  const d = new Date(`${giorno}T${String(order.orarioRichiesto).padStart(5, '0')}:00`);
  return isNaN(d) ? null : d;
}
function catDiNome(nome){
  const n = String(nome || '').trim();
  const g = MENU_CATALOG.find(x => !String(x.keyPrefix).startsWith('EXTRA_') && x.items.includes(n));
  if (g) return g.cat;
  const c = (customMenuItemsCache || []).find(x => x.nome === n);
  return c ? c.cat : '';
}
function testoProgrammato(o, articoli, parte){
  const L = ['================================', '*** DA PREPARARE ORA ***', `ORDINE ONLINE #${o.numeroOrdine}`,
    o.modalita === 'consegna' ? 'CONSEGNA A DOMICILIO' : 'RITIRO IN SEDE',
    `PER LE ORE: ${String(o.orarioRichiesto || '').padStart(5, '0')}`];
  if (o.name || o.nome) L.push(`Cliente: ${o.name || [o.nome, o.cognome].filter(Boolean).join(' ')}`);
  if (o.phone) L.push(`Tel: ${o.phone}`);
  if (o.modalita === 'consegna' && o.address) L.push(`Indirizzo: ${o.address}`);
  if (parte) L.push(`>>> ${parte} <<<`);
  L.push('================================');
  articoli.forEach((a, i) => {
    if (i && CONFIG.stampa.spazioTraProdotti) L.push('');
    L.push(CONFIG.stampa.prezziComanda ? rigaPrezzo(`${a.qty}x ${a.nome}`, Number(a.prezzo) || 0) : `${a.qty}x ${a.nome}`);
    (a.dettagli || []).filter(d => !/panino\s+classico/i.test(d)).forEach(d => L.push(`   ${d}`));
  });
  if (o.note) { L.push(''); L.push(`NOTE: ${o.note}`); }
  if (CONFIG.stampa.totaleComanda) { L.push('--------------------------------'); L.push(rigaPrezzo('TOTALE', Number(o.grandTotal) || 0)); }
  L.push(o.pagatoOnline ? 'PAGATO ONLINE' : 'DA PAGARE');
  L.push('================================');
  return L.join('\n');
}
async function stampaProgrammati(){
  const ora = Date.now();
  let lista = [];
  if (ordersCollection) {
    try {
      lista = await ordersCollection.find({ programmato: true, promemoriaFatto: { $ne: true },
        programmatoPer: { $lte: new Date(ora + 20 * 60000).toISOString(), $gte: new Date(ora - 3 * 3600000).toISOString() } }).limit(30).toArray();
    } catch (e) { console.error('Errore ordini programmati:', e); }
  } else lista = orderHistory.filter(o => o.programmato && !o.promemoriaFatto && Date.parse(o.programmatoPer) <= ora + 20 * 60000 && Date.parse(o.programmatoPer) >= ora - 3 * 3600000);
  for (const o of lista) {
    const mem = orderHistory.find(x => x.numeroOrdine === o.numeroOrdine && x.ricevutoAlle === o.ricevutoAlle); if (mem) mem.promemoriaFatto = true;
    if (ordersCollection) await ordersCollection.updateOne(filtroOrdine(o), { $set: { promemoriaFatto: true } }).catch(() => {});
    const art = o.articoli || [];
    const rif = `Ordine #${o.numeroOrdine} per le ${o.orarioRichiesto}`;
    if (CONFIG.stampa.dividi === false) { stampaStaff(testoProgrammato(o, art), rif, 'sito'); continue; }
    const parti = ['pizze', 'panini'].map(g => ({ g, a: art.filter(x => gruppoRiga({ cat: catDiNome(x.nome) }) === g) })).filter(p => p.a.length);
    parti.forEach((p, i) => stampaStaff(testoProgrammato(o, p.a, (p.g === 'pizze' ? 'PIZZE' : 'PANINI') + (parti.length > 1 ? ` (${i + 1} di ${parti.length})` : '')), `${rif} · ${p.g}`, p.g));
  }
}
setInterval(() => stampaProgrammati().catch(() => {}), 60 * 1000);

async function finalizeOrder(order, customerId){
  await storicoPronto;   // il numero d'ordine si assegna solo dopo aver ripreso la numerazione
  order.numeroOrdine = ++orderCounter;
  order.ricevutoAlle = new Date().toISOString();
  order.stato = 'da_preparare';
  order.metodoPagamento = order.pagatoOnline ? 'online' : null; // 'online' | 'contanti' | 'bancomat' | null (da registrare)
  // l'ordine risulta stampato solo quando il pannello conferma che è uscito davvero (POST /api/orders/segna-stampato).
  // Prima veniva segnato stampato appena c'era un pannello collegato: se la linea del tablet era caduta
  // senza che il server se ne accorgesse, l'ordine non usciva e non veniva più recuperato.
  order.stampato = false;
  // ordine "per le 21:00" fatto con largo anticipo: subito esce solo un avviso, la comanda completa 20 minuti prima.
  // SPENTO su richiesta di Marco (16/10/2026): ogni ordine stampa subito la comanda completa con l'orario.
  // Per riattivarlo: ORDINI_PROGRAMMATI=1 su Render.
  if (process.env.ORDINI_PROGRAMMATI === '1') {
    const quando = orarioProgrammato(order);
    if (quando && quando.getTime() - Date.now() > 40 * 60 * 1000) {
      order.programmato = true; order.programmatoPer = quando.toISOString(); order.promemoriaFatto = false;
    }
  }
  order.phoneNormalized = normalizePhone(order.phone);
  order.addressNormalized = normalizeAddress(order.address);
  if (CONFIG.fedelta.attiva && order.phoneNormalized) {
    try { order.fedelta = await statoFedelta(order.phoneNormalized, pizzeIn(order.articoli)); } catch (e) { console.error('Errore punti fedeltà:', e); }
  }
  orderHistory.unshift(order);
  if (orderHistory.length > MAX_HISTORY) orderHistory.pop();

  if (ordersCollection) {
    ordersCollection.insertOne({ ...order, customerId: customerId || null }).catch(err => {
      console.error('Errore salvataggio storico ordine:', err);
    });
  }

  broadcastOrder(order);
  if (!order.interno) pushSicura(['titolare'], { titolo: `🛵 Nuovo ordine online #${order.numeroOrdine || ''}`, testo: `${order.name || 'Cliente'} · ${order.modalita === 'consegna' ? 'consegna' : 'ritiro'} · ${money(Number(order.grandTotal) || 0)}${order.pagatoOnline ? ' · pagato online' : ''}`, tag: 'ordine-' + (order.numeroOrdine || ''), url: './' }, 1800);
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
  pushSicura(['titolare'], { titolo: '📅 Nuova prenotazione dal sito', testo: `${nome} · ${persone} persone · ${data} alle ${ora}`, tag: 'pren-' + reservationCounter, url: './' }, 3600);
  try {
    await prenotazioniArch.save({ _id: crypto.randomUUID(), numero: reservationCounter, fonte: 'sito', stato: 'nuova', tavolo: '',
      ...pulisciPrenotazione({ nome, telefono, data, ora, persone, note }), ricevutoAlle });
    broadcastOrder({ evento: 'prenotazioni_aggiornate' });
  } catch (err) { console.error('Errore salvataggio prenotazione:', err); }
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

  {
    const vietato = articoloSoloSala(order.articoli);
    if (vietato) {
      return res.status(409).json({
        ok: false, error: 'solo_sala',
        message: `"${vietato}" si può ordinare solo al tavolo, in pizzeria. Toglilo dal carrello per continuare.`
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
  // metodi di pagamento accettati (impostazioni del titolare)
  if (!(order.pagamento === 'carta' ? CONFIG.sito.pagamenti.carta : CONFIG.sito.pagamenti.contanti)) {
    return res.status(400).json({ ok: false, error: 'pagamento_non_disponibile', message: 'Questo metodo di pagamento al momento non è disponibile: scegline un altro.' });
  }

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

  {
    const vietato = articoloSoloSala(order.articoli);
    if (vietato) {
      return res.status(409).json({
        ok: false, error: 'solo_sala',
        message: `"${vietato}" si può ordinare solo al tavolo, in pizzeria. Toglilo dal carrello per continuare.`
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
  if (!CONFIG.sito.pagamenti.online) {
    return res.status(400).json({ ok: false, error: 'pagamento_non_disponibile', message: 'Il pagamento online al momento non è disponibile: scegli contanti o carta alla consegna.' });
  }

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

  res.soloAvvisi = req.query.solo_avvisi === '1';
  printClients.push(res);

  req.on('close', () => {
    printClients = printClients.filter(c => c !== res);
  });
});

// ---------- Endpoint: storico ordini (utile per controlli/debug) ----------
app.get('/api/orders', (req, res) => {
  res.json(orderHistory);
});

// ricerca per nome o telefono tra gli ordini salvati nel database (ultimi 90 giorni), usata da Jarvis
app.get('/api/orders/cerca', async (req, res) => {
  const q = String(req.query.q || '').trim().slice(0, 60);
  if (q.length < 2) return res.json([]);
  const esc = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const cifre = q.replace(/\D/g, '');
  const da = new Date(Date.now() - 90 * 86400000).toISOString();
  const filtro = { ricevutoAlle: { $gte: da }, $or: [{ name: { $regex: esc, $options: 'i' } }, { nome: { $regex: esc, $options: 'i' } }, { cognome: { $regex: esc, $options: 'i' } }] };
  if (cifre.length >= 6) filtro.$or.push({ phoneNormalized: { $regex: cifre.slice(-9) } });
  if (/^\d{3,6}$/.test(q)) filtro.$or.push({ numeroOrdine: Number(q) });   // anche per numero d'ordine
  try {
    if (!ordersCollection) return res.json(orderHistory.filter(o => new RegExp(esc, 'i').test(`${o.name || ''} ${o.nome || ''} ${o.cognome || ''}`)).slice(0, 10));
    const trovati = await ordersCollection.find(filtro, { projection: { _id: 0 } }).sort({ ricevutoAlle: -1 }).limit(10).toArray();
    res.json(trovati);
  } catch (err) {
    console.error('Errore ricerca ordini:', err);
    res.status(500).json({ ok: false, error: 'ricerca non riuscita' });
  }
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
  const chi = String((req.body || {}).fattorino || '').slice(0, 30);
  if (chi) posizioniFattorini.set(chi, driverLocation);
  res.json({ ok: true });
});

app.get('/api/driver-location', async (req, res) => {
  // con più fattorini: la posizione di chi porta QUESTO ordine (?ordine=numero)
  const n = Number(req.query.ordine);
  if (n) {
    const o = orderHistory.find(x => x.numeroOrdine === n);
    const p = o && o.fattorino && posizioniFattorini.get(o.fattorino);
    if (p && Date.now() - new Date(p.aggiornataAlle).getTime() < 5 * 60 * 1000) return res.json({ disponibile: true, ...p });
    if (o && o.fattorino) return res.json({ disponibile: false });
  }
  if (!driverLocation) return res.json({ disponibile: false });
  // se la posizione non si aggiorna da più di 5 minuti, consideriamola scaduta
  const eta = Date.now() - new Date(driverLocation.aggiornataAlle).getTime();
  if (eta > 5 * 60 * 1000) return res.json({ disponibile: false });
  res.json({ disponibile: true, ...driverLocation });
});

// info minime e pubbliche su un ordine, usate dalla pagina di tracciamento del cliente
// (nessun dato sensibile: solo ciò che serve per mostrare la mappa)
app.get('/api/orders/:numeroOrdine/pubblico', async (req, res) => {
  const numeroOrdine = Number(req.params.numeroOrdine);
  const order = await trovaOrdine(numeroOrdine);
  if (!order) return res.status(404).json({ ok: false, error: 'Ordine non trovato' });
  res.json({
    ok: true,
    numeroOrdine: order.numeroOrdine,
    modalita: order.modalita,
    address: order.modalita === 'consegna' ? order.address : null,
    stato: order.stato || 'da_preparare',
    orarioLabel: order.orarioLabel || '',
    ricevutoAlle: order.ricevutoAlle || null,
    prontoAlle: order.prontoAlle || null,
    inConsegnaAlle: order.inConsegnaAlle || null
  });
});

// ---------- Endpoint: il pannello di stampa segna qui un ordine come pronto ----------
app.post('/api/orders/:numeroOrdine/pronto', async (req, res) => {
  const numeroOrdine = Number(req.params.numeroOrdine);
  const order = await trovaOrdine(numeroOrdine);
  if (!order) return res.status(404).json({ ok: false, error: 'Ordine non trovato' });
  segnaOrdinePronto(order);
  res.json({ ok: true });
});
function segnaOrdinePronto(order){
  const numeroOrdine = order.numeroOrdine;
  order.stato = 'pronto';
  order.prontoAlle = new Date().toISOString();

  if (ordersCollection) {
    ordersCollection.updateOne(filtroOrdine(order), { $set: { stato: 'pronto', prontoAlle: order.prontoAlle } }).catch(err => {
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
  if (order.modalita === 'consegna') pushSicura(['fattorino'], { titolo: `🛵 Ordine #${numeroOrdine} pronto`, testo: `${order.name || 'Cliente'} · ${order.address || ''}`, tag: 'cons-' + numeroOrdine, url: './' }, 900);
}

// ---------- Endpoint: il pannello di stampa registra qui come ha pagato il cliente (contanti/bancomat) ----------
app.post('/api/orders/:numeroOrdine/pagamento', async (req, res) => {
  const numeroOrdine = Number(req.params.numeroOrdine);
  const { metodo } = req.body || {};
  if (metodo !== 'contanti' && metodo !== 'bancomat') {
    return res.status(400).json({ ok: false, error: 'Metodo non valido' });
  }
  const order = await trovaOrdine(numeroOrdine);
  if (!order) return res.status(404).json({ ok: false, error: 'Ordine non trovato' });
  if (order.pagatoOnline) return res.status(400).json({ ok: false, error: 'Questo ordine è già pagato online' });

  order.metodoPagamento = metodo;

  if (ordersCollection) {
    ordersCollection.updateOne(filtroOrdine(order), { $set: { metodoPagamento: metodo } }).catch(err => {
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
  const { cat, nome, descrizione, prezzo, soloSala } = req.body || {};
  const nuovoPrezzo = Number(prezzo);
  if (!cat || !nome || typeof cat !== 'string' || typeof nome !== 'string' || !Number.isFinite(nuovoPrezzo) || nuovoPrezzo < 0) {
    return res.status(400).json({ ok: false, error: 'Dati non validi' });
  }
  const chiave = `${cat}|${nome}`;
  const item = { _id: chiave, cat, nome, descrizione: descrizione || '', prezzo: nuovoPrezzo, createdAt: new Date().toISOString() };
  if (soloSala) { soloSalaCache.add(chiave); salvaSoloSala(); }

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
  if (soloSalaCache.delete(chiave)) salvaSoloSala();
  if (soloOnlineCache.delete(chiave)) salvaSoloOnline();
  customMenuItemsCache = customMenuItemsCache.filter(i => i.cat !== cat || i.nome !== nome);
  if (customMenuItemsCollection) {
    customMenuItemsCollection.deleteOne({ _id: chiave }).catch(err => {
      console.error('Errore rimozione piatto:', err);
    });
  }
  res.json({ ok: true });
});

// ---------- Esauriti a tempo ----------
// La "giornata di lavoro" finisce alle 5 di mattina: un esaurito di stasera vale anche dopo mezzanotte
function giornoServizio(d){
  return dateKey(new Date((d ? d.getTime() : Date.now()) - 5 * 60 * 60 * 1000));
}
function esauritiDettagli(){
  const out = {};
  soldOutCache.forEach(k => { out[k] = soldOutFino.has(k) ? soldOutFino.get(k) : null; });
  return out;
}
function avvisaEsauriti(){
  broadcastOrder({ evento: 'esauriti_aggiornati', esauriti: [...soldOutCache], fino: esauritiDettagli() });
}
// toglie gli esauriti scaduti (il giorno dopo tornano disponibili da soli)
function scadenzaEsauriti(){
  const oggi = giornoServizio();
  const scaduti = [...soldOutCache].filter(k => { const f = soldOutFino.get(k); return f && f < oggi; });
  if (!scaduti.length) return false;
  scaduti.forEach(k => { soldOutCache.delete(k); soldOutFino.delete(k); });
  if (soldOutCollection) {
    soldOutCollection.deleteMany({ _id: { $in: scaduti } }).catch(err => console.error('Errore scadenza esauriti:', err));
  }
  console.log(`Di nuovo disponibili: ${scaduti.join(', ')}`);
  avvisaEsauriti();
  return true;
}
setInterval(scadenzaEsauriti, 60 * 1000);

// ---------- Endpoint: elenco prodotti attualmente esauriti ----------
app.get('/api/sold-out', (req, res) => {
  scadenzaEsauriti();
  res.json([...soldOutCache]);
});
// stesso elenco con la scadenza di ognuno (per il pannello)
app.get('/api/sold-out/dettagli', (req, res) => {
  scadenzaEsauriti();
  res.json({ ok: true, oggi: giornoServizio(), fino: esauritiDettagli() });
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

// ---------- Piatti "solo sala": visibili solo nell'app staff, non ordinabili dal sito ----------
function salvaSoloSala(){
  if (settingsCollection) {
    settingsCollection.updateOne({ _id: 'soloSala' }, { $set: { value: [...soloSalaCache] } }, { upsert: true })
      .catch(err => console.error('Errore salvataggio solo sala:', err));
  }
}
// un articolo è vietato online se il suo nome esiste SOLO tra i piatti solo sala
// (così un omonimo in un'altra categoria ordinabile online non viene bloccato per errore)
function articoloSoloSala(articoli){
  if (!soloSalaCache.size || !Array.isArray(articoli)) return null;
  const nomiSala = new Set([...soloSalaCache].map(k => k.split('|').slice(1).join('|')));
  const nomiOnline = new Set();
  MENU_CATALOG.forEach(g => g.items.forEach(n => { if (!soloSalaCache.has(`${g.keyPrefix}|${n}`)) nomiOnline.add(n); }));
  customMenuItemsCache.forEach(i => { if (!soloSalaCache.has(`${i.cat}|${i.nome}`)) nomiOnline.add(i.nome); });
  const a = articoli.find(x => x && nomiSala.has(x.nome) && !nomiOnline.has(x.nome));
  return a ? a.nome : null;
}
app.get('/api/solo-sala', (req, res) => res.json([...soloSalaCache]));
app.post('/api/solo-sala/toggle', (req, res) => {
  const { chiave, soloSala } = req.body || {};
  if (!chiave || typeof chiave !== 'string') return res.status(400).json({ ok: false, error: 'Dati non validi' });
  if (soloSala) soloSalaCache.add(chiave); else soloSalaCache.delete(chiave);
  salvaSoloSala();
  res.json({ ok: true, soloSala: [...soloSalaCache] });
});

// ---------- Piatti "solo online": non si vedono in sala (app staff, QR tavolo e QR banco) ----------
function salvaSoloOnline(){
  if (settingsCollection) {
    settingsCollection.updateOne({ _id: 'soloOnline' }, { $set: { value: [...soloOnlineCache] } }, { upsert: true })
      .catch(err => console.error('Errore salvataggio solo online:', err));
  }
}
app.get('/api/solo-online', (req, res) => res.json([...soloOnlineCache]));

// =====================================================================
//  GESTIONE DEL MENU dall'app Titolare (Impostazioni → Menu e piatti)
//  Per ogni piatto: dove si vende (sito online / sala), prezzo, esaurito, foto, descrizione.
//  I piatti di base si possono nascondere ovunque; quelli nuovi si possono anche modificare ed eliminare.
// =====================================================================
function gruppiMenu(){
  const gruppi = MENU_CATALOG.map(g => ({ cat: g.cat, keyPrefix: g.keyPrefix, items: [...g.items] }));
  customMenuItemsCache.forEach(item => {
    let g = gruppi.find(x => x.cat === item.cat && !String(x.keyPrefix).startsWith('EXTRA_'));
    if (!g) { g = { cat: item.cat, keyPrefix: item.cat, items: [] }; gruppi.push(g); }
    if (!g.items.includes(item.nome)) g.items.push(item.nome);
  });
  return gruppi;
}
function testoMenuValido(t){ return typeof t === 'string' && t.length > 0 && t.length <= 60 && !t.includes('|'); }
function infoPiatto(g, nome){
  const chiave = `${g.keyPrefix}|${nome}`;
  const custom = customMenuItemsCache.find(i => i.cat === g.cat && i.nome === nome);
  const esaurito = soldOutCache.has(chiave);
  return { nome, chiave, prezzo: getCurrentPrice(chiave), esaurito, fino: esaurito ? (soldOutFino.has(chiave) ? soldOutFino.get(chiave) : null) : undefined,
    online: !soloSalaCache.has(chiave), sala: !soloOnlineCache.has(chiave), custom: !!custom, mostrato: (!custom && menuTestiCache[chiave] && menuTestiCache[chiave].nome) || '', desc: custom ? (custom.descrizione || '') : ((menuTestiCache[chiave] && menuTestiCache[chiave].desc) || ''), foto: !!productPhotosCache[chiave] };
}
// applica i canali a un piatto; ritorna se qualcosa è cambiato
function impostaCanali(chiave, canali){
  let sala1 = false, onl = false;
  if (typeof canali.online === 'boolean') {
    if (canali.online) sala1 = soloSalaCache.delete(chiave);
    else if (!soloSalaCache.has(chiave)) { soloSalaCache.add(chiave); sala1 = true; }
  }
  if (typeof canali.sala === 'boolean') {
    if (canali.sala) onl = soloOnlineCache.delete(chiave);
    else if (!soloOnlineCache.has(chiave)) { soloOnlineCache.add(chiave); onl = true; }
  }
  if (sala1) salvaSoloSala();
  if (onl) salvaSoloOnline();
  return sala1 || onl;
}
app.get('/api/menu/gestione', soloTitolare, (req, res) => {
  scadenzaEsauriti();
  res.json({ ok: true, oggi: giornoServizio(), categorie: gruppiMenu().map(g => ({
    cat: g.cat, keyPrefix: g.keyPrefix, extra: String(g.keyPrefix).startsWith('EXTRA_'), items: g.items.map(n => infoPiatto(g, n))
  })) });
});
app.post('/api/menu/canali', soloTitolare, (req, res) => {
  const b = req.body || {};
  const chiave = String(b.chiave || '');
  const esiste = gruppiMenu().some(g => !String(g.keyPrefix).startsWith('EXTRA_') && g.items.some(n => `${g.keyPrefix}|${n}` === chiave));
  if (!esiste) return res.status(404).json({ ok: false, error: 'Piatto non trovato' });
  impostaCanali(chiave, b);
  res.json({ ok: true, online: !soloSalaCache.has(chiave), sala: !soloOnlineCache.has(chiave) });
});
app.post('/api/menu/canali-gruppo', soloTitolare, (req, res) => {
  const b = req.body || {};
  const g = gruppiMenu().find(x => x.keyPrefix === b.keyPrefix && !String(x.keyPrefix).startsWith('EXTRA_'));
  if (!g) return res.status(404).json({ ok: false, error: 'Categoria non trovata' });
  g.items.forEach(n => impostaCanali(`${g.keyPrefix}|${n}`, b));
  res.json({ ok: true, piatti: g.items.length });
});
// toglie del tutto un piatto nuovo (prezzo, esaurito, canali, foto compresi)
async function rimuoviPiattoNuovo(chiave){
  const i = customMenuItemsCache.findIndex(x => `${x.cat}|${x.nome}` === chiave);
  if (i >= 0) customMenuItemsCache.splice(i, 1);
  delete priceOverridesCache[chiave];
  soldOutCache.delete(chiave); soldOutFino.delete(chiave);
  delete productPhotosCache[chiave];
  const sala1 = soloSalaCache.delete(chiave), onl = soloOnlineCache.delete(chiave);
  if (sala1) salvaSoloSala();
  if (onl) salvaSoloOnline();
  const ops = [];
  if (customMenuItemsCollection) ops.push(customMenuItemsCollection.deleteOne({ _id: chiave }));
  if (priceOverridesCollection) ops.push(priceOverridesCollection.deleteOne({ _id: chiave }));
  if (soldOutCollection) ops.push(soldOutCollection.deleteOne({ _id: chiave }));
  if (productPhotosCollection) ops.push(productPhotosCollection.deleteOne({ _id: chiave }));
  await Promise.all(ops.map(p => p.catch(err => console.error('Errore rimozione piatto:', err))));
}
// =====================================================================
//  INCASSI SUMUP (POS) per la dashboard del Titolare — sola lettura.
//  Richiede su Render la variabile SUMUP_API_KEY (stessa chiave usata da Jarvis). Facoltativa: SUMUP_MERCHANT_CODE.
// =====================================================================
let sumupMerchantCode = null;
const sumupCache = {};
function dataRoma(d) { return new Intl.DateTimeFormat('sv-SE', { timeZone: 'Europe/Rome' }).format(d || new Date()); }
function sommaGiorni(iso, n) { const d = new Date(iso + 'T12:00:00Z'); d.setUTCDate(d.getUTCDate() + n); return d.toISOString().slice(0, 10); }
// mezzanotte di Roma per una data (gestisce ora legale/solare)
function mezzanotteRoma(iso) {
  for (const off of ['+02:00', '+01:00']) {
    const t = new Date(iso + 'T00:00:00' + off);
    if (dataRoma(t) === iso && new Intl.DateTimeFormat('en-GB', { timeZone: 'Europe/Rome', hour: '2-digit', hour12: false }).format(t).replace('24', '00') === '00') return t;
  }
  return new Date(iso + 'T00:00:00+01:00');
}
async function sumupIncassi(periodo) {
  const key = process.env.SUMUP_API_KEY;
  const H = { authorization: 'Bearer ' + key };
  if (!sumupMerchantCode) {
    sumupMerchantCode = process.env.SUMUP_MERCHANT_CODE;
    if (!sumupMerchantCode) {
      const r = await fetch('https://api.sumup.com/v0.1/me', { headers: H }); const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error('SumUp: chiave non valida');
      sumupMerchantCode = d.merchant_profile && d.merchant_profile.merchant_code;
    }
    if (!sumupMerchantCode) throw new Error('SumUp: codice esercente non trovato');
  }
  const oggi = dataRoma();
  const da = periodo === 'settimana' ? sommaGiorni(oggi, -6) : periodo === 'mese' ? oggi.slice(0, 8) + '01' : oggi;
  const a = sommaGiorni(oggi, 1);
  let url = `https://api.sumup.com/v2.1/merchants/${sumupMerchantCode}/transactions/history?limit=100&order=descending&statuses[]=SUCCESSFUL&oldest_time=${encodeURIComponent(mezzanotteRoma(da).toISOString())}&newest_time=${encodeURIComponent(mezzanotteRoma(a).toISOString())}`;
  const items = [];
  for (let i = 0; i < 10 && url; i++) {
    const r = await fetch(url, { headers: H }); const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error('SumUp: ' + (d.message || d.error_message || r.status));
    items.push(...(d.items || []));
    const next = (d.links || []).find(l => l.rel === 'next');
    const h = next && next.href;
    url = h ? (h.startsWith('http') ? h : `https://api.sumup.com/v2.1/merchants/${sumupMerchantCode}/transactions/history?${h.replace(/^\?/, '')}`) : null;
  }
  const arr = n => Math.round(n * 100) / 100;
  let contanti = 0, carte = 0, nCont = 0, nCarte = 0;
  items.forEach(t => { const x = Number(t.amount || 0); if (t.payment_type === 'CASH') { contanti += x; nCont++; } else { carte += x; nCarte++; } });
  return { ok: true, configurato: true, periodo, dal: da, transazioni: items.length, totale: arr(contanti + carte), carte: arr(carte), nCarte, contanti: arr(contanti), nContanti: nCont };
}
app.get('/api/sumup/incassi', soloTitolare, async (req, res) => {
  if (!process.env.SUMUP_API_KEY) return res.json({ ok: true, configurato: false });
  const periodo = ['oggi', 'settimana', 'mese'].includes(req.query.periodo) ? req.query.periodo : 'oggi';
  const c = sumupCache[periodo];
  if (c && Date.now() - c.t < 60000) return res.json(c.d);
  try { const d = await sumupIncassi(periodo); sumupCache[periodo] = { t: Date.now(), d }; res.json(d); }
  catch (err) { console.error('Errore SumUp:', err.message); res.status(502).json({ ok: false, configurato: true, error: err.message }); }
});

// testi mostrati sul sito per i piatti di base (la chiave interna non cambia: prezzi, foto e ordini restano collegati)
app.get('/api/menu-testi', (req, res) => { res.json(menuTestiCache); });
app.post('/api/menu/testi', soloTitolare, async (req, res) => {
  try {
    const b = req.body || {};
    const chiave = String(b.chiave || '');
    const eBase = MENU_CATALOG.some(g => !String(g.keyPrefix).startsWith('EXTRA_') && g.items.some(n => `${g.keyPrefix}|${n}` === chiave));
    if (!eBase) return res.status(400).json({ ok: false, error: 'Questo non è un piatto di base.' });
    const nome = String(b.nome || '').trim().slice(0, 60), desc = String(b.descrizione || '').trim().slice(0, 200);
    if (nome.includes('|')) return res.status(400).json({ ok: false, error: 'Nel nome non si può usare il simbolo |.' });
    if (!nome && !desc) { delete menuTestiCache[chiave]; if (menuTestiCollection) await menuTestiCollection.deleteOne({ _id: chiave }); }
    else { menuTestiCache[chiave] = { nome, desc }; if (menuTestiCollection) await menuTestiCollection.updateOne({ _id: chiave }, { $set: { nome, desc } }, { upsert: true }); }
    res.json({ ok: true });
  } catch (err) { console.error('Errore salvataggio testi:', err); res.status(500).json({ ok: false, error: 'Errore di salvataggio' }); }
});
app.post('/api/menu/piatto', soloTitolare, async (req, res) => {
  try {
    const b = req.body || {};
    const cat = String(b.cat || '').trim(), nome = String(b.nome || '').trim();
    const descrizione = String(b.descrizione || '').trim().slice(0, 200);
    const prezzo = Number(String(b.prezzo ?? '').replace(',', '.'));
    if (!testoMenuValido(cat) || !testoMenuValido(nome) || cat.startsWith('EXTRA_')) {
      return res.status(400).json({ ok: false, error: 'Scrivi il nome e la categoria (massimo 60 lettere, senza il simbolo |).' });
    }
    if (!Number.isFinite(prezzo) || prezzo < 0 || prezzo > 500) {
      return res.status(400).json({ ok: false, error: 'Il prezzo deve essere tra 0 e 500 euro.' });
    }
    const chiave = `${cat}|${nome}`;
    const vecchiaChiave = (b.vecchiaCat && b.vecchioNome) ? `${b.vecchiaCat}|${b.vecchioNome}` : '';
    const eBase = MENU_CATALOG.some(g => g.keyPrefix === cat && g.items.includes(nome));
    if (eBase) return res.status(409).json({ ok: false, error: 'Esiste già un piatto di base con questo nome in questa categoria.' });
    const esistente = customMenuItemsCache.find(i => i.cat === cat && i.nome === nome);
    if (esistente && vecchiaChiave !== chiave) return res.status(409).json({ ok: false, error: 'Esiste già un piatto con questo nome in questa categoria.' });
    // se cambio nome o categoria di un piatto nuovo, porto con me prezzo, esaurito, canali e foto
    let creato = esistente ? esistente.createdAt : new Date().toISOString();
    if (vecchiaChiave && vecchiaChiave !== chiave) {
      const vecchio = customMenuItemsCache.find(i => `${i.cat}|${i.nome}` === vecchiaChiave);
      if (!vecchio) return res.status(404).json({ ok: false, error: 'Piatto da modificare non trovato (si rinominano solo i piatti nuovi).' });
      creato = vecchio.createdAt || creato;
      const eraEsaurito = soldOutCache.has(vecchiaChiave), finoV = soldOutFino.get(vecchiaChiave);
      const online = !soloSalaCache.has(vecchiaChiave), sala = !soloOnlineCache.has(vecchiaChiave);
      let fotoDoc = null;
      if (productPhotosCollection && productPhotosCache[vecchiaChiave]) { try { fotoDoc = await productPhotosCollection.findOne({ _id: vecchiaChiave }); } catch (e) {} }
      await rimuoviPiattoNuovo(vecchiaChiave);
      if (b.online === undefined) b.online = online;
      if (b.sala === undefined) b.sala = sala;
      if (eraEsaurito) {
        soldOutCache.add(chiave); soldOutFino.set(chiave, finoV === undefined ? null : finoV);
        if (soldOutCollection) soldOutCollection.updateOne({ _id: chiave }, { $set: { _id: chiave, fino: finoV === undefined ? null : finoV } }, { upsert: true }).catch(() => {});
      }
      if (fotoDoc && fotoDoc.data) {
        productPhotosCache[chiave] = true; productPhotosVer[chiave] = Date.now();
        productPhotosCollection.updateOne({ _id: chiave }, { $set: { data: fotoDoc.data, updatedAt: new Date().toISOString() } }, { upsert: true }).catch(() => {});
      }
    }
    const item = { _id: chiave, cat, nome, descrizione, prezzo, createdAt: creato };
    customMenuItemsCache = customMenuItemsCache.filter(i => i.cat !== cat || i.nome !== nome);
    customMenuItemsCache.push(item);
    priceOverridesCache[chiave] = prezzo;
    if (customMenuItemsCollection) await customMenuItemsCollection.updateOne({ _id: chiave }, { $set: item }, { upsert: true });
    if (priceOverridesCollection) await priceOverridesCollection.updateOne({ _id: chiave }, { $set: { prezzo } }, { upsert: true });
    impostaCanali(chiave, { online: typeof b.online === 'boolean' ? b.online : true, sala: typeof b.sala === 'boolean' ? b.sala : true });
    res.json({ ok: true, item: infoPiatto({ cat, keyPrefix: cat }, nome) });
  } catch (err) { console.error('Errore salvataggio piatto:', err); res.status(500).json({ ok: false, error: 'Errore di salvataggio' }); }
});
app.post('/api/menu/elimina', soloTitolare, async (req, res) => {
  const chiave = String((req.body || {}).chiave || '');
  if (!customMenuItemsCache.some(i => `${i.cat}|${i.nome}` === chiave)) {
    return res.status(400).json({ ok: false, error: 'piatto_base', messaggio: 'I piatti di base non si cancellano: si nascondono (togli Online e Sala).' });
  }
  await rimuoviPiattoNuovo(chiave);
  res.json({ ok: true });
});

// ---------- Endpoint: grandezza caratteri in stampa (decisa dal titolare) ----------
app.get('/api/stampa/dimensione', (req, res) => res.json({ ok: true, dimensione: dimensioneStampa }));
app.post('/api/stampa/dimensione', async (req, res) => {
  const d = String((req.body && req.body.dimensione) || '');
  if (!DIMENSIONI_STAMPA.includes(d)) return res.status(400).json({ ok: false, error: 'dimensione_non_valida' });
  dimensioneStampa = d;
  if (settingsCollection) {
    settingsCollection.updateOne({ _id: 'dimensioneStampa' }, { $set: { value: d } }, { upsert: true })
      .catch(err => console.error('Errore salvataggio dimensione stampa:', err));
  }
  broadcastOrder({ evento: 'dimensione_stampa', dimensione: d }); // tutti i pannelli aperti si aggiornano subito
  res.json({ ok: true, dimensione: d });
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
// costo ingredienti per piatto (nome -> euro): si modifica dal Titolare (⚙️ → Costo ingredienti)
let COSTO_INGREDIENTI = {
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
    try {
      const filtro = inMemoria ? filtroOrdine(inMemoria) : { numeroOrdine, ricevutoAlle: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString() } };
      await ordersCollection.updateOne(filtro, { $set: { stampato: true } });
    }
    catch (err) { console.error('Errore salvataggio stampato:', err); }
  }
  res.json({ ok: true });
});

app.get('/api/dashboard-stats', soloTitolare, async (req, res) => {
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
app.get('/api/product-photos/versions', (req, res) => {
  const out = {}; Object.keys(productPhotosCache).forEach(k => { out[k] = productPhotosVer[k] || 1; });
  res.set('Cache-Control', 'no-cache');
  res.json(out);
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
    res.set('Cache-Control', req.query.v ? 'public, max-age=31536000, immutable' : 'public, max-age=3600');
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
  productPhotosCache[chiave] = true; productPhotosVer[chiave] = Date.now();
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
  const eligible = SCONTO_PRIMO_ORDINE > 0 && await isFirstOrderForPhone(req.query.phone, req.query.address);
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
async function comandeList(filtro, limite = 200){
  if (comandeCollection) return await comandeCollection.find(filtro).sort({ creataAlle: -1 }).limit(limite).toArray();
  return Object.values(comandeMemoria).filter(c => Object.entries(filtro).every(([k, v]) => {
    if (v && typeof v === 'object' && (v.$gte || v.$lte)) return (!v.$gte || c[k] >= v.$gte) && (!v.$lte || c[k] <= v.$lte);
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

// opzioni a pagamento dell'app staff (uguali a quelle del sito clienti)
const STAFF_PANE_PREZZI = { 'Panino Classico': 0, 'Pan Pizza': 1.00, 'Tortilla': 0.50 };
const STAFF_SENZA_GLUTINE = 4.00; // solo Pizza
const STAFF_FORMATI_FRITTI = {
  'Patatine con Buccia': { 'Piccola': 3.00, 'Media': 5.00 },
  'Anelli di Cipolla': { '12 Pezzi': 3.00, '20 Pezzi': 4.50 },
  'Mozzarelline Impanate': { '15 Pezzi': 3.50, '30 Pezzi': 7.00 },
  'Bocconcini Pollo Amadori Impanato Piccante': { '7 Pezzi': 3.50, '12 Pezzi': 5.50 },
  'Vaschetta di Kebab': { 'Piccola': 3.00, 'Media': 5.00 }
};
const listaTesti = (a, max = 20) => (Array.isArray(a) ? a : []).slice(0, max).map(x => String(x).slice(0, 60)).filter(Boolean);

// pulisce le righe mandate dall'app e mette il prezzo giusto preso dal listino del server
function normalizzaRighe(righe){
  if (!Array.isArray(righe)) return [];
  return righe.slice(0, 300).map(r => {
    const chiave = String(r.chiave || '');
    const listino = getCurrentPrice(chiave);
    const cat = String(r.cat || '').slice(0, 80);
    const nome = String(r.nome || '').slice(0, 120);
    const o = r.opzioni || {};
    const formati = STAFF_FORMATI_FRITTI[nome];
    const formato = formati && formati[o.formato] !== undefined ? o.formato : '';
    const max = cat === 'Pizza' && !!o.max;
    const mezzaMax = cat === 'Pizza' && !max && !!o.mezzaMax; // mezza Max = metà della Max: prezzo normale
    const glutine = cat === 'Pizza' && !!o.glutine;
    const opzioni = {
      senza: listaTesti(o.senza), cottura: String(o.cottura || '').slice(0, 30),
      max, mezzaMax, glutine, formato, rifinitura: listaTesti(o.rifinitura, 5), salse: listaTesti(o.salse, 12)
    };
    let base = listino != null ? listino : Math.max(0, Number(r.prezzoBase ?? r.prezzo) || 0); // voci libere: prezzo scritto dallo staff
    if (formato) base = formati[formato];
    if (max) base = base * 2;
    // ingredienti extra: prezzo sempre dal listino del server
    const extra = (Array.isArray(r.extra) ? r.extra : []).slice(0, 30).map(e => {
      const k = String(e.chiave || '');
      const p = getCurrentPrice(k);
      return p == null ? null : { chiave: k, nome: String(e.nome || k.split('|')[1] || '').slice(0, 60), prezzo: round2(p) };
    }).filter(Boolean);
    const pane = STAFF_PANE_PREZZI[r.pane] !== undefined ? r.pane : '';
    // varianti libere scritte dallo staff (es. "metà diavola", "+ nduja"): testo e prezzo decisi a mano
    const varianti = (Array.isArray(r.varianti) ? r.varianti : []).slice(0, 10).map(v => {
      const testo = String((v && v.testo) || '').trim().slice(0, 60);
      const pr = Number(v && v.prezzo);
      return testo ? { testo, prezzo: Number.isFinite(pr) && pr >= -50 && pr <= 50 ? round2(pr) : 0 } : null;
    }).filter(Boolean);
    const varTot = varianti.reduce((t, v) => t + v.prezzo, 0);
    const extraTot = extra.reduce((t, e) => t + e.prezzo, 0) * (max ? 2 : 1); // con la Max anche gli extra raddoppiano
    const prezzoListino = base + extraTot + varTot + (glutine ? STAFF_SENZA_GLUTINE : 0) + (pane ? STAFF_PANE_PREZZI[pane] : 0);
    // prezzo deciso a mano dallo staff per questo piatto (sconto, offerta, piatto speciale)
    const manuale = r.prezzoManuale === null || r.prezzoManuale === undefined || r.prezzoManuale === '' ? null : Number(r.prezzoManuale);
    const prezzoManuale = Number.isFinite(manuale) && manuale >= 0 && manuale <= 999 ? round2(manuale) : null;
    const prezzo = prezzoManuale !== null ? prezzoManuale : prezzoListino;
    return {
      rid: String(r.rid || crypto.randomUUID()),
      chiave, nome, cat,
      qty: Math.max(0, Math.min(99, parseInt(r.qty, 10) || 0)),
      note: String(r.note || '').slice(0, 200),
      pane, extra, varianti, opzioni, prezzoManuale,
      prezzoBase: round2(listino != null ? listino : Math.max(0, Number(r.prezzoBase ?? r.prezzo) || 0)),
      prezzo: round2(prezzo) // prezzo di un pezzo, varianti comprese
    };
  }).filter(r => r.nome && r.qty > 0);
}

// ---------- pagamenti separati: un cliente paga i suoi piatti, il resto rimane nella comanda ----------
function pagatoComanda(c){
  return round2((c.pagamenti || []).reduce((t, p) => t + (Number(p.importo) || 0), 0));
}
function residuoComanda(c){
  const piatti = (c.righe || []).reduce((t, r) => t + r.prezzo * Math.max(0, r.qty - (r.pagate || 0)), 0);
  return round2(piatti + (c.stato === 'chiusa' ? 0 : (c.spese || 0))); // la consegna si paga alla chiusura
}
function conTotali(c){
  return { ...c, totale: totaleComanda(c), pagato: pagatoComanda(c), residuo: residuoComanda(c) };
}
// quando l'app salva le righe, i pezzi già pagati non si possono perdere né togliere
function mantieniPagate(vecchie, nuove){
  const prima = new Map((vecchie || []).map(r => [r.rid, r]));
  nuove.forEach(r => {
    const p = prima.get(r.rid);
    r.pagate = p ? Math.min(p.pagate || 0, 99) : 0;
    if (r.qty < r.pagate) r.qty = r.pagate;
    if (!r.pagate) delete r.pagate;
  });
  (vecchie || []).forEach(p => { if ((p.pagate || 0) > 0 && !nuove.some(r => r.rid === p.rid)) nuove.push({ ...p, qty: p.pagate }); });
  return nuove;
}

function totaleComanda(c){
  return round2((c.righe || []).reduce((t, r) => t + r.prezzo * r.qty, 0));
}

// "firma" delle varianti: se cambia su un piatto già in cucina, va ristampato come modificato
function firmaRiga(r){
  const o = r.opzioni || {};
  return JSON.stringify([r.note || '', r.pane || '', (r.extra || []).map(e => e.chiave).sort(),
    [...(o.senza || [])].sort(), o.cottura || '', !!o.max, !!o.mezzaMax, !!o.glutine, o.formato || '',
    [...(o.rifinitura || [])].sort(), [...(o.salse || [])].sort(), (r.varianti || []).map(v => v.testo + '=' + v.prezzo)]);
}
// righe di stampa per un piatto: nome, pane, extra, nota
// extra uguali messi più volte (doppio prosciutto...): "2x Prosciutto"
function nomiExtra(list){
  const m = new Map();
  (list || []).forEach(e => { const k = e.chiave || e.nome; const x = m.get(k); if (x) x.n++; else m.set(k, { nome: e.nome, n: 1 }); });
  return [...m.values()].map(x => (x.n > 1 ? `${x.n}x ` : '') + x.nome);
}
// riga con il prezzo a destra (32 caratteri = larghezza dello scontrino)
function rigaPrezzo(sx, prezzo){
  const dx = (prezzo < 0 ? '-' : '') + money(Math.abs(prezzo));
  return sx.length + dx.length + 2 <= 32 ? sx + ' '.repeat(32 - sx.length - dx.length) + dx : `${sx}  ${dx}`;
}
function righeStampa(r, prefisso){
  const o = r.opzioni || {};
  const testa = `${prefisso}${r.qty}x ${r.nome}${o.max ? ' MAX' : o.mezzaMax ? ' MEZZA MAX' : ''}`;
  const out = [CONFIG.stampa.prezziComanda ? rigaPrezzo(testa, (Number(r.prezzo) || 0) * r.qty) : testa];
  if (o.formato) out.push(`   formato: ${o.formato}`);
  if (r.pane && r.pane !== 'Panino Classico') out.push(`   pane: ${r.pane}`); // il pane classico è il normale: si scrive solo Tortilla / Pan Pizza
  if (o.cottura && o.cottura !== 'Normale') out.push(`   cottura: ${o.cottura}`);
  if (o.glutine) out.push('   *** SENZA GLUTINE ***');
  if (o.senza && o.senza.length) out.push(`   SENZA: ${o.senza.join(', ')}`);
  if (r.extra && r.extra.length) out.push(`   + ${nomiExtra(r.extra).join(', + ')}`);
  (r.varianti || []).forEach(v => out.push(`   * ${v.testo}`));
  if (o.rifinitura && o.rifinitura.length) out.push(`   con: ${o.rifinitura.join(', ')}`);
  if (o.salse && o.salse.length) out.push(`   salse: ${o.salse.join(', ')}`);
  if (r.note) out.push(`   >> ${r.note}`);
  return out;
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
      if (firmaRiga(r) !== firmaRiga(p)) note.push(r);
    }
  });
  prima.forEach((p, rid) => { if (!dopo.has(rid)) tolte.push({ ...p }); });
  return { aggiunte, tolte, note };
}

// ===== Comande divise: pizze (con focacce e fritture) da una parte, panini (con hamburger e bevande) dall'altra =====
const CAT_PANINI = new Set(['Panini', 'Hamburger', 'Fritture', 'Bevande', 'Extra']);
function gruppoRiga(r){ return CAT_PANINI.has(String((r && r.cat) || '').trim()) ? 'panini' : 'pizze'; }
function stampaComandaCucina(c, diff, primaVolta, rif, ritocca, stampante){
  const fai = t => ritocca ? ritocca(t) : t;
  // scelta a mano col tasto tenuto premuto: tutta la comanda su quella stampante, senza dividere
  if (stampante === 1 || stampante === 2) return stampaStaff(fai(testoComandaCucina(c, diff, primaVolta)), `${rif} → ${stampante === 1 ? (CONFIG.stampa.nome1 || 'Stampante 1') : (CONFIG.stampa.nome2 || 'Stampante 2')}`, 'p' + stampante, c._id);
  if (CONFIG.stampa.dividi === false) return stampaStaff(fai(testoComandaCucina(c, diff, primaVolta)), rif, 'noi', c._id);
  const parti = ['pizze', 'panini'].map(g => ({ g, d: {
    aggiunte: (diff.aggiunte || []).filter(r => gruppoRiga(r) === g),
    tolte: (diff.tolte || []).filter(r => gruppoRiga(r) === g),
    note: (diff.note || []).filter(r => gruppoRiga(r) === g) } }))
    .filter(p => p.d.aggiunte.length || p.d.tolte.length || p.d.note.length);
  if (!parti.length) return stampaStaff(fai(testoComandaCucina(c, diff, primaVolta)), rif, 'noi', c._id);
  parti.forEach((p, i) => {
    const etichetta = (p.g === 'pizze' ? 'PIZZE' : 'PANINI') + (parti.length > 1 ? ` (${i + 1} di ${parti.length})` : '');
    stampaStaff(fai(testoComandaCucina(c, p.d, primaVolta, etichetta)), `${rif} · ${p.g}`, p.g, c._id);
  });
}
function testoComandaCucina(c, diff, primaVolta, parte){
  const L = [];
  L.push('================================');
  L.push(etichettaComanda(c));
  if (c.nome) L.push(`Cliente: ${c.nome}`);
  if (c.tipo === 'consegna' && c.indirizzo) L.push(`Indirizzo: ${c.indirizzo}`);
  if (c.telefono && c.tipo !== 'tavolo') L.push(`Tel: ${c.telefono}`);
  if (c.orario) L.push(`Per le ore: ${c.orario}`);
  L.push(primaVolta ? `NUOVA COMANDA - ore ${oraIT()}` : `*** MODIFICA n.${c.invii} - ore ${oraIT()} ***`);
  if (parte) L.push(`>>> ${parte} <<<`);
  L.push('================================');
  if (diff.aggiunte.length){
    if (!primaVolta) L.push('AGGIUNGERE:');
    diff.aggiunte.forEach((r, i) => { if (i && CONFIG.stampa.spazioTraProdotti) L.push(''); L.push(...righeStampa(r, primaVolta ? '' : '+ ')); }); // riga vuota tra un prodotto e l'altro
  }
  if (diff.tolte.length){
    if (diff.aggiunte.length) L.push('');
    L.push('TOGLIERE:');
    diff.tolte.forEach((r, i) => { if (i && CONFIG.stampa.spazioTraProdotti) L.push(''); L.push(CONFIG.stampa.prezziComanda ? rigaPrezzo(`- ${r.qty}x ${r.nome}`, -(Number(r.prezzo) || 0) * r.qty) : `- ${r.qty}x ${r.nome}`); });
  }
  if (diff.note.length){
    if (diff.aggiunte.length || diff.tolte.length) L.push('');
    L.push('CAMBIARE COSI\':');
    diff.note.forEach((r, i) => { if (i && CONFIG.stampa.spazioTraProdotti) L.push(''); L.push(...righeStampa(r, '* ')); });
  }
  if (primaVolta && c.noteComanda) { L.push(''); L.push(`NOTE: ${c.noteComanda}`); }
  if (CONFIG.stampa.totaleComanda) {
    L.push('--------------------------------');
    if (c.spese) L.push(rigaPrezzo('Consegna', c.spese));
    L.push(rigaPrezzo(primaVolta ? 'TOTALE' : 'TOTALE COMANDA', totaleComanda(c) + (c.spese || 0)));
  }
  L.push('================================');
  return L.join('\n');
}

// selezione: [{rid, qty}] = conto parziale solo di quei pezzi; senza selezione = tutto quello che resta da pagare
function testoConto(c, selezione){
  const L = [];
  String(CONFIG.stampa.intestazioneConto || '').split('\n').filter(x => x.trim()).forEach(x => L.push(x));
  L.push('--------------------------------');
  L.push(`${etichettaComanda(c)} - ${oraIT()}`);
  L.push(selezione ? 'CONTO PARZIALE (non fiscale)' : 'PRECONTO (non fiscale)');
  // asporto e domicilio: dati del cliente (serve al fattorino che porta il conto)
  if (c.tipo !== 'tavolo') {
    if (c.nome) L.push(`Cliente: ${c.nome}`);
    if (c.telefono) L.push(`Tel: ${c.telefono}`);
    if (c.tipo === 'consegna') L.push(`Indirizzo: ${c.indirizzo || '(manca indirizzo)'}`);
    if (c.orario) L.push(`Per le ore: ${c.orario}`);
  }
  L.push('--------------------------------');
  const sel = selezione ? new Map(selezione.map(v => [v.rid, v.qty])) : null;
  let tot = 0;
  (c.righe || []).forEach(r => {
    const n = sel ? (sel.get(r.rid) || 0) : Math.max(0, r.qty - (r.pagate || 0));
    if (!n) return;
    const o = r.opzioni || {};
    tot += r.prezzo * n;
    L.push(rigaPrezzo(`${n}x ${r.nome}${o.max ? ' MAX' : o.mezzaMax ? ' MEZZA MAX' : ''}${o.formato ? ' ' + o.formato : ''}`, r.prezzo * n));
    nomiExtra(r.extra).forEach(x => L.push(`   + ${x}`));
    (r.varianti || []).forEach(v => L.push(`   * ${v.testo}`));
    if (o.glutine) L.push('   senza glutine');
    if (r.pane && STAFF_PANE_PREZZI[r.pane]) L.push(`   pane: ${r.pane}`);
  });
  L.push('--------------------------------');
  if (!sel && c.spese) { L.push(rigaPrezzo('Consegna', c.spese)); tot += c.spese; }
  const pagato = pagatoComanda(c);
  if (!sel && pagato > 0) L.push(rigaPrezzo("Gia' pagato", pagato));
  L.push(rigaPrezzo(sel ? 'DA PAGARE' : pagato > 0 ? 'RESTA DA PAGARE' : 'TOTALE', tot));
  if (CONFIG.stampa.piedeConto && CONFIG.stampa.piedeConto.trim()) { L.push(''); String(CONFIG.stampa.piedeConto).split('\n').forEach(x => L.push(x)); }
  return L.join('\n');
}
function selezioneValida(c, voci){
  if (!Array.isArray(voci)) return { errore: 'Scegli almeno un prodotto' };
  const out = [];
  for (const v of voci.slice(0, 300)) {
    const r = (c.righe || []).find(x => x.rid === String(v.rid || ''));
    const n = parseInt(v.qty, 10) || 0;
    if (!r || n <= 0) continue;
    const resta = r.qty - (r.pagate || 0);
    if (n > resta) return { errore: `${r.nome}: ne restano da pagare solo ${resta}` };
    out.push({ rid: r.rid, qty: n });
  }
  return out.length ? out : { errore: 'Scegli almeno un prodotto' };
}

// tipo = su quale stampante va (vedi CONFIG.stampa.instrada): noi | conti | cassa | sito | banco
// Ogni stampa ha un id e resta "in sospeso" finché il tablet che stampa non conferma (/api/stampe/fatta).
// Se in quel momento il tablet era scollegato, appena torna le recupera da /api/stampe/in-sospeso.
const stampeMemoria = []; // copia in memoria (serve anche se il database non c'è)
function stampaStaff(testo, rif, tipo, comandaId){
  const job = { id: crypto.randomBytes(8).toString('hex'), testoStampa: testo, rif: rif || '', tipo: tipo || 'noi', creata: new Date(), fatta: null, comandaId: comandaId || null };
  stampeMemoria.push(job);
  while (stampeMemoria.length > 300) stampeMemoria.shift();
  if (stampeCollection) stampeCollection.insertOne({ ...job, _id: job.id }).catch(() => {});
  broadcastOrder({ evento: 'stampa_staff', id: job.id, testoStampa: testo, rif: job.rif, tipo: job.tipo, creata: job.creata });
}
async function stampeInSospeso(){
  const da = new Date(Date.now() - 12 * 60 * 60 * 1000);
  if (stampeCollection) {
    try {
      const docs = await stampeCollection.find({ fatta: null, creata: { $gte: da } }).sort({ creata: 1 }).limit(60).toArray();
      return docs.map(d => ({ id: d.id || d._id, testoStampa: d.testoStampa, rif: d.rif, tipo: d.tipo, creata: d.creata }));
    } catch (e) { /* se il database non risponde usiamo la memoria */ }
  }
  return stampeMemoria.filter(j => !j.fatta && j.creata >= da).slice(-60);
}
app.get('/api/stampe/in-sospeso', async (req, res) => {
  const stampe = await stampeInSospeso();
  res.json({ ok: true, stampe });
});
app.post('/api/stampe/fatta', async (req, res) => {
  const id = String((req.body || {}).id || '').slice(0, 40);
  if (!id) return res.status(400).json({ ok: false, error: 'id mancante' });
  const ora = new Date();
  const m = stampeMemoria.find(j => j.id === id); if (m) m.fatta = ora;
  if (stampeCollection) {
    try {
      await stampeCollection.updateOne({ _id: id }, { $set: { fatta: ora } });
      // pulizia: le stampe confermate più vecchie di 3 giorni non servono più
      stampeCollection.deleteMany({ fatta: { $ne: null }, creata: { $lt: new Date(Date.now() - 3 * 86400000) } }).catch(() => {});
    } catch (e) {}
  }
  broadcastOrder({ evento: 'stampa_confermata', id });
  res.json({ ok: true });
});

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
    const filtro = stato === 'aperta' ? { stato: 'aperta' } : { stato: 'chiusa', giorno: giornoServizio() }; // la serata finisce alle 5 di mattina
    const lista = await comandeList(filtro);
    res.json(lista.map(c => (conTotali(c))));
  } catch (err) { console.error(err); res.status(500).json({ ok: false, error: 'Errore server' }); }
});

app.get('/api/staff/comande/:id', async (req, res) => {
  const c = await comandaGet(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Comanda non trovata' });
  res.json(conTotali(c));
});

// nuova comanda
app.post('/api/staff/comande', async (req, res) => {
  try {
    const info = infoComandaDaBody(req.body || {});
    if (info.tipo === 'tavolo' && !info.tavolo) return res.status(400).json({ ok: false, error: 'Scrivi il numero del tavolo' });
    if (info.tipo === 'tavolo') {
      const giaAperta = (await comandeList({ stato: 'aperta' })).find(c => c.tipo === 'tavolo' && c.tavolo === info.tavolo);
      if (giaAperta) return res.json({ ok: true, esistente: true, comanda: conTotali(giaAperta) });
    }
    const giorno = giornoServizio(); // dopo mezzanotte resta la stessa serata
    const diOggi = await comandeList({ giorno });
    const numero = diOggi.reduce((m, c) => Math.max(m, c.numero || 0), 0) + 1;
    const c = {
      _id: crypto.randomUUID(), numero, giorno, ...info, cameriere: String((req.body || {}).cameriere || '').slice(0, 30),
      righe: [], inviate: [], invii: 0, stato: 'aperta',
      creataAlle: new Date().toISOString()
    };
    await comandaSave(c);
    res.json({ ok: true, comanda: conTotali(c) });
  } catch (err) { console.error(err); res.status(500).json({ ok: false, error: 'Errore server' }); }
});

// salva (senza stampare) righe e/o dati della comanda
app.put('/api/staff/comande/:id', async (req, res) => {
  const c = await comandaGet(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Comanda non trovata' });
  const b = req.body || {};
  if (Array.isArray(b.righe)) c.righe = mantieniPagate(c.righe, normalizzaRighe(b.righe));
  if (b.info) {
    const info = infoComandaDaBody(b.info, c);
    if (info.tipo === 'tavolo' && info.tavolo !== c.tavolo) {
      const occupato = (await comandeList({ stato: 'aperta' })).find(x => x._id !== c._id && x.tipo === 'tavolo' && x.tavolo === info.tavolo);
      if (occupato) return res.status(409).json({ ok: false, error: `Il tavolo ${info.tavolo} è già occupato` });
    }
    Object.assign(c, info);
  }
  await comandaSave(c);
  res.json({ ok: true, comanda: conTotali(c) });
});

// manda in cucina: stampa solo le differenze rispetto all'ultimo invio
app.post('/api/staff/comande/:id/invia', async (req, res) => {
  const c = await comandaGet(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Comanda non trovata' });
  if (Array.isArray((req.body || {}).righe)) c.righe = mantieniPagate(c.righe, normalizzaRighe(req.body.righe));
  const diff = diffComanda(c.inviate, c.righe);
  if (!diff.aggiunte.length && !diff.tolte.length && !diff.note.length) {
    return res.json({ ok: true, nienteDaInviare: true, comanda: conTotali(c) });
  }
  const primaVolta = c.invii === 0;
  c.invii += 1;
  if ((req.body || {}).cameriere) { c.ultimoCameriere = String(req.body.cameriere).slice(0, 30); if (!c.cameriere) c.cameriere = c.ultimoCameriere; }
  const senzaStampa = !!(req.body || {}).senzaStampa; // "salva senza stampare": segna come già in cucina, niente scontrino
  const stampante = [1, 2].includes(Number((req.body || {}).stampante)) ? Number(req.body.stampante) : 0; // 0 = come da impostazioni
  if (!senzaStampa) stampaComandaCucina(c, diff, primaVolta, `${etichettaComanda(c)} #${c.invii}`, null, stampante);
  else c.salvateSenzaStampa = (c.salvateSenzaStampa || 0) + 1;
  c.inviate = c.righe.map(r => ({ ...r }));
  c.ultimoInvio = new Date().toISOString();
  c.ultimoDiff = { aggiunte: diff.aggiunte.map(r => r.rid), tolte: diff.tolte.map(r => ({ qty: r.qty, nome: r.nome })), primaVolta };
  await comandaSave(c);
  res.json({ ok: true, comanda: conTotali(c) });
});

// "Servito": ferma il contatore dell'attesa in cucina (si riattiva da solo al prossimo invio)
app.post('/api/staff/comande/:id/servito', async (req, res) => {
  const c = await comandaGet(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Comanda non trovata' });
  c.servitoAlle = (req.body || {}).servito === false ? null : new Date().toISOString();
  await comandaSave(c);
  res.json({ ok: true, comanda: conTotali(c) });
});

app.post('/api/staff/comande/:id/ristampa', async (req, res) => {
  const c = await comandaGet(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Comanda non trovata' });
  if (!c.invii) return res.status(400).json({ ok: false, error: 'Non è ancora stata mandata in cucina' });
  stampaComandaCucina(c, { aggiunte: c.inviate || [], tolte: [], note: [] }, true, `Ristampa ${etichettaComanda(c)}`,
    t => t.replace(/NUOVA COMANDA - ore/, 'RISTAMPA COMPLETA - ore'));
  res.json({ ok: true });
});

app.post('/api/staff/comande/:id/conto', async (req, res) => {
  const c = await comandaGet(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Comanda non trovata' });
  const voci = (req.body || {}).voci;
  if (Array.isArray(voci)) {
    const sel = selezioneValida(c, voci);
    if (sel.errore) return res.status(400).json({ ok: false, error: sel.errore });
    stampaStaff(testoConto(c, sel), `Conto parziale ${etichettaComanda(c)}`, 'conti');
  } else {
    stampaStaff(testoConto(c), `Conto ${etichettaComanda(c)}`, 'conti');
  }
  res.json({ ok: true });
});

// paga solo alcuni pezzi: restano nella comanda segnati come pagati, il resto si paga dopo
app.post('/api/staff/comande/:id/paga-parte', async (req, res) => {
  const c = await comandaGet(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Comanda non trovata' });
  if (c.stato !== 'aperta') return res.status(400).json({ ok: false, error: 'La comanda non è aperta' });
  const b = req.body || {};
  if (Array.isArray(b.righe)) c.righe = mantieniPagate(c.righe, normalizzaRighe(b.righe)); // ultime modifiche non ancora salvate
  const sel = selezioneValida(c, b.voci);
  if (sel.errore) return res.status(400).json({ ok: false, error: sel.errore });
  const metodo = b.pagamento === 'carta' ? 'carta' : 'contanti';
  let importo = 0;
  const voci = sel.map(v => {
    const r = c.righe.find(x => x.rid === v.rid);
    r.pagate = (r.pagate || 0) + v.qty;
    importo += r.prezzo * v.qty;
    return { rid: r.rid, nome: r.nome, qty: v.qty, prezzo: r.prezzo };
  });
  c.pagamenti = c.pagamenti || [];
  c.pagamenti.push({ importo: round2(importo), metodo, voci, alle: new Date().toISOString() });
  let chiusa = false;
  if (!c.spese && residuoComanda(c) <= 0.004) { // pagato tutto: la comanda si chiude da sola
    c.stato = 'chiusa';
    c.totaleIncassato = pagatoComanda(c);
    c.pagamento = c.pagamenti.every(p => p.metodo === 'carta') ? 'carta' : c.pagamenti.every(p => p.metodo === 'contanti') ? 'contanti' : 'misto';
    c.chiusaAlle = new Date().toISOString();
    chiusa = true;
  }
  await comandaSave(c);
  res.json({ ok: true, importo: round2(importo), chiusa, comanda: conTotali(c) });
});

app.post('/api/staff/comande/:id/chiudi', async (req, res) => {
  const c = await comandaGet(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Comanda non trovata' });
  const pagamento = ['contanti', 'carta'].includes((req.body || {}).pagamento) ? req.body.pagamento : 'contanti';
  // quello che resta da pagare si incassa adesso; i pagamenti separati fatti prima restano
  const resto = residuoComanda(c);
  c.pagamenti = c.pagamenti || [];
  if (resto > 0) {
    c.pagamenti.push({ importo: resto, metodo: pagamento, chiusura: true, alle: new Date().toISOString() });
    c.righe.forEach(r => { r.pagate = r.qty; });
  }
  c.stato = 'chiusa';
  if ((req.body || {}).cameriere) c.chiusaDa = String(req.body.cameriere).slice(0, 30);
  c.pagamento = c.pagamenti.length && c.pagamenti.every(p => p.metodo === pagamento) ? pagamento : (c.pagamenti.length ? 'misto' : pagamento);
  c.totaleIncassato = pagatoComanda(c);
  c.chiusaAlle = new Date().toISOString();
  await comandaSave(c);
  res.json({ ok: true });
});

app.post('/api/staff/comande/:id/riapri', async (req, res) => {
  const c = await comandaGet(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Comanda non trovata' });
  c.stato = 'aperta';
  // tolgo l'incasso della chiusura (i pagamenti separati fatti prima restano validi)
  const chiusura = (c.pagamenti || []).find(p => p.chiusura);
  if (chiusura) {
    c.pagamenti = c.pagamenti.filter(p => p !== chiusura);
    const pagatiPrima = new Map();
    c.pagamenti.forEach(p => (p.voci || []).forEach(v => pagatiPrima.set(v.rid, (pagatiPrima.get(v.rid) || 0) + v.qty)));
    (c.righe || []).forEach(r => { r.pagate = Math.min(r.qty, pagatiPrima.get(r.rid) || 0); if (!r.pagate) delete r.pagate; });
  }
  delete c.pagamento; delete c.totaleIncassato; delete c.chiusaAlle;
  await comandaSave(c);
  res.json({ ok: true, comanda: conTotali(c) });
});

// annulla: non stampa niente; e se qualche scontrino di questa comanda non era ancora uscito, non esce più
async function annullaStampeComanda(comandaId){
  const ora = new Date(), ids = new Set();
  stampeMemoria.forEach(j => { if (j.comandaId === comandaId && !j.fatta) { j.fatta = ora; j.annullata = true; ids.add(j.id); } });
  if (stampeCollection) {
    try {
      const docs = await stampeCollection.find({ comandaId, fatta: null }).toArray();
      docs.forEach(d => ids.add(d.id || d._id));
      if (docs.length) await stampeCollection.updateMany({ comandaId, fatta: null }, { $set: { fatta: ora, annullata: true } });
    } catch (e) {}
  }
  ids.forEach(id => broadcastOrder({ evento: 'stampa_confermata', id }));
}
app.post('/api/staff/comande/:id/annulla', async (req, res) => {
  const c = await comandaGet(req.params.id);
  if (!c) return res.status(404).json({ ok: false, error: 'Comanda non trovata' });
  await annullaStampeComanda(c._id);
  c.stato = 'annullata';
  await comandaSave(c);
  res.json({ ok: true });
});

// ---------- Accesso Titolare: password controllata dal server ----------
const cryptoTit = require('crypto');
// password: quella su Render (TITOLARE_PASSWORD) ha la precedenza; altrimenti quella scelta dall'app Titolare
let titolarePwHash = '';
function passwordAttiva(){ return TITOLARE_PASSWORD || titolarePwHash; }
function tokenTitolare(){
  // il "pass" dura finché non cambi la password: cambiandola, tutti i telefoni devono rientrare
  return cryptoTit.createHmac('sha256', JWT_SECRET).update('titolare:' + passwordAttiva()).digest('hex');
}
function uguali(a, b){
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && cryptoTit.timingSafeEqual(x, y);
}
function soloTitolare(req, res, next){
  if (!passwordAttiva()) return next(); // nessuna password impostata: accesso libero
  const t = req.get('x-titolare-token') || '';
  if (!t || !uguali(t, tokenTitolare())) return res.status(401).json({ ok: false, error: 'accesso_negato' });
  next();
}
const tentativiLogin = new Map(); // ip -> { n, dal }
app.post('/api/titolare/login', (req, res) => {
  if (!passwordAttiva()) return res.status(503).json({ ok: false, error: 'La password non è ancora impostata.' });
  const ip = req.ip || 'x';
  const t = tentativiLogin.get(ip) || { n: 0, dal: Date.now() };
  if (Date.now() - t.dal > 10 * 60 * 1000) { t.n = 0; t.dal = Date.now(); }
  if (t.n >= 5) return res.status(429).json({ ok: false, error: 'Troppi tentativi. Riprova tra 10 minuti.' });
  const pw = String((req.body || {}).password || '');
  const giusta = TITOLARE_PASSWORD ? uguali(pw, TITOLARE_PASSWORD) : (() => { try { return bcrypt.compareSync(pw, titolarePwHash); } catch (e) { return false; } })();
  if (!giusta) {
    t.n++; tentativiLogin.set(ip, t);
    return res.status(401).json({ ok: false, error: 'Password sbagliata' });
  }
  tentativiLogin.delete(ip);
  res.json({ ok: true, token: tokenTitolare() });
});

// statistiche delle comande dello staff (sala, banco, telefono) per la dashboard dell'app titolare
app.get('/api/staff/stats', soloTitolare, async (req, res) => {
  try {
    const now = new Date(Date.now() - 5 * 60 * 60 * 1000); // la serata finisce alle 5 di mattina
    const oggi = dateKey(now);
    const dow = now.getDay();
    const lunedi = new Date(now.getFullYear(), now.getMonth(), now.getDate() - (dow === 0 ? 6 : dow - 1));
    const inizioSett = dateKey(lunedi);
    const inizioMese = dateKey(new Date(now.getFullYear(), now.getMonth(), 1));
    const da14 = dateKey(new Date(now.getFullYear(), now.getMonth(), now.getDate() - 13));
    const daQuando = da14 < inizioMese ? da14 : inizioMese;
    const chiuse = await comandeList({ stato: 'chiusa', giorno: { $gte: daQuando } }, 20000);

    const vuoto = () => ({ incasso: 0, comande: 0, contanti: 0, carta: 0, tavoli: 0, asporto: 0, piatti: {}, pezzi: 0, pezziNoti: 0, ricavoNoto: 0, costo: 0, camerieri: {} });
    const per = { oggi: vuoto(), settimana: vuoto(), mese: vuoto() };
    const giorni = {};
    chiuse.forEach(c => {
      const imp = Number(c.totaleIncassato) || 0;
      giorni[c.giorno] = (giorni[c.giorno] || 0) + imp;
      const dove = [];
      if (c.giorno === oggi) dove.push(per.oggi);
      if (c.giorno >= inizioSett) dove.push(per.settimana);
      if (c.giorno >= inizioMese) dove.push(per.mese);
      dove.forEach(a => {
        a.incasso += imp; a.comande++;
        if (Array.isArray(c.pagamenti) && c.pagamenti.length) {
          c.pagamenti.forEach(p => { if (p.metodo === 'carta') a.carta += Number(p.importo) || 0; else a.contanti += Number(p.importo) || 0; });
        } else if (c.pagamento === 'carta') a.carta += imp; else a.contanti += imp;
        if (c.tipo === 'tavolo') a.tavoli++; else a.asporto++;
        const cam = c.cameriere || 'Senza nome';
        if (!a.camerieri[cam]) a.camerieri[cam] = { conti: 0, incasso: 0 };
        a.camerieri[cam].conti++; a.camerieri[cam].incasso += imp;
        (c.righe || []).forEach(r => {
          if (!a.piatti[r.nome]) a.piatti[r.nome] = { qty: 0, incasso: 0 };
          a.piatti[r.nome].qty += r.qty;
          a.piatti[r.nome].incasso += r.prezzo * r.qty;
          a.pezzi += r.qty;
          const costo = COSTO_INGREDIENTI[r.nome];
          if (costo != null) { a.pezziNoti += r.qty; a.ricavoNoto += r.prezzo * r.qty; a.costo += costo * r.qty; }
        });
      });
    });
    const fine = a => ({
      incasso: round2(a.incasso), comande: a.comande, contanti: round2(a.contanti), carta: round2(a.carta),
      tavoli: a.tavoli, asporto: a.asporto, medio: a.comande ? round2(a.incasso / a.comande) : 0,
      pezzi: a.pezzi, pezziNoti: a.pezziNoti, ricavoNoto: round2(a.ricavoNoto), costo: round2(a.costo),
      camerieri: Object.entries(a.camerieri).map(([nome, v]) => ({ nome, conti: v.conti, incasso: round2(v.incasso) })).sort((x, y) => y.incasso - x.incasso),
      top: Object.entries(a.piatti).map(([nome, v]) => ({ nome, qty: v.qty, incasso: round2(v.incasso) }))
        .sort((x, y) => y.qty - x.qty).slice(0, 8)
    });
    const ultimi14 = [];
    for (let i = 13; i >= 0; i--) {
      const k = dateKey(new Date(now.getFullYear(), now.getMonth(), now.getDate() - i));
      ultimi14.push({ data: k, incasso: round2(giorni[k] || 0) });
    }
    const aperte = await comandeList({ stato: 'aperta' });
    res.json({
      oggi: fine(per.oggi), settimana: fine(per.settimana), mese: fine(per.mese), ultimi14,
      aperte: { numero: aperte.length, totale: round2(aperte.reduce((t, c) => t + residuoComanda(c), 0)) }
    });
  } catch (err) { console.error('Errore statistiche staff:', err); res.status(500).json({ ok: false, error: 'Errore server' }); }
});

// listino per l'app staff: categorie, voci con prezzo attuale ed esauriti
app.get('/api/staff/menu', (req, res) => {
  const categorie = MENU_CATALOG.map(g => ({ cat: g.cat, keyPrefix: g.keyPrefix, items: [...g.items] }));
  customMenuItemsCache.forEach(item => {
    let g = categorie.find(x => x.cat === item.cat && !String(x.keyPrefix).startsWith('EXTRA_'));
    if (!g) { g = { cat: item.cat, keyPrefix: item.cat, items: [] }; categorie.push(g); }
    if (!g.items.includes(item.nome)) g.items.push(item.nome);
  });
  // i piatti "solo online" non si vedono in sala (app staff, QR tavolo e QR banco)
  // (con ?tutti=1 il personale e il titolare vedono comunque tutto, anche i piatti solo online)
  if (req.query.tutti !== '1') categorie.forEach(g => { if (!String(g.keyPrefix).startsWith('EXTRA_')) g.items = g.items.filter(nome => !soloOnlineCache.has(`${g.keyPrefix}|${nome}`)); });
  res.json(categorie.filter(g => g.items.length || String(g.keyPrefix).startsWith('EXTRA_')).map(g => ({
    cat: g.cat,
    gruppoExtra: String(g.keyPrefix).startsWith('EXTRA_') ? g.keyPrefix : null,
    tipiPane: ['Panini', 'Hamburger'].includes(g.cat) ? BREAD_TYPES : [],
    extra: String(g.keyPrefix).startsWith('EXTRA_'),
    items: g.items.map(nome => {
      const chiave = `${g.keyPrefix}|${nome}`;
      const custom = customMenuItemsCache.find(i => i.cat === g.cat && i.nome === nome);
      return { nome, chiave, prezzo: getCurrentPrice(chiave), esaurito: soldOutCache.has(chiave), soloSala: soloSalaCache.has(chiave), soloOnline: soloOnlineCache.has(chiave), desc: custom ? custom.descrizione || '' : undefined };
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
  soldOutFino = new Map();
  if (soldOutCollection) {
    await soldOutCollection.deleteMany({}).catch(err => {
      console.error('Errore azzeramento esauriti:', err);
    });
  }
  avvisaEsauriti();
  res.json({ ok: true });
});

// ---------- Endpoint: segna/togli un prodotto come esaurito ----------
// esaurisci / rendi disponibile un'intera categoria in un colpo solo
app.post('/api/sold-out/bulk', async (req, res) => {
  const b = req.body || {};
  const chiavi = (Array.isArray(b.chiavi) ? b.chiavi : []).map(String).filter(k => k.includes('|')).slice(0, 300);
  if (!chiavi.length) return res.status(400).json({ ok: false, error: 'Nessun prodotto' });
  const oggi = giornoServizio();
  let fino = oggi;
  const richiesto = String(b.fino || 'oggi');
  if (richiesto === 'sempre') fino = null;
  else if (/^\d{4}-\d{2}-\d{2}$/.test(richiesto) && richiesto >= oggi) fino = richiesto;
  for (const k of chiavi) {
    if (b.esaurito) {
      soldOutCache.add(k); soldOutFino.set(k, fino);
      if (soldOutCollection) await soldOutCollection.updateOne({ _id: k }, { $set: { _id: k, fino } }, { upsert: true }).catch(() => {});
    } else {
      soldOutCache.delete(k); soldOutFino.delete(k);
      if (soldOutCollection) await soldOutCollection.deleteOne({ _id: k }).catch(() => {});
    }
  }
  avvisaEsauriti();
  res.json({ ok: true, esauriti: [...soldOutCache], fino: esauritiDettagli(), oggi });
});

app.post('/api/sold-out/toggle', async (req, res) => {
  const { chiave, esaurito } = req.body || {};
  if (!chiave) return res.status(400).json({ ok: false, error: 'Manca la chiave del prodotto' });

  if (esaurito) {
    // fino: 'oggi' (predefinito: domani torna disponibile), una data 'YYYY-MM-DD', oppure 'sempre'
    const richiesto = String((req.body && req.body.fino) || 'oggi');
    const oggi = giornoServizio();
    let fino = oggi;
    if (richiesto === 'sempre') fino = null;
    else if (/^\d{4}-\d{2}-\d{2}$/.test(richiesto) && richiesto >= oggi) fino = richiesto;
    soldOutCache.add(chiave);
    soldOutFino.set(chiave, fino);
    if (soldOutCollection) {
      await soldOutCollection.updateOne({ _id: chiave }, { $set: { _id: chiave, fino } }, { upsert: true }).catch(err => {
        console.error('Errore salvataggio esaurito:', err);
      });
    }
  } else {
    soldOutCache.delete(chiave);
    soldOutFino.delete(chiave);
    if (soldOutCollection) {
      await soldOutCollection.deleteOne({ _id: chiave }).catch(err => {
        console.error('Errore rimozione esaurito:', err);
      });
    }
  }

  avvisaEsauriti();
  res.json({ ok: true, esauriti: [...soldOutCache], fino: esauritiDettagli(), oggi: giornoServizio() });
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
app.post('/api/orders/:numeroOrdine/in-consegna', async (req, res) => {
  const numeroOrdine = Number(req.params.numeroOrdine);
  const order = await trovaOrdine(numeroOrdine);
  if (!order) return res.status(404).json({ ok: false, error: 'Ordine non trovato' });
  segnaOrdineInConsegna(order);
  res.json({ ok: true });
});
function segnaOrdineInConsegna(order){
  const numeroOrdine = order.numeroOrdine;
  order.stato = 'in_consegna';
  order.inConsegnaAlle = new Date().toISOString();

  if (ordersCollection) {
    ordersCollection.updateOne(filtroOrdine(order), { $set: { stato: 'in_consegna', inConsegnaAlle: order.inConsegnaAlle } }).catch(err => {
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

}

// =====================================================================
//  JARVIS / PERSONALE: ristampa comande e ordini presi a voce (telefono, banco, tavolo)
// =====================================================================
// Facoltativo: impostando STAFF_KEY su Render, questi endpoint accettano solo chi manda
// l'intestazione x-staff-key uguale (Jarvis la manda se ha la stessa chiave).
const STAFF_KEY = process.env.STAFF_KEY || '';
function staffOk(req){ return !STAFF_KEY || req.get('x-staff-key') === STAFF_KEY; }

// Ristampa: il pannello di stampa riceve l'ordine e lo ristampa (non lo aggiunge di nuovo alla lista)
app.post('/api/orders/:numeroOrdine/ristampa', async (req, res) => {
  if (!staffOk(req)) return res.status(403).json({ ok: false, error: 'non autorizzato' });
  const numeroOrdine = Number(req.params.numeroOrdine);
  const order = await trovaOrdine(numeroOrdine);
  if (!order) return res.status(404).json({ ok: false, error: 'Ordine non trovato' });
  if (!order.testoStampa) return res.status(400).json({ ok: false, error: 'Comanda senza testo da stampare' });
  stampaStaff('*** RISTAMPA ***\n' + order.testoStampa, `Ristampa ordine #${numeroOrdine}`, order.fonte === 'banco' ? 'banco' : order.interno ? 'noi' : 'sito');
  res.json({ ok: true, numeroOrdine, pannelli: pannelliStampa() });
});

// ---------- ricerca delle voci del menu per nome (come le dice una persona) ----------
const normNome = s => String(s || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '')
  .replace(/&/g, ' e ').replace(/[^a-z0-9 ]+/g, ' ').replace(/\s+/g, ' ').trim()
  .replace(/\bquattro\b/g, '4').replace(/\bsette\b/g, '7').replace(/\bdieci\b/g, '10').replace(/\bwurstel\b/g, 'wurstel');
function vociMenu(){
  const out = [];
  MENU_CATALOG.forEach(g => g.items.forEach(nome => out.push({ chiave: `${g.keyPrefix}|${nome}`, nome, cat: g.cat, prefisso: g.keyPrefix })));
  customMenuItemsCache.forEach(i => out.push({ chiave: `${i.cat}|${i.nome}`, nome: i.nome, cat: i.cat, prefisso: i.cat, prezzoCustom: i.prezzo }));
  return out;
}
function trovaVoce(nome, categoria, prefissoExtra){
  const q = normNome(nome);
  if (!q) return null;
  let voci = vociMenu().filter(v => prefissoExtra ? v.prefisso === prefissoExtra : !String(v.prefisso).startsWith('EXTRA_'));
  const qc = normNome(categoria);
  if (qc) { const f = voci.filter(v => normNome(v.cat).includes(qc) || qc.includes(normNome(v.prefisso))); if (f.length) voci = f; }
  const n = v => normNome(v.nome);
  const senzaPizza = q.replace(/^pizza /, '');
  return voci.find(v => n(v) === q) || voci.find(v => n(v) === senzaPizza) || voci.find(v => n(v) === 'pizza ' + senzaPizza)
    || voci.find(v => n(v).startsWith(q)) || voci.find(v => n(v).split(' ').includes(senzaPizza))
    || voci.find(v => n(v).includes(q)) || voci.find(v => n(v).length > 3 && q.includes(n(v)))
    || voci.find(v => { const t = n(v).split(' '); return senzaPizza.split(' ').filter(w => w.length > 1 && w !== 'e' && w !== 'di').every(w => t.some(x => x.startsWith(w))); })
    || null;
}
function prezzoVoce(v){
  const p = getCurrentPrice(v.chiave);
  return p !== null && p !== undefined && Number.isFinite(Number(p)) ? Number(p) : (Number(v.prezzoCustom) || 0);
}

// Ordine interno (telefono, banco, tavolo): i prezzi li calcola il server dal menu.
// Senza "conferma: true" restituisce solo l'anteprima (nulla viene creato né stampato).
app.post('/api/orders/interno', async (req, res) => {
  if (!staffOk(req)) return res.status(403).json({ ok: false, error: 'non autorizzato' });
  const b = req.body || {};
  const righe = Array.isArray(b.articoli) ? b.articoli.slice(0, 60) : [];
  if (!righe.length) return res.status(400).json({ ok: false, error: 'Nessun articolo' });

  const nonTrovati = [], esauriti = [], articoli = [];
  let subtotale = 0;
  for (const r of righe) {
    const voce = trovaVoce(r.nome, r.categoria);
    if (!voce) { nonTrovati.push(String(r.nome || '')); continue; }
    const qty = Math.max(1, Math.min(50, parseInt(r.qty, 10) || 1));
    let unit = prezzoVoce(voce);
    const dettagli = [];
    const prefExtra = /pizza|focacc/i.test(voce.prefisso + ' ' + voce.cat) ? 'EXTRA_PIZZA' : 'EXTRA_PANINO';
    for (const e of (Array.isArray(r.aggiunte) ? r.aggiunte : [])) {
      const ve = trovaVoce(e, '', prefExtra);
      if (!ve) { nonTrovati.push(`aggiunta «${e}» per ${voce.nome}`); continue; }
      const pe = prezzoVoce(ve); unit += pe;
      dettagli.push(`+ ${ve.nome} (${money(pe)})`);
    }
    for (const s of (Array.isArray(r.senza) ? r.senza : [])) dettagli.push(`Senza: ${s}`);
    if (r.pane) dettagli.push(`Pane: ${String(r.pane).slice(0, 40)}`);
    if (r.note) dettagli.push(String(r.note).slice(0, 120));
    if (soldOutCache.has(voce.chiave)) esauriti.push(voce.nome);
    const prezzo = round2(unit * qty);
    subtotale += prezzo;
    articoli.push({ qty, nome: voce.nome, prezzo, dettagli, chiave: voce.chiave });
  }
  if (nonTrovati.length) {
    return res.status(422).json({ ok: false, error: 'voci_non_trovate', non_trovati: nonTrovati,
      message: 'Non trovo nel menu: ' + nonTrovati.join(', ') });
  }

  const modalita = ['consegna', 'tavolo'].includes(b.modalita) ? b.modalita : 'ritiro';
  subtotale = round2(subtotale);
  // spese di consegna: calcolate dalla distanza come per il sito (si possono forzare con speseConsegna)
  let spese = 0, zonaInfo = null;
  if (modalita === 'consegna' && b.indirizzo) {
    if (b.speseConsegna != null && b.speseConsegna !== '') spese = round2(Number(b.speseConsegna) || 0);
    else {
      zonaInfo = await calcolaZonaConsegna({ address: String(b.indirizzo), zonaDichiarata: b.fuoriPaese === true ? 'fuori' : b.fuoriPaese === false ? 'paese' : null });
      if (!zonaInfo.ok) return res.status(400).json(zonaInfo);
      spese = round2(Number(zonaInfo.spese) || 0);
    }
  }
  const orario = /^\d{1,2}:\d{2}$/.test(String(b.orario || '')) ? String(b.orario).padStart(5, '0') : '';
  const nome = String(b.nome || (modalita === 'tavolo' ? `Tavolo ${b.tavolo || ''}` : 'Cliente')).slice(0, 60);
  const fonte = String(b.fonte || 'jarvis').slice(0, 20);
  const etichettaFonte = modalita === 'tavolo' ? 'TAVOLO' : fonte === 'banco' ? 'BANCO' : 'TELEFONO';

  if (modalita === 'consegna' && !b.indirizzo) return res.status(400).json({ ok: false, error: 'manca_indirizzo', message: "Per la consegna serve l'indirizzo." });

  const anteprima = {
    modalita, nome, tavolo: modalita === 'tavolo' ? String(b.tavolo || '') : '', orario: orario || 'il prima possibile',
    articoli: articoli.map(a => ({ qty: a.qty, nome: a.nome, prezzo: a.prezzo, dettagli: a.dettagli })),
    subtotale, speseConsegna: spese, totale: round2(subtotale + spese), esauriti,
    zona: zonaInfo ? { distanzaKm: zonaInfo.distanzaKm ?? null, fuoriPaese: !!zonaInfo.fuoriPaese, daVerificare: !!zonaInfo.daVerificare, chiediZona: !!zonaInfo.chiediZona } : null,
  };
  if (!b.conferma) return res.json({ ok: true, anteprima: true, ...anteprima });

  const sep = '------------------------------';
  let testo = `ORDINE ${etichettaFonte} — LA CASA DI CARTA\n${sep}\n`;
  testo += `Modalità: ${modalita === 'consegna' ? 'Consegna a domicilio' : modalita === 'tavolo' ? 'Al tavolo ' + (b.tavolo || '') : 'Ritiro in sede'}\n`;
  testo += `Orario richiesto: ${orario ? 'Alle ' + orario : (modalita === 'tavolo' ? 'Subito' : 'Il prima possibile')}\n`;
  testo += `Nome: ${nome}\n`;
  if (b.telefono) testo += `Telefono: ${b.telefono}\n`;
  if (modalita === 'consegna') {
    testo += `Indirizzo: ${b.indirizzo}\n`;
    if (zonaInfo && zonaInfo.distanzaKm != null) testo += `Distanza: ${String(zonaInfo.distanzaKm).replace('.', ',')} km${zonaInfo.fuoriPaese ? ' (fuori paese)' : ''}\n`;
    if (zonaInfo && zonaInfo.daVerificare) testo += `⚠️ ZONA DA VERIFICARE: indirizzo non trovato sulla mappa\n`;
  }
  testo += `${sep}\n`;
  articoli.forEach(a => { testo += `${a.qty}x ${a.nome}  ${money(a.prezzo)}\n`; a.dettagli.forEach(d => { testo += `   ${d}\n`; }); });
  testo += `${sep}\nSubtotale: ${money(subtotale)}\n`;
  if (spese) testo += `Spese di consegna: ${money(spese)}\n`;
  testo += `Totale: ${money(subtotale + spese)}\n`;
  if (b.note) testo += `Note: ${b.note}\n`;

  const order = {
    fonte, interno: true, modalita, numeroTavolo: modalita === 'tavolo' ? String(b.tavolo || '') : undefined,
    nome, name: nome, phone: String(b.telefono || ''), address: modalita === 'consegna' ? String(b.indirizzo) : '',
    note: String(b.note || '').slice(0, 300), articoli, subtotaleBase: subtotale, scontoPrimoOrdine: 0, subtotale,
    speseConsegna: spese, grandTotal: round2(subtotale + spese), pagamento: b.pagamento === 'carta' ? 'carta' : 'contanti',
    timing: orario ? 'orario' : 'prima', orarioRichiesto: orario || undefined, testoStampa: testo,
    oggettoEmail: `Nuovo ordine (${etichettaFonte.toLowerCase()}) — ${nome}`,
    distanzaKm: zonaInfo ? zonaInfo.distanzaKm : undefined, fuoriPaese: zonaInfo ? !!zonaInfo.fuoriPaese : undefined,
    zonaDaVerificare: zonaInfo ? !!zonaInfo.daVerificare : undefined,
  };

  if (modalita === 'consegna' && !b.forza) {
    const slot = await assignDeliverySlotIfNeeded(order);
    if (!slot.ok) return res.status(409).json(slot);
  } else {
    order.orarioLabel = modalita === 'tavolo' ? (orario ? `Tavolo ${b.tavolo || ''} · alle ${orario}` : `Tavolo ${b.tavolo || ''}`) : orario ? `Alle ${orario}` : 'Il prima possibile';
  }

  order.pagatoOnline = false;
  await finalizeOrder(order, null);
  res.json({ ok: true, numeroOrdine: order.numeroOrdine, totale: order.grandTotal, orario: order.orarioLabel, pannelli: pannelliStampa(), esauriti });
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
  // alle 3 di notte: se la cassa non è stata chiusa, manda lo stesso il riepilogo completo della serata
  if (now.getHours() === 3 && now.getMinutes() === 0 && ultimoResocontoInviatoIl !== oggiKey) {
    ultimoResocontoInviatoIl = oggiKey;
    const g = giornoServizio(now);
    chiusureArch.get(g).then(ch => { if (!ch || !ch.mailSerata) mandaRiepilogoSerata(g); }).catch(() => mandaRiepilogoSerata(g));
  }
}, 60 * 1000);

// ---------- Pagina di controllo semplice ----------
app.get('/', (req, res) => {
  res.send(`
    <h2>Server ordini La Casa di Carta — attivo ✅</h2>
    <p>Ordini ricevuti in totale: ${orderHistory.length}</p>
    <p>Pannelli di stampa collegati ora: ${pannelliStampa()}</p>
  `);
});

const PORT = process.env.PORT || 3000;
// ===== archivi semplici: database, oppure memoria se il database non c'è =====
const memArchivi = {};
function archivio(nome){
  const mem = memArchivi[nome] || (memArchivi[nome] = {});
  const coll = () => db ? db.collection(nome) : null;
  const ok = (d, f) => Object.entries(f || {}).every(([k, v]) => {
    if (v && typeof v === 'object' && !Array.isArray(v)) return (v.$gte === undefined || d[k] >= v.$gte) && (v.$lte === undefined || d[k] <= v.$lte) && (v.$ne === undefined || d[k] !== v.$ne) && (v.$in === undefined || v.$in.includes(d[k]));
    return d[k] === v;
  });
  return {
    async get(id){ const c = coll(); return c ? c.findOne({ _id: id }) : (mem[id] ? JSON.parse(JSON.stringify(mem[id])) : null); },
    async save(doc){ const c = coll(); if (c) await c.replaceOne({ _id: doc._id }, doc, { upsert: true }); else mem[doc._id] = JSON.parse(JSON.stringify(doc)); return doc; },
    async list(f = {}, ordina = null, limite = 1000){
      const c = coll();
      if (c) { let q = c.find(f); if (ordina) q = q.sort(ordina); return q.limit(limite).toArray(); }
      let r = Object.values(mem).filter(d => ok(d, f)).map(d => JSON.parse(JSON.stringify(d)));
      if (ordina) { const keys = Object.entries(ordina); r.sort((a, b) => { for (const [k, dir] of keys) { if (a[k] > b[k]) return dir; if (a[k] < b[k]) return -dir; } return 0; }); }
      return r.slice(0, limite);
    },
    async del(id){ const c = coll(); if (c) await c.deleteOne({ _id: id }); else delete mem[id]; }
  };
}
function giornoAggiunto(giorno, n){ const d = new Date(giorno + 'T12:00:00'); d.setDate(d.getDate() + n); return dateKey(d); }

// ===== PRENOTAZIONI TAVOLI (dal sito o prese al telefono), visibili nella Sala dell'app staff =====
const prenotazioniArch = archivio('prenotazioni');
const STATI_PRENOTAZIONE = ['nuova', 'confermata', 'arrivata', 'annullata'];
function pulisciPrenotazione(b, p = {}){
  const out = {};
  if (b.nome !== undefined) out.nome = String(b.nome || '').slice(0, 80);
  if (b.telefono !== undefined) out.telefono = String(b.telefono || '').slice(0, 30);
  if (b.data !== undefined && /^\d{4}-\d{2}-\d{2}$/.test(b.data)) out.data = b.data;
  if (b.ora !== undefined && /^\d{1,2}:\d{2}$/.test(b.ora)) out.ora = String(b.ora).padStart(5, '0');
  if (b.persone !== undefined) out.persone = Math.max(1, Math.min(99, parseInt(b.persone, 10) || 1));
  if (b.note !== undefined) out.note = String(b.note || '').slice(0, 300);
  if (b.tavolo !== undefined) out.tavolo = String(b.tavolo || '').slice(0, 10);
  if (b.stato !== undefined && STATI_PRENOTAZIONE.includes(b.stato)) out.stato = b.stato;
  return { ...p, ...out };
}
app.get('/api/prenotazioni', async (req, res) => {
  try {
    const re = /^\d{4}-\d{2}-\d{2}$/;
    const da = re.test(req.query.da || '') ? req.query.da : giornoServizio();
    const a = re.test(req.query.a || '') ? req.query.a : giornoAggiunto(da, 30);
    const lista = await prenotazioniArch.list({ data: { $gte: da, $lte: a } }, { data: 1, ora: 1 }, 500);
    res.json({ ok: true, prenotazioni: lista });
  } catch (err) { console.error(err); res.status(500).json({ ok: false, error: 'Errore server' }); }
});
// prenotazione presa al telefono dallo staff
app.post('/api/prenotazioni', async (req, res) => {
  const p = pulisciPrenotazione(req.body || {});
  if (!p.nome || !p.data || !p.ora) return res.status(400).json({ ok: false, error: 'Servono nome, giorno e ora' });
  const tutte = await prenotazioniArch.list({}, null, 100000);
  const doc = { _id: crypto.randomUUID(), numero: tutte.length + 1, fonte: 'telefono', stato: 'confermata', tavolo: '', persone: 2, telefono: '', note: '', ...p, ricevutoAlle: new Date().toISOString() };
  await prenotazioniArch.save(doc);
  broadcastOrder({ evento: 'prenotazioni_aggiornate' });
  res.json({ ok: true, prenotazione: doc });
});
app.put('/api/prenotazioni/:id', async (req, res) => {
  const p = await prenotazioniArch.get(req.params.id);
  if (!p) return res.status(404).json({ ok: false, error: 'Prenotazione non trovata' });
  const nuova = pulisciPrenotazione(req.body || {}, p);
  nuova.aggiornataAlle = new Date().toISOString();
  await prenotazioniArch.save(nuova);
  broadcastOrder({ evento: 'prenotazioni_aggiornate' });
  res.json({ ok: true, prenotazione: nuova });
});

// ===== CAMERIERI: chi usa l'app staff (con PIN facoltativo) =====
const tentativiPin = new Map();
app.post('/api/staff/cameriere', (req, res) => {
  const nome = String((req.body || {}).nome || '');
  const c = (CONFIG.camerieri || []).find(x => x.nome === nome);
  if (!c) return res.status(404).json({ ok: false, error: 'Cameriere non trovato' });
  if (!c.pin) return res.json({ ok: true, nome });
  const ip = req.ip || 'x';
  const t = tentativiPin.get(ip) || { n: 0, dal: Date.now() };
  if (Date.now() - t.dal > 10 * 60 * 1000) { t.n = 0; t.dal = Date.now(); }
  if (t.n >= 10) return res.status(429).json({ ok: false, error: 'Troppi tentativi, riprova tra qualche minuto' });
  if (String((req.body || {}).pin || '') !== c.pin) { t.n++; tentativiPin.set(ip, t); return res.status(401).json({ ok: false, error: 'PIN sbagliato' }); }
  tentativiPin.delete(ip);
  res.json({ ok: true, nome });
});

// ===== ORDINE DAL TAVOLO CON IL QR: il cliente ordina, lo staff accetta =====
const richiesteArch = archivio('richiesteTavolo');
// piatti scelti dal cliente dal telefono (QR tavolo / QR banco): solo voci del menu, i prezzi li rimette normalizzaRighe
function righeDaCliente(lista, conSoloOnline){
  return (Array.isArray(lista) ? lista : []).slice(0, 40)
    .filter(r => r && getCurrentPrice(String(r.chiave || '')) != null && !soldOutCache.has(String(r.chiave)) && (conSoloOnline || !soloOnlineCache.has(String(r.chiave))) && !String(r.chiave).startsWith('EXTRA_'))
    .map(r => ({ chiave: String(r.chiave), nome: String(r.nome || String(r.chiave).split('|')[1] || ''), cat: String(r.cat || String(r.chiave).split('|')[0] || ''), qty: Math.min(20, Math.max(1, parseInt(r.qty, 10) || 1)), note: String(r.note || '').slice(0, 120),
      // extra, pane e "senza" scelti dal cliente: i prezzi li rimette normalizzaRighe dal listino
      extra: (Array.isArray(r.extra) ? r.extra : []).slice(0, 15).map(e => ({ chiave: String((e && e.chiave) || ''), nome: String((e && e.nome) || '') }))
        .filter(e => e.chiave.startsWith('EXTRA_') && getCurrentPrice(e.chiave) != null && !soldOutCache.has(e.chiave)),
      pane: STAFF_PANE_PREZZI[r.pane] !== undefined && !soldOutCache.has('PANE|' + r.pane) ? r.pane : '',
      opzioni: { senza: (r.opzioni && Array.isArray(r.opzioni.senza)) ? r.opzioni.senza.slice(0, 12).map(x => String(x).slice(0, 40)) : [],
        salse: (r.opzioni && Array.isArray(r.opzioni.salse)) ? r.opzioni.salse.slice(0, 12).map(x => String(x).slice(0, 40)) : [] } }));
}
const tentativiQr = new Map();
// =====================================================================
//  QR AL BANCO: il cliente in pizzeria ordina dal telefono, scrive solo il nome,
//  sceglie contanti (paga alla cassa) o pagamento online, e aspetta il suo numero.
// =====================================================================
function ordineBanco(righe, nome, online){
  const sep = '------------------------------';
  const articoli = righe.map(r => {
    const o = r.opzioni || {}, dettagli = [];
    if (r.pane && r.pane !== 'Panino Classico') dettagli.push(`Pane: ${r.pane}`);
    if ((o.senza || []).length) dettagli.push(`Senza: ${o.senza.join(', ')}`);
    nomiExtra(r.extra).forEach(x => dettagli.push(`+ ${x}`));
    if ((o.salse || []).length) dettagli.push(`Salse: ${o.salse.join(', ')}`);
    if (r.note) dettagli.push(r.note);
    return { qty: r.qty, nome: r.nome, prezzo: round2(r.prezzo * r.qty), dettagli, chiave: r.chiave };
  });
  const totale = round2(articoli.reduce((t, a) => t + a.prezzo, 0));
  let testo = `ORDINE AL BANCO (QR) — LA CASA DI CARTA\n${sep}\nModalità: Ritiro in sede — aspetta al banco\nOrario richiesto: Il prima possibile\nNome: ${nome}\n${sep}\n`;
  articoli.forEach(a => { testo += `${a.qty}x ${a.nome}  ${money(a.prezzo)}\n`; a.dettagli.forEach(d => { testo += `   ${d}\n`; }); });
  testo += `${sep}\nTotale: ${money(totale)}\n`;
  testo += online ? 'PAGATO ONLINE\n' : 'DA PAGARE ALLA CASSA (contanti)\n';
  return {
    fonte: 'banco', interno: true, modalita: 'ritiro', nome, name: nome, phone: '', address: '', note: '',
    articoli, subtotaleBase: totale, scontoPrimoOrdine: 0, subtotale: totale, speseConsegna: 0, grandTotal: totale,
    pagamento: 'contanti', timing: 'prima', orarioLabel: 'Al banco — il prima possibile', testoStampa: testo,
    oggettoEmail: `Nuovo ordine (banco QR) — ${nome}`
  };
}
app.post('/api/banco/ordine', async (req, res) => {
  const b = req.body || {};
  const nome = String(b.nome || '').trim().slice(0, 40);
  if (!nome) return res.status(400).json({ ok: false, error: 'Scrivi il tuo nome: ti chiamiamo così quando è pronto.' });
  if (ordersPaused) return res.status(403).json({ ok: false, error: 'In questo momento siamo pieni: chiedi al banco.' });
  if (isClosedDate(dateKey(new Date()))) return res.status(409).json({ ok: false, error: 'Oggi siamo chiusi.' });
  const online = b.pagamento === 'online';
  if (online && (!stripe || !CONFIG.sito.pagamenti.online)) return res.status(400).json({ ok: false, error: 'Il pagamento online ora non è disponibile: scegli contanti.' });
  const ip = req.ip || 'x';
  const t = tentativiQr.get(ip) || { n: 0, dal: Date.now() };
  if (Date.now() - t.dal > 10 * 60 * 1000) { t.n = 0; t.dal = Date.now(); }
  if (t.n >= 8) return res.status(429).json({ ok: false, error: 'Troppi ordini di seguito: chiedi al banco.' });
  const righe = normalizzaRighe(righeDaCliente(b.righe, true)); // al banco si ordina anche quello che in sala non c'è (solo online)
  if (!righe.length) return res.status(400).json({ ok: false, error: 'Il carrello è vuoto o i piatti non sono più disponibili' });
  t.n++; tentativiQr.set(ip, t);
  const order = ordineBanco(righe, nome, online);
  order.ipCliente = ip;
  if (!online) {
    order.pagatoOnline = false;
    await finalizeOrder(order, null);
    return res.json({ ok: true, numeroOrdine: order.numeroOrdine, totale: order.grandTotal });
  }
  try {
    const session = await stripe.checkout.sessions.create({
      mode: 'payment', payment_method_types: ['card'],
      line_items: [{ price_data: { currency: 'eur', product_data: { name: `Ordine al banco — ${nome}` }, unit_amount: Math.round(order.grandTotal * 100) }, quantity: 1 }],
      success_url: `${SITE_URL}/banco.html?sessione={CHECKOUT_SESSION_ID}`,
      cancel_url: `${SITE_URL}/banco.html?annullato=1`
    });
    order.pagamento = 'carta_online'; order.pagatoOnline = true; order.stripeSession = session.id;
    const pendingData = { order, customerId: null };
    if (pendingOrdersCollection) await pendingOrdersCollection.insertOne({ _id: session.id, ...pendingData, createdAt: new Date() });
    else pendingOnlineOrders[session.id] = pendingData;
    res.json({ ok: true, url: session.url });
  } catch (err) {
    console.error('Errore pagamento banco:', err);
    res.status(500).json({ ok: false, error: 'Pagamento non avviato: riprova o scegli contanti.' });
  }
});
// dopo il pagamento online: il telefono del cliente chiede qui il suo numero d'ordine
app.get('/api/banco/sessione/:id', async (req, res) => {
  const id = String(req.params.id || '').slice(0, 200);
  let o = orderHistory.find(x => x.stripeSession === id);
  if (!o && ordersCollection) { try { o = await ordersCollection.findOne({ stripeSession: id }); } catch (e) {} }
  if (o) return res.json({ ok: true, numeroOrdine: o.numeroOrdine, stato: o.stato || 'da_preparare' });
  res.json({ ok: true, inAttesa: true }); // il pagamento sta ancora arrivando da Stripe
});
// tavolo già assegnato a un gruppo del QR universale (solo se quella comanda è ancora aperta)
async function tavoloDelGruppo(gruppo){
  if (!gruppo) return '';
  const da = new Date(Date.now() - 8 * 3600 * 1000).toISOString();
  const prima = (await richiesteArch.list({ gruppo, stato: 'accettata', creataAlle: { $gte: da } }, { creataAlle: -1 }, 1))[0];
  if (!prima || !prima.tavolo) return '';
  const aperta = (await comandeList({ stato: 'aperta' })).some(x => x.tipo === 'tavolo' && x.tavolo === prima.tavolo);
  return aperta ? prima.tavolo : '';
}
// il tavolo ha già ordinato col QR e il cameriere ha accettato: i nuovi ordini dal QR vanno dritti in cucina
async function comandaQrGiaAccettata(tavolo, gruppo){
  if (!tavolo) return null;
  const c = (await comandeList({ stato: 'aperta' })).find(x => x.tipo === 'tavolo' && x.tavolo === tavolo);
  if (!c) return null;
  const da = new Date(Date.now() - 8 * 3600 * 1000).toISOString();
  const ok = (await richiesteArch.list({ stato: 'accettata', creataAlle: { $gte: da } }, null, 300)).some(x => x.comanda === c._id || (gruppo && x.gruppo === gruppo && x.tavolo === tavolo));
  return ok ? c : null;
}
async function riordinoQrInCucina(c, richieste){
  for (const q of richieste) {
    q.righe.forEach(x => c.righe.push({ ...x, rid: crypto.randomUUID() }));
    if (q.nota) c.noteComanda = [c.noteComanda, q.nota].filter(Boolean).join(' · ');
  }
  const diff = diffComanda(c.inviate, c.righe);
  const primaVolta = (c.invii || 0) === 0;
  c.invii = (c.invii || 0) + 1;
  stampaComandaCucina(c, diff, primaVolta, `${etichettaComanda(c)} #${c.invii} (QR)`);
  c.inviate = c.righe.map(r => ({ ...r }));
  c.ultimoInvio = new Date().toISOString();
  c.ultimoDiff = { aggiunte: diff.aggiunte.map(r => r.rid), tolte: diff.tolte.map(r => ({ qty: r.qty, nome: r.nome })), primaVolta };
  await comandaSave(c);
  for (const q of richieste) {
    q.tavolo = c.tavolo; q.stato = 'accettata'; q.auto = true; q.gestitaAlle = new Date().toISOString(); q.comanda = c._id;
    await richiesteArch.save(q);
    broadcastOrder({ evento: 'richiesta_tavolo', tavolo: c.tavolo, id: q._id });
  }
  const pezzi = richieste.reduce((t, q) => t + q.righe.reduce((u, x) => u + x.qty, 0), 0);
  pushSicura(['staff', 'titolare'], { titolo: `📱 Tavolo ${c.tavolo} ha riordinato dal QR`, testo: `${pezzi} ${pezzi === 1 ? 'piatto mandato' : 'piatti mandati'} in cucina`, tag: 'qr-' + c.tavolo, url: './' }, 600);
}
app.post('/api/tavolo/richiesta', async (req, res) => {
  if (!CONFIG.sala.qrAttivo) return res.status(403).json({ ok: false, error: 'Gli ordini dal tavolo sono spenti: chiama il cameriere.' });
  const b = req.body || {};
  let tavolo = String(b.tavolo || '').trim().slice(0, 10);
  // QR universale: nessun tavolo nel QR. Le persone dello stesso tavolo condividono un codice gruppo;
  // il cameriere assegna il tavolo quando accetta, e i successivi ordini del gruppo vanno da soli a quel tavolo.
  const gruppo = String(b.gruppo || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
  if (!tavolo && !gruppo) return res.status(400).json({ ok: false, error: 'Tavolo mancante' });
  if (!tavolo) tavolo = await tavoloDelGruppo(gruppo);
  const ip = req.ip || 'x';
  const t = tentativiQr.get(ip) || { n: 0, dal: Date.now() };
  if (Date.now() - t.dal > 10 * 60 * 1000) { t.n = 0; t.dal = Date.now(); }
  if (t.n >= 8) return res.status(429).json({ ok: false, error: 'Troppi ordini di seguito: chiama il cameriere.' });
  const grezze = righeDaCliente(b.righe);

  const righe = normalizzaRighe(grezze);
  if (!righe.length) return res.status(400).json({ ok: false, error: 'Il carrello è vuoto o i piatti non sono più disponibili' });
  t.n++; tentativiQr.set(ip, t);
  // bozza = l'ordine di questa persona aspetta gli altri del tavolo: al cameriere arriva UNA notifica
  // quando qualcuno tocca "Tutti hanno scelto" (o da sola dopo qualche minuto senza nuovi ordini)
  const bozza = !!b.bozza && !!tavolo;
  const r = { _id: crypto.randomUUID(), tavolo, gruppo, righe, nome: String(b.nome || '').slice(0, 40), nota: String(b.nota || '').slice(0, 200),
    stato: bozza ? 'bozza' : 'attesa', totale: round2(righe.reduce((x, y) => x + y.prezzo * y.qty, 0)), creataAlle: new Date().toISOString() };
  await richiesteArch.save(r);
  if (!bozza) {
    const giaAccettata = await comandaQrGiaAccettata(tavolo, gruppo);
    if (giaAccettata) { await riordinoQrInCucina(giaAccettata, [r]); return res.json({ ok: true, id: r._id, bozza: false, inCucina: true }); }
    broadcastOrder({ evento: 'richiesta_tavolo', tavolo, id: r._id });
    pushSicura(['staff', 'titolare'], { titolo: `📱 Tavolo ${tavolo}: ordine dal QR`, testo: 'Da controllare e accettare', tag: 'qr-' + tavolo, url: './' }, 600);
  }
  res.json({ ok: true, id: r._id, bozza });
});
// ordine del tavolo in preparazione: cosa hanno già scelto gli altri (solo nomi e piatti)
async function bozzeTavolo(tavolo){
  const da = new Date(Date.now() - 3 * 3600 * 1000).toISOString();
  return (await richiesteArch.list({ tavolo, stato: 'bozza', creataAlle: { $gte: da } }, { creataAlle: 1 }, 60));
}
app.get('/api/tavolo/:tavolo/bozza', async (req, res) => {
  const lista = await bozzeTavolo(String(req.params.tavolo).slice(0, 10));
  res.json({ ok: true, persone: lista.map(r => ({ nome: r.nome || 'Qualcuno', piatti: r.righe.reduce((t, x) => t + x.qty, 0), righe: r.righe.map(x => `${x.qty}× ${x.nome}`) })),
    totale: round2(lista.reduce((t, r) => t + r.totale, 0)) });
});
// "Tutti hanno scelto": l'ordine del tavolo parte verso il cameriere, con una sola notifica
async function inviaBozzeTavolo(tavolo){
  const lista = await bozzeTavolo(tavolo);
  if (!lista.length) return 0;
  const giaAccettata = await comandaQrGiaAccettata(tavolo, lista[0].gruppo);
  if (giaAccettata) { await riordinoQrInCucina(giaAccettata, lista); return lista.length; }
  for (const r of lista) { r.stato = 'attesa'; r.inviataAlle = new Date().toISOString(); await richiesteArch.save(r); }
  broadcastOrder({ evento: 'richiesta_tavolo', tavolo, id: lista[0]._id, persone: lista.length });
  pushSicura(['staff', 'titolare'], { titolo: `📱 Tavolo ${tavolo}: ordine dal QR`, testo: `${lista.length > 1 ? lista.length + ' persone hanno scelto' : 'Da controllare e accettare'}`, tag: 'qr-' + tavolo, url: './' }, 600);
  return lista.length;
}
app.post('/api/tavolo/:tavolo/invia', async (req, res) => {
  const n = await inviaBozzeTavolo(String(req.params.tavolo).slice(0, 10));
  res.json({ ok: true, inviate: n });
});
// se nessuno tocca "Tutti hanno scelto", dopo qualche minuto senza nuovi ordini al tavolo parte da solo
const MINUTI_AUTO_INVIO_TAVOLO = 6;
setInterval(async () => {
  try {
    const da = new Date(Date.now() - 3 * 3600 * 1000).toISOString();
    const bozze = await richiesteArch.list({ stato: 'bozza', creataAlle: { $gte: da } }, null, 500);
    const ultimo = new Map();
    bozze.forEach(r => { if (!ultimo.has(r.tavolo) || r.creataAlle > ultimo.get(r.tavolo)) ultimo.set(r.tavolo, r.creataAlle); });
    for (const [tav, ora] of ultimo) if (Date.now() - new Date(ora).getTime() > MINUTI_AUTO_INVIO_TAVOLO * 60 * 1000) await inviaBozzeTavolo(tav);
  } catch (e) { console.error('Invio automatico ordini tavolo:', e.message); }
}, 60 * 1000);
app.get('/api/tavolo/richiesta/:id', async (req, res) => {
  const r = await richiesteArch.get(req.params.id);
  if (!r) return res.status(404).json({ ok: false, error: 'Non trovata' });
  res.json({ ok: true, stato: r.stato, tavolo: r.tavolo, totale: r.totale, righe: r.righe.map(x => ({ nome: x.nome, qty: x.qty })) });
});
app.get('/api/tavolo/richieste', async (req, res) => {
  const da = new Date(Date.now() - 12 * 3600 * 1000).toISOString();
  const lista = await richiesteArch.list({ stato: 'attesa', creataAlle: { $gte: da } }, { creataAlle: 1 }, 100);
  res.json({ ok: true, richieste: lista });
});
app.post('/api/tavolo/richieste/:id/:azione', async (req, res) => {
  const r = await richiesteArch.get(req.params.id);
  if (!r) return res.status(404).json({ ok: false, error: 'Richiesta non trovata' });
  if (r.stato !== 'attesa') return res.status(409).json({ ok: false, error: 'Già gestita da un altro dispositivo' });
  if (req.params.azione === 'rifiuta') {
    r.stato = 'rifiutata'; r.gestitaAlle = new Date().toISOString();
    await richiesteArch.save(r);
    broadcastOrder({ evento: 'richiesta_tavolo', tavolo: r.tavolo, id: r._id });
    return res.json({ ok: true });
  }
  if (req.params.azione !== 'accetta') return res.status(400).json({ ok: false, error: 'Azione sconosciuta' });
  // QR universale: il cameriere sceglie il tavolo adesso
  if (!r.tavolo) {
    const scelto = String((req.body || {}).tavolo || '').trim().slice(0, 10);
    if (!scelto) return res.status(400).json({ ok: false, error: 'Scegli il numero del tavolo' });
    r.tavolo = scelto;
  }
  // insieme a questa, accetto anche gli altri ordini in attesa dello stesso gruppo (stesso tavolo)
  // (stesso gruppo, oppure stesso numero di tavolo scritto da ognuno dal proprio telefono)
  const altri = (await richiesteArch.list({ stato: 'attesa' })).filter(x => x._id !== r._id && ((r.gruppo && x.gruppo === r.gruppo) || (x.tavolo && x.tavolo === r.tavolo)));
  // aggiungo i piatti alla comanda aperta di quel tavolo (o ne apro una nuova): NON vanno in cucina da soli
  let c = (await comandeList({ stato: 'aperta' })).find(x => x.tipo === 'tavolo' && x.tavolo === r.tavolo);
  if (!c) {
    const giorno = giornoServizio();
    const numero = (await comandeList({ giorno })).reduce((m, x) => Math.max(m, x.numero || 0), 0) + 1;
    c = { _id: crypto.randomUUID(), numero, giorno, tipo: 'tavolo', tavolo: r.tavolo, nome: '', telefono: '', indirizzo: '', orario: '', noteComanda: '', spese: 0,
      cameriere: String((req.body || {}).cameriere || '').slice(0, 30), righe: [], inviate: [], invii: 0, stato: 'aperta', creataAlle: new Date().toISOString() };
  }
  for (const q of [r, ...altri]) {
    q.righe.forEach(x => c.righe.push({ ...x, rid: crypto.randomUUID() }));
    if (q.nota) c.noteComanda = [c.noteComanda, q.nota].filter(Boolean).join(' · ');
  }
  await comandaSave(c);
  for (const q of [r, ...altri]) {
    q.tavolo = r.tavolo; q.stato = 'accettata'; q.gestitaAlle = new Date().toISOString(); q.comanda = c._id;
    await richiesteArch.save(q);
    broadcastOrder({ evento: 'richiesta_tavolo', tavolo: r.tavolo, id: q._id });
  }
  res.json({ ok: true, comanda: conTotali(c) });
});

// ===== DAL TAVOLO: stato dell'ordine per i clienti e "chiama il cameriere" =====
// stato della comanda del tavolo, visto dal telefono del cliente (niente prezzi né dati personali)
app.get('/api/tavolo/:tavolo/stato', async (req, res) => {
  try {
    let tavolo = String(req.params.tavolo || '').trim().slice(0, 10);
    const gruppo = String(req.query.gruppo || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
    if ((!tavolo || tavolo === '-') && gruppo) tavolo = await tavoloDelGruppo(gruppo);
    const da = new Date(Date.now() - 4 * 3600 * 1000).toISOString();
    const inAttesa = tavolo ? (await richiesteArch.list({ tavolo, stato: 'attesa', creataAlle: { $gte: da } }, null, 20)).length
      : (gruppo ? (await richiesteArch.list({ gruppo, stato: 'attesa', creataAlle: { $gte: da } }, null, 20)).length : 0);
    const c = tavolo ? (await comandeList({ stato: 'aperta' })).find(x => x.tipo === 'tavolo' && x.tavolo === tavolo) : null;
    let stato = 'nessuno';
    if (inAttesa) stato = 'da_confermare';
    else if (c) {
      const daMandare = diffComanda(c.inviate, c.righe);
      const servito = c.servitoAlle && c.ultimoInvio && c.servitoAlle >= c.ultimoInvio;
      if (daMandare.aggiunte.length && !servito && !c.invii) stato = 'confermato';
      else if (c.invii && !servito) stato = 'in_preparazione';
      else if (servito) stato = 'servito';
      else stato = 'confermato';
    }
    // ultima chiamata di questo tavolo: aperta, oppure presa da un cameriere negli ultimi 5 minuti
    const chiamata = [...chiamateTavolo].reverse().find(x => ((tavolo && x.tavolo === tavolo) || (gruppo && x.gruppo === gruppo))
      && (!x.gestita || Date.now() - new Date(x.presaAlle).getTime() < 5 * 60 * 1000));
    res.json({ ok: true, tavolo, stato, minuti: c && c.ultimoInvio ? Math.max(0, Math.round((Date.now() - new Date(c.ultimoInvio).getTime()) / 60000)) : null,
      piatti: c ? (c.righe || []).map(r => ({ nome: r.nome, qty: r.qty })) : [], chiamata: chiamata ? { motivo: chiamata.motivo, presa: !!chiamata.gestita, presaDa: chiamata.presaDa || '' } : null });
  } catch (e) { console.error(e); res.status(500).json({ ok: false, error: 'Errore' }); }
});
// chiamate dal tavolo: restano in memoria finché un cameriere non tocca "Vado io"
const chiamateTavolo = [];
const tentativiChiamata = new Map();
const MOTIVI_CHIAMATA = { cameriere: 'chiama il cameriere', conto: 'chiede il conto', acqua: 'chiede da bere', aiuto: 'ha bisogno di aiuto' };
app.post('/api/tavolo/chiama', async (req, res) => {
  const b = req.body || {};
  let tavolo = String(b.tavolo || '').trim().slice(0, 10);
  const gruppo = String(b.gruppo || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
  if (!tavolo && gruppo) tavolo = await tavoloDelGruppo(gruppo);
  if (!tavolo && !gruppo) return res.status(400).json({ ok: false, error: 'Tavolo mancante' });
  const motivo = MOTIVI_CHIAMATA[b.motivo] ? b.motivo : 'cameriere';
  const ip = req.ip || 'x', ora = Date.now();
  const t = tentativiChiamata.get(ip) || [];
  const recenti = t.filter(x => ora - x < 10 * 60 * 1000);
  if (recenti.length && ora - recenti[recenti.length - 1] < 45 * 1000) return res.json({ ok: true, gia: true }); // tocchi ripetuti: una sola chiamata
  if (recenti.length >= 6) return res.status(429).json({ ok: false, error: 'Hai già chiamato: il cameriere sta arrivando.' });
  recenti.push(ora); tentativiChiamata.set(ip, recenti);
  // se c'è già una chiamata aperta per quel tavolo si aggiorna quella
  let ch = chiamateTavolo.find(x => !x.gestita && ((tavolo && x.tavolo === tavolo) || (gruppo && x.gruppo === gruppo)));
  if (ch) { ch.motivo = motivo; ch.ora = new Date().toISOString(); ch.volte = (ch.volte || 1) + 1; }
  else {
    ch = { id: crypto.randomBytes(6).toString('hex'), tavolo, gruppo, motivo, nome: String(b.nome || '').slice(0, 30), ora: new Date().toISOString(), volte: 1, gestita: false };
    chiamateTavolo.push(ch);
    while (chiamateTavolo.length > 200) chiamateTavolo.shift();
  }
  broadcastOrder({ evento: 'chiamata_tavolo', ...ch, testo: MOTIVI_CHIAMATA[motivo] });
  pushSicura(['staff', 'titolare'], { titolo: `🙋 Tavolo ${tavolo || gruppo}`, testo: `Il tavolo ${MOTIVI_CHIAMATA[motivo]}${ch.volte > 1 ? ` (${ch.volte}ª volta)` : ''}`, tag: 'chiamata-' + (tavolo || gruppo), url: './' }, 300);
  res.json({ ok: true });
});
app.get('/api/tavolo/chiamate', (req, res) => {
  const da = Date.now() - 2 * 3600 * 1000;
  res.json({ ok: true, chiamate: chiamateTavolo.filter(x => !x.gestita && new Date(x.ora).getTime() > da).map(x => ({ ...x, testo: MOTIVI_CHIAMATA[x.motivo] })) });
});
app.post('/api/tavolo/chiamate/:id/presa', (req, res) => {
  const ch = chiamateTavolo.find(x => x.id === req.params.id);
  if (!ch) return res.status(404).json({ ok: false, error: 'Chiamata non trovata' });
  ch.gestita = true; ch.presaDa = String((req.body || {}).cameriere || '').slice(0, 30); ch.presaAlle = new Date().toISOString();
  broadcastOrder({ evento: 'chiamata_presa', id: ch.id, tavolo: ch.tavolo });
  res.json({ ok: true });
});

// ===== OFFERTE: verifica di un codice sconto dal sito =====
const tentativiCodice = new Map();
app.get('/api/offerte/verifica', (req, res) => {
  const ip = req.ip || 'x';
  const t = tentativiCodice.get(ip) || { n: 0, dal: Date.now() };
  if (Date.now() - t.dal > 10 * 60 * 1000) { t.n = 0; t.dal = Date.now(); }
  t.n++; tentativiCodice.set(ip, t);
  if (t.n > 30) return res.status(429).json({ ok: false, error: 'Troppi tentativi, riprova tra qualche minuto' });
  const codice = String(req.query.codice || '').trim().toUpperCase();
  const subtotale = Math.max(0, Number(req.query.subtotale) || 0);
  const o = (CONFIG.offerte || []).find(x => x.attiva && x.codice && x.codice === codice);
  if (!o) return res.json({ ok: true, valido: false, messaggio: 'Codice non valido' });
  const oggi = giornoServizio(), dow = new Date(oggi + 'T12:00:00').getDay();
  if (o.scadenza && o.scadenza < oggi) return res.json({ ok: true, valido: false, messaggio: 'Codice scaduto' });
  if (o.giorni && o.giorni.length && !o.giorni.includes(dow)) return res.json({ ok: true, valido: false, messaggio: 'Codice non valido oggi' });
  if (subtotale < (o.minimo || 0)) return res.json({ ok: true, valido: false, messaggio: `Valido con una spesa di almeno ${money(o.minimo)}` });
  const sconto = round2(o.tipo === 'euro' ? Math.min(o.valore, subtotale) : subtotale * o.valore / 100);
  res.json({ ok: true, valido: true, nome: o.nome, sconto, tipo: o.tipo, valore: o.valore });
});

// ===== PUNTI FEDELTÀ (contati sul numero di telefono: tot pizze = premio) =====
const fedeltaArch = archivio('fedelta');
function nomiPizze(){
  const s = new Set();
  MENU_CATALOG.filter(g => g.cat === 'Pizza').forEach(g => g.items.forEach(n => s.add(n)));
  customMenuItemsCache.filter(i => i.cat === 'Pizza').forEach(i => s.add(i.nome));
  return s;
}
function pizzeIn(articoli){ const s = nomiPizze(); return (articoli || []).reduce((t, a) => t + (s.has(a.nome) ? (Number(a.qty) || 0) : 0), 0); }
async function statoFedelta(tel, extra = 0){
  const f = CONFIG.fedelta;
  let pizze = extra;
  if (ordersCollection) {
    const ord = await ordersCollection.find({ phoneNormalized: tel }, { projection: { articoli: 1 } }).toArray();
    ord.forEach(o => { pizze += pizzeIn(o.articoli); });
  } else orderHistory.filter(o => o.phoneNormalized === tel).forEach(o => { pizze += pizzeIn(o.articoli); });
  (await comandeList({ stato: 'chiusa' }, 50000)).filter(c => c.telefono && normalizePhone(c.telefono) === tel)
    .forEach(c => (c.righe || []).forEach(r => { if (r.cat === 'Pizza') pizze += r.qty; }));
  const doc = await fedeltaArch.get(tel);
  const usati = doc ? doc.riscatti || 0 : 0;
  const totPremi = Math.floor(pizze / f.ogni);
  const disponibili = Math.max(0, totPremi - usati);
  return { pizze, ogni: f.ogni, premio: f.premio, premi: disponibili, punti: pizze - totPremi * f.ogni, riscatti: usati };
}
app.get('/api/fedelta', async (req, res) => {
  if (!CONFIG.fedelta.attiva) return res.json({ ok: true, attiva: false });
  const tel = normalizePhone(req.query.telefono);
  if (!tel || tel.length < 6) return res.json({ ok: true, attiva: true, pizze: 0, punti: 0, premi: 0, ogni: CONFIG.fedelta.ogni, premio: CONFIG.fedelta.premio });
  res.json({ ok: true, attiva: true, ...(await statoFedelta(tel)) });
});
app.post('/api/fedelta/riscatta', async (req, res) => {
  const tel = normalizePhone((req.body || {}).telefono);
  if (!tel) return res.status(400).json({ ok: false, error: 'Numero mancante' });
  const st = await statoFedelta(tel);
  if (st.premi <= 0) return res.status(400).json({ ok: false, error: 'Nessun premio disponibile' });
  const doc = (await fedeltaArch.get(tel)) || { _id: tel, riscatti: 0, storico: [] };
  doc.riscatti = (doc.riscatti || 0) + 1;
  doc.storico = [...(doc.storico || []), { alle: new Date().toISOString(), da: String((req.body || {}).cameriere || '').slice(0, 30) }].slice(-50);
  await fedeltaArch.save(doc);
  res.json({ ok: true, ...(await statoFedelta(tel)) });
});

// ===== SCHEDA CLIENTE: storico ordini, piatti preferiti, note (es. allergie) =====
const clientiArch = archivio('clienti');
async function ordiniDi(tel){
  if (ordersCollection) return ordersCollection.find({ phoneNormalized: tel }, { projection: { _id: 0, numeroOrdine: 1, ricevutoAlle: 1, grandTotal: 1, articoli: 1, nome: 1, name: 1, cognome: 1, address: 1, modalita: 1, email: 1 } }).sort({ ricevutoAlle: -1 }).limit(300).toArray();
  return orderHistory.filter(o => o.phoneNormalized === tel);
}
// ===== PROMEMORIA AI CLIENTI VIA E-MAIL (deciso dal titolare, con link per non riceverne più) =====
const disiscrittiArch = archivio('disiscrittiEmail');   // _id = email
const promemoriaArch = archivio('promemoriaInviati');   // _id = email, ultimo invio
const emailValida = e => /^[^\s@<>"']{1,64}@[^\s@<>"']{1,180}\.[a-z]{2,}$/i.test(String(e || '').trim());
function firmaDisiscrivi(email){ return crypto.createHmac('sha256', JWT_SECRET).update('unsub:' + email.toLowerCase()).digest('hex').slice(0, 20); }
async function clientiDaRichiamare(giorni){
  const limite = Date.now() - giorni * 86400000, da = new Date(Date.now() - 365 * 86400000).toISOString();
  const ordini = ordersCollection
    ? await ordersCollection.find({ ricevutoAlle: { $gte: da }, email: { $exists: true, $ne: '' } }, { projection: { email: 1, name: 1, nome: 1, grandTotal: 1, ricevutoAlle: 1 } }).limit(20000).toArray()
    : orderHistory.filter(o => o.email && o.ricevutoAlle >= da);
  const m = new Map();
  ordini.forEach(o => {
    const e = String(o.email || '').trim().toLowerCase(); if (!emailValida(e)) return;
    const x = m.get(e) || { email: e, nome: '', ordini: 0, speso: 0, ultimo: '' };
    if (!x.nome) x.nome = String(o.nome || o.name || '').trim().split(' ')[0];
    x.ordini++; x.speso += Number(o.grandTotal) || 0; if (o.ricevutoAlle > x.ultimo) x.ultimo = o.ricevutoAlle;
    m.set(e, x);
  });
  const out = [];
  for (const x of m.values()) {
    if (new Date(x.ultimo).getTime() > limite) continue;
    if (await disiscrittiArch.get(x.email)) continue;
    const pr = await promemoriaArch.get(x.email);
    x.ultimoPromemoria = pr ? pr.alle : null;
    x.speso = round2(x.speso);
    out.push(x);
  }
  return out.sort((a, b) => b.speso - a.speso).slice(0, 300);
}
app.get('/api/titolare/promemoria', soloTitolare, async (req, res) => {
  try {
    const giorni = Math.min(365, Math.max(7, parseInt(req.query.giorni, 10) || 30));
    res.json({ ok: true, clienti: await clientiDaRichiamare(giorni), emailAttiva: !!RESEND_API_KEY,
      offerte: (CONFIG.offerte || []).filter(o => o.attiva && o.codice).map(o => ({ id: o.id, nome: o.nome, codice: o.codice, tipo: o.tipo, valore: o.valore, scadenza: o.scadenza })) });
  } catch (err) { console.error('Errore promemoria:', err); res.status(500).json({ ok: false, error: 'Errore server' }); }
});
function htmlPromemoria(nome, messaggio, offerta, linkStop){
  const sconto = offerta ? (offerta.tipo === 'euro' ? `${money(offerta.valore)} di sconto` : `${offerta.valore}% di sconto`) : '';
  const escH = t => String(t || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return `<!DOCTYPE html><html lang="it"><body style="margin:0;background:#f4f1ee;font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="padding:20px 0;"><tr><td align="center">
<table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#fff;border-radius:18px;overflow:hidden;">
<tr><td style="background:linear-gradient(135deg,#c1382b,#7a1f16);padding:26px;text-align:center;color:#fff;">
<img src="${SITE_URL}/icon-512.png?v=${ASSET_VERSION}" width="64" height="64" alt="La Casa di Carta" style="border-radius:16px;display:block;margin:0 auto 10px;">
<div style="font-size:22px;font-weight:800;">Ciao ${escH(nome || '')}!</div></td></tr>
<tr><td style="padding:22px;font-size:16px;line-height:1.5;color:#333;">${escH(messaggio).replace(/\n/g, '<br>')}
${offerta ? `<div style="margin:18px 0;padding:16px;border:2px dashed #c1382b;border-radius:14px;text-align:center;"><div style="font-size:14px;color:#7a1f16;">Per te ${sconto}${offerta.scadenza ? ` fino al ${new Date(offerta.scadenza + 'T12:00:00').toLocaleDateString('it-IT')}` : ''}</div><div style="font-size:26px;font-weight:800;letter-spacing:2px;color:#c1382b;margin-top:4px;">${escH(offerta.codice)}</div><div style="font-size:13px;color:#777;">scrivi il codice quando ordini online</div></div>` : ''}
<div style="text-align:center;margin-top:16px;"><a href="${SITE_URL}" style="display:inline-block;background:#c1382b;color:#fff;text-decoration:none;font-weight:800;padding:14px 26px;border-radius:12px;">🍕 Ordina ora</a></div>
</td></tr>
<tr><td style="padding:14px 22px 22px;font-size:12px;color:#999;text-align:center;">Pizzeria La Casa di Carta · Via XX Settembre 192, Niscemi<br>Ricevi questa mail perché hai ordinato da noi online. <a href="${linkStop}" style="color:#999;">Non voglio più ricevere queste e-mail</a></td></tr>
</table></td></tr></table></body></html>`;
}
app.post('/api/titolare/promemoria', soloTitolare, async (req, res) => {
  try {
    if (!RESEND_API_KEY) return res.status(400).json({ ok: false, error: 'Invio e-mail non configurato (manca RESEND_API_KEY su Render)' });
    const b = req.body || {};
    const emails = [...new Set((Array.isArray(b.emails) ? b.emails : []).map(e => String(e).trim().toLowerCase()).filter(emailValida))].slice(0, 100);
    if (!emails.length) return res.status(400).json({ ok: false, error: 'Nessun cliente scelto' });
    const messaggio = String(b.messaggio || '').slice(0, 1200) || 'È da un po\' che non ci vediamo! Ti aspettiamo con le nostre pizze appena sfornate.';
    const oggetto = String(b.oggetto || '').slice(0, 120) || 'Ci manchi! 🍕 La Casa di Carta';
    const offerta = b.offertaId ? (CONFIG.offerte || []).find(o => o.id === b.offertaId && o.attiva && o.codice) : null;
    const nomi = new Map((Array.isArray(b.nomi) ? b.nomi : []).map(x => [String(x.email || '').toLowerCase(), String(x.nome || '').slice(0, 40)]));
    let inviate = 0, saltate = 0;
    for (const e of emails) {
      if (await disiscrittiArch.get(e)) { saltate++; continue; }
      const link = `https://${req.get('host')}/api/disiscrivi?e=${encodeURIComponent(e)}&k=${firmaDisiscrivi(e)}`;
      const nome = nomi.get(e) || '';
      const testo = `Ciao ${nome}!\n\n${messaggio}\n${offerta ? `\nCodice sconto: ${offerta.codice}\n` : ''}\nOrdina qui: ${SITE_URL}\n\nPer non ricevere più queste e-mail: ${link}`;
      await sendEmail(e, oggetto, testo, htmlPromemoria(nome, messaggio, offerta, link));
      await promemoriaArch.save({ _id: e, alle: new Date().toISOString() });
      inviate++;
      await new Promise(r => setTimeout(r, 600)); // piano piano: niente invii a raffica
    }
    res.json({ ok: true, inviate, saltate });
  } catch (err) { console.error('Errore invio promemoria:', err); res.status(500).json({ ok: false, error: 'Errore server' }); }
});
app.get('/api/disiscrivi', async (req, res) => {
  const e = String(req.query.e || '').trim().toLowerCase(), k = String(req.query.k || '');
  const pagina = (t) => `<!DOCTYPE html><html lang="it"><meta name="viewport" content="width=device-width,initial-scale=1"><body style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#f4f1ee;display:flex;align-items:center;justify-content:center;min-height:90vh;margin:0;padding:16px;"><div style="background:#fff;border-radius:18px;padding:28px;max-width:420px;text-align:center;"><div style="font-size:40px;">🍕</div><h2 style="color:#7a1f16;">La Casa di Carta</h2><p style="font-size:16px;color:#333;">${t}</p></div></body></html>`;
  if (!emailValida(e) || !uguali(k, firmaDisiscrivi(e))) return res.status(400).send(pagina('Link non valido.'));
  await disiscrittiArch.save({ _id: e, alle: new Date().toISOString() });
  res.send(pagina('Fatto: non riceverai più le nostre e-mail promozionali. Le conferme dei tuoi ordini continueranno ad arrivare normalmente.'));
});

app.get('/api/clienti/cerca', async (req, res) => {
  try {
    const q = String(req.query.q || '').trim().slice(0, 40);
    const mappa = new Map();
    const aggiungi = (tel, nome, imp, quando) => {
      if (!tel) return;
      const x = mappa.get(tel) || { telefono: tel, nome: '', ordini: 0, speso: 0, ultimo: '' };
      if (nome && !x.nome) x.nome = nome;
      x.ordini++; x.speso += imp; if (quando > x.ultimo) x.ultimo = quando;
      mappa.set(tel, x);
    };
    const da = new Date(Date.now() - 365 * 86400000).toISOString();
    const esc = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const cifre = q.replace(/\D/g, '');
    let ordini = [];
    if (ordersCollection) {
      const filtro = { ricevutoAlle: { $gte: da }, phoneNormalized: { $exists: true, $ne: '' } };
      if (q) filtro.$or = cifre.length >= 3 ? [{ phoneNormalized: { $regex: cifre } }] : [{ name: { $regex: esc, $options: 'i' } }, { nome: { $regex: esc, $options: 'i' } }, { cognome: { $regex: esc, $options: 'i' } }];
      ordini = await ordersCollection.find(filtro, { projection: { phoneNormalized: 1, name: 1, nome: 1, grandTotal: 1, ricevutoAlle: 1 } }).limit(5000).toArray();
    } else ordini = orderHistory.filter(o => o.phoneNormalized);
    ordini.forEach(o => { if (!q || cifre.length >= 3 ? (!q || o.phoneNormalized.includes(cifre)) : new RegExp(esc, 'i').test(`${o.name || ''} ${o.nome || ''}`)) aggiungi(o.phoneNormalized, o.name || o.nome, Number(o.grandTotal) || 0, o.ricevutoAlle); });
    (await comandeList({ stato: 'chiusa' }, 50000)).filter(c => c.telefono).forEach(c => {
      const tel = normalizePhone(c.telefono);
      if (q && !(cifre.length >= 3 ? tel.includes(cifre) : new RegExp(esc, 'i').test(c.nome || ''))) return;
      aggiungi(tel, c.nome, Number(c.totaleIncassato) || 0, c.chiusaAlle || c.creataAlle);
    });
    const schede = await clientiArch.list({}, null, 5000);
    schede.forEach(sc => { const x = mappa.get(sc._id); if (x) { x.nota = sc.note || ''; if (sc.nome) x.nome = sc.nome; } else if (q && (sc._id.includes(cifre || '~') || new RegExp(esc, 'i').test(sc.nome || ''))) mappa.set(sc._id, { telefono: sc._id, nome: sc.nome, ordini: 0, speso: 0, ultimo: '', nota: sc.note || '' }); });
    const lista = [...mappa.values()].map(x => ({ ...x, speso: round2(x.speso) })).sort((a, b) => q ? b.ultimo.localeCompare(a.ultimo) : b.speso - a.speso).slice(0, 40);
    res.json({ ok: true, clienti: lista });
  } catch (err) { console.error('Errore ricerca clienti:', err); res.status(500).json({ ok: false, error: 'Errore server' }); }
});
app.get('/api/clienti/:tel', async (req, res) => {
  try {
    const tel = normalizePhone(req.params.tel);
    if (!tel || tel.length < 6) return res.status(400).json({ ok: false, error: 'Numero non valido' });
    const ordini = await ordiniDi(tel);
    const comande = (await comandeList({ stato: 'chiusa' }, 50000)).filter(c => c.telefono && normalizePhone(c.telefono) === tel);
    const scheda = (await clientiArch.get(tel)) || {};
    const piatti = {};
    ordini.forEach(o => (o.articoli || []).forEach(a => { piatti[a.nome] = (piatti[a.nome] || 0) + (Number(a.qty) || 0); }));
    comande.forEach(c => (c.righe || []).forEach(r => { piatti[r.nome] = (piatti[r.nome] || 0) + r.qty; }));
    const ultimoInd = (ordini.find(o => o.modalita === 'consegna' && o.address) || comande.find(c => c.indirizzo) || {});
    const pren = await prenotazioniArch.list({}, null, 5000);
    res.json({ ok: true, cliente: {
      telefono: tel,
      nome: scheda.nome || (ordini[0] && (ordini[0].name || [ordini[0].nome, ordini[0].cognome].filter(Boolean).join(' '))) || (comande[0] && comande[0].nome) || '',
      note: scheda.note || '',
      indirizzo: ultimoInd.address || ultimoInd.indirizzo || '',
      email: (ordini.find(o => o.email) || {}).email || '',
      online: { ordini: ordini.length, speso: round2(ordini.reduce((t, o) => t + (Number(o.grandTotal) || 0), 0)) },
      sala: { conti: comande.length, speso: round2(comande.reduce((t, c) => t + (Number(c.totaleIncassato) || 0), 0)) },
      prenotazioni: pren.filter(p => normalizePhone(p.telefono) === tel).length,
      bloccato: blockedPhonesCache.has(tel),
      preferiti: Object.entries(piatti).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([nome, qty]) => ({ nome, qty })),
      ultimi: [...ordini.map(o => ({ quando: o.ricevutoAlle, tipo: o.modalita === 'consegna' ? 'Consegna' : 'Ritiro', totale: Number(o.grandTotal) || 0, cosa: (o.articoli || []).map(a => `${a.qty}x ${a.nome}`).join(', ') })),
               ...comande.map(c => ({ quando: c.chiusaAlle || c.creataAlle, tipo: c.tipo === 'consegna' ? 'Consegna (tel.)' : c.tipo === 'asporto' ? 'Asporto (tel.)' : 'Sala', totale: Number(c.totaleIncassato) || 0, cosa: (c.righe || []).map(r => `${r.qty}x ${r.nome}`).join(', ') }))]
        .sort((a, b) => String(b.quando).localeCompare(String(a.quando))).slice(0, 12),
      fedelta: CONFIG.fedelta.attiva ? await statoFedelta(tel) : null
    } });
  } catch (err) { console.error('Errore scheda cliente:', err); res.status(500).json({ ok: false, error: 'Errore server' }); }
});
app.put('/api/clienti/:tel', async (req, res) => {
  const tel = normalizePhone(req.params.tel);
  if (!tel || tel.length < 6) return res.status(400).json({ ok: false, error: 'Numero non valido' });
  const b = req.body || {};
  const doc = (await clientiArch.get(tel)) || { _id: tel };
  if (b.note !== undefined) doc.note = String(b.note || '').slice(0, 500);
  if (b.nome !== undefined) doc.nome = String(b.nome || '').slice(0, 80);
  doc.aggiornato = new Date().toISOString();
  await clientiArch.save(doc);
  res.json({ ok: true });
});

// ===== SCORTE DI MAGAZZINO =====
const scorteArch = archivio('scorte');
async function segnaEsauritiDaScorta(chiavi, finiti){
  if (!chiavi || !chiavi.length) return;
  for (const k of chiavi) {
    if (finiti) { soldOutCache.add(k); soldOutFino.set(k, null); if (soldOutCollection) await soldOutCollection.updateOne({ _id: k }, { $set: { _id: k, fino: null, daScorta: true } }, { upsert: true }).catch(() => {}); }
    else if (soldOutCache.has(k)) { soldOutCache.delete(k); soldOutFino.delete(k); if (soldOutCollection) await soldOutCollection.deleteOne({ _id: k }).catch(() => {}); }
  }
  avvisaEsauriti();
}
function pulisciScorta(b, p = {}){
  const out = { ...p };
  if (b.nome !== undefined) out.nome = String(b.nome || '').slice(0, 60).trim();
  if (b.unita !== undefined) out.unita = String(b.unita || '').slice(0, 15);
  if (b.quantita !== undefined) out.quantita = round2(Math.max(0, Number(String(b.quantita).replace(',', '.')) || 0));
  if (b.soglia !== undefined) out.soglia = round2(Math.max(0, Number(String(b.soglia).replace(',', '.')) || 0));
  if (Array.isArray(b.collegati)) out.collegati = b.collegati.map(String).filter(k => k.includes('|')).slice(0, 60);
  return out;
}
app.get('/api/scorte', async (req, res) => res.json({ ok: true, scorte: await scorteArch.list({}, { nome: 1 }, 500) }));
app.post('/api/scorte', async (req, res) => {
  const b = req.body || {};
  const vecchia = b._id ? await scorteArch.get(String(b._id)) : null;
  const sc = pulisciScorta(b, vecchia || { _id: crypto.randomUUID(), nome: '', unita: 'pz', quantita: 0, soglia: 0, collegati: [] });
  if (!sc.nome) return res.status(400).json({ ok: false, error: 'Scrivi il nome' });
  sc.aggiornata = new Date().toISOString(); delete sc.daContare;
  await scorteArch.save(sc);
  const eraFinita = vecchia && vecchia.quantita <= 0, finita = sc.quantita <= 0;
  if (finita !== eraFinita || (vecchia && JSON.stringify(vecchia.collegati) !== JSON.stringify(sc.collegati))) await segnaEsauritiDaScorta(sc.collegati, finita);
  broadcastOrder({ evento: 'scorte_aggiornate' });
  res.json({ ok: true, scorta: sc });
});
app.post('/api/scorte/:id/movimento', async (req, res) => {
  const sc = await scorteArch.get(req.params.id);
  if (!sc) return res.status(404).json({ ok: false, error: 'Non trovata' });
  const prima = sc.quantita;
  sc.quantita = round2(Math.max(0, prima + (Number((req.body || {}).delta) || 0)));
  sc.aggiornata = new Date().toISOString(); delete sc.daContare;
  await scorteArch.save(sc);
  if ((prima <= 0) !== (sc.quantita <= 0)) await segnaEsauritiDaScorta(sc.collegati, sc.quantita <= 0);
  broadcastOrder({ evento: 'scorte_aggiornate' });
  res.json({ ok: true, scorta: sc });
});
// ----- Scorte collegate all'app Fornitori (listino) e al ricevimento merce HACCP -----
// Su Render: FORNITORI_URL = indirizzo dell'app fornitori (es. https://fornitori.pizzerialacasadicarta.it), FORNITORI_PIN = il suo PIN (se l'hai messo).
async function leggiFornitori(){
  const base = String(process.env.FORNITORI_URL || '').replace(/\/+$/, '');
  if (!base) return null;
  const headers = {}; if (process.env.FORNITORI_PIN) headers['x-pin'] = process.env.FORNITORI_PIN;
  const r = await fetch(base + '/api/fornitori', { headers, signal: AbortSignal.timeout(15000) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || ('app fornitori: errore ' + r.status));
  return (d.fornitori || []).map(f => ({ id: f.id, nome: f.nome, whatsapp: f.whatsapp || '', referente: f.referente || '', prodotti: (f.prodotti || []).map(p => ({ id: p.id, nome: p.nome, unita: p.unita || 'pezzo', conf: p.conf || '' })) }));
}
app.get('/api/scorte/fornitori', async (req, res) => {
  try {
    const fornitori = await leggiFornitori();
    if (!fornitori) return res.json({ ok: true, configurato: false });
    const scorte = await scorteArch.list({}, null, 500);
    res.json({ ok: true, configurato: true, fornitori, collegati: scorte.filter(x => x.prodottoId).map(x => x.prodottoId) });
  } catch (err) { console.error('Errore lettura fornitori:', err.message); res.status(502).json({ ok: false, error: err.message }); }
});
app.post('/api/scorte/importa', async (req, res) => {
  const voci = Array.isArray((req.body || {}).voci) ? req.body.voci.slice(0, 200) : [];
  const esistenti = await scorteArch.list({}, null, 1000);
  const gia = new Set(esistenti.flatMap(x => [x.prodottoId, ...(x.prodottoIds || [])]).filter(Boolean));
  const chiaveNome = (f, n) => String(f) + '|' + String(n).toLowerCase().replace(/\s+/g, ' ').trim();
  const giaNomi = new Set(esistenti.filter(x => x.fornitoreId).map(x => chiaveNome(x.fornitoreId, x.nome)));
  let creati = 0;
  for (const v of voci) {
    const prodottoId = String(v.prodottoId || '').slice(0, 40), fornitoreId = String(v.fornitoreId || '').slice(0, 40);
    if (!prodottoId || !fornitoreId || gia.has(prodottoId)) continue;
    const nome = String(v.nome || '').slice(0, 60).trim(); if (!nome) continue;
    if (giaNomi.has(chiaveNome(fornitoreId, nome))) { gia.add(prodottoId); continue; }
    giaNomi.add(chiaveNome(fornitoreId, nome));
    const sc = { _id: crypto.randomUUID(), nome, unita: String(v.unita || 'pezzo').slice(0, 15), quantita: 0, soglia: Math.max(0, Number(v.soglia) || 0), daContare: true, collegati: [],
      fornitoreId, fornitoreNome: String(v.fornitoreNome || '').slice(0, 60), prodottoId, aggiornata: new Date().toISOString() };
    await scorteArch.save(sc); gia.add(prodottoId); creati++;
  }
  broadcastOrder({ evento: 'scorte_aggiornate' });
  res.json({ ok: true, creati });
});
// sistema le scorte importate: unisce i doppioni (stesso fornitore e nome) e segna "da contare" quelle mai caricate
app.post('/api/scorte/sistema', async (req, res) => {
  const tutte = await scorteArch.list({}, null, 2000);
  const kn = x => String(x.fornitoreId) + '|' + String(x.nome).toLowerCase().replace(/\s+/g, ' ').trim();
  const visti = new Map(); let uniti = 0, daContare = 0;
  for (const x of tutte) {
    if (!x.fornitoreId || !x.prodottoId) continue;
    const k = kn(x), base = visti.get(k);
    if (!base) { visti.set(k, x); continue; }
    base.prodottoIds = [...new Set([...(base.prodottoIds || []), x.prodottoId, ...(x.prodottoIds || [])])];
    base.quantita = round2((base.quantita || 0) + (x.quantita || 0));
    base.collegati = [...new Set([...(base.collegati || []), ...(x.collegati || [])])];
    if (x.ultimoCarico && !base.ultimoCarico) base.ultimoCarico = x.ultimoCarico;
    if (!x.daContare) base.daContare = false;
    await scorteArch.del(x._id); uniti++;
  }
  for (const x of visti.values()) {
    if (x.daContare === undefined && !x.ultimoCarico && !(x.quantita > 0) && (x.soglia || 0) <= 1 && !(x.collegati || []).length) { x.daContare = true; x.soglia = 0; }
    if (x.daContare) daContare++;
    await scorteArch.save(x);
  }
  broadcastOrder({ evento: 'scorte_aggiornate' });
  res.json({ ok: true, uniti, daContare });
});
// carico automatico: arriva dall'app fornitori quando una fattura scansionata nel ricevimento merce HACCP viene letta
const caricoScorteArch = archivio('caricoScorte');
app.post('/api/scorte/carico', async (req, res) => {
  const k = process.env.STAFF_KEY;
  if (k && req.get('x-staff-key') !== k && !(req.get('x-titolare-token'))) return res.status(401).json({ ok: false, error: 'chiave non valida' });
  const carichi = Array.isArray((req.body || {}).carichi) ? req.body.carichi.slice(0, 300) : [];
  const scorte = await scorteArch.list({}, null, 1000);
  let caricati = 0, giaVisti = 0, senzaScorta = 0;
  for (const c of carichi) {
    const chiave = String(c.chiave || '').slice(0, 200), q = round2(Number(c.quantita));
    if (!chiave || !Number.isFinite(q) || q <= 0 || q > 100000) continue;
    if (await caricoScorteArch.get(chiave)) { giaVisti++; continue; }
    const sc = scorte.find(x => x.prodottoId && (x.prodottoId === String(c.prodottoId) || (x.prodottoIds || []).includes(String(c.prodottoId))));
    await caricoScorteArch.save({ _id: chiave, quando: new Date().toISOString(), prodottoId: String(c.prodottoId || ''), quantita: q, applicato: !!sc });
    if (!sc) { senzaScorta++; continue; }
    const prima = sc.quantita; sc.quantita = round2(prima + q); sc.aggiornata = new Date().toISOString(); sc.ultimoCarico = { quando: sc.aggiornata, quantita: q }; delete sc.daContare;
    await scorteArch.save(sc);
    if (prima <= 0 && sc.quantita > 0) await segnaEsauritiDaScorta(sc.collegati, false);
    caricati++;
  }
  if (caricati) broadcastOrder({ evento: 'scorte_aggiornate' });
  res.json({ ok: true, caricati, giaVisti, senzaScorta });
});
// svuota tutto il magazzino (solo titolare)
app.post('/api/scorte/azzera', soloTitolare, async (req, res) => {
  if ((req.body || {}).conferma !== true) return res.status(400).json({ ok: false, error: 'Serve la conferma' });
  const tutte = await scorteArch.list({}, null, 5000);
  for (const x of tutte) await scorteArch.del(x._id);
  broadcastOrder({ evento: 'scorte_aggiornate' });
  res.json({ ok: true, eliminate: tutte.length });
});
app.delete('/api/scorte/:id', async (req, res) => {
  await scorteArch.del(req.params.id);
  res.json({ ok: true });
});

// ===== ALLERGENI E INTOLLERANZE (Reg. UE 1169/2011: i 14 allergeni) =====
// Il titolare conferma piatto per piatto: finché non e' "verificato" il sito NON elenca gli allergeni, dice di chiedere al personale.
const ALLERGENI_ELENCO = [
  { id: 'glutine', nome: 'Cereali contenenti glutine', emoji: '🌾' }, { id: 'crostacei', nome: 'Crostacei', emoji: '🦐' },
  { id: 'uova', nome: 'Uova', emoji: '🥚' }, { id: 'pesce', nome: 'Pesce', emoji: '🐟' },
  { id: 'arachidi', nome: 'Arachidi', emoji: '🥜' }, { id: 'soia', nome: 'Soia', emoji: '🫘' },
  { id: 'latte', nome: 'Latte e derivati (lattosio)', emoji: '🥛' }, { id: 'guscio', nome: 'Frutta a guscio', emoji: '🌰' },
  { id: 'sedano', nome: 'Sedano', emoji: '🥬' }, { id: 'senape', nome: 'Senape', emoji: '🟡' },
  { id: 'sesamo', nome: 'Semi di sesamo', emoji: '⚪' }, { id: 'solfiti', nome: 'Anidride solforosa e solfiti', emoji: '🍷' },
  { id: 'lupini', nome: 'Lupini', emoji: '🌼' }, { id: 'molluschi', nome: 'Molluschi', emoji: '🦪' }
];
const ALLERGENI_IDS = new Set(ALLERGENI_ELENCO.map(a => a.id));
const DESCR_BASE = {"Pizza|Faccia Di Vecchia": "Olio evo, sale, origano", "Pizza|Rossa": "Polpa di pomodoro, olio evo", "Pizza|Biancaneve": "Fior di latte di Napoli, olio evo", "Pizza|Marinara": "Polpa di pomodoro, aglio, origano, olio evo", "Pizza|Margherita": "Pomodoro, fior di latte di Napoli, olio evo", "Pizza|Patapizza": "Pomodoro, fior di latte di Napoli, patatine fritte", "Pizza|Bufala": "Polpa di pomodoro, mozzarella di bufala, olio evo, basilico", "Pizza|Diavola": "Pomodoro, fior di latte di Napoli, salame piccante, olive", "Pizza|Pizza Regina": "Pomodoro, fior di latte di Napoli, prosciutto cotto, funghi freschi", "Pizza|Tonno & Cipolla": "Pomodoro, fior di latte di Napoli, tonno, cipolla", "Pizza|Napoli": "Pomodoro, fior di latte di Napoli, acciughe, olive", "Pizza|Oslo": "Pomodoro, fior di latte di Napoli, prosciutto cotto, panna", "Pizza|Norma": "Pomodoro, fior di latte di Napoli, melanzana fritta, ricotta salata", "Pizza|Berlino": "Pomodoro, fior di latte di Napoli, wurstel, patatine fritte", "Pizza|Tropea": "Pomodoro, fior di latte di Napoli, svizzero, porcini, tonno, cipolla di Tropea", "Pizza|Helsinki": "Fior di latte di Napoli, pancetta, funghi porcini, grana P dop, basilico", "Pizza|Sfiziosa": "Fior di latte di Napoli, salame piccante, salsiccia, spinaci, olive, grana P dop", "Pizza|Nairobi": "Fior di latte di Napoli, crema di pistacchio, mortadella, granella di pistacchio, grana P dop", "Pizza|Mosca": "Fior di latte di Napoli, crema di pistacchio, speck, granella di pistacchio, grana P dop", "Pizza|Rio": "Pomodoro, fior di latte di Napoli, polpette di cavallo, patatine fritte", "Pizza|Tutti I Gusti": "Pomodoro, fior di latte di Napoli, prosciutto, funghi, uova, wurstel, piselli, olive, carciofi", "Pizza|Ripiegata": "Pomodoro, mozzarella di bufala, crudo, rucola, pomodorini, grana", "Pizza|4 Formaggi": "Pomodoro, fior di latte di Napoli, gorgonzola, svizzero, grana", "Pizza|007": "Pomodoro, fior di latte di Napoli, prosciutto, uovo, wurstel, piselli", "Pizza|La Casa Di Carta": "Pomodoro, fior di latte di Napoli, svizzero, salsiccia, scamorza, funghi", "Pizza|Parmigiana": "Pomodoro, fior di latte di Napoli, melanzane fritte, prosciutto cotto, uovo, grana", "Pizza|4 Stagioni": "Pomodoro, fior di latte di Napoli, prosciutto, funghi, carciofi, olive", "Pizza|Bella Ciao": "Fior di latte di Napoli, crudo Ferrarini, rucola, pomodorini, grana Padana dop", "Pizza|Marsiglia": "Fior di latte di Napoli, capuliato, svizzero, patate della nonna, grana", "Pizza|Ai Porcini": "Pomodoro, fior di latte di Napoli, funghi porcini, crudo Ferrarini, grana Padana dop", "Pizza|Vegetariana": "Pomodoro, fior di latte di Napoli, melanzane fritte, funghi freschi, carciofi, olive, spinaci", "Pizza|Pizza Kebab": "Pomodoro, fior di latte di Napoli, kebab, patatine fritte", "Pizza|Gustosa": "Mozzarella, patate della nonna, salsiccia, spinaci, cipolla", "Pizza|Tokio": "Pomodoro, fior di latte di Napoli, bacon, porcini, scamorza", "Pizza|Bogotà": "Fior di latte di Napoli, salmone, porcini, panna, prezzemolo", "Pizza|Frutti Di Mare": "Pomodoro, fior di latte di Napoli, misto pesce, gamberoni", "Pizza|Cincinnati": "Pomodoro, fior di latte di Napoli, svizzero, funghi porcini, speck, granella pistacchio, grana P dop", "Pizza|Suprema": "Fior di latte di Napoli, patate con buccia extra croccante, bacon croccante, stracciatella pugliese, crema e granella di pistacchio", "Pizza|Denver": "Fior di latte di Napoli, prosciutto cotto, crocchette di patate, stracciata di bufala", "Pizza|Capricciosa": "Pomodoro, fior di latte di Napoli, prosciutto, funghi, uovo, olive", "Pizza Dolce|Nutella": "Nutella Ferrero, zucchero a velo", "Pizza Dolce|Kinder Bueno": "Nutella, kinder bueno, crema alle nocciole e zucchero a velo", "Pizza Dolce|Dubai": "Cioccolata, crema al pistacchio e kataifi", "Panini|Panino Patatine, Wurstel": "Patatine, Wurstel", "Panini|Panino con Patatine": "Patatine", "Panini|Panino Crocchette di Patate & Patatine": "Crocchette di patate, Patatine", "Panini|Panino Patatine, Wurstel in Salsa Rosa": "Patatine, Cocktail di würstel in salsa rosa", "Panini|Panino Pollo al Curry & Patatine": "Pollo al curry, Patatine", "Panini|Panino Pollo ai Funghi & Patatine": "Pollo ai funghi, Patatine", "Panini|Panino Pollo Impanato & Patatine": "Pollo impanato, Patatine", "Panini|Panino Pollo Messicano & Patatine": "Pollo messicano, Patatine", "Panini|Panino Pollo al Barbecue & Patatine": "Pollo al barbecue, Patatine", "Panini|Panino Petto di Pollo alla Griglia & Patatine": "Petto di pollo alla griglia, Patatine", "Panini|Panino Arrosto di Pollo & Patatine": "Arrosto di pollo, Patatine", "Panini|Panino Petto di Pollo Sfilettato & Patatine": "Petto di pollo sfilettato, Patatine", "Panini|Panino Porchettata & Patatine": "Patatine, Porchetta, Svizzero alla griglia", "Panini|Panino Salame Piccante e Mozzarella & Patatine": "Salame piccante, Mozzarella, Patatine", "Panini|Panino Salame Piccante e Svizzero & Patatine": "Salame piccante, Svizzero, Patatine", "Panini|Panino Bella Ciao & Patatine": "Patatine, Mozzarella, Crudo, Ciliegino, Rucola, Grana Padano DOP", "Panini|Panino 4 Formaggi & Patatine": "Patatine, Mozzarella, Formaggio, Svizzero, Gorgonzola, Grana Padano DOP", "Panini|Panino Prosciutto Mozzarella & Patatine": "Patatine, Prosciutto, Mozzarella alla griglia", "Panini|Cocktail Di Tonno & Patatine": "Patatine, Tonno, Lattuga, Maionese", "Panini|Panino Kebab & Patatine": "Carne kebab, Patatine", "Panini|Panino Polpette di Cavallo & Patatine": "Polpette di cavallo, Patatine", "Panini|Panino Cavallo & Patatine": "Carne di cavallo, Patatine", "Panini|Panino Salsiccia & Patatine": "Salsiccia, Patatine", "Panini|Panino in Cocktail di Gamberi in Salsa Rosa & Patatine": "Gamberi, Salsa rosa, Patatine", "Panini|Hamburger di Scottona & Patatine": "Patatine, Hamburger di scottona 200gr", "Panini|Hamburger di Angus & Patatine": "Patatine, Hamburger di Angus 200gr", "Panini|Panino Porchetta Artigianale e Patatine": "Patatine, Porchetta artigianale", "Panini|Panino con Salsiccia di Cavallo & Patatine": "Salsiccia di cavallo, Patatine", "Hamburger|Brooklyn": "Buns americano 12cm, hamburger, cheddar, salsa burger", "Hamburger|Bronx": "Doppia polpetta di cavallo, scamorza affumicata, cipolla caramellata, funghi piccanti, rucola, salsa barbecue", "Hamburger|Spicy": "Doppio hamburger di bovino, cheddar, funghi piccanti, cipolla caramellata, bacon, salsa samurai (piccante)", "Hamburger|Manathan": "Buns americano 12cm, hamburger di Angus 200gr, cheddar, bacon, pomodoro, lattuga, salsa burger, patatine", "Hamburger|Queens": "Buns americano 12cm, cotoletta di pollo croccante, lattuga, maionese", "Focacce|Focaccia Vuota Da Condire": "", "Focacce|Casareccia": "Capuliato, acciughe, olive, olio evo", "Focacce|Focaccia Prosciutto": "Prosciutto cotto, mozzarella, olive, olio", "Focacce|Focaccia Caprese": "Prosciutto cotto, mozzarella, ciliegino, origano, olio", "Focacce|Focaccia Del Pirata": "Mozzarella, tonno, ciliegino, lattuga, tabasco, maionese", "Focacce|Focaccia Mista": "Prosciutto cotto, mozzarella, uovo, olive, wurstel, olio", "Focacce|Deliziosa": "Salame piccante, mozzarella, funghi freschi, olive, olio evo", "Focacce|Focaccia 4 Formaggi": "Mozzarella, svizzero, gorgonzola, grana P dop", "Focacce|Bella Ciao": "Mozzarella, prosciutto crudo Ferrarini, rucola, pomodorini, grana P dop", "Focacce|Focaccia Nairobi": "Mozzarella, mortadella, crema di pistacchio, granella di pistacchio, grana", "Fritture|Vaschetta Piccola — Patatine": "", "Fritture|Vaschetta Media — Patatine": "", "Fritture|Patatine con Buccia": "Irresistibili, gustose e croccanti", "Fritture|Vaschetta Piccola — 4 Würstel & Patatine": "", "Fritture|Vaschetta — 8 Würstel": "", "Fritture|Vaschetta — Crocchette di Patate": "", "Fritture|Vaschetta di Kebab": "", "Fritture|Anelli di Cipolla": "", "Fritture|Panzerotti Fritti Mignon Pomodoro e Mozzarella": "", "Fritture|Mozzarelline Impanate": "", "Fritture|Bocconcini Pollo Amadori Impanato Piccante": "Dimensione normale", "Fritture|Arancini Mignon al Ragù": "7 arancini mignon al ragù", "Fritture|Nuggets 10 Pezzi": "Nuggets Amadori", "Bevande|Gassosa": "", "Bevande|Acqua Naturale Piccola": "", "Bevande|Acqua Frizzante": "", "Bevande|Coca Cola 33": "", "Bevande|Coca Cola Zero": "", "Bevande|Birra Moretti": "", "Bevande|Birra Peroni": "", "Bevande|Coca Cola Vetro cl 33": "", "Bevande|Estathe Pesca": "", "Bevande|Estathe Limone": "", "Bevande|Nastro Azzurro": "", "Bevande|Ceres": "", "Bevande|Coca Cola Bottiglia Grande": "", "Bevande|Birra Messina Grande": "Cristalli di sale", "Bevande|Birra Nastro Azzurro Grande": "", "Bevande|Peroni Chill Lemon": "", "Extra|Bustina Maionese": "", "Extra|Bustina Ketchup": ""};
const SALSE_GRATIS = ['Ketchup', 'Maionese', 'Salsa Cheddar', 'Salsa Barbecue', 'Salsa Chili', 'Salsa Curry', 'Salsa Rosa', 'Salsa Hamburger', 'Salsa Yogurt', 'Tabasco'];
// suggerimento automatico dagli ingredienti: serve solo come punto di partenza, il titolare deve controllare le etichette
function suggerisciAllergeni(cat, nome, desc){
  const t = (nome + ' ' + (desc || '')).toLowerCase(), a = new Set();
  const ha = re => re.test(t);
  if (['Pizza', 'Pizza Dolce', 'Panini', 'Hamburger', 'Focacce', 'Pane'].includes(cat)) a.add('glutine');
  if (ha(/impanat|nuggets|arancin|panzerott|crocchett|cotoletta|cipolla croccante|anelli di cipolla|polpett|birra|moretti|peroni|ceres|messina|nastro azzurro|kinder|kebab|bun|tortilla|pan pizza/)) a.add('glutine');
  if (ha(/fior di latte|mozzarell|bufala|stracciat|gorgonzola|svizzer|grana|scamorz|ricotta|panna|cheddar|formaggio|nutella|kinder|pistacchi|yogurt|burrata|cioccolat|kebab/)) a.add('latte');
  if (ha(/\buov[ao]|maionese|salsa rosa|salsa burger|salsa hamburger|impanat|nuggets|arancin|cotoletta|polpett|mozzarelline/)) a.add('uova');
  if (ha(/tonno|acciugh|salmone|pesce/)) a.add('pesce');
  if (ha(/gamber|misto pesce|frutti di mare/)) a.add('crostacei');
  if (ha(/frutti di mare|misto pesce|cozze|vongol|calamar/)) a.add('molluschi');
  if (ha(/pistacchi|nocciol|nutella|kinder|kataifi/)) a.add('guscio');
  if (ha(/nutella|kinder|cioccolat/)) a.add('soia');
  if (ha(/rag[uù]|arancin/)) a.add('sedano');
  if (ha(/maionese|salsa burger|salsa hamburger|barbecue|curry|salsa rosa/)) a.add('senape');
  if (ha(/buns americano|\bbun\b/)) a.add('sesamo');
  if (ha(/olive|funghi|porcin|carciofi|cipolla caramellata|birra|moretti|peroni|ceres|messina|nastro azzurro|capuliato/)) a.add('solfiti');
  return ALLERGENI_ELENCO.map(x => x.id).filter(id => a.has(id));
}
const allergeniArch = archivio('allergeni');
function gruppiAllergeni(){
  const gruppi = [];
  const aggiungi = (cat, chiave, nome, desc) => {
    let g = gruppi.find(x => x.cat === cat); if (!g) { g = { cat, voci: [] }; gruppi.push(g); }
    if (!g.voci.some(v => v.chiave === chiave)) g.voci.push({ chiave, nome, desc: desc || '', suggeriti: suggerisciAllergeni(cat.replace(/^🧀 Extra ingredienti.*/, 'Extra'), nome, desc) });
  };
  MENU_CATALOG.forEach(g => {
    if (String(g.keyPrefix).startsWith('EXTRA_')) { g.items.forEach(n => aggiungi(g.cat, `${g.keyPrefix}|${n}`, n, '')); return; }
    g.items.forEach(n => {
      const chiave = `${g.keyPrefix}|${n}`, t = menuTestiCache[chiave] || {};
      aggiungi(g.cat, chiave, t.nome || n, t.desc !== undefined ? t.desc : (DESCR_BASE[chiave] || ''));
    });
  });
  customMenuItemsCache.forEach(i => aggiungi(i.cat, `${i.cat}|${i.nome}`, i.nome, i.descrizione || ''));
  aggiungi('Salse gratuite', 'SALSA|__', '', '');
  gruppi.find(g => g.cat === 'Salse gratuite').voci = (Array.isArray(CONFIG.salse) ? CONFIG.salse : SALSE_GRATIS).map(n => ({ chiave: `SALSA|${n}`, nome: n, desc: '', suggeriti: suggerisciAllergeni('Salse', n, '') }));
  gruppi.push({ cat: 'Tipo di pane (Panini e Hamburger)', voci: BREAD_TYPES.map(n => ({ chiave: `PANE|${n}`, nome: n, desc: '', suggeriti: suggerisciAllergeni('Pane', n, '') })) });
  return gruppi;
}
async function allergeniSalvati(){
  const m = {}; (await allergeniArch.list({}, null, 2000)).forEach(x => { m[x._id] = x; }); return m;
}
// pagina pubblica: elenca gli allergeni solo dei piatti confermati dal titolare
app.get('/api/allergeni', async (req, res) => {
  try {
    const salvati = await allergeniSalvati();
    const gruppi = gruppiAllergeni().map(g => ({ cat: g.cat, voci: g.voci.map(v => {
      const s = salvati[v.chiave]; const ok = !!(s && s.verificato);
      return { nome: v.nome, desc: v.desc, a: ok ? (s.a || []) : null };
    }) }));
    const conf = Object.values(salvati).filter(x => x.verificato).map(x => x.aggiornato || '').sort().pop() || '';
    res.json({ ok: true, allergeni: ALLERGENI_ELENCO, gruppi, aggiornato: conf });
  } catch (err) { console.error('Errore allergeni:', err); res.status(500).json({ ok: false, error: 'Errore server' }); }
});
app.get('/api/allergeni/gestione', soloTitolare, async (req, res) => {
  const salvati = await allergeniSalvati();
  res.json({ ok: true, allergeni: ALLERGENI_ELENCO, gruppi: gruppiAllergeni().map(g => ({ cat: g.cat, voci: g.voci.map(v => {
    const s = salvati[v.chiave]; return { ...v, a: s ? (s.a || []) : v.suggeriti, verificato: !!(s && s.verificato) };
  }) })) });
});
app.post('/api/allergeni/salva', soloTitolare, async (req, res) => {
  const voci = Array.isArray((req.body || {}).voci) ? req.body.voci.slice(0, 500) : [];
  let n = 0;
  for (const v of voci) {
    const chiave = String(v.chiave || '').slice(0, 160); if (!chiave) continue;
    const a = (Array.isArray(v.a) ? v.a : []).map(String).filter(x => ALLERGENI_IDS.has(x));
    await allergeniArch.save({ _id: chiave, a: [...new Set(a)], verificato: v.verificato === true, aggiornato: new Date().toISOString() });
    n++;
  }
  res.json({ ok: true, salvati: n });
});

// ===== RICHIESTA DI RECENSIONE GOOGLE (email il giorno dopo l'ordine) =====
const recensioniArch = archivio('recensioniChieste');
let recensioniInCorso = false;
async function inviaRichiesteRecensione(){
  const r = CONFIG.recensioni;
  if (recensioniInCorso || !r.attiva || !r.link || !ordersCollection || !RESEND_API_KEY) return;
  recensioniInCorso = true;
  try {
    const al = new Date(Date.now() - r.dopoOre * 3600000).toISOString();
    const dal = new Date(Date.now() - (r.dopoOre + 24) * 3600000).toISOString();
    const ordini = await ordersCollection.find({ ricevutoAlle: { $gte: dal, $lte: al }, email: { $exists: true, $ne: '' }, recensioneChiesta: { $ne: true } },
      { projection: { numeroOrdine: 1, ricevutoAlle: 1, email: 1, name: 1, nome: 1 } }).limit(50).toArray();
    for (const o of ordini) {
      const email = String(o.email).trim().toLowerCase();
      const gia = await recensioniArch.get(email);
      await ordersCollection.updateOne({ numeroOrdine: o.numeroOrdine, ricevutoAlle: o.ricevutoAlle }, { $set: { recensioneChiesta: true } });
      if (gia && Date.now() - new Date(gia.ultima).getTime() < 90 * 86400000) continue; // al massimo una volta ogni 3 mesi
      const nome = (o.nome || o.name || '').split(' ')[0];
      const testo = `Ciao ${nome},\n\ngrazie per aver ordinato da La Casa di Carta! Ti è piaciuto?\nUna recensione su Google ci aiuta tantissimo: bastano 30 secondi.\n\n${r.link}\n\nGrazie di cuore,\nLa Casa di Carta`;
      const html = `<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px;color:#222"><h2 style="margin:0 0 12px">Ciao ${String(nome).replace(/[<>&"]/g, '')}, ti è piaciuto? 🍕</h2>
        <p>Grazie per aver ordinato da <b>La Casa di Carta</b>! Una recensione su Google ci aiuta tantissimo: bastano 30 secondi.</p>
        <p style="text-align:center;margin:28px 0"><a href="${r.link}" style="background:#e6432f;color:#fff;text-decoration:none;padding:14px 24px;border-radius:10px;font-weight:bold;display:inline-block">⭐ Lascia una recensione</a></p>
        <p style="color:#777;font-size:13px">Grazie di cuore,<br>La Casa di Carta · Via XX Settembre 192, Niscemi</p></div>`;
      await sendEmail(email, 'Com’era la tua pizza? ⭐ — La Casa di Carta', testo, html);
      await recensioniArch.save({ _id: email, ultima: new Date().toISOString(), ordine: o.numeroOrdine });
    }
  } catch (err) { console.error('Errore richieste recensione:', err); }
  finally { recensioniInCorso = false; }
}
setInterval(inviaRichiesteRecensione, 30 * 60 * 1000);
setTimeout(inviaRichiesteRecensione, 3 * 60 * 1000);

// ===== CHIUSURA CASSA DI FINE SERATA =====
const chiusureArch = archivio('chiusureCassa');
async function riepilogoGiornata(giorno){
  const sala = { incasso: 0, conti: 0, contanti: 0, carta: 0 };
  (await comandeList({ stato: 'chiusa', giorno }, 20000)).forEach(c => {
    const imp = Number(c.totaleIncassato) || 0;
    sala.incasso += imp; sala.conti++;
    if (Array.isArray(c.pagamenti) && c.pagamenti.length) c.pagamenti.forEach(p => { if (p.metodo === 'carta') sala.carta += Number(p.importo) || 0; else sala.contanti += Number(p.importo) || 0; });
    else if (c.pagamento === 'carta') sala.carta += imp; else sala.contanti += imp;
  });
  const online = { incasso: 0, ordini: 0, online: 0, contanti: 0, bancomat: 0, nonRegistrato: 0, sconti: 0 };
  // la serata va dalle 5 del mattino alle 5 del giorno dopo
  const dal = new Date(giorno + 'T05:00:00').toISOString(), al = new Date(giornoAggiunto(giorno, 1) + 'T05:00:00').toISOString();
  const ordini = ordersCollection
    ? await ordersCollection.find({ ricevutoAlle: { $gte: dal, $lt: al } }, { projection: { grandTotal: 1, subtotale: 1, metodoPagamento: 1, scontoPrimoOrdine: 1 } }).toArray()
    : orderHistory.filter(o => o.ricevutoAlle >= dal && o.ricevutoAlle < al);
  ordini.forEach(o => {
    const imp = Number(o.grandTotal != null ? o.grandTotal : o.subtotale) || 0;
    online.incasso += imp; online.ordini++;
    online[['online', 'contanti', 'bancomat'].includes(o.metodoPagamento) ? o.metodoPagamento : 'nonRegistrato'] += imp;
    online.sconti += Number(o.scontoPrimoOrdine) || 0;
  });
  const aperte = await comandeList({ stato: 'aperta' }, 2000);
  const r2 = o => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, typeof v === 'number' && !['conti', 'ordini'].includes(k) ? round2(v) : v]));
  return {
    giorno, sala: r2(sala), online: r2(online),
    aperte: { numero: aperte.length, residuo: round2(aperte.reduce((t, c) => t + residuoComanda(c), 0)) },
    totale: round2(sala.incasso + online.incasso),
    contantiIncassati: round2(sala.contanti + online.contanti)
  };
}
// comande rimaste aperte a fine serata: si chiudono da sole e finiscono negli incassi
// (conteggiate in contanti, segnate "chiusa in automatico"); quelle vuote si annullano
async function chiudiComandeRimaste(prendi){
  const aperte = await comandeList({ stato: 'aperta' }, 5000);
  let chiuse = 0, totale = 0;
  for (const c of aperte) {
    if (!prendi(c.giorno || '')) continue;
    const ora = new Date().toISOString();
    if (!(c.righe || []).length) { c.stato = 'annullata'; c.annullataAuto = true; c.annullataAlle = ora; await comandaSave(c); continue; }
    const resto = residuoComanda(c);
    c.pagamenti = c.pagamenti || [];
    if (resto > 0) {
      c.pagamenti.push({ importo: resto, metodo: 'contanti', chiusura: true, auto: true, alle: ora });
      c.righe.forEach(r => { r.pagate = r.qty; });
    }
    c.stato = 'chiusa'; c.chiusaAuto = true;
    c.pagamento = c.pagamenti.every(p => p.metodo === 'contanti') ? 'contanti' : 'misto';
    c.totaleIncassato = pagatoComanda(c);
    c.chiusaAlle = ora;
    await comandaSave(c);
    chiuse++; totale += c.totaleIncassato;
  }
  if (chiuse) { console.log(`Chiuse in automatico ${chiuse} comande rimaste aperte (${money(totale)})`); broadcastOrder({ evento: 'comande_chiuse_auto', numero: chiuse }); }
  return { chiuse, totale: round2(totale) };
}
// alle 5 di mattina (inizio della nuova "giornata") chiude quelle della sera prima
setInterval(() => chiudiComandeRimaste(g => g && g < giornoServizio()).catch(err => console.error('Errore chiusura automatica:', err)), 10 * 60 * 1000);
setTimeout(() => chiudiComandeRimaste(g => g && g < giornoServizio()).catch(() => {}), 90 * 1000);

function testoChiusura(r, ch){
  const L = [];
  L.push('================================');
  L.push('CHIUSURA CASSA');
  L.push(new Date(r.giorno + 'T12:00:00').toLocaleDateString('it-IT', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' }));
  L.push(`Stampata alle ${oraIT()}`);
  L.push('================================');
  L.push(rigaPrezzo('SALA E BANCO', r.sala.incasso));
  L.push(`   conti: ${r.sala.conti}`);
  L.push(rigaPrezzo('   contanti', r.sala.contanti));
  L.push(rigaPrezzo('   carta', r.sala.carta));
  L.push('');
  L.push(rigaPrezzo('ORDINI ONLINE', r.online.incasso));
  L.push(`   ordini: ${r.online.ordini}`);
  L.push(rigaPrezzo('   pagati online', r.online.online));
  L.push(rigaPrezzo('   contanti', r.online.contanti));
  L.push(rigaPrezzo('   bancomat', r.online.bancomat));
  if (r.online.nonRegistrato) L.push(rigaPrezzo('   non registrato', r.online.nonRegistrato));
  if (r.online.sconti) L.push(rigaPrezzo('   sconti primo ordine', -r.online.sconti));
  L.push('--------------------------------');
  L.push(rigaPrezzo('TOTALE GIORNATA', r.totale));
  L.push('--------------------------------');
  if (ch) {
    L.push(rigaPrezzo('Fondo cassa', ch.fondoCassa));
    L.push(rigaPrezzo('Contanti incassati', r.contantiIncassati));
    L.push(rigaPrezzo('Contanti attesi', ch.attesi));
    L.push(rigaPrezzo('Contanti contati', ch.contati));
    L.push(rigaPrezzo(ch.differenza >= 0 ? 'AVANZANO' : 'MANCANO', Math.abs(ch.differenza)));
    if (r.online.nonRegistrato) L.push('(ordini online "non registrato": controlla se pagati in contanti)');
  }
  if (ch && ch.comandeChiuseAuto) L.push(`Chiuse in automatico: ${ch.comandeChiuseAuto} comande (contate in contanti)`);
  if (r.aperte.numero) L.push(`ATTENZIONE: ${r.aperte.numero} comande ancora aperte (${money(r.aperte.residuo)})`);
  if (ch && ch.note) { L.push(''); L.push(`Note: ${ch.note}`); }
  L.push('================================');
  return L.join('\n');
}
app.get('/api/titolare/chiusura', soloTitolare, async (req, res) => {
  try {
    const giorno = /^\d{4}-\d{2}-\d{2}$/.test(req.query.giorno || '') ? req.query.giorno : giornoServizio();
    const r = await riepilogoGiornata(giorno);
    const fatta = await chiusureArch.get(giorno);
    const prima = (await chiusureArch.list({ giorno: { $lte: giornoAggiunto(giorno, -1) } }, { giorno: -1 }, 1))[0];
    res.json({ ok: true, riepilogo: r, chiusura: fatta, fondoSuggerito: fatta ? fatta.fondoCassa : prima ? prima.fondoProssimo ?? prima.fondoCassa : 0 });
  } catch (err) { console.error('Errore riepilogo cassa:', err); res.status(500).json({ ok: false, error: 'Errore server' }); }
});
app.post('/api/titolare/chiusura', soloTitolare, async (req, res) => {
  try {
    const b = req.body || {};
    const giorno = /^\d{4}-\d{2}-\d{2}$/.test(b.giorno || '') ? b.giorno : giornoServizio();
    // chiudendo la cassa, le comande ancora aperte di quella serata vanno negli incassi
    const auto = b.chiudiAperte === false ? { chiuse: 0, totale: 0 } : await chiudiComandeRimaste(g => g && g <= giorno);
    const r = await riepilogoGiornata(giorno);
    const num = v => round2(Math.max(0, Number(String(v ?? '').replace(',', '.')) || 0));
    const fondoCassa = num(b.fondoCassa), contati = num(b.contantiContati);
    const attesi = round2(fondoCassa + r.contantiIncassati);
    const ch = { _id: giorno, giorno, fondoCassa, contati, attesi, differenza: round2(contati - attesi),
      fondoProssimo: b.fondoProssimo !== undefined && b.fondoProssimo !== '' ? num(b.fondoProssimo) : fondoCassa,
      note: String(b.note || '').slice(0, 300), riepilogo: r, chiusaAlle: new Date().toISOString(), comandeChiuseAuto: auto.chiuse };
    await chiusureArch.save(ch);
    if (b.stampa !== false) stampaStaff(testoChiusura(r, ch), `Chiusura cassa ${giorno}`, 'cassa');
    setTimeout(() => mandaRiepilogoSerata(giorno).catch(() => {}), 1500); // mail con il riepilogo della serata
    res.json({ ok: true, chiusura: ch });
  } catch (err) { console.error('Errore chiusura cassa:', err); res.status(500).json({ ok: false, error: 'Errore server' }); }
});

// ===== RIEPILOGO SERATA COMPLETO (sala + asporto + online, piatti più venduti, confronto con la settimana prima) =====
async function serataCompleta(giorno){
  const r = await riepilogoGiornata(giorno);
  const tipi = { tavolo: { n: 0, tot: 0 }, asporto: { n: 0, tot: 0 }, consegna: { n: 0, tot: 0 }, online: { n: r.online.ordini, tot: r.online.incasso } };
  const piatti = new Map();
  const conta = (nome, qty, tot) => { if (!nome) return; const k = String(nome).trim(); const v = piatti.get(k) || { nome: k, qty: 0, tot: 0 }; v.qty += Number(qty) || 0; v.tot += Number(tot) || 0; piatti.set(k, v); };
  (await comandeList({ stato: 'chiusa', giorno }, 20000)).forEach(c => {
    const t = tipi[c.tipo] ? c.tipo : 'tavolo';
    tipi[t].n++; tipi[t].tot += Number(c.totaleIncassato) || 0;
    (c.righe || []).forEach(x => conta(x.nome, x.qty, (Number(x.prezzo) || 0) * (Number(x.qty) || 0)));
  });
  const dal = new Date(giorno + 'T05:00:00').toISOString(), al = new Date(giornoAggiunto(giorno, 1) + 'T05:00:00').toISOString();
  const ordini = ordersCollection
    ? await ordersCollection.find({ ricevutoAlle: { $gte: dal, $lt: al } }, { projection: { articoli: 1 } }).toArray()
    : orderHistory.filter(o => o.ricevutoAlle >= dal && o.ricevutoAlle < al);
  ordini.forEach(o => (o.articoli || []).forEach(a => conta(a.nome, a.qty, a.prezzo)));
  const tuttiPiatti = [...piatti.values()].sort((a, b) => b.qty - a.qty || b.tot - a.tot).map(v => ({ ...v, tot: round2(v.tot) }));
  const top = tuttiPiatti.slice(0, 10);
  const pezzi = [...piatti.values()].reduce((t, v) => t + v.qty, 0);
  const gPrima = giornoAggiunto(giorno, -7);
  const prima = await riepilogoGiornata(gPrima);
  Object.values(tipi).forEach(v => { v.tot = round2(v.tot); });
  return { ...r, tipi, top, piatti: tuttiPiatti, pezzi, scontrinoMedio: (() => { const n = tipi.tavolo.n + tipi.asporto.n + tipi.consegna.n + tipi.online.n; return n ? round2(r.totale / n) : 0; })(),
    settimanaPrima: { giorno: gPrima, totale: prima.totale, differenza: round2(r.totale - prima.totale), percento: prima.totale ? Math.round((r.totale - prima.totale) / prima.totale * 100) : null } };
}
function htmlSerata(s){
  const data = new Date(s.giorno + 'T12:00:00').toLocaleDateString('it-IT', { weekday: 'long', day: 'numeric', month: 'long' });
  const riga = (a, b, forte) => `<tr><td style="padding:7px 0;border-bottom:1px solid #eee;color:#333;${forte ? 'font-weight:700;' : ''}">${a}</td><td style="padding:7px 0;border-bottom:1px solid #eee;text-align:right;${forte ? 'font-weight:800;' : ''}">${b}</td></tr>`;
  const sp = s.settimanaPrima;
  const conf = sp.totale ? `${sp.differenza >= 0 ? '▲' : '▼'} ${money(Math.abs(sp.differenza))}${sp.percento !== null ? ` (${sp.percento >= 0 ? '+' : ''}${sp.percento}%)` : ''} rispetto a ${new Date(sp.giorno + 'T12:00:00').toLocaleDateString('it-IT', { weekday: 'long', day: 'numeric', month: 'long' })} (${money(sp.totale)})` : 'Nessun dato della settimana prima';
  const top = s.top.map((p, i) => riga(`${i + 1}. ${p.nome}`, `${p.qty} pz · ${money(p.tot)}`)).join('');
  return `<!DOCTYPE html><html lang="it"><body style="margin:0;background:#f4f1ee;font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="padding:20px 0;"><tr><td align="center">
<table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#fff;border-radius:18px;overflow:hidden;">
<tr><td style="background:linear-gradient(135deg,#c1382b,#7a1f16);padding:24px;text-align:center;color:#fff;">
<div style="font-size:14px;opacity:.85;text-transform:capitalize;">${data}</div>
<div style="font-size:34px;font-weight:800;margin-top:4px;">${money(s.totale)}</div>
<div style="font-size:14px;margin-top:6px;">${conf}</div></td></tr>
<tr><td style="padding:18px 22px;">
<div style="font-weight:800;color:#7a1f16;margin-bottom:6px;">Da dove arrivano</div>
<table width="100%" cellpadding="0" cellspacing="0" style="font-size:15px;">
${riga(`🍽️ Tavoli (${s.tipi.tavolo.n})`, money(s.tipi.tavolo.tot))}${riga(`🏠 Asporto (${s.tipi.asporto.n})`, money(s.tipi.asporto.tot))}${riga(`🛵 Consegne (${s.tipi.consegna.n})`, money(s.tipi.consegna.tot))}${riga(`🌐 Ordini online (${s.tipi.online.n})`, money(s.tipi.online.tot))}
${riga('Scontrino medio', money(s.scontrinoMedio), true)}</table>
<div style="font-weight:800;color:#7a1f16;margin:16px 0 6px;">Pagamenti</div>
<table width="100%" cellpadding="0" cellspacing="0" style="font-size:15px;">
${riga('💵 Contanti (sala + online)', money(s.contantiIncassati))}${riga('💳 Carta in sala', money(s.sala.carta))}${riga('💳 Pagati online', money(s.online.online))}${riga('💳 Bancomat consegne', money(s.online.bancomat))}${s.online.nonRegistrato ? riga('⚠️ Online non registrati', money(s.online.nonRegistrato)) : ''}</table>
<div style="font-weight:800;color:#7a1f16;margin:16px 0 6px;">Più venduti (${s.pezzi} pezzi in tutto)</div>
<table width="100%" cellpadding="0" cellspacing="0" style="font-size:15px;">${top || riga('Nessun piatto', '')}</table>
${s.aperte.numero ? `<p style="color:#b3261e;font-weight:700;">Attenzione: ${s.aperte.numero} comande ancora aperte (${money(s.aperte.residuo)})</p>` : ''}
</td></tr></table></td></tr></table></body></html>`;
}
function testoSerata(s){
  return `RIEPILOGO SERATA ${s.giorno}\nTotale: ${money(s.totale)}\nTavoli ${s.tipi.tavolo.n}: ${money(s.tipi.tavolo.tot)}\nAsporto ${s.tipi.asporto.n}: ${money(s.tipi.asporto.tot)}\nConsegne ${s.tipi.consegna.n}: ${money(s.tipi.consegna.tot)}\nOnline ${s.tipi.online.n}: ${money(s.tipi.online.tot)}\nSettimana prima: ${money(s.settimanaPrima.totale)}\n\nPiù venduti:\n` + s.top.map((p, i) => `${i + 1}. ${p.nome} — ${p.qty}`).join('\n');
}
const serateInviate = new Set();
async function mandaRiepilogoSerata(giorno){
  if (serateInviate.has(giorno)) return false;
  serateInviate.add(giorno);
  try {
    const s = await serataCompleta(giorno);
    await sendEmail(ORDER_EMAIL, `Serata ${new Date(giorno + 'T12:00:00').toLocaleDateString('it-IT', { weekday: 'long', day: 'numeric', month: 'long' })} — ${money(s.totale)}`, testoSerata(s), htmlSerata(s));
    try { const ch = await chiusureArch.get(giorno); if (ch) { ch.mailSerata = new Date().toISOString(); await chiusureArch.save(ch); } } catch (e) {}
    console.log('Riepilogo serata inviato:', giorno);
    return true;
  } catch (e) { serateInviate.delete(giorno); console.error('Errore riepilogo serata:', e); return false; }
}
app.get('/api/titolare/serata', soloTitolare, async (req, res) => {
  try {
    const giorno = /^\d{4}-\d{2}-\d{2}$/.test(req.query.giorno || '') ? req.query.giorno : giornoServizio();
    res.json({ ok: true, serata: await serataCompleta(giorno) });
  } catch (err) { console.error('Errore serata:', err); res.status(500).json({ ok: false, error: 'Errore server' }); }
});
app.post('/api/titolare/serata/invia', soloTitolare, async (req, res) => {
  const giorno = /^\d{4}-\d{2}-\d{2}$/.test((req.body || {}).giorno || '') ? req.body.giorno : giornoServizio();
  serateInviate.delete(giorno);
  const ok = await mandaRiepilogoSerata(giorno);
  res.json({ ok, email: ORDER_EMAIL ? ORDER_EMAIL.replace(/(.{2}).*(@.*)/, '$1…$2') : '' });
});
// ===== RIEPILOGO SETTIMANALE (mail il lunedì mattina) =====
function lunediDi(giorno){ const d = new Date(giorno + 'T12:00:00'); const g = (d.getDay() + 6) % 7; d.setDate(d.getDate() - g); return dateKey(d); }
async function settimanaCompleta(lunedi){
  const giorni = Array.from({ length: 7 }, (_, i) => giornoAggiunto(lunedi, i));
  const serate = [];
  for (const g of giorni) serate.push(await serataCompleta(g));
  const prima = [];
  for (const g of giorni) prima.push((await riepilogoGiornata(giornoAggiunto(g, -7))).totale);
  const totale = round2(serate.reduce((t, x) => t + x.totale, 0)), totalePrima = round2(prima.reduce((t, x) => t + x, 0));
  const tipi = { tavolo: { n: 0, tot: 0 }, asporto: { n: 0, tot: 0 }, consegna: { n: 0, tot: 0 }, online: { n: 0, tot: 0 } };
  const piatti = new Map();
  serate.forEach(x => {
    Object.keys(tipi).forEach(k => { tipi[k].n += x.tipi[k].n; tipi[k].tot += x.tipi[k].tot; });
    (x.piatti || x.top).forEach(p => { const v = piatti.get(p.nome) || { nome: p.nome, qty: 0, tot: 0 }; v.qty += p.qty; v.tot += p.tot; piatti.set(p.nome, v); });
  });
  Object.values(tipi).forEach(v => { v.tot = round2(v.tot); });
  // ore più piene: comande aperte e ordini online arrivati, per fascia oraria
  const ore = {};
  const dal = new Date(lunedi + 'T05:00:00').toISOString(), al = new Date(giornoAggiunto(lunedi, 7) + 'T05:00:00').toISOString();
  const conta = iso => { if (!iso) return; const h = new Date(iso).getHours(); ore[h] = (ore[h] || 0) + 1; };
  for (const g of giorni) (await comandeList({ stato: 'chiusa', giorno: g }, 20000)).forEach(c => conta(c.creataAlle));
  const ordini = ordersCollection
    ? await ordersCollection.find({ ricevutoAlle: { $gte: dal, $lt: al } }, { projection: { ricevutoAlle: 1 } }).toArray()
    : orderHistory.filter(o => o.ricevutoAlle >= dal && o.ricevutoAlle < al);
  ordini.forEach(o => conta(o.ricevutoAlle));
  const oreTop = Object.entries(ore).map(([h, n]) => ({ ora: +h, n })).sort((a, b) => b.n - a.n).slice(0, 4);
  const tutti = [...piatti.values()].map(v => ({ ...v, tot: round2(v.tot) })).sort((a, b) => b.qty - a.qty);
  const nTot = tipi.tavolo.n + tipi.asporto.n + tipi.consegna.n + tipi.online.n;
  const migliore = serate.reduce((m, x) => x.totale > (m ? m.totale : -1) ? x : m, null);
  return { lunedi, domenica: giorni[6], totale, totalePrima, differenza: round2(totale - totalePrima), percento: totalePrima ? Math.round((totale - totalePrima) / totalePrima * 100) : null,
    giorni: serate.map((x, i) => ({ giorno: x.giorno, totale: x.totale, prima: prima[i] })), tipi, scontrinoMedio: nTot ? round2(totale / nTot) : 0,
    oreTop, top: tutti.slice(0, 10), menoVenduti: tutti.filter(v => v.qty > 0).slice(-5).reverse(), migliore: migliore && migliore.totale > 0 ? { giorno: migliore.giorno, totale: migliore.totale } : null };
}
function htmlSettimana(w){
  const gg = d => new Date(d + 'T12:00:00').toLocaleDateString('it-IT', { weekday: 'long', day: 'numeric', month: 'long' });
  const riga = (a, b, forte) => `<tr><td style="padding:7px 0;border-bottom:1px solid #eee;color:#333;${forte ? 'font-weight:700;' : ''}">${a}</td><td style="padding:7px 0;border-bottom:1px solid #eee;text-align:right;${forte ? 'font-weight:800;' : ''}">${b}</td></tr>`;
  const conf = w.totalePrima ? `${w.differenza >= 0 ? '▲' : '▼'} ${money(Math.abs(w.differenza))}${w.percento !== null ? ` (${w.percento >= 0 ? '+' : ''}${w.percento}%)` : ''} rispetto alla settimana prima (${money(w.totalePrima)})` : 'Nessun dato della settimana prima';
  const max = Math.max(1, ...w.giorni.map(g => g.totale));
  const barre = w.giorni.map(g => `<tr><td style="padding:4px 0;width:90px;color:#555;font-size:14px;text-transform:capitalize;">${new Date(g.giorno + 'T12:00:00').toLocaleDateString('it-IT', { weekday: 'short', day: 'numeric' })}</td><td style="padding:4px 6px;width:100%;"><div style="background:#c1382b;height:14px;border-radius:7px;width:${Math.max(2, Math.round(g.totale / max * 100))}%;"></div></td><td style="padding:4px 0;text-align:right;font-size:14px;white-space:nowrap;">${money(g.totale)}</td></tr>`).join('');
  return `<!DOCTYPE html><html lang="it"><body style="margin:0;background:#f4f1ee;font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="padding:20px 0;"><tr><td align="center">
<table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#fff;border-radius:18px;overflow:hidden;">
<tr><td style="background:linear-gradient(135deg,#c1382b,#7a1f16);padding:24px;text-align:center;color:#fff;">
<div style="font-size:14px;opacity:.85;">Settimana dal ${gg(w.lunedi)} a ${gg(w.domenica)}</div>
<div style="font-size:34px;font-weight:800;margin-top:4px;">${money(w.totale)}</div>
<div style="font-size:14px;margin-top:6px;">${conf}</div></td></tr>
<tr><td style="padding:18px 22px;">
<div style="font-weight:800;color:#7a1f16;margin-bottom:6px;">Giorno per giorno</div>
<table width="100%" cellpadding="0" cellspacing="0">${barre}</table>
${w.migliore ? `<p style="font-size:14px;color:#555;margin:8px 0 0;">Serata migliore: <b style="text-transform:capitalize;">${gg(w.migliore.giorno)}</b> con ${money(w.migliore.totale)}</p>` : ''}
<div style="font-weight:800;color:#7a1f16;margin:16px 0 6px;">Da dove arrivano</div>
<table width="100%" cellpadding="0" cellspacing="0" style="font-size:15px;">
${riga(`🍽️ Tavoli (${w.tipi.tavolo.n})`, money(w.tipi.tavolo.tot))}${riga(`🏠 Asporto (${w.tipi.asporto.n})`, money(w.tipi.asporto.tot))}${riga(`🛵 Consegne (${w.tipi.consegna.n})`, money(w.tipi.consegna.tot))}${riga(`🌐 Online (${w.tipi.online.n})`, money(w.tipi.online.tot))}${riga('Scontrino medio', money(w.scontrinoMedio), true)}</table>
${w.oreTop.length ? `<div style="font-weight:800;color:#7a1f16;margin:16px 0 6px;">Ore più piene</div><table width="100%" cellpadding="0" cellspacing="0" style="font-size:15px;">${w.oreTop.map(o => riga(`${String(o.ora).padStart(2, '0')}:00 – ${String((o.ora + 1) % 24).padStart(2, '0')}:00`, `${o.n} ordini e tavoli`)).join('')}</table>` : ''}
<div style="font-weight:800;color:#7a1f16;margin:16px 0 6px;">Più venduti</div>
<table width="100%" cellpadding="0" cellspacing="0" style="font-size:15px;">${w.top.map((p, i) => riga(`${i + 1}. ${p.nome}`, `${p.qty} pz · ${money(p.tot)}`)).join('') || riga('Nessuna vendita', '')}</table>
${w.menoVenduti.length ? `<div style="font-weight:800;color:#7a1f16;margin:16px 0 6px;">Meno venduti (tra quelli usciti)</div><table width="100%" cellpadding="0" cellspacing="0" style="font-size:15px;">${w.menoVenduti.map(p => riga(p.nome, `${p.qty} pz`)).join('')}</table>` : ''}
</td></tr></table></td></tr></table></body></html>`;
}
function testoSettimana(w){
  return `SETTIMANA ${w.lunedi} - ${w.domenica}\nTotale: ${money(w.totale)} (settimana prima ${money(w.totalePrima)})\n` + w.giorni.map(g => `${g.giorno}: ${money(g.totale)}`).join('\n') + '\n\nPiù venduti:\n' + w.top.map((p, i) => `${i + 1}. ${p.nome} — ${p.qty}`).join('\n');
}
const settimaneArch = archivio('riepiloghiSettimana');
async function mandaRiepilogoSettimana(lunedi, forza){
  if (!forza && await settimaneArch.get(lunedi)) return false;
  const w = await settimanaCompleta(lunedi);
  await sendEmail(ORDER_EMAIL, `Settimana ${new Date(lunedi + 'T12:00:00').toLocaleDateString('it-IT', { day: 'numeric', month: 'long' })} – ${new Date(w.domenica + 'T12:00:00').toLocaleDateString('it-IT', { day: 'numeric', month: 'long' })}: ${money(w.totale)}`, testoSettimana(w), htmlSettimana(w));
  await settimaneArch.save({ _id: lunedi, inviataAlle: new Date().toISOString() });
  console.log('Riepilogo settimanale inviato:', lunedi);
  return true;
}
// ogni lunedì alle 10: la settimana appena finita (lunedì–domenica)
setInterval(() => {
  const now = new Date();
  if (now.getDay() !== 1 || now.getHours() !== 10) return;
  mandaRiepilogoSettimana(giornoAggiunto(lunediDi(dateKey(now)), -7)).catch(e => console.error('Errore riepilogo settimanale:', e));
}, 5 * 60 * 1000);
app.get('/api/titolare/settimana', soloTitolare, async (req, res) => {
  try {
    const lunedi = /^\d{4}-\d{2}-\d{2}$/.test(req.query.lunedi || '') ? lunediDi(req.query.lunedi) : giornoAggiunto(lunediDi(giornoServizio()), -7);
    res.json({ ok: true, settimana: await settimanaCompleta(lunedi) });
  } catch (err) { console.error('Errore settimana:', err); res.status(500).json({ ok: false, error: 'Errore server' }); }
});
app.post('/api/titolare/settimana/invia', soloTitolare, async (req, res) => {
  try {
    const l = (req.body || {}).lunedi;
    const lunedi = /^\d{4}-\d{2}-\d{2}$/.test(l || '') ? lunediDi(l) : giornoAggiunto(lunediDi(giornoServizio()), -7);
    const ok = await mandaRiepilogoSettimana(lunedi, true);
    res.json({ ok, lunedi });
  } catch (err) { console.error('Errore invio settimana:', err); res.status(500).json({ ok: false, error: 'Errore server' }); }
});
app.get('/api/titolare/chiusure', soloTitolare, async (req, res) => {
  const lista = await chiusureArch.list({}, { giorno: -1 }, 60);
  res.json({ ok: true, chiusure: lista.map(c => ({ giorno: c.giorno, totale: c.riepilogo && c.riepilogo.totale, differenza: c.differenza, contati: c.contati, attesi: c.attesi })) });
});

// ===== COSTO INGREDIENTI (per il margine nella dashboard) =====
app.get('/api/costi', soloTitolare, (req, res) => {
  const piatti = [];
  MENU_CATALOG.forEach(g => { if (!String(g.keyPrefix).startsWith('EXTRA_') && g.cat !== 'Extra') g.items.forEach(n => piatti.push({ cat: g.cat, nome: n, prezzo: getCurrentPrice(`${g.keyPrefix}|${n}`) })); });
  customMenuItemsCache.forEach(i => piatti.push({ cat: i.cat, nome: i.nome, prezzo: getCurrentPrice(`${i.cat}|${i.nome}`) }));
  res.json({ ok: true, costi: COSTO_INGREDIENTI, piatti });
});
app.post('/api/costi', soloTitolare, async (req, res) => {
  const inp = (req.body || {}).costi;
  if (!inp || typeof inp !== 'object') return res.status(400).json({ ok: false, error: 'Nessun costo ricevuto' });
  const out = {};
  Object.entries(inp).slice(0, 1000).forEach(([nome, v]) => {
    const n = Number(String(v ?? '').replace(',', '.'));
    if (String(v ?? '').trim() !== '' && Number.isFinite(n) && n >= 0 && n < 500) out[String(nome).slice(0, 120)] = round2(n);
  });
  COSTO_INGREDIENTI = out;
  if (settingsCollection) await settingsCollection.updateOne({ _id: 'costi' }, { $set: { value: out } }, { upsert: true });
  res.json({ ok: true, costi: out });
});

// ---------- Impostazioni del titolare ----------
function configPubblica(){
  // il pagamento online si mostra ai clienti solo se Stripe è davvero collegato (chiave su Render)
  const sito = { ...CONFIG.sito, pagamenti: { ...CONFIG.sito.pagamenti, online: !!(stripe && CONFIG.sito.pagamenti.online) } };
  return { ...CONFIG, sito, pagamentoOnlineCollegato: !!stripe, camerieri: (CONFIG.camerieri || []).map(x => ({ nome: x.nome, pin: !!x.pin })),
    offerte: (CONFIG.offerte || []).filter(o => o.attiva).map(o => ({ ...o, codice: undefined, conCodice: !!o.codice })) };
}
// =====================================================================
//  NOTIFICHE PUSH (Web Push, senza librerie esterne)
//  Arrivano sul telefono anche con l'app chiusa: Android (Chrome) e iPhone (app aggiunta alla schermata Home).
//  Le chiavi VAPID si creano da sole la prima volta e restano salvate nel database.
// =====================================================================
const cryptoPush = require('crypto');
const httpsPush = require('https');
let vapid = null, pushCollection = null;
const pushIscritti = new Map(); // id -> { _id, sub, ruolo, cameriere, creata }
const b64u = buf => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const ub64 = str => Buffer.from(String(str).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
function nuoveChiaviVapid(){ const ec = cryptoPush.createECDH('prime256v1'); ec.generateKeys(); return { pub: b64u(ec.getPublicKey()), priv: b64u(ec.getPrivateKey()) }; }
function chiaviVapid(){ if (!vapid) vapid = nuoveChiaviVapid(); return vapid; }
let chiavePrivataCache = null;
function jwtVapid(aud){
  const v = chiaviVapid();
  if (!chiavePrivataCache || chiavePrivataCache.pub !== v.pub) {
    const pub = ub64(v.pub);
    chiavePrivataCache = { pub: v.pub, key: cryptoPush.createPrivateKey({ key: { kty: 'EC', crv: 'P-256', d: v.priv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) }, format: 'jwk' }) };
  }
  const h = b64u(JSON.stringify({ typ: 'JWT', alg: 'ES256' }));
  const p = b64u(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: 'mailto:info@pizzerialacasadicarta.it' }));
  const firma = cryptoPush.sign('sha256', Buffer.from(h + '.' + p), { key: chiavePrivataCache.key, dsaEncoding: 'ieee-p1363' });
  return h + '.' + p + '.' + b64u(firma);
}
const hkdfPush = (salt, ikm, info, n) => Buffer.from(cryptoPush.hkdfSync('sha256', ikm, salt, info, n));
// cifratura aes128gcm (RFC 8291 / 8188)
function cifraPush(sub, testo){
  const uaPub = ub64(sub.keys.p256dh), auth = ub64(sub.keys.auth);
  const ec = cryptoPush.createECDH('prime256v1'); ec.generateKeys();
  const asPub = ec.getPublicKey(), comune = ec.computeSecret(uaPub);
  const ikm = hkdfPush(auth, comune, Buffer.concat([Buffer.from('WebPush: info\0'), uaPub, asPub]), 32);
  const salt = cryptoPush.randomBytes(16);
  const cek = hkdfPush(salt, ikm, Buffer.from('Content-Encoding: aes128gcm\0'), 16);
  const nonce = hkdfPush(salt, ikm, Buffer.from('Content-Encoding: nonce\0'), 12);
  const c = cryptoPush.createCipheriv('aes-128-gcm', cek, nonce);
  const corpo = Buffer.concat([c.update(Buffer.concat([Buffer.from(testo, 'utf8'), Buffer.from([2])])), c.final(), c.getAuthTag()]);
  const testa = Buffer.alloc(21); salt.copy(testa, 0); testa.writeUInt32BE(4096, 16); testa.writeUInt8(65, 20);
  return Buffer.concat([testa, asPub, corpo]);
}
function mandaPushA(sub, dati, ttl){
  return new Promise(resolve => {
    try {
      const u = new URL(sub.endpoint);
      const corpo = cifraPush(sub, JSON.stringify(dati));
      const req = httpsPush.request({ method: 'POST', hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search, timeout: 10000,
        headers: { 'Content-Type': 'application/octet-stream', 'Content-Encoding': 'aes128gcm', 'Content-Length': corpo.length, TTL: String(ttl || 600), Urgency: 'high',
          Authorization: 'vapid t=' + jwtVapid(u.origin) + ', k=' + chiaviVapid().pub } },
        res => { res.resume(); resolve(res.statusCode); });
      req.on('error', () => resolve(0));
      req.on('timeout', () => { req.destroy(); resolve(0); });
      req.end(corpo);
    } catch (e) { resolve(0); }
  });
}
// dati: { titolo, testo, tag, url } — ruoli: ['staff','titolare']
// le ultime notifiche restano anche in memoria: l'app Android del tablet (che non può ricevere le push web) le legge da qui
const ultimeNotifiche = []; let numNotifica = 0;
async function inviaPush(ruoli, dati, ttl, soloNome){
  ultimeNotifiche.push({ id: ++numNotifica, t: Date.now(), ruoli, nome: soloNome || '', titolo: dati.titolo || '', testo: dati.testo || '', tag: dati.tag || '' });
  while (ultimeNotifiche.length > 200) ultimeNotifiche.shift();
  const lista = [...pushIscritti.values()].filter(x => ruoli.includes(x.ruolo) && (!soloNome || x.cameriere === soloNome));
  await Promise.all(lista.map(async x => {
    const st = await mandaPushA(x.sub, dati, ttl);
    if (st === 404 || st === 410) { // iscrizione scaduta (app disinstallata o permesso tolto)
      pushIscritti.delete(x._id);
      if (pushCollection) pushCollection.deleteOne({ _id: x._id }).catch(() => {});
    }
  }));
}
function pushSicura(ruoli, dati, ttl, soloNome){ inviaPush(ruoli, dati, ttl, soloNome).catch(e => console.error('Push non inviata:', e.message)); }
app.get('/api/push/recenti', (req, res) => {
  const ruolo = ['titolare', 'fattorino'].includes(req.query.ruolo) ? req.query.ruolo : 'staff';
  const nome = String(req.query.nome || ''), dopo = Number(req.query.dopo) || 0, da = Date.now() - 10 * 60 * 1000;
  const lista = ultimeNotifiche.filter(n => n.id > dopo && n.t >= da && n.ruoli.includes(ruolo) && (!n.nome || n.nome === nome))
    .map(n => ({ id: n.id, titolo: n.titolo, testo: n.testo, tag: n.tag }));
  res.json({ ok: true, ultimo: numNotifica, notifiche: lista });
});
app.get('/api/push/chiave', (req, res) => res.json({ ok: true, chiave: chiaviVapid().pub }));
app.post('/api/push/iscrivi', async (req, res) => {
  const b = req.body || {}, sub = b.sub || {};
  let u; try { u = new URL(String(sub.endpoint || '')); } catch (e) { return res.status(400).json({ ok: false, error: 'Iscrizione non valida' }); }
  if (u.protocol !== 'https:' || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) return res.status(400).json({ ok: false, error: 'Iscrizione non valida' });
  const id = cryptoPush.createHash('sha256').update(u.href).digest('hex').slice(0, 32);
  const doc = { _id: id, sub: { endpoint: u.href, keys: { p256dh: String(sub.keys.p256dh).slice(0, 200), auth: String(sub.keys.auth).slice(0, 60) } },
    ruolo: ['titolare', 'fattorino'].includes(b.ruolo) ? b.ruolo : 'staff', cameriere: String(b.cameriere || '').slice(0, 30), creata: new Date().toISOString() };
  pushIscritti.set(id, doc);
  if (pushCollection) { try { await pushCollection.replaceOne({ _id: id }, doc, { upsert: true }); } catch (e) {} }
  res.json({ ok: true });
});
app.post('/api/push/prova', async (req, res) => {
  const ruolo = ['titolare', 'fattorino'].includes((req.body || {}).ruolo) ? req.body.ruolo : 'staff';
  await inviaPush([ruolo], { titolo: '🔔 Notifiche attive', testo: 'Da ora gli avvisi arrivano qui anche con l\'app chiusa.', tag: 'prova' });
  res.json({ ok: true, iscritti: [...pushIscritti.values()].filter(x => x.ruolo === ruolo).length });
});

// =====================================================================
//  CONSEGNE (più fattorini), DISPLAY CUCINA e SCHERMO "ORDINI PRONTI"
// =====================================================================
let fattorini = ['Fattorino 1', 'Fattorino 2'];
const posizioniFattorini = new Map(); // nome -> { lat, lng, aggiornataAlle }
const daQuando = ore => new Date(Date.now() - ore * 3600 * 1000).toISOString();
const nomeBreve = n => { const p = String(n || '').trim().split(/\s+/).filter(Boolean); return p.length ? p[0] + (p[1] ? ' ' + p[1][0].toUpperCase() + '.' : '') : ''; };
function salvaOrdineCampi(order, campi){
  Object.assign(order, campi);
  if (ordersCollection) ordersCollection.updateOne(filtroOrdine(order), { $set: campi }).catch(e => console.error('Errore salvataggio ordine:', e.message));
}
// ordini online di stasera (in memoria) e comande dello staff di stasera
function ordiniStasera(){ const da = daQuando(14); return orderHistory.filter(o => o && o.ricevutoAlle && o.ricevutoAlle >= da && o.tipo !== 'prenotazione'); }
async function comandeStasera(){
  const aperte = await comandeList({ stato: 'aperta' }, 300);
  const chiuse = await comandeList({ stato: 'chiusa', giorno: giornoServizio() }, 300);
  return aperte.concat(chiuse);
}

// ---------- CONSEGNE ----------
function consegnaDaOrdine(o){
  return { id: 'o' + o.numeroOrdine, fonte: 'online', numero: '#' + o.numeroOrdine, nome: o.name || [o.nome, o.cognome].filter(Boolean).join(' ') || 'Cliente',
    telefono: o.phone || '', indirizzo: o.address || '', note: o.note || o.notes || '', orario: o.orarioLabel || '', ricevuto: o.ricevutoAlle,
    totale: round2(Number(o.grandTotal) || 0), pagato: !!o.pagatoOnline || !!o.metodoPagamento,
    pagamento: o.pagatoOnline ? 'online' : (o.metodoPagamento || ''), scelto: o.pagamento === 'carta' ? 'carta' : 'contanti',
    stato: o.stato || 'da_preparare', fattorino: o.fattorino || '', giro: o.giro || 0,
    pezzi: (o.articoli || []).reduce((t, a) => t + (Number(a.qty) || 1), 0) };
}
function consegnaDaComanda(c){
  const pagato = c.stato === 'chiusa' || residuoComanda(c) <= 0;
  return { id: 'c' + c._id, fonte: 'staff', numero: 'S' + c.numero, nome: c.nome || 'Cliente', telefono: c.telefono || '', indirizzo: c.indirizzo || '',
    note: c.noteComanda || '', orario: c.orario || '', ricevuto: c.creataAlle,
    totale: round2(totaleComanda(c) + (c.spese || 0)), pagato: pagato || !!c.incassoFattorino,
    pagamento: c.incassoFattorino ? c.incassoFattorino.metodo : (pagato ? (c.pagamento || 'pagato') : ''), scelto: 'contanti',
    stato: c.statoConsegna || (c.prontoCucinaAlle ? 'pronto' : 'da_preparare'), fattorino: c.fattorino || '', giro: c.giro || 0,
    pezzi: (c.righe || []).reduce((t, r) => t + (r.qty || 0), 0) };
}
async function elencoConsegne(){
  const da = daQuando(14);
  const lista = ordiniStasera().filter(o => o.modalita === 'consegna').map(consegnaDaOrdine);
  (await comandeStasera()).filter(c => c.tipo === 'consegna' && c.creataAlle >= da).forEach(c => lista.push(consegnaDaComanda(c)));
  return lista.sort((a, b) => String(a.ricevuto).localeCompare(String(b.ricevuto)));
}
async function trovaConsegna(id){
  id = String(id || '');
  if (id[0] === 'o') { const o = await trovaOrdine(Number(id.slice(1))); return o ? { tipo: 'o', o } : null; }
  if (id[0] === 'c') { const c = await comandaGet(id.slice(1)); return c && c.tipo === 'consegna' ? { tipo: 'c', c } : null; }
  return null;
}
async function aggiornaConsegna(k, campi){
  if (k.tipo === 'o') salvaOrdineCampi(k.o, campi);
  else { Object.assign(k.c, campi); await comandaSave(k.c); }
}
app.get('/api/consegne', async (req, res) => {
  try { res.json({ ok: true, fattorini, consegne: await elencoConsegne() }); }
  catch (e) { console.error(e); res.status(500).json({ ok: false, error: 'Errore server' }); }
});
app.post('/api/consegne/fattorini', soloTitolare, async (req, res) => {
  const nomi = (Array.isArray((req.body || {}).nomi) ? req.body.nomi : []).map(x => String(x || '').trim().slice(0, 30)).filter(Boolean).slice(0, 8);
  if (!nomi.length) return res.status(400).json({ ok: false, error: 'Scrivi almeno un nome' });
  fattorini = [...new Set(nomi)];
  if (settingsCollection) await settingsCollection.updateOne({ _id: 'fattorini' }, { $set: { value: fattorini } }, { upsert: true }).catch(() => {});
  broadcastOrder({ evento: 'consegne_aggiornate' });
  res.json({ ok: true, fattorini });
});
app.post('/api/consegne/:id/assegna', async (req, res) => {
  const k = await trovaConsegna(req.params.id);
  if (!k) return res.status(404).json({ ok: false, error: 'Consegna non trovata' });
  const chi = String((req.body || {}).fattorino || '').slice(0, 30);
  if (chi && !fattorini.includes(chi)) return res.status(400).json({ ok: false, error: 'Fattorino sconosciuto' });
  const prima = k.tipo === 'o' ? k.o.fattorino : k.c.fattorino;
  await aggiornaConsegna(k, { fattorino: chi, giro: 0 });
  broadcastOrder({ evento: 'consegne_aggiornate' });
  if (chi && chi !== prima) {
    const x = k.tipo === 'o' ? consegnaDaOrdine(k.o) : consegnaDaComanda(k.c);
    pushSicura(['fattorino'], { titolo: `🛵 Nuova consegna ${x.numero}`, testo: `${x.nome} · ${x.indirizzo}${x.stato === 'pronto' ? ' · PRONTA' : ''}`, tag: 'cons-' + x.id, url: './' }, 1800, chi);
  }
  res.json({ ok: true });
});
// stato: in_consegna | consegnato | pronto (per tornare indietro) — pagamento: contanti | bancomat (se non era pagato)
app.post('/api/consegne/:id/stato', async (req, res) => {
  const k = await trovaConsegna(req.params.id);
  if (!k) return res.status(404).json({ ok: false, error: 'Consegna non trovata' });
  const b = req.body || {}, stato = String(b.stato || '');
  if (!['in_consegna', 'consegnato', 'pronto'].includes(stato)) return res.status(400).json({ ok: false, error: 'Stato non valido' });
  const metodo = ['contanti', 'bancomat'].includes(b.pagamento) ? b.pagamento : '';
  const ora = new Date().toISOString();
  if (k.tipo === 'o') {
    if (stato === 'in_consegna' && k.o.stato !== 'in_consegna') segnaOrdineInConsegna(k.o);
    else if (stato === 'pronto') { salvaOrdineCampi(k.o, { stato: 'pronto' }); broadcastOrder({ evento: 'stato_aggiornato', numeroOrdine: k.o.numeroOrdine, stato: 'pronto' }); }
    else if (stato === 'consegnato') {
      const campi = { stato: 'consegnato', consegnatoAlle: ora };
      if (metodo && !k.o.pagatoOnline && !k.o.metodoPagamento) campi.metodoPagamento = metodo;
      salvaOrdineCampi(k.o, campi);
      broadcastOrder({ evento: 'stato_aggiornato', numeroOrdine: k.o.numeroOrdine, stato: 'consegnato' });
      if (campi.metodoPagamento) broadcastOrder({ evento: 'pagamento_registrato', numeroOrdine: k.o.numeroOrdine, metodoPagamento: metodo });
    }
  } else {
    const campi = { statoConsegna: stato === 'pronto' ? null : stato };
    if (stato === 'in_consegna') campi.inConsegnaAlle = ora;
    if (stato === 'consegnato') { campi.consegnatoAlle = ora; if (metodo && k.c.stato !== 'chiusa') campi.incassoFattorino = { metodo, importo: round2(residuoComanda(k.c)), fattorino: k.c.fattorino || '', alle: ora }; }
    await aggiornaConsegna(k, campi);
  }
  broadcastOrder({ evento: 'consegne_aggiornate' });
  res.json({ ok: true });
});
// "Avvia giro": il fattorino parte con queste consegne, in quest'ordine
app.post('/api/consegne/giro', async (req, res) => {
  const b = req.body || {}, chi = String(b.fattorino || '').slice(0, 30);
  const ids = (Array.isArray(b.ids) ? b.ids : []).slice(0, 20);
  if (!chi || !ids.length) return res.status(400).json({ ok: false, error: 'Niente da consegnare' });
  let n = 0;
  for (const id of ids) {
    const k = await trovaConsegna(id); if (!k) continue;
    n++;
    await aggiornaConsegna(k, { fattorino: chi, giro: n });
    if (k.tipo === 'o') { if (k.o.stato !== 'in_consegna' && k.o.stato !== 'consegnato') segnaOrdineInConsegna(k.o); }
    else if (k.c.statoConsegna !== 'consegnato') await aggiornaConsegna(k, { statoConsegna: 'in_consegna', inConsegnaAlle: new Date().toISOString() });
  }
  broadcastOrder({ evento: 'consegne_aggiornate' });
  res.json({ ok: true, partite: n });
});

// ---------- DISPLAY CUCINA ----------
function rigaCucina(r, nuove){
  const o = r.opzioni || {};
  const det = righeStampa(r, '').slice(1).map(x => x.trim());
  return { qty: r.qty, nome: r.nome + (o.max ? ' MAX' : o.mezzaMax ? ' MEZZA MAX' : ''), det, nuovo: !!(nuove && nuove.has(r.rid)), glutine: !!o.glutine };
}
async function elencoCucina(){
  const out = [];
  (await comandeStasera()).forEach(c => {
    if (!c.ultimoInvio || !(c.inviate || []).length) return;
    if (c.prontoCucinaAlle && c.prontoCucinaAlle >= c.ultimoInvio) return;
    if (c.servitoAlle && c.servitoAlle >= c.ultimoInvio) return;
    const d = c.ultimoDiff || {};
    const nuove = c.invii > 1 ? new Set(d.aggiunte || []) : null;
    out.push({ id: 'c' + c._id, fonte: 'staff', tipo: c.tipo, etichetta: c.tipo === 'tavolo' ? 'Tavolo ' + c.tavolo : (c.tipo === 'consegna' ? 'Consegna S' : 'Asporto S') + c.numero,
      nome: c.tipo === 'tavolo' ? '' : (c.nome || ''), orario: c.orario || '', da: c.ultimoInvio, primo: c.creataAlle, invio: c.invii || 1,
      iniziata: !!(c.inPrepAlle && c.inPrepAlle >= c.ultimoInvio),
      righe: (c.inviate || []).filter(r => r.qty > 0).map(r => rigaCucina(r, nuove)), tolte: c.invii > 1 ? (d.tolte || []) : [], note: c.noteComanda || '' });
  });
  ordiniStasera().forEach(o => {
    const st = o.stato || 'da_preparare';
    if (st !== 'da_preparare' && st !== 'nuovo') return;
    out.push({ id: 'o' + o.numeroOrdine, fonte: 'online', tipo: o.modalita === 'consegna' ? 'consegna' : 'asporto', etichetta: '#' + o.numeroOrdine + (o.modalita === 'consegna' ? ' Consegna' : ' Ritiro'),
      nome: o.name || '', orario: o.orarioLabel || '', da: o.ricevutoAlle, primo: o.ricevutoAlle, invio: 1, iniziata: !!o.inPrepAlle,
      righe: (o.articoli || []).map(a => ({ qty: Number(a.qty) || 1, nome: a.nome, det: (a.dettagli || []).map(String), nuovo: false, glutine: /glutine/i.test((a.dettagli || []).join(' ')) })), tolte: [], note: o.note || '' });
  });
  return out.sort((a, b) => String(a.da).localeCompare(String(b.da)));
}
app.get('/api/cucina', async (req, res) => {
  try { res.json({ ok: true, ora: new Date().toISOString(), comande: await elencoCucina() }); }
  catch (e) { console.error(e); res.status(500).json({ ok: false, error: 'Errore server' }); }
});
app.post('/api/cucina/:id/pronto', async (req, res) => {
  const id = String(req.params.id || '');
  if (id[0] === 'o') {
    const o = await trovaOrdine(Number(id.slice(1)));
    if (!o) return res.status(404).json({ ok: false, error: 'Ordine non trovato' });
    segnaOrdinePronto(o);
    if (o.modalita !== 'consegna') pushSicura(['titolare'], { titolo: `✅ Ordine #${o.numeroOrdine} pronto`, testo: `${o.name || 'Cliente'} può ritirare`, tag: 'pronto-o' + o.numeroOrdine, url: './' }, 900);
  } else if (id[0] === 'c') {
    const c = await comandaGet(id.slice(1));
    if (!c) return res.status(404).json({ ok: false, error: 'Comanda non trovata' });
    c.prontoCucinaAlle = new Date().toISOString();
    await comandaSave(c);
    const chi = c.tipo === 'tavolo' ? `Tavolo ${c.tavolo}` : `${c.tipo === 'consegna' ? 'Consegna' : 'Asporto'} S${c.numero}${c.nome ? ' (' + c.nome + ')' : ''}`;
    pushSicura(['staff', 'titolare'], { titolo: `🍕 ${chi}: pronto`, testo: c.tipo === 'tavolo' ? 'Da portare al tavolo' : 'Pronto da consegnare', tag: 'pronto-' + c._id, url: './' }, 900);
    if (c.tipo === 'consegna') pushSicura(['fattorino'], { titolo: `🛵 Consegna S${c.numero} pronta`, testo: `${c.nome || 'Cliente'} · ${c.indirizzo || ''}`, tag: 'cons-c' + c._id, url: './' }, 900, c.fattorino || undefined);
  } else return res.status(400).json({ ok: false, error: 'Comanda non valida' });
  broadcastOrder({ evento: 'cucina_aggiornata' });
  res.json({ ok: true });
});
// "In preparazione": la cucina ha iniziato questa comanda (sulla TV della sala il tavolo compare da qui)
app.post('/api/cucina/:id/inizia', async (req, res) => {
  const id = String(req.params.id || ''), ora = new Date().toISOString();
  const via = (req.body || {}).annulla === true;
  if (id[0] === 'o') { const o = await trovaOrdine(Number(id.slice(1))); if (!o) return res.status(404).json({ ok: false, error: 'Ordine non trovato' }); salvaOrdineCampi(o, { inPrepAlle: via ? null : ora }); }
  else if (id[0] === 'c') { const c = await comandaGet(id.slice(1)); if (!c) return res.status(404).json({ ok: false, error: 'Comanda non trovata' }); c.inPrepAlle = via ? null : ora; await comandaSave(c); }
  else return res.status(400).json({ ok: false, error: 'Comanda non valida' });
  broadcastOrder({ evento: 'cucina_aggiornata' });
  res.json({ ok: true });
});
app.post('/api/cucina/:id/riapri', async (req, res) => { // "annulla": era stato toccato per sbaglio
  const id = String(req.params.id || '');
  if (id[0] === 'o') { const o = await trovaOrdine(Number(id.slice(1))); if (o) { salvaOrdineCampi(o, { stato: 'da_preparare', prontoAlle: null }); broadcastOrder({ evento: 'stato_aggiornato', numeroOrdine: o.numeroOrdine, stato: 'da_preparare' }); } }
  else if (id[0] === 'c') { const c = await comandaGet(id.slice(1)); if (c) { c.prontoCucinaAlle = null; await comandaSave(c); } }
  broadcastOrder({ evento: 'cucina_aggiornata' });
  res.json({ ok: true });
});

// ---------- SCHERMO "ORDINI PRONTI" (pubblico: solo numero e nome breve) ----------
app.get('/api/coda', async (req, res) => {
  try {
    const prep = [], pronti = [], adesso = Date.now(), MIN30 = 30 * 60 * 1000;
    ordiniStasera().filter(o => o.modalita !== 'consegna').forEach(o => {
      const st = o.stato || 'da_preparare', voce = { n: String(o.numeroOrdine), nome: nomeBreve(o.name || o.nome) };
      if (st === 'pronto') { if (o.prontoAlle && adesso - new Date(o.prontoAlle).getTime() < MIN30) pronti.push({ ...voce, da: o.prontoAlle }); }
      else if (st === 'da_preparare' || st === 'nuovo') prep.push(voce);
    });
    (await comandeList({ stato: 'aperta' }, 300)).filter(c => c.tipo === 'asporto').forEach(c => {
      const voce = { n: 'S' + c.numero, nome: nomeBreve(c.nome) };
      if (c.prontoCucinaAlle && (!c.ultimoInvio || c.prontoCucinaAlle >= c.ultimoInvio)) { if (adesso - new Date(c.prontoCucinaAlle).getTime() < MIN30) pronti.push({ ...voce, da: c.prontoCucinaAlle }); }
      else if (c.ultimoInvio) prep.push(voce);
    });
    pronti.sort((a, b) => String(b.da).localeCompare(String(a.da)));
    // tavoli della sala: in preparazione (mandati in cucina) e pronti da servire
    const tPrep = [], tPronti = [];
    (await comandeList({ stato: 'aperta' }, 300)).filter(c => c.tipo === 'tavolo' && c.ultimoInvio).forEach(c => {
      if (c.servitoAlle && c.servitoAlle >= c.ultimoInvio) return;
      if (c.prontoCucinaAlle && c.prontoCucinaAlle >= c.ultimoInvio) {
        if (adesso - new Date(c.prontoCucinaAlle).getTime() < MIN30) tPronti.push({ n: String(c.tavolo), da: c.prontoCucinaAlle });
      } else if (c.inPrepAlle && c.inPrepAlle >= c.ultimoInvio) tPrep.push({ n: String(c.tavolo), da: c.inPrepAlle }); // solo quando la cucina l'ha messo in preparazione
    });
    const perNum = (a, b) => (parseInt(a.n, 10) || 999) - (parseInt(b.n, 10) || 999) || a.n.localeCompare(b.n);
    res.json({ ok: true, preparazione: prep.slice(0, 30), pronti: pronti.slice(0, 30), tavoli: { preparazione: tPrep.sort(perNum).slice(0, 40), pronti: tPronti.sort((a, b) => String(b.da).localeCompare(String(a.da))).slice(0, 40) } });
  } catch (e) { console.error(e); res.status(500).json({ ok: false, error: 'Errore server' }); }
});

// ---------- VIE DI NISCEMI (da OpenStreetMap, gratis): per suggerire e controllare gli indirizzi ----------
let vieNiscemi = { vie: [], aggiornate: null };
let vieInCarica = null;
async function scaricaVie(){
  const q = '[out:json][timeout:90];area["name"="Niscemi"]["boundary"="administrative"]->.a;(way["highway"]["name"](area.a);node["place"]["name"](area.a);way["place"]["name"](area.a););out tags;';
  for (const host of ['https://overpass-api.de/api/interpreter', 'https://overpass.kumi.systems/api/interpreter']) {
    try {
      const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 100000);
      const r = await fetch(host, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'LaCasaDiCarta-Ordini/1.0' }, body: 'data=' + encodeURIComponent(q), signal: ctrl.signal });
      clearTimeout(t);
      if (!r.ok) continue;
      const d = await r.json();
      const nomi = new Set();
      (d.elements || []).forEach(e => { const n = e.tags && String(e.tags.name || '').trim(); if (n && n.length <= 80) nomi.add(n); });
      if (nomi.size < 20) continue; // risposta sospetta: meglio tenere la lista vecchia
      return [...nomi].sort((a, b) => a.localeCompare(b, 'it'));
    } catch (e) { console.error('Vie: scaricamento non riuscito da', host, e.message); }
  }
  return null;
}
async function aggiornaVie(forza){
  const vecchie = vieNiscemi.aggiornate && Date.now() - new Date(vieNiscemi.aggiornate).getTime() > 30 * 86400000;
  if (!forza && vieNiscemi.vie.length && !vecchie) return;
  if (vieInCarica) return vieInCarica;
  vieInCarica = (async () => {
    const vie = await scaricaVie();
    if (vie) {
      vieNiscemi = { vie, aggiornate: new Date().toISOString() };
      if (settingsCollection) await settingsCollection.updateOne({ _id: 'vieNiscemi' }, { $set: { value: vieNiscemi } }, { upsert: true }).catch(() => {});
      console.log(`Vie di Niscemi aggiornate: ${vie.length}`);
    }
  })().finally(() => { vieInCarica = null; });
  return vieInCarica;
}
app.get('/api/vie', async (req, res) => {
  if (!vieNiscemi.vie.length) await Promise.race([aggiornaVie(), new Promise(r => setTimeout(r, 20000))]);
  else aggiornaVie().catch(() => {});
  res.set('Cache-Control', 'public, max-age=3600');
  res.json({ ok: true, vie: vieNiscemi.vie, aggiornate: vieNiscemi.aggiornate });
});

// ---------- PIANTINA DELLA SALA (disegnata dal titolare, la leggono titolare e camerieri) ----------
const PIANTINA_INIZIALE = {"zone":[{"id":"dentro","nome":"Dentro","w":800},{"id":"fuori","nome":"Fuori (estate)"}],"oggetti":[{"etichetta":"Fuori sala","fisso":"vuoto","h":242,"id":"vuoto01","tipo":"fisso","w":456,"x":344,"y":398,"zona":"dentro"},{"etichetta":"Vetrata","fisso":"vetrata","h":10,"id":"vetra01","tipo":"fisso","w":368,"x":376,"y":0,"zona":"dentro"},{"etichetta":"Panca","fisso":"panca","h":140,"id":"panca01","tipo":"fisso","w":22,"x":0,"y":120,"zona":"dentro"},{"etichetta":"Frigo","fisso":"frigo","h":40,"id":"frigo01","tipo":"fisso","w":60,"x":26,"y":590,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"t01","num":"","posti":4,"tipo":"tavolo","w":62,"x":26,"y":125,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"t02","num":"","posti":3,"tipo":"tavolo","w":62,"x":26,"y":187,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"t08","num":"","posti":4,"tipo":"tavolo","w":62,"x":363,"y":258,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"t09","num":"","posti":4,"tipo":"tavolo","w":62,"x":491,"y":258,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"t11","num":"","posti":4,"tipo":"tavolo","w":62,"x":363,"y":320,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"t12","num":"","posti":4,"tipo":"tavolo","w":62,"x":491,"y":320,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"t14","num":"","posti":4,"tipo":"tavolo","w":62,"x":274,"y":380,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"t15","num":"","posti":4,"tipo":"tavolo","w":62,"x":274,"y":442,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"t16","num":"","posti":4,"tipo":"tavolo","w":62,"x":274,"y":504,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"t17","num":"","posti":4,"tipo":"tavolo","w":62,"x":274,"y":566,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"t18","num":"","posti":4,"tipo":"tavolo","w":62,"x":474,"y":26,"zona":"dentro"},{"etichetta":"Vetrata del locale","fisso":"vetrata","h":10,"id":"ammu53j","tipo":"fisso","w":800,"x":100,"y":0,"zona":"fuori"},{"forma":"quadrato","h":70,"id":"dvvlnro","num":"","posti":4,"tipo":"tavolo","w":70,"x":100,"y":180,"zona":"fuori"},{"forma":"quadrato","h":70,"id":"pk2m8ut","num":"","posti":4,"tipo":"tavolo","w":70,"x":270,"y":180,"zona":"fuori"},{"forma":"quadrato","h":70,"id":"99a6zcg","num":"","posti":4,"tipo":"tavolo","w":70,"x":440,"y":180,"zona":"fuori"},{"forma":"quadrato","h":70,"id":"o0rmuo2","num":"","posti":4,"tipo":"tavolo","w":70,"x":610,"y":180,"zona":"fuori"},{"forma":"quadrato","h":70,"id":"fpwb946","num":"","posti":4,"tipo":"tavolo","w":70,"x":780,"y":180,"zona":"fuori"},{"forma":"quadrato","h":70,"id":"1fg0hnp","num":"","posti":4,"tipo":"tavolo","w":70,"x":100,"y":380,"zona":"fuori"},{"forma":"quadrato","h":70,"id":"u6e3u9s","num":"","posti":4,"tipo":"tavolo","w":70,"x":270,"y":380,"zona":"fuori"},{"forma":"quadrato","h":70,"id":"y0oe9g7","num":"","posti":4,"tipo":"tavolo","w":70,"x":440,"y":380,"zona":"fuori"},{"forma":"quadrato","h":70,"id":"med00vq","num":"","posti":4,"tipo":"tavolo","w":70,"x":610,"y":380,"zona":"fuori"},{"forma":"quadrato","h":70,"id":"ozm0ejf","num":"","posti":4,"tipo":"tavolo","w":70,"x":780,"y":380,"zona":"fuori"},{"forma":"quadrato","h":62,"id":"otbgtac","num":"","posti":4,"tipo":"tavolo","w":62,"x":18,"y":370,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"fkrf1z4","num":"7","posti":4,"tipo":"tavolo","w":62,"x":18,"y":300,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"dz0jiaw","num":"","posti":2,"tipo":"tavolo","w":62,"x":730,"y":150,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"t6cnf3t","num":"","posti":2,"tipo":"tavolo","w":62,"x":730,"y":30,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"3whh9cb","num":"","posti":2,"tipo":"tavolo","w":62,"x":660,"y":150,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"ml3mgwk","num":"","posti":2,"tipo":"tavolo","w":62,"x":590,"y":150,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"z9vtqlc","num":"","posti":2,"tipo":"tavolo","w":62,"x":530,"y":150,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"nykpgr6","num":"","posti":2,"tipo":"tavolo","w":62,"x":563,"y":30,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"r456wkl","num":"","posti":2,"tipo":"tavolo","w":62,"x":633,"y":30,"zona":"dentro"},{"etichetta":"Ingresso","fisso":"porta","h":12,"id":"ipk04tv","tipo":"fisso","w":115,"x":28,"y":20,"zona":"dentro"},{"etichetta":"Bancone","fisso":"bancone","h":40,"id":"34d9bvb","tipo":"fisso","w":140,"x":142,"y":20,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"oz98vxf","num":"","posti":4,"tipo":"tavolo","w":62,"x":323,"y":130,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"yptohs3","num":"","posti":4,"tipo":"tavolo","w":62,"x":186,"y":80,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"u8l5u29","num":"","posti":4,"tipo":"tavolo","w":62,"x":682,"y":260,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"zlfpmoi","num":"","posti":4,"tipo":"tavolo","w":62,"x":682,"y":330,"zona":"dentro"},{"fisso":"colonna","h":26,"id":"ex837u6","tipo":"fisso","w":26,"x":292,"y":20,"zona":"dentro"},{"forma":"quadrato","h":62,"id":"186ga9i","num":"","posti":4,"tipo":"tavolo","w":62,"x":393,"y":130,"zona":"dentro"}],"aggiornato":"2026-10-16T01:35:22.644Z"};
let piantinaSala = null;
function pulisciPiantina(p){
  const num = (v, a, b, d) => { v = Math.round(Number(v)); return Number.isFinite(v) ? Math.max(a, Math.min(b, v)) : d; };
  const testo = (v, n) => String(v == null ? '' : v).slice(0, n);
  const zone = (Array.isArray(p.zone) ? p.zone : []).slice(0, 10).map(z => {
    const o = { id: testo(z.id, 20) || 'sala', nome: testo(z.nome, 30) || 'Sala' };
    if (z.w) o.w = num(z.w, 400, 1400, 1000);
    return o;
  });
  if (!zone.length) zone.push({ id: 'dentro', nome: 'Dentro' });
  const ids = new Set(zone.map(z => z.id));
  const oggetti = (Array.isArray(p.oggetti) ? p.oggetti : []).slice(0, 400).filter(o => o && ids.has(o.zona)).map(o => {
    const b = { id: testo(o.id, 20), zona: o.zona, tipo: o.tipo === 'tavolo' ? 'tavolo' : 'fisso', x: num(o.x, 0, 1400, 0), y: num(o.y, 0, 640, 0), w: num(o.w, 4, 1400, 60), h: num(o.h, 4, 640, 60) };
    if (b.tipo === 'tavolo') { b.forma = ['quadrato', 'rettangolo', 'tondo', 'alto'].includes(o.forma) ? o.forma : 'quadrato'; b.posti = num(o.posti, 1, 30, 4); b.num = testo(o.num, 6).trim(); }
    else { b.fisso = testo(o.fisso, 20); if (o.etichetta) b.etichetta = testo(o.etichetta, 24); }
    return b;
  });
  return { zone, oggetti, aggiornato: new Date().toISOString() };
}
app.get('/api/piantina', (req, res) => res.json({ ok: true, piantina: piantinaSala || PIANTINA_INIZIALE }));
app.post('/api/piantina', soloTitolare, async (req, res) => {
  const p = (req.body || {}).piantina;
  if (!p || typeof p !== 'object') return res.status(400).json({ ok: false, error: 'Piantina mancante' });
  piantinaSala = pulisciPiantina(p);
  if (settingsCollection) {
    try { await settingsCollection.updateOne({ _id: 'piantina' }, { $set: { value: piantinaSala } }, { upsert: true }); }
    catch (e) { return res.status(500).json({ ok: false, error: 'Non salvata: riprova' }); }
  }
  res.json({ ok: true, piantina: piantinaSala });
});

function configTitolare(){
  return { ...CONFIG, camerieri: (CONFIG.camerieri || []).map(x => ({ nome: x.nome, pin: x.pin ? '***' : '' })) };
}
app.get('/api/config', (req, res) => res.json({ ok: true, config: configPubblica() }));
app.get('/api/config/completa', soloTitolare, (req, res) => res.json({ ok: true, config: configTitolare() }));
app.post('/api/config', soloTitolare, async (req, res) => {
  const nuova = (req.body || {}).config;
  if (!nuova || typeof nuova !== 'object') return res.status(400).json({ ok: false, error: 'Nessuna impostazione ricevuta' });
  impostaConfig(nuova);
  if (settingsCollection) {
    try { await settingsCollection.updateOne({ _id: 'config' }, { $set: { value: CONFIG, aggiornataAlle: new Date().toISOString() } }, { upsert: true }); }
    catch (err) { console.error('Errore salvataggio impostazioni:', err); return res.status(500).json({ ok: false, error: 'Non riesco a salvare nel database' }); }
  }
  broadcastOrder({ evento: 'config_aggiornata', config: configPubblica() }); // sito, staff e pannello si aggiornano da soli
  res.json({ ok: true, config: configTitolare() });
});

// ---------- Password dell'app Titolare (scelta dall'app, senza toccare Render) ----------
app.get('/api/titolare/password', soloTitolare, (req, res) => {
  res.json({ ok: true, attiva: !!passwordAttiva(), daRender: !!TITOLARE_PASSWORD });
});
app.post('/api/titolare/password', soloTitolare, async (req, res) => {
  if (TITOLARE_PASSWORD) return res.status(400).json({ ok: false, error: 'La password è impostata su Render (TITOLARE_PASSWORD): cambiala da lì.' });
  const nuova = String((req.body || {}).nuova || '').trim();
  if (nuova && nuova.length < 4) return res.status(400).json({ ok: false, error: 'La password deve avere almeno 4 caratteri' });
  if (nuova.length > 100) return res.status(400).json({ ok: false, error: 'Password troppo lunga' });
  titolarePwHash = nuova ? bcrypt.hashSync(nuova, 10) : '';
  if (settingsCollection) {
    if (titolarePwHash) await settingsCollection.updateOne({ _id: 'titolarePassword' }, { $set: { hash: titolarePwHash } }, { upsert: true });
    else await settingsCollection.deleteOne({ _id: 'titolarePassword' });
  }
  res.json({ ok: true, attiva: !!titolarePwHash, token: titolarePwHash ? tokenTitolare() : '' });
});

// ---------- Storico incassi giorno per giorno (sala/banco + ordini online), per il Titolare ----------
app.get('/api/titolare/storico', soloTitolare, async (req, res) => {
  try {
    const re = /^\d{4}-\d{2}-\d{2}$/;
    const oggi = dateKey(new Date());
    let a = re.test(req.query.a || '') ? req.query.a : oggi;
    let da = re.test(req.query.da || '') ? req.query.da : dateKey(new Date(Date.now() - 30 * 86400000));
    if (da > a) [da, a] = [a, da];
    if ((new Date(a) - new Date(da)) / 86400000 > 400) da = dateKey(new Date(new Date(a + 'T12:00:00').getTime() - 400 * 86400000));
    const giorni = {};
    const g = k => giorni[k] || (giorni[k] = { data: k,
      sala: { incasso: 0, conti: 0, contanti: 0, carta: 0 },
      online: { incasso: 0, ordini: 0, online: 0, contanti: 0, bancomat: 0, nonRegistrato: 0 } });
    const chiuse = await comandeList({ stato: 'chiusa', giorno: { $gte: da, $lte: a } }, 50000);
    chiuse.forEach(c => {
      const x = g(c.giorno).sala, imp = Number(c.totaleIncassato) || 0;
      x.incasso += imp; x.conti++;
      if (Array.isArray(c.pagamenti) && c.pagamenti.length) c.pagamenti.forEach(p => { if (p.metodo === 'carta') x.carta += Number(p.importo) || 0; else x.contanti += Number(p.importo) || 0; });
      else if (c.pagamento === 'carta') x.carta += imp; else x.contanti += imp;
    });
    if (ordersCollection) {
      const dal = new Date(da + 'T00:00:00').toISOString(), al = new Date(a + 'T23:59:59.999').toISOString();
      const ordini = await ordersCollection.find({ ricevutoAlle: { $gte: dal, $lte: al } }, { projection: { ricevutoAlle: 1, grandTotal: 1, subtotale: 1, metodoPagamento: 1 } }).toArray();
      ordini.forEach(o => {
        const x = g(dateKey(new Date(o.ricevutoAlle))).online, imp = Number(o.grandTotal != null ? o.grandTotal : o.subtotale) || 0;
        x.incasso += imp; x.ordini++;
        const m = ['online', 'contanti', 'bancomat'].includes(o.metodoPagamento) ? o.metodoPagamento : 'nonRegistrato';
        x[m] += imp;
      });
    }
    const lista = Object.values(giorni).sort((x, y) => y.data.localeCompare(x.data)).map(x => {
      Object.keys(x.sala).forEach(k => { if (k !== 'conti') x.sala[k] = round2(x.sala[k]); });
      Object.keys(x.online).forEach(k => { if (k !== 'ordini') x.online[k] = round2(x.online[k]); });
      return { ...x, totale: round2(x.sala.incasso + x.online.incasso) };
    });
    res.json({ ok: true, da, a, giorni: lista, totale: round2(lista.reduce((t, x) => t + x.totale, 0)) });
  } catch (err) { console.error('Errore storico:', err); res.status(500).json({ ok: false, error: 'Errore server' }); }
});

// =====================================================================
//  COPIA DI SICUREZZA DEL DATABASE (ogni settimana, per email al titolare)
// =====================================================================
// Esporta tutte le raccolte (ordini, clienti, comande, menu, prezzi, esauriti, impostazioni...)
// in un unico file .json.gz. Formato EJSON: date e id restano identici per un eventuale ripristino.
const zlibBackup = require('zlib');
const BACKUP_GIORNI = 7;
const BACKUP_MAX_BYTES = 30 * 1024 * 1024; // limite allegati email: se si supera, le foto si scaricano a parte
function ejsonStringify(x){
  try { const { BSON } = require('mongodb'); if (BSON && BSON.EJSON) return BSON.EJSON.stringify(x, { relaxed: false }); } catch (e) {}
  return JSON.stringify(x);
}
async function creaBackup(opz = {}){
  if (!db) throw new Error('Database non collegato');
  const raccolte = (await db.listCollections({}, { nameOnly: true }).toArray()).map(c => c.name).sort();
  const escludi = new Set(opz.senzaFoto ? ['productPhotos'] : []);
  const dati = {}, conteggi = {};
  for (const nome of raccolte) {
    if (escludi.has(nome)) continue;
    const docs = await db.collection(nome).find({}).toArray();
    dati[nome] = docs; conteggi[nome] = docs.length;
  }
  const contenuto = { creatoIl: new Date().toISOString(), database: 'lacasadicarta', raccolte: conteggi, dati };
  const gz = zlibBackup.gzipSync(Buffer.from(ejsonStringify(contenuto)), { level: 9 });
  if (!opz.senzaFoto && gz.length > BACKUP_MAX_BYTES && raccolte.includes('productPhotos')) return creaBackup({ senzaFoto: true });
  const giorno = dateKey(new Date());
  return { nomeFile: `backup-lacasadicarta-${giorno}${opz.senzaFoto ? '-senza-foto' : ''}.json.gz`, gz, conteggi, senzaFoto: !!opz.senzaFoto };
}
async function inviaBackupEmail(motivo){
  if (!RESEND_API_KEY) throw new Error('Email non configurata (RESEND_API_KEY su Render)');
  const b = await creaBackup();
  const righe = Object.entries(b.conteggi).map(([k, n]) => `- ${k}: ${n}`).join('\n');
  const testo = `Copia di sicurezza ${motivo === 'manuale' ? 'richiesta dal titolare' : 'settimanale'} del database della pizzeria.\n\n` +
    `File: ${b.nomeFile} (${(b.gz.length / 1024).toFixed(0)} KB)\n\nContenuto:\n${righe}\n\n` +
    (b.senzaFoto ? 'Nota: le foto dei piatti non sono incluse (file troppo grande per l\'email): le foto restano sul sito.\n\n' : '') +
    'Conserva questa email: serve solo se un giorno bisogna ripristinare i dati.';
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: FROM_EMAIL, to: ORDER_EMAIL, subject: `💾 Copia di sicurezza La Casa di Carta — ${dateKey(new Date())}`, text: testo,
      attachments: [{ filename: b.nomeFile, content: b.gz.toString('base64') }] })
  });
  if (!r.ok) throw new Error('Invio email non riuscito (' + r.status + '): ' + (await r.text()).slice(0, 200));
  const quando = new Date().toISOString();
  if (settingsCollection) await settingsCollection.updateOne({ _id: 'ultimoBackup' }, { $set: { value: quando, kb: Math.round(b.gz.length / 1024) } }, { upsert: true });
  console.log(`Copia di sicurezza inviata a ${ORDER_EMAIL} (${Math.round(b.gz.length / 1024)} KB)`);
  return { quando, kb: Math.round(b.gz.length / 1024), senzaFoto: b.senzaFoto };
}
// controllo ogni ora: se l'ultima copia ha più di 7 giorni, ne manda una (funziona anche se Render riavvia il server)
let backupInCorso = false;
async function controllaBackupSettimanale(){
  if (backupInCorso || !db || !settingsCollection || !RESEND_API_KEY) return;
  try {
    const doc = await settingsCollection.findOne({ _id: 'ultimoBackup' });
    const ultimo = doc && doc.value ? new Date(doc.value).getTime() : 0;
    if (Date.now() - ultimo < BACKUP_GIORNI * 24 * 60 * 60 * 1000) return;
    backupInCorso = true;
    await inviaBackupEmail('settimanale');
  } catch (err) { console.error('Errore copia di sicurezza settimanale:', err.message || err); }
  finally { backupInCorso = false; }
}
setTimeout(controllaBackupSettimanale, 2 * 60 * 1000);
setInterval(controllaBackupSettimanale, 60 * 60 * 1000);

// dal Titolare: scarica subito la copia, oppure mandala per email adesso
app.get('/api/backup/scarica', soloTitolare, async (req, res) => {
  try {
    const b = await creaBackup();
    res.setHeader('Content-Type', 'application/gzip');
    res.setHeader('Content-Disposition', `attachment; filename="${b.nomeFile}"`);
    res.end(b.gz);
  } catch (err) { console.error('Errore copia di sicurezza:', err); res.status(500).json({ ok: false, error: err.message || 'Errore' }); }
});
app.post('/api/backup/invia', soloTitolare, async (req, res) => {
  if (backupInCorso) return res.status(409).json({ ok: false, error: 'Copia già in corso, riprova tra un minuto' });
  backupInCorso = true;
  try { const r = await inviaBackupEmail('manuale'); res.json({ ok: true, ...r, a: ORDER_EMAIL }); }
  catch (err) { console.error('Errore invio copia:', err); res.status(500).json({ ok: false, error: err.message || 'Errore' }); }
  finally { backupInCorso = false; }
});
app.get('/api/backup/stato', soloTitolare, async (req, res) => {
  const doc = settingsCollection ? await settingsCollection.findOne({ _id: 'ultimoBackup' }).catch(() => null) : null;
  res.json({ ok: true, ultimo: doc ? doc.value : null, kb: doc ? doc.kb : null, email: ORDER_EMAIL, ogniGiorni: BACKUP_GIORNI });
});

// ---------- "Segnala un problema" dall'app Android ----------
// L'app manda locale, tablet, versione, ultimi errori e stato delle stampanti: si salva e arriva per email.
const segnalazioniPerIp = new Map();
app.post('/api/segnalazioni', async (req, res) => {
  const ip = req.ip || 'x', ora = Date.now();
  const recenti = (segnalazioniPerIp.get(ip) || []).filter(t => ora - t < 10 * 60 * 1000);
  if (recenti.length >= 5) return res.status(429).json({ ok: false, error: 'Troppe segnalazioni: riprova tra qualche minuto' });
  recenti.push(ora); segnalazioniPerIp.set(ip, recenti);
  const b = req.body || {};
  const t = (v, n) => String(v == null ? '' : (typeof v === 'string' ? v : JSON.stringify(v))).slice(0, n);
  const doc = { creata: new Date().toISOString(), locale: t(b.locale, 120), dispositivo: t(b.dispositivo, 200), versione: t(b.versione, 60),
    nota: t(b.nota, 3000), stampanti: t(b.stampanti, 4000), errori: t(b.errori, 10000), registro: t(b.registro, 30000) };
  try { if (db) await db.collection('segnalazioni').insertOne({ ...doc }); } catch (e) { console.error('Errore salvataggio segnalazione:', e.message); }
  let stampanti = doc.stampanti;
  try { const s = JSON.parse(doc.stampanti); stampanti = `Xprinter ${s.ipXprinter}: ${s.xprinterOk ? 'ok' : 'NON risponde ' + (s.xprinterErrore || '')}\nEpson ${s.ipEpson}: ${s.epsonOk ? 'ok' : 'NON risponde ' + (s.epsonErrore || '')}\nPonte di stampa: ${s.ponte ? 'attivo' : 'FERMO ' + (s.ponteErrore || '')}\nTablet nel Wi-Fi: ${s.ipTablet}`; } catch (e) {}
  const testo = `Segnalazione dall'app\n\nLocale: ${doc.locale}\nTablet: ${doc.dispositivo}\nVersione: ${doc.versione}\nQuando: ${new Date().toLocaleString('it-IT', { timeZone: 'Europe/Rome' })}\n\n` +
    `COSA È SUCCESSO:\n${doc.nota || '(nessuna nota)'}\n\nSTAMPANTI:\n${stampanti}\n\nULTIMI ERRORI:\n${doc.errori || '(nessuno)'}\n\nULTIMI EVENTI:\n${doc.registro}`;
  console.log(`Segnalazione da ${doc.locale} (${doc.dispositivo})`);
  sendEmail(ORDER_EMAIL, `🛟 Segnalazione app — ${doc.locale || 'locale'} — ${doc.nota.slice(0, 60) || doc.dispositivo}`, testo);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`Server ordini in ascolto sulla porta ${PORT}`);
});
