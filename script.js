// ============================================================
//  Reading Log — Auth + App Logic
//  Auth: PBKDF2 (SHA-256, 200k iterations) + random salt
//        stored in localStorage. Session via sessionStorage
//        so login clears when the tab closes.
//  Rate-limit: 5 failed attempts → 30-second lockout.
// ============================================================

'use strict';

const AUTH_KEY    = 'rl_auth_v1';
const SESSION_KEY = 'rl_session_v1';
const BOOKS_KEY   = 'rl_books_v1';
const ATTEMPTS_KEY = 'rl_attempts_v1';

// ── Crypto helpers ───────────────────────────────────────────

async function deriveKey(password, saltHex) {
  const enc  = new TextEncoder();
  const salt = hexToBytes(saltHex);
  const raw  = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 200_000, hash: 'SHA-256' },
    raw, 256
  );
  return bytesToHex(new Uint8Array(bits));
}

function generateSalt() {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
}

function bytesToHex(arr) {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return arr;
}

/** Constant-time string comparison to mitigate timing attacks. */
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ── Auth state ───────────────────────────────────────────────

function hasAuth()    { return !!localStorage.getItem(AUTH_KEY); }
function isLoggedIn() { return !!sessionStorage.getItem(SESSION_KEY); }
function setSession() { sessionStorage.setItem(SESSION_KEY, crypto.randomUUID()); }
function clearSession() { sessionStorage.removeItem(SESSION_KEY); }

function getAuthRecord() {
  try { return JSON.parse(localStorage.getItem(AUTH_KEY)); } catch { return null; }
}

async function setupPassword(password) {
  const salt = generateSalt();
  const hash = await deriveKey(password, salt);
  localStorage.setItem(AUTH_KEY, JSON.stringify({ hash, salt }));
  setSession();
}

async function verifyPassword(password) {
  const record = getAuthRecord();
  if (!record) return false;
  const hash = await deriveKey(password, record.salt);
  return constantTimeEqual(hash, record.hash);
}

// ── Rate limiting ────────────────────────────────────────────

const MAX_ATTEMPTS = 5;
const LOCKOUT_MS   = 30_000;

function getAttemptState() {
  try { return JSON.parse(sessionStorage.getItem(ATTEMPTS_KEY)) || { count: 0, lockedUntil: 0 }; }
  catch { return { count: 0, lockedUntil: 0 }; }
}

function recordFailedAttempt() {
  const s = getAttemptState();
  s.count++;
  if (s.count >= MAX_ATTEMPTS) s.lockedUntil = Date.now() + LOCKOUT_MS;
  sessionStorage.setItem(ATTEMPTS_KEY, JSON.stringify(s));
  return s;
}

function resetAttempts() {
  sessionStorage.removeItem(ATTEMPTS_KEY);
}

function isLockedOut() {
  const s = getAttemptState();
  if (s.lockedUntil && Date.now() < s.lockedUntil) return s.lockedUntil;
  return false;
}

// ── Books data ───────────────────────────────────────────────

function getBooks() {
  try { return JSON.parse(localStorage.getItem(BOOKS_KEY)) || []; }
  catch { return []; }
}

function saveBooks(books) { localStorage.setItem(BOOKS_KEY, JSON.stringify(books)); }

function sanitize(str) { return String(str).trim().slice(0, 1000); }

function addBook(data) {
  const books = getBooks();
  const book  = {
    id:        crypto.randomUUID(),
    title:     sanitize(data.title),
    author:    sanitize(data.author),
    status:    data.status,
    rating:    Number(data.rating) || 0,
    notes:     sanitize(data.notes || ''),
    dateAdded: new Date().toISOString(),
  };
  books.unshift(book);
  saveBooks(books);
  return book;
}

function updateBook(id, data) {
  const books = getBooks();
  const idx   = books.findIndex(b => b.id === id);
  if (idx === -1) return;
  books[idx] = {
    ...books[idx],
    title:  sanitize(data.title),
    author: sanitize(data.author),
    status: data.status,
    rating: Number(data.rating) || 0,
    notes:  sanitize(data.notes || ''),
  };
  saveBooks(books);
}

function deleteBook(id) { saveBooks(getBooks().filter(b => b.id !== id)); }

// ── DOM refs ─────────────────────────────────────────────────

const authScreen    = document.getElementById('auth-screen');
const appScreen     = document.getElementById('app-screen');
const authSubtitle  = document.getElementById('auth-subtitle');
const setupForm     = document.getElementById('setup-form');
const loginForm     = document.getElementById('login-form');
const setupError    = document.getElementById('setup-error');
const loginError    = document.getElementById('login-error');
const loginLockout  = document.getElementById('login-lockout');
const bookList      = document.getElementById('book-list');
const emptyState    = document.getElementById('empty-state');
const bookCountEl   = document.getElementById('book-count');
const filterTabs    = document.querySelectorAll('.filter-tab');
const bookModal     = document.getElementById('book-modal');
const bookForm      = document.getElementById('book-form');
const modalTitle    = document.getElementById('modal-title');
const deleteBookBtn = document.getElementById('delete-book-btn');
const starRating    = document.getElementById('star-rating');
const bookRatingInput = document.getElementById('book-rating');

let currentFilter = 'all';
let currentRating = 0;

// ── Screen helpers ───────────────────────────────────────────

function showError(el, msg) { el.textContent = msg; el.hidden = false; }
function hideError(el)      { el.hidden = true; el.textContent = ''; }

function showAuthScreen() {
  authScreen.hidden = false;
  appScreen.hidden  = true;
  if (!hasAuth()) {
    authSubtitle.textContent = 'Set up your reading log';
    setupForm.hidden = false;
    loginForm.hidden = true;
  } else {
    authSubtitle.textContent = 'Welcome back';
    loginForm.hidden = false;
    setupForm.hidden = true;
  }
}

function showAppScreen() {
  authScreen.hidden = true;
  appScreen.hidden  = false;
  renderBooks();
}

// ── Auth forms ───────────────────────────────────────────────

setupForm.addEventListener('submit', async e => {
  e.preventDefault();
  hideError(setupError);
  const password = document.getElementById('setup-password').value;
  const confirm  = document.getElementById('setup-confirm').value;

  if (password !== confirm) { showError(setupError, 'Passwords do not match.'); return; }
  if (password.length < 8)  { showError(setupError, 'Password must be at least 8 characters.'); return; }

  const btn = setupForm.querySelector('button[type="submit"]');
  btn.disabled    = true;
  btn.textContent = 'Setting up…';
  try {
    await setupPassword(password);
    showAppScreen();
  } catch {
    showError(setupError, 'Something went wrong. Please try again.');
    btn.disabled    = false;
    btn.textContent = 'Create Password';
  }
});

loginForm.addEventListener('submit', async e => {
  e.preventDefault();
  hideError(loginError);

  const locked = isLockedOut();
  if (locked) {
    const secs = Math.ceil((locked - Date.now()) / 1000);
    loginLockout.textContent = `Too many attempts. Try again in ${secs}s.`;
    loginLockout.hidden = false;
    return;
  }
  loginLockout.hidden = true;

  const password = document.getElementById('login-password').value;
  const btn      = loginForm.querySelector('button[type="submit"]');
  btn.disabled    = true;
  btn.textContent = 'Signing in…';

  try {
    const ok = await verifyPassword(password);
    if (ok) {
      resetAttempts();
      setSession();
      showAppScreen();
    } else {
      const state = recordFailedAttempt();
      if (state.lockedUntil) {
        showError(loginError, `Too many failed attempts. Locked for 30 seconds.`);
      } else {
        const remaining = MAX_ATTEMPTS - state.count;
        showError(loginError, `Incorrect password. ${remaining} attempt${remaining !== 1 ? 's' : ''} remaining.`);
      }
      btn.disabled    = false;
      btn.textContent = 'Sign In';
      document.getElementById('login-password').value = '';
    }
  } catch {
    showError(loginError, 'Something went wrong. Please try again.');
    btn.disabled    = false;
    btn.textContent = 'Sign In';
  }
});

document.getElementById('logout-btn').addEventListener('click', () => {
  clearSession();
  showAuthScreen();
});

// ── Filter tabs ──────────────────────────────────────────────

filterTabs.forEach(tab => {
  tab.addEventListener('click', () => {
    filterTabs.forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    currentFilter = tab.dataset.filter;
    renderBooks();
  });
});

// ── Book rendering ───────────────────────────────────────────

function escapeHtml(str) {
  const div = document.createElement('div');
  div.appendChild(document.createTextNode(String(str)));
  return div.innerHTML;
}

function renderBooks() {
  const books    = getBooks();
  const filtered = currentFilter === 'all'
    ? books
    : books.filter(b => b.status === currentFilter);

  const total = books.length;
  bookCountEl.textContent = total === 0 ? '' : `${total} book${total !== 1 ? 's' : ''}`;

  bookList.innerHTML = '';

  if (filtered.length === 0) {
    emptyState.hidden = false;
    bookList.hidden   = true;
    return;
  }

  emptyState.hidden = true;
  bookList.hidden   = false;

  const statusLabel = { reading: 'Reading', finished: 'Finished', 'want-to-read': 'Want to Read' };

  filtered.forEach(book => {
    const card  = document.createElement('div');
    card.className = 'book-card';
    card.setAttribute('role', 'button');
    card.setAttribute('tabindex', '0');
    card.setAttribute('aria-label', `${book.title} by ${book.author}`);

    const stars = book.rating > 0
      ? '★'.repeat(book.rating) + '☆'.repeat(5 - book.rating)
      : '';

    // Build with safe DOM methods to prevent XSS
    const header = document.createElement('div');
    header.className = 'book-card-header';

    const info   = document.createElement('div');
    const titleEl  = document.createElement('div');
    titleEl.className   = 'book-card-title';
    titleEl.textContent = book.title;
    const authorEl = document.createElement('div');
    authorEl.className   = 'book-card-author';
    authorEl.textContent = book.author;
    info.append(titleEl, authorEl);

    const badge = document.createElement('span');
    badge.className   = `book-status-badge ${book.status}`;
    badge.textContent = statusLabel[book.status] || book.status;

    header.append(info, badge);
    card.appendChild(header);

    if (stars) {
      const starsEl = document.createElement('div');
      starsEl.className   = 'book-card-stars';
      starsEl.textContent = stars;
      card.appendChild(starsEl);
    }

    if (book.notes) {
      const notesEl = document.createElement('div');
      notesEl.className   = 'book-card-notes';
      notesEl.textContent = book.notes;
      card.appendChild(notesEl);
    }

    card.addEventListener('click', () => openEditModal(book));
    card.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') openEditModal(book); });
    bookList.appendChild(card);
  });
}

// ── Modal ────────────────────────────────────────────────────

document.getElementById('add-book-btn').addEventListener('click', openAddModal);
document.getElementById('modal-close').addEventListener('click', closeModal);
document.getElementById('modal-cancel').addEventListener('click', closeModal);

function openAddModal() {
  modalTitle.textContent = 'Add a Book';
  bookForm.reset();
  document.getElementById('book-id').value = '';
  deleteBookBtn.hidden = true;
  setRating(0);
  bookModal.hidden = false;
  document.getElementById('book-title').focus();
}

function openEditModal(book) {
  modalTitle.textContent = 'Edit Book';
  document.getElementById('book-id').value     = book.id;
  document.getElementById('book-title').value  = book.title;
  document.getElementById('book-author').value = book.author;
  document.getElementById('book-status').value = book.status;
  document.getElementById('book-notes').value  = book.notes || '';
  setRating(book.rating || 0);
  deleteBookBtn.hidden = false;
  bookModal.hidden = false;
}

function closeModal() { bookModal.hidden = true; }

bookModal.addEventListener('click', e => { if (e.target === bookModal) closeModal(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape' && !bookModal.hidden) closeModal(); });

bookForm.addEventListener('submit', e => {
  e.preventDefault();
  const id   = document.getElementById('book-id').value;
  const data = {
    title:  document.getElementById('book-title').value,
    author: document.getElementById('book-author').value,
    status: document.getElementById('book-status').value,
    rating: parseInt(bookRatingInput.value, 10),
    notes:  document.getElementById('book-notes').value,
  };
  if (id) updateBook(id, data); else addBook(data);
  closeModal();
  renderBooks();
});

deleteBookBtn.addEventListener('click', () => {
  const id = document.getElementById('book-id').value;
  if (id && confirm('Delete this book from your log?')) {
    deleteBook(id);
    closeModal();
    renderBooks();
  }
});

// ── Star rating ──────────────────────────────────────────────

function setRating(value) {
  currentRating         = value;
  bookRatingInput.value = value;
  document.querySelectorAll('.star').forEach(s => {
    s.classList.toggle('active', parseInt(s.dataset.value) <= value);
  });
}

starRating.addEventListener('click', e => {
  const star = e.target.closest('.star');
  if (!star) return;
  const val = parseInt(star.dataset.value);
  setRating(currentRating === val ? 0 : val);
});

starRating.addEventListener('mouseover', e => {
  const star = e.target.closest('.star');
  if (!star) return;
  const val = parseInt(star.dataset.value);
  document.querySelectorAll('.star').forEach(s => {
    s.classList.toggle('active', parseInt(s.dataset.value) <= val);
  });
});

starRating.addEventListener('mouseleave', () => setRating(currentRating));

// ── Init ─────────────────────────────────────────────────────

if (isLoggedIn()) {
  showAppScreen();
} else {
  showAuthScreen();
}
