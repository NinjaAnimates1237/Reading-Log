// ============================================================
//  Reading Log — Auth + App Logic
//  Auth: PBKDF2 (SHA-256, 200k iterations) + random salt
//        per account in localStorage. Session via sessionStorage
//        so login clears when the tab closes.
//  Rate-limit: 5 failed attempts → 30-second lockout.
// ============================================================

'use strict';

const AUTH_KEY    = 'rl_accounts_v1';
const SESSION_KEY = 'rl_session_v1';
const BOOKS_KEY_PREFIX = 'rl_books_v1_';
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

function normalizeUsername(value) {
  return String(value || '').trim().toLowerCase();
}

function isValidUsername(value) {
  return /^[a-z0-9_-]{2,20}$/.test(value);
}

// ── Auth state ───────────────────────────────────────────────

function hasAuth() {
  return getAccountCount() > 0;
}

function isLoggedIn() {
  return !!getSessionUser();
}

function setSession(username) {
  const session = { id: crypto.randomUUID(), user: normalizeUsername(username) };
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

function clearSession() {
  sessionStorage.removeItem(SESSION_KEY);
}

function getSessionUser() {
  try {
    const raw = JSON.parse(sessionStorage.getItem(SESSION_KEY));
    return raw && raw.user ? normalizeUsername(raw.user) : null;
  } catch {
    return null;
  }
}

function getBooksKeyForUser(username) {
  return `${BOOKS_KEY_PREFIX}${normalizeUsername(username)}`;
}

function normalizeDate(value) {
  const str = String(value || '').trim();
  if (!str) return '';
  return /^\d{4}-\d{2}-\d{2}$/.test(str) ? str : '';
}

function migrateLegacyAuthIfNeeded() {
  const raw = localStorage.getItem(AUTH_KEY);
  if (!raw) return;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return;
  }

  if (parsed && parsed.hash && parsed.salt) {
    const migrated = { users: { owner: { hash: parsed.hash, salt: parsed.salt, createdAt: new Date().toISOString() } } };
    localStorage.setItem(AUTH_KEY, JSON.stringify(migrated));
  }
}

function getAuthStore() {
  migrateLegacyAuthIfNeeded();
  try {
    const parsed = JSON.parse(localStorage.getItem(AUTH_KEY));
    if (parsed && parsed.users && typeof parsed.users === 'object') return parsed;
  } catch {
    // Ignore parse errors and return empty store.
  }
  return { users: {} };
}

function saveAuthStore(store) {
  localStorage.setItem(AUTH_KEY, JSON.stringify(store));
}

function getAccountCount() {
  return Object.keys(getAuthStore().users).length;
}

function getAccountNames() {
  return Object.keys(getAuthStore().users).sort();
}

function getAuthRecord(username) {
  const store = getAuthStore();
  return store.users[normalizeUsername(username)] || null;
}

async function setupPassword(username, password) {
  const normalized = normalizeUsername(username);
  const store = getAuthStore();
  if (store.users[normalized]) return { ok: false, reason: 'exists' };

  const salt = generateSalt();
  const hash = await deriveKey(password, salt);
  store.users[normalized] = {
    hash,
    salt,
    createdAt: new Date().toISOString(),
  };
  saveAuthStore(store);
  setSession(normalized);
  return { ok: true };
}

async function verifyPassword(username, password) {
  const record = getAuthRecord(username);
  if (!record) return false;
  const hash = await deriveKey(password, record.salt);
  return constantTimeEqual(hash, record.hash);
}

// ── Rate limiting ────────────────────────────────────────────

const MAX_ATTEMPTS = 5;
const LOCKOUT_MS   = 30_000;

function getAttemptState() {
  try { return JSON.parse(sessionStorage.getItem(ATTEMPTS_KEY)) || {}; }
  catch { return {}; }
}

function getUserAttemptState(username) {
  const states = getAttemptState();
  const key = normalizeUsername(username);
  return states[key] || { count: 0, lockedUntil: 0 };
}

function recordFailedAttempt(username) {
  const states = getAttemptState();
  const key = normalizeUsername(username);
  const current = states[key] || { count: 0, lockedUntil: 0 };
  current.count += 1;
  if (current.count >= MAX_ATTEMPTS) current.lockedUntil = Date.now() + LOCKOUT_MS;
  states[key] = current;
  sessionStorage.setItem(ATTEMPTS_KEY, JSON.stringify(states));
  return current;
}

function resetAttempts(username) {
  const states = getAttemptState();
  delete states[normalizeUsername(username)];
  sessionStorage.setItem(ATTEMPTS_KEY, JSON.stringify(states));
}

function isLockedOut(username) {
  const s = getUserAttemptState(username);
  if (s.lockedUntil && Date.now() < s.lockedUntil) return s.lockedUntil;
  return false;
}

// ── Books data ───────────────────────────────────────────────

function getBooks() {
  const user = getSessionUser();
  if (!user) return [];
  try { return JSON.parse(localStorage.getItem(getBooksKeyForUser(user))) || []; }
  catch { return []; }
}

function getBooksForUser(username) {
  const normalized = normalizeUsername(username);
  if (!normalized) return [];
  try { return JSON.parse(localStorage.getItem(getBooksKeyForUser(normalized))) || []; }
  catch { return []; }
}

function saveBooks(books) {
  const user = getSessionUser();
  if (!user) return;
  localStorage.setItem(getBooksKeyForUser(user), JSON.stringify(books));
}

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
    lastReadOn: normalizeDate(data.lastReadOn),
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
    lastReadOn: normalizeDate(data.lastReadOn),
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
const authUsersEl   = document.getElementById('auth-users');
const showSetupBtn  = document.getElementById('show-setup-btn');
const backToLoginBtn = document.getElementById('back-to-login-btn');
const bookList      = document.getElementById('book-list');
const emptyState    = document.getElementById('empty-state');
const bookCountEl   = document.getElementById('book-count');
const switchAccountSelect = document.getElementById('switch-account-select');
const switchAccountBtn = document.getElementById('switch-account-btn');
const profilesListEl = document.getElementById('profiles-list');
const profileReadingEl = document.getElementById('profile-reading');
const filterTabs    = document.querySelectorAll('.filter-tab');
const bookModal     = document.getElementById('book-modal');
const bookForm      = document.getElementById('book-form');
const modalTitle    = document.getElementById('modal-title');
const deleteBookBtn = document.getElementById('delete-book-btn');
const starRating    = document.getElementById('star-rating');
const bookRatingInput = document.getElementById('book-rating');

let currentFilter = 'all';
let currentRating = 0;
let selectedProfile = null;

// ── Screen helpers ───────────────────────────────────────────

function showError(el, msg) { el.textContent = msg; el.hidden = false; }
function hideError(el)      { el.hidden = true; el.textContent = ''; }

function showAccountList() {
  const names = getAccountNames();
  if (names.length === 0) {
    authUsersEl.hidden = true;
    authUsersEl.textContent = '';
    return;
  }
  authUsersEl.hidden = false;
  authUsersEl.textContent = `Accounts: ${names.join(', ')}`;
}

function showSetupMode(canGoBack) {
  setupForm.hidden = false;
  loginForm.hidden = true;
  backToLoginBtn.hidden = !canGoBack;
  showAccountList();
}

function showLoginMode() {
  loginForm.hidden = false;
  setupForm.hidden = true;
  showAccountList();
}

function showAuthScreen() {
  authScreen.hidden = false;
  appScreen.hidden  = true;
  hideError(setupError);
  hideError(loginError);
  loginLockout.hidden = true;

  if (!hasAuth()) {
    authSubtitle.textContent = 'Set up your reading log';
    showSetupMode(false);
  } else {
    authSubtitle.textContent = 'Welcome back';
    showLoginMode();
  }
}

function showAppScreen() {
  authScreen.hidden = true;
  appScreen.hidden  = false;
  renderBooks();
  renderProfiles();
  renderSwitchAccountOptions();
}

function renderSwitchAccountOptions() {
  const currentUser = getSessionUser();
  const otherNames = getAccountNames().filter(name => name !== currentUser);

  switchAccountSelect.innerHTML = '';
  const placeholder = document.createElement('option');
  placeholder.value = '';
  placeholder.textContent = otherNames.length === 0 ? 'No other accounts' : 'Choose account';
  switchAccountSelect.appendChild(placeholder);

  otherNames.forEach(name => {
    const option = document.createElement('option');
    option.value = name;
    option.textContent = name;
    switchAccountSelect.appendChild(option);
  });

  if (otherNames.length > 0) {
    switchAccountSelect.value = otherNames[0];
    switchAccountSelect.disabled = false;
    switchAccountBtn.disabled = false;
    switchAccountBtn.textContent = 'Go';
  } else {
    switchAccountSelect.disabled = true;
    switchAccountBtn.disabled = true;
    switchAccountBtn.textContent = 'Go';
  }
}

switchAccountSelect.addEventListener('change', () => {
  switchAccountBtn.disabled = !switchAccountSelect.value;
});

switchAccountBtn.addEventListener('click', () => {
  const nextUser = normalizeUsername(switchAccountSelect.value);
  if (!nextUser) return;

  clearSession();
  showAuthScreen();
  showLoginMode();
  document.getElementById('login-username').value = nextUser;
  document.getElementById('login-password').value = '';
  authSubtitle.textContent = `Switch account: ${nextUser}`;
  document.getElementById('login-password').focus();
});

// ── Auth forms ───────────────────────────────────────────────

setupForm.addEventListener('submit', async e => {
  e.preventDefault();
  hideError(setupError);
  const username = normalizeUsername(document.getElementById('setup-username').value);
  const password = document.getElementById('setup-password').value;
  const confirm  = document.getElementById('setup-confirm').value;

  if (!isValidUsername(username)) {
    showError(setupError, 'Username must be 2-20 chars: letters, numbers, _ or -.');
    return;
  }
  if (password !== confirm) { showError(setupError, 'Passwords do not match.'); return; }
  if (password.length < 8)  { showError(setupError, 'Password must be at least 8 characters.'); return; }

  const btn = setupForm.querySelector('button[type="submit"]');
  btn.disabled    = true;
  btn.textContent = 'Setting up…';
  try {
    const result = await setupPassword(username, password);
    if (!result.ok && result.reason === 'exists') {
      showError(setupError, 'That username already exists. Pick another one.');
      btn.disabled = false;
      btn.textContent = 'Create Password';
      return;
    }
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
  const username = normalizeUsername(document.getElementById('login-username').value);

  if (!isValidUsername(username)) {
    showError(loginError, 'Enter a valid username.');
    return;
  }

  const locked = isLockedOut(username);
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
    const ok = await verifyPassword(username, password);
    if (ok) {
      resetAttempts(username);
      setSession(username);
      showAppScreen();
    } else {
      const state = recordFailedAttempt(username);
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

showSetupBtn.addEventListener('click', () => {
  hideError(loginError);
  showSetupMode(true);
});

backToLoginBtn.addEventListener('click', () => {
  hideError(setupError);
  showLoginMode();
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

    if (book.lastReadOn) {
      const dateEl = document.createElement('div');
      dateEl.className = 'book-card-date';
      dateEl.textContent = `Last read on ${book.lastReadOn}`;
      card.appendChild(dateEl);
    }

    card.addEventListener('click', () => openEditModal(book));
    card.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') openEditModal(book); });
    bookList.appendChild(card);
  });
}

function renderProfiles() {
  const names = getAccountNames();
  const currentUser = getSessionUser();
  const otherNames = names.filter(name => name !== currentUser);
  profilesListEl.innerHTML = '';

  if (names.length === 0) {
    profileReadingEl.hidden = false;
    profileReadingEl.textContent = 'No profiles yet.';
    return;
  }

  if (otherNames.length === 0) {
    profileReadingEl.hidden = false;
    profileReadingEl.innerHTML = '';
    const msg = document.createElement('div');
    msg.className = 'profile-empty';
    msg.textContent = 'No other profiles yet. Create another account to view other readers.';
    profileReadingEl.appendChild(msg);
    return;
  }

  if (!selectedProfile || !otherNames.includes(selectedProfile)) {
    selectedProfile = otherNames[0];
  }

  otherNames.forEach(name => {
    const userBooks = getBooksForUser(name);
    const currentlyReadingCount = userBooks.filter(book => book.status === 'reading').length;

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'profile-pill';
    if (name === selectedProfile) btn.classList.add('active');
    btn.textContent = name;

    const meta = document.createElement('span');
    meta.className = 'profile-pill-meta';
    meta.textContent = `${currentlyReadingCount} currently reading`;
    btn.appendChild(meta);
    btn.addEventListener('click', () => {
      selectedProfile = name;
      renderProfiles();
    });
    profilesListEl.appendChild(btn);
  });

  const readingBooks = getBooksForUser(selectedProfile)
    .filter(book => book.status === 'reading');
  const allBooksCount = getBooksForUser(selectedProfile).length;

  profileReadingEl.hidden = false;
  profileReadingEl.innerHTML = '';

  const header = document.createElement('div');
  header.className = 'profile-reading-header';
  header.textContent = `${selectedProfile} is currently reading`;
  profileReadingEl.appendChild(header);

  if (readingBooks.length === 0) {
    const none = document.createElement('div');
    none.className = 'profile-reading-meta';
    none.textContent = allBooksCount === 0
      ? 'No books added yet for this profile.'
      : 'No books are marked as currently reading for this profile.';
    profileReadingEl.appendChild(none);
    return;
  }

  const list = document.createElement('div');
  list.className = 'profile-reading-list';

  readingBooks.forEach(book => {
    const item = document.createElement('div');
    item.className = 'profile-reading-item';

    const title = document.createElement('div');
    title.className = 'profile-reading-title';
    title.textContent = book.title;

    const meta = document.createElement('div');
    meta.className = 'profile-reading-meta';
    meta.textContent = `by ${book.author}${book.lastReadOn ? ` • last read ${book.lastReadOn}` : ''}`;

    item.append(title, meta);
    list.appendChild(item);
  });

  profileReadingEl.appendChild(list);
}

// ── Modal ────────────────────────────────────────────────────

document.getElementById('add-book-btn').addEventListener('click', openAddModal);
document.getElementById('modal-close').addEventListener('click', closeModal);
document.getElementById('modal-cancel').addEventListener('click', closeModal);

function openAddModal() {
  modalTitle.textContent = 'Add a Book';
  bookForm.reset();
  document.getElementById('book-id').value = '';
  document.getElementById('book-last-read').value = '';
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
  document.getElementById('book-last-read').value = normalizeDate(book.lastReadOn);
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
    lastReadOn: document.getElementById('book-last-read').value,
  };
  if (id) updateBook(id, data); else addBook(data);
  closeModal();
  renderBooks();
  renderProfiles();
});

deleteBookBtn.addEventListener('click', () => {
  const id = document.getElementById('book-id').value;
  if (id && confirm('Delete this book from your log?')) {
    deleteBook(id);
    closeModal();
    renderBooks();
    renderProfiles();
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
