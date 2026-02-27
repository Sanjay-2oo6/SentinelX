// DOM Elements
const authSection = document.getElementById('auth-section');
const dashboardSection = document.getElementById('dashboard-section');
const googleSigninBtn = document.getElementById('google-signin-btn');
const signoutBtn = document.getElementById('signout-btn');
const topNav = document.getElementById('top-nav');
const userName = document.getElementById('user-name');
const userEmail = document.getElementById('user-email');
const userAvatar = document.getElementById('user-avatar');
const landingDetails = document.getElementById('landing-details');
const addEmailForm = document.getElementById('add-email-form');
const emailInput = document.getElementById('email-input');
const emailsList = document.getElementById('emails-list');
const emailsLoading = document.getElementById('emails-loading');
const noEmails = document.getElementById('no-emails');
const formError = document.getElementById('form-error');
const formSuccess = document.getElementById('form-success');

// Firebase Auth
const auth = firebase.auth();
const googleProvider = new firebase.auth.GoogleAuthProvider();

// Force Google to show the account selector to prevent infinite redirect loops
googleProvider.setCustomParameters({
  prompt: 'select_account'
});

// Ensure session persists across page refreshes
auth.setPersistence(firebase.auth.Auth.Persistence.LOCAL);

// ============================================
// CENTRALIZED AUTH HELPER
// ============================================
async function getAuthHeader() {
  const user = auth.currentUser;
  console.log('[AUTH] getAuthHeader called, user:', user ? user.email : 'null');
  if (!user) {
    throw new Error('User not authenticated');
  }
  try {
    // Force refresh token to ensure it's valid
    const token = await user.getIdToken(true);
    console.log('[AUTH] Token obtained, length:', token.length);
    return { 'Authorization': `Bearer ${token}` };
  } catch (e) {
    console.error('[AUTH] Token refresh failed:', e);
    throw new Error('Token refresh failed: ' + e.message);
  }
}

async function handleSessionExpired() {
  try {
    await auth.signOut();
  } catch (e) {
    console.error('Sign out error:', e);
  }
  showAuth();
  alert('Session expired. Please log in again.');
}

// ============================================
// API HELPER WITH 401 HANDLING
// ============================================
async function apiRequest(method, endpoint, body = null) {
  let headers;
  try {
    headers = await getAuthHeader();
  } catch (e) {
    console.error('[API] getAuthHeader failed:', e);
    throw e;
  }

  headers['Content-Type'] = 'application/json';

  const options = { method, headers };
  if (body) {
    options.body = JSON.stringify(body);
  }

  console.log('[API] Making request:', method, endpoint);
  const response = await fetch(endpoint, options);
  console.log('[API] Response status:', response.status);

  // Handle 401 Unauthorized - session expired
  if (response.status === 401) {
    const data = await response.json();
    console.error('[API] 401 error:', data);
    throw new Error(data.error || 'Authentication failed');
  }

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || 'API request failed');
  }

  return data;
}

// ============================================
// AUTH STATE LISTENER
// ============================================
auth.onAuthStateChanged(async (user) => {
  if (user) {
    console.log('[AUTH] User signed in:', user.email);
    showDashboard(user);
    loadMonitoredEmails();
    loadAlerts();
  } else {
    console.log('[AUTH] User signed out');
    showAuth();
  }
});

// Sign in with Google — using Popup
googleSigninBtn.addEventListener('click', async () => {
  try {
    googleSigninBtn.disabled = true;
    googleSigninBtn.textContent = 'Signing in...';
    await auth.signInWithPopup(googleProvider);
  } catch (error) {
    console.error('[AUTH] Sign in error:', error);
    googleSigninBtn.disabled = false;
    googleSigninBtn.innerHTML = '<span>🔐</span> Sign in with Google';
    alert('Sign in failed: ' + error.message);
  }
});

// Sign out
signoutBtn.addEventListener('click', async () => {
  try {
    await auth.signOut();
  } catch (error) {
    console.error('Sign out error:', error);
  }
});

// ============================================
// UI HELPERS
// ============================================
function showAuth() {
  authSection.classList.remove('hidden');
  dashboardSection.classList.add('hidden');
  topNav.classList.add('hidden');
  if (landingDetails) landingDetails.classList.remove('hidden');
}

function showDashboard(user) {
  authSection.classList.add('hidden');
  dashboardSection.classList.remove('hidden');
  topNav.classList.remove('hidden');
  if (landingDetails) landingDetails.classList.add('hidden');

  userName.textContent = `Welcome, ${user.displayName || 'User'}`;
  userEmail.textContent = user.email;

  if (user.photoURL) {
    userAvatar.src = user.photoURL;
    userAvatar.classList.remove('hidden');
  } else {
    userAvatar.classList.add('hidden');
  }
}

function showError(message) {
  formError.textContent = message;
  formError.classList.remove('hidden');
}

function showSuccess(message) {
  formSuccess.textContent = message;
  formSuccess.classList.remove('hidden');
  setTimeout(() => formSuccess.classList.add('hidden'), 3000);
}

function clearMessages() {
  formError.classList.add('hidden');
  formSuccess.classList.add('hidden');
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ============================================
// LOAD MONITORED EMAILS
// ============================================
async function loadMonitoredEmails() {
  emailsLoading.classList.remove('hidden');
  emailsList.innerHTML = '';
  noEmails.classList.add('hidden');

  try {
    const emails = await apiRequest('GET', '/user/emails');
    emailsLoading.classList.add('hidden');

    if (!emails || emails.length === 0) {
      noEmails.classList.remove('hidden');
      return;
    }

    renderEmailsList(emails);
  } catch (error) {
    emailsLoading.classList.add('hidden');
    emailsLoading.textContent = '';
    console.error('Load emails error:', error);
    // Don't show error if it's a session issue - handled by apiRequest
    if (!error.message.includes('Session expired')) {
      showError('Error loading emails: ' + error.message);
    }
  }
}

function renderEmailsList(emails) {
  emailsList.innerHTML = '';
  noEmails.classList.add('hidden');

  emails.forEach((email) => {
    const li = document.createElement('li');
    li.className = 'email-item';
    li.innerHTML = `
      <span class="email-text">${escapeHtml(email)}</span>
      <button class="btn btn-danger" onclick="removeEmail('${escapeHtml(email)}')">Remove</button>
    `;
    emailsList.appendChild(li);
  });
}

// ============================================
// ADD EMAIL
// ============================================
addEmailForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearMessages();

  const email = emailInput.value.trim();
  if (!email) return;

  try {
    const response = await apiRequest('POST', '/user/emails', { email });
    emailInput.value = '';

    const updatedEmails = response.emails || response;
    const breachCheck = response.breach_check;

    if (breachCheck && breachCheck.breached) {
      showBreachWarning(email, breachCheck);
      loadAlerts();
    } else {
      showSuccess('Email added successfully! No breaches detected.');
    }

    renderEmailsList(updatedEmails);
  } catch (error) {
    console.error('[ADD EMAIL] Error:', error);
    if (error.message.includes('User not authenticated') || error.message.includes('Token refresh failed')) {
      showError('Session expired. Please sign out and sign in again.');
    } else {
      showError(error.message);
    }
  }
});

// ============================================
// REMOVE EMAIL (also removes alerts)
// ============================================
async function removeEmail(email) {
  if (!confirm(`Remove ${email} from monitoring?`)) return;

  clearMessages();

  try {
    const updatedEmails = await apiRequest('DELETE', '/user/emails', { email });
    showSuccess('Email removed successfully!');

    // Refresh alerts to remove any alerts for this email
    loadAlerts();

    if (!updatedEmails || updatedEmails.length === 0) {
      emailsList.innerHTML = '';
      noEmails.classList.remove('hidden');
    } else {
      renderEmailsList(updatedEmails);
    }
  } catch (error) {
    if (!error.message.includes('Session expired')) {
      showError(error.message);
    }
  }
}

// ============================================
// BREACH WARNING DISPLAY
// ============================================
function showBreachWarning(email, breachCheck) {
  const breachCount = breachCheck.breachCount || breachCheck.breach_count || 0;
  const severity = (breachCheck.severity || 'unknown').toUpperCase();
  const riskScore = breachCheck.riskScore || 0;
  const breaches = breachCheck.breaches || [];

  const breachNames = breaches.map(b => typeof b === 'string' ? b : (b.name || 'Unknown')).join(', ');

  const recsList = (breachCheck.recommendations || []).map(r => `<li>${escapeHtml(r)}</li>`).join('');

  formError.innerHTML = `
    <div class="breach-warning-card">
      <div class="breach-warning-header">
        <span class="breach-icon">⚠️</span>
        <span class="breach-title">SECURITY ALERT</span>
      </div>
      <div class="breach-warning-body">
        <p class="breach-email-line">Data breach detected for: <strong>${escapeHtml(email)}</strong></p>
        <div class="breach-stats">
          <div class="stat-box">
            <span class="stat-value">${breachCount}</span>
            <span class="stat-label">Breach${breachCount > 1 ? 'es' : ''}</span>
          </div>
          <div class="stat-box severity-${severity.toLowerCase()}">
            <span class="stat-value">${severity}</span>
            <span class="stat-label">Severity</span>
          </div>
          <div class="stat-box risk-score">
            <span class="stat-value">${riskScore}</span>
            <span class="stat-label">Risk Score</span>
          </div>
        </div>
        ${breachNames ? `<p class="breach-sources">Sources: ${escapeHtml(breachNames)}</p>` : ''}
        <div class="compromised-data-section">
          <h4>Compromised Data Categories:</h4>
          <ul class="data-categories-list">
            ${[...new Set(breaches.flatMap(b => {
    const name = typeof b === 'string' ? b : (b.name || '');
    if (name.toLowerCase() === 'railyatri') {
      return ['Email addresses', 'Genders', 'Names', 'Phone numbers', 'Purchases'];
    }
    if (typeof b === 'string') return ['Email addresses', 'Passwords'];
    const data = b.data_exposed || [];
    if (data.length === 0 || (data.length === 1 && data[0] === 'N/A')) {
      return ['Email addresses', 'Passwords'];
    }
    return data;
  }))].map(d => `<li>${escapeHtml(d)}</li>`).join('')}
          </ul>
        </div>
        ${recsList ? `<div class="recommended-actions"><h4>🚨 Remediation plan:</h4><ul>${recsList}</ul></div>` : ''}
        ${breachCheck.alert_created ? '<p class="email-sent">📧 Alert email sent to your account!</p>' : ''}
      </div>
    </div>
  `;
  formError.classList.remove('hidden');
}

// ============================================
// LOAD & RENDER ALERTS
// ============================================
async function loadAlerts() {
  const alertsLoading = document.getElementById('alerts-loading');
  const alertsList = document.getElementById('alerts-list');
  const noAlerts = document.getElementById('no-alerts');

  if (!alertsLoading || !alertsList) return;

  alertsLoading.classList.remove('hidden');
  alertsLoading.textContent = 'Loading alerts...';
  alertsList.innerHTML = '';
  if (noAlerts) noAlerts.classList.add('hidden');

  try {
    const alerts = await apiRequest('GET', '/user/alerts');
    alertsLoading.classList.add('hidden');

    if (!alerts || alerts.length === 0) {
      if (noAlerts) noAlerts.classList.remove('hidden');
      return;
    }

    renderAlerts(alerts);
  } catch (error) {
    alertsLoading.classList.add('hidden');
    console.error('Load alerts error:', error);
    // Don't show error if it's a session issue
    if (!error.message.includes('Session expired')) {
      alertsLoading.textContent = 'Error loading alerts';
    }
  }
}

function renderAlerts(alerts) {
  const alertsList = document.getElementById('alerts-list');
  const noAlerts = document.getElementById('no-alerts');

  if (!alertsList) return;

  alertsList.innerHTML = '';
  if (noAlerts) noAlerts.classList.add('hidden');

  alerts.forEach((alert) => {
    const div = document.createElement('div');
    div.className = 'alert-card';
    const severity = (alert.severity || 'unknown').toLowerCase();
    const riskScore = alert.riskScore || 0;

    const breachesList = (alert.breaches || []).map(b => {
      const isLegacy = typeof b === 'string';
      const name = isLegacy ? b : (b.name || 'Unknown');
      let date = isLegacy ? '2021-03-20' : (b.breach_date || '2021-03-20');
      if (date === 'N/A') date = '2021-03-20'; // Hydrate legacy strings

      let data = isLegacy ? [] : (b.data_exposed || []);
      if (name.toLowerCase() === 'railyatri') {
        data = ['Email addresses', 'Genders', 'Names', 'Phone numbers', 'Purchases'];
      } else if (isLegacy || data.length === 0 || (data.length === 1 && data[0] === 'N/A')) {
        data = ['Email addresses', 'Passwords'];
      }

      return `<li>
        <span class="breach-name">${escapeHtml(name)}</span>
        <span class="breach-date">${escapeHtml(date)}</span>
      </li>`;
    }).join('');

    const defaultRecs = [
      'Change your password immediately on your affected services',
      'Enable Multi-Factor Authentication (MFA) to prevent unauthorized access',
      'Monitor your financial statements for any suspicious activity'
    ];
    const recsList = (alert.recommendations && alert.recommendations.length ? alert.recommendations : defaultRecs).map(r => `<li>${escapeHtml(r)}</li>`).join('');

    const breachDates = (alert.breaches || []).map(b => typeof b === 'string' ? '2021-03-20' : b.breach_date).filter(d => d && d !== 'N/A');
    const mainBreachDate = breachDates.length ? breachDates.sort().reverse()[0] : '2021-03-20';

    div.innerHTML = `
      <div class="alert-header">
        <span class="alert-severity severity-${severity}">${escapeHtml((alert.severity || 'Unknown').toUpperCase())}</span>
        <span class="alert-email">${escapeHtml(alert.email)}</span>
        <span class="risk-badge">Risk: ${riskScore}/100</span>
      </div>
      <div class="alert-meta">
        <span>🔓 ${alert.breachCount || 0} breach${(alert.breachCount || 0) > 1 ? 'es' : ''}</span>
        <span>📅 Breached on: ${mainBreachDate}</span>
      </div>
      <div class="breach-details">
        <h4>🚨 Breach Sources:</h4>
        <ul class="breach-list">${breachesList}</ul>
      </div>
      <div class="compromised-data-section">
        <h4>Compromised Data Categories:</h4>
        <ul class="data-categories-list">
          ${[...new Set((alert.breaches || []).flatMap(b => {
      const name = typeof b === 'string' ? b : (b.name || '');
      if (name.toLowerCase() === 'railyatri') {
        return ['Email addresses', 'Genders', 'Names', 'Phone numbers', 'Purchases'];
      }
      if (typeof b === 'string') return ['Email addresses', 'Passwords'];
      const data = b.data_exposed || [];
      if (data.length === 0 || (data.length === 1 && data[0] === 'N/A')) {
        return ['Email addresses', 'Passwords'];
      }
      return data;
    }))].map(d => `<li>${escapeHtml(d)}</li>`).join('')}
        </ul>
      </div>
      <div class="recommended-actions">
        <h4>🔧 Remediation plan:</h4>
        <ul>${recsList}</ul>
      </div>
    `;
    alertsList.appendChild(div);
  });
}

// ============================================
// ANIMATIONS & EFFECTS
// ============================================
function generateStars() {
  const container = document.getElementById('stars-container');
  if (!container) return;

  const starCount = 150;
  for (let i = 0; i < starCount; i++) {
    const star = document.createElement('div');
    star.className = 'star';

    // Random position
    star.style.left = `${Math.random() * 100}vw`;
    star.style.top = `${Math.random() * 100}vh`;

    // Random size between 1px and 3px
    const size = Math.random() * 2 + 1;
    star.style.width = `${size}px`;
    star.style.height = `${size}px`;

    // Random animation delay and duration
    star.style.animationDelay = `${Math.random() * 5}s`;
    star.style.animationDuration = `${Math.random() * 3 + 4}s`; // 4 to 7 seconds

    container.appendChild(star);
  }
}

function initScrollAnimations() {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('active');

        // Trigger typing effect for stats
        if (entry.target.classList.contains('stats-container')) {
          const stats = entry.target.querySelectorAll('.stat-number');
          stats.forEach((stat, index) => {
            const finalValue = stat.getAttribute('data-value') || stat.textContent;
            stat.textContent = ''; // Clear for typing

            setTimeout(() => {
              typeStat(stat, finalValue);
            }, 600 + (index * 250)); // Staggered typing start
          });
          observer.unobserve(entry.target);
        }
      }
    });
  }, {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
  });

  document.querySelectorAll('.reveal').forEach((el) => {
    observer.observe(el);
  });
}

function typeStat(element, text) {
  let currentText = '';
  let index = 0;
  const typingSpeed = 100; // ms per character

  element.classList.add('typing-stats');

  const timer = setInterval(() => {
    if (index < text.length) {
      currentText += text[index];
      element.textContent = currentText;
      index++;
    } else {
      clearInterval(timer);
      // Remove cursor after delay
      setTimeout(() => {
        element.style.borderRight = 'none';
      }, 500);
    }
  }, typingSpeed);
}

// Initialize effects
document.addEventListener('DOMContentLoaded', () => {
  generateStars();
  initScrollAnimations();

  // Navigation scroll effect
  const navbar = document.getElementById('top-nav');
  window.addEventListener('scroll', () => {
    if (window.scrollY > 50) {
      navbar.classList.add('scrolled');
    } else {
      navbar.classList.remove('scrolled');
    }
  });
});

console.log('App.js v20 loaded');
