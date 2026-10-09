// Shared API helpers for Smart Course Companion
const API = {
  async get(url) {
    const res = await fetch(url);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || 'Request failed');
    }
    return res.json();
  },
  async post(url, data) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || 'Request failed');
    }
    return res.json();
  },
  async put(url, data) {
    const res = await fetch(url, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || 'Request failed');
    }
    return res.json();
  },
  async delete(url) {
    const res = await fetch(url, { method: 'DELETE' });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || 'Request failed');
    }
    return res.json();
  },
  async patch(url, data) {
    const res = await fetch(url, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data || {})
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || 'Request failed');
    }
    return res.json();
  }
};

function showToast(msg, type = 'success') {
  let t = document.getElementById('toast');
  if (!t) {
    t = document.createElement('div');
    t.id = 'toast';
    t.style.cssText = `
      position:fixed;bottom:30px;right:30px;padding:12px 20px;border-radius:8px;
      font-family:inherit;font-size:14px;font-weight:600;z-index:9999;
      transition:opacity 0.3s;pointer-events:none;max-width:320px;
      box-shadow:0 4px 20px rgba(0,0,0,0.3);
    `;
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.style.background = type === 'success' ? 'rgba(30,180,80,0.95)' : 'rgba(200,40,40,0.95)';
  t.style.color = '#fff';
  t.style.opacity = '1';
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.style.opacity = '0'; }, 3000);
}

// Auth guard — call on each protected page
async function guardPage(requiredRole, loginPage) {
  try {
    const data = await API.get('/api/auth/me');
    if (!data.loggedIn || data.role !== requiredRole) {
      window.location.href = loginPage || 'Login_Front_Page.html';
      return null;
    }
    // Show user name if element exists
    const nameEl = document.getElementById('userName');
    if (nameEl) nameEl.textContent = data.name;
    return data;
  } catch {
    window.location.href = loginPage || 'Login_Front_Page.html';
    return null;
  }
}

// Logout handler
function setupLogout() {
  document.querySelectorAll('.logout-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      await API.post('/api/auth/logout', {});
      window.location.href = 'Login_Front_Page.html';
    });
  });
}
