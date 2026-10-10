(() => {
  const byId = (id) => document.getElementById(id);
  const login = byId('login');
  const logout = byId('logout');
  const refresh = byId('refresh');

  async function loadProfile() {
    byId('state-label').textContent = '正在检查登录状态';
    byId('pulse').classList.remove('online');
    try {
      const response = await fetch('/profile', {
        headers: { Accept: 'application/json' },
        credentials: 'same-origin',
        cache: 'no-store'
      });
      if (response.status === 401 || response.status === 403) {
        showGuest();
        return;
      }
      if (!response.ok) throw new Error(`profile request failed (${response.status})`);
      const profile = await response.json();
      byId('state-label').textContent = '已通过 SDK 验证';
      byId('pulse').classList.add('online');
      byId('user-name').textContent = profile.name || profile.username || '已登录用户';
      byId('user-email').textContent = profile.email || '身份已确认';
      byId('user-sub').textContent = profile.subject || '—';
      byId('avatar').textContent = (profile.name || profile.username || 'U').trim().slice(0, 1).toUpperCase();
      login.hidden = true;
      logout.hidden = false;
      byId('logout-note').hidden = false;
    } catch (error) {
      byId('state-label').textContent = '暂时无法连接示例应用';
      byId('user-email').textContent = '请确认本地 RP 服务已启动后刷新页面';
      console.error(error);
    }
  }

  function showGuest() {
    byId('state-label').textContent = '尚未登录';
    byId('pulse').classList.remove('online');
    byId('user-name').textContent = '访客';
    byId('user-email').textContent = '登录后，验证后的身份信息会显示在这里';
    byId('user-sub').textContent = '—';
    byId('avatar').textContent = '?';
    login.hidden = false;
    logout.hidden = true;
    byId('logout-note').hidden = true;
  }

  logout.addEventListener('click', async () => {
    logout.disabled = true;
    logout.textContent = '正在退出…';
    try {
      const response = await fetch('/sso/logout', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          [document.querySelector('meta[name="csrf-header"]').content]:
            document.querySelector('meta[name="csrf-token"]').content
        }
      });
      if (!response.ok) throw new Error(`logout failed (${response.status})`);
      showGuest();
    } catch (error) {
      logout.disabled = false;
      logout.textContent = '退出当前应用';
      console.error(error);
    }
  });
  refresh.addEventListener('click', loadProfile);
  loadProfile();
})();
