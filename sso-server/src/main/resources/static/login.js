(() => {
  const form = document.querySelector('.login-form');
  const password = document.querySelector('#password');
  const toggle = document.querySelector('.toggle-password');
  const submit = document.querySelector('.submit-button');
  const caps = document.querySelector('.caps-hint');
  toggle?.addEventListener('click', () => {
    const visible = password.type === 'text';
    password.type = visible ? 'password' : 'text';
    toggle.textContent = visible ? '\u663e\u793a' : '\u9690\u85cf';
    toggle.setAttribute('aria-label', visible ? '\u663e\u793a\u5bc6\u7801' : '\u9690\u85cf\u5bc6\u7801');
  });
  password?.addEventListener('keyup', (event) => { caps.hidden = !event.getModifierState('CapsLock'); });
  form?.addEventListener('submit', () => { submit.disabled = true; submit.querySelector('span').textContent = '\u6b63\u5728\u9a8c\u8bc1?'; });
})();
