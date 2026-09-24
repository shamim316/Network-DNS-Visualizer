/* app.js — navigation, routing, theming. */
(function () {
  'use strict';
  const DV = (window.DV = window.DV || {});
  DV.sections = DV.sections || [];
  DV.register = (s) => DV.sections.push(s);

  let player = null;

  function theme(t) {
    const root = document.documentElement;
    if (t) root.dataset.theme = t;
    const cur = root.dataset.theme || 'dark';
    const btn = document.querySelector('.theme-btn');
    if (btn) {
      btn.innerHTML = DV.icon(cur === 'dark' ? 'sun' : 'moon');
      btn.title = cur === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
    }
  }

  function renderNav() {
    const nav = document.querySelector('.nav-list');
    nav.innerHTML = DV.sections
      .map((s, i) => `<li><a href="#${s.id}" data-id="${s.id}" title="${i}. ${s.nav || s.title}">${DV.icon(s.icon)}<span class="nav-n">${i}</span><span class="nav-t">${s.nav || s.title}</span></a></li>`)
      .join('');
  }

  function route() {
    const id = (location.hash || '#overview').slice(1);
    const sec = DV.sections.find((s) => s.id === id) || DV.sections[0];
    const index = DV.sections.indexOf(sec);
    document.querySelectorAll('.nav-list a').forEach((a) => {
      const on = a.dataset.id === sec.id;
      a.classList.toggle('active', on);
      if (on) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    });
    if (player) { player.destroy(); player = null; }
    const main = document.querySelector('.content');
    main.innerHTML = '<div class="lesson"></div>';
    const host = main.firstChild;
    host.dataset.section = sec.id;
    if (sec.render) sec.render(host, index);
    else player = new DV.Player(host, sec, index);
    DV.player = player;
    // prev/next section links
    const prev = DV.sections[index - 1], next = DV.sections[index + 1];
    const pager = document.createElement('nav');
    pager.className = 'pager';
    pager.innerHTML = `${prev ? `<a href="#${prev.id}" class="pg prev"><small>← Previous</small><span>${prev.nav || prev.title}</span></a>` : '<span></span>'}
      ${next ? `<a href="#${next.id}" class="pg next"><small>Next →</small><span>${next.nav || next.title}</span></a>` : ''}`;
    host.appendChild(pager);
    document.title = `${sec.nav || sec.title} · DNS Visualizer`;
    document.body.classList.remove('nav-open');
    window.scrollTo(0, 0);
  }

  document.addEventListener('DOMContentLoaded', () => {
    let saved = null;
    try { saved = localStorage.getItem('dnsviz-theme'); } catch (e) { /* storage unavailable */ }
    if (saved) document.documentElement.dataset.theme = saved;
    else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) document.documentElement.dataset.theme = 'light';
    theme();
    document.querySelector('.theme-btn').onclick = () => {
      const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
      theme(next);
      try { localStorage.setItem('dnsviz-theme', next); } catch (e) { /* ignore */ }
    };
    document.querySelector('.menu-btn').innerHTML = DV.icon('menu');
    document.querySelector('.menu-btn').onclick = () => document.body.classList.toggle('nav-open');
    renderNav();
    window.addEventListener('hashchange', route);
    route();
  });
})();
