/*
 * engine.js — the lesson player.
 *
 * A lesson (section) provides build(opts) → scene:
 *   { nodes:[{id,x,y,icon,tier,label,sub,hidden,cacheAt}], links:[[a,b]], groups:[{x,y,w,h,label}],
 *     hud:'lookup'|'clock'|'both', panel:{title,html}, setup:[actions], intro:'html', steps:[step] }
 * step: { title, text, deep, focus:[ids], actions:[action] }
 *
 * Actions are declarative so that any step can be reached by instantly replaying
 * the earlier steps and then animating the chosen one.
 */
(function () {
  'use strict';
  const DV = (window.DV = window.DV || {});
  const W = 1000, H = 560;
  const ABORT = { abort: true };
  const NS = 'http://www.w3.org/2000/svg';
  const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  DV.esc = esc;
  const svg = (tag, attrs) => {
    const el = document.createElementNS(NS, tag);
    for (const k in attrs || {}) el.setAttribute(k, attrs[k]);
    return el;
  };
  const ease = (t) => (t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2);
  const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function fmtClock(ms) {
    const s = ms / 1000;
    if (s < 10) return s.toFixed(3) + ' s';
    const m = Math.floor(s / 60), r = Math.floor(s % 60);
    const hh = Math.floor(m / 60);
    return hh ? `${hh}h ${String(m % 60).padStart(2, '0')}m ${String(r).padStart(2, '0')}s` : `${m}m ${String(r).padStart(2, '0')}s`;
  }
  function fmtTTL(s) {
    if (s <= 0) return 'expired';
    if (s < 120) return s + 's';
    if (s < 7200) return Math.floor(s / 60) + 'm ' + (s % 60 ? (s % 60) + 's' : '');
    if (s < 172800) return Math.floor(s / 3600) + 'h ' + (Math.floor(s / 60) % 60 ? (Math.floor(s / 60) % 60) + 'm' : '');
    return Math.floor(s / 86400) + 'd';
  }

  class Player {
    constructor(host, section, index) {
      this.host = host;
      this.sec = section;
      this.index = index;
      this.opts = {};
      (section.options || []).forEach((o) => (this.opts[o.id] = o.value));
      this.speed = 1;
      this.idx = -1;
      this.playing = false;
      this.animating = false;
      this.token = 0;
      this.follow = true;
      this.raf = new Set();
      this.renderShell();
      this.rebuild();
      this.onKey = (e) => {
        if (/input|select|textarea/i.test(e.target.tagName) || e.metaKey || e.ctrlKey || e.altKey) return;
        if (e.key === ' ' || e.key === 'k') { e.preventDefault(); this.toggle(); }
        else if (e.key === 'ArrowRight' || e.key === 'l') { e.preventDefault(); this.next(); }
        else if (e.key === 'ArrowLeft' || e.key === 'j') { e.preventDefault(); this.prev(); }
        else if (e.key === 'r') this.reset();
      };
      document.addEventListener('keydown', this.onKey);
    }

    destroy() {
      this.token++;
      this.playing = false;
      clearTimeout(this.dwellTimer);
      this.raf.forEach((id) => cancelAnimationFrame(id));
      document.removeEventListener('keydown', this.onKey);
    }

    /* ------------------------------------------------------------ shell */
    renderShell() {
      const s = this.sec;
      this.host.innerHTML = `
        <header class="lesson-head">
          <div class="eyebrow">${DV.icon(s.icon)} Section ${this.index}</div>
          <h1>${s.title}</h1>
          <div class="lead">${s.intro || ''}</div>
        </header>
        <div class="scenario card" ${s.options && s.options.length ? '' : 'hidden'}>
          <div class="scenario-label">Scenario</div>
          <div class="opt-row"></div>
        </div>
        <div class="workspace">
          <div class="main-col">
            <div class="card stage-card">
              <div class="stage-scroll"><div class="stage">
                <svg class="layer-links" viewBox="0 0 ${W} ${H}"></svg>
                <div class="layer-nodes"></div>
                <svg class="layer-pkts" viewBox="0 0 ${W} ${H}"><g class="trails"></g><g class="pkts"></g></svg>
                <div class="layer-over"></div>
                <div class="hud"></div>
              </div></div>
              <div class="controls">
                <button class="btn icon-btn" data-act="reset" title="Restart (R)" aria-label="Restart">${DV.icon('restart')}</button>
                <button class="btn icon-btn" data-act="prev" title="Previous step (←)" aria-label="Previous step">${DV.icon('prev')}</button>
                <button class="btn play-btn" data-act="play" title="Play / pause (Space)" aria-label="Play">${DV.icon('play')}<span>Play</span></button>
                <button class="btn icon-btn" data-act="next" title="Next step (→)" aria-label="Next step">${DV.icon('next')}</button>
                <div class="progress" title="Step progress"><div class="bar"></div></div>
                <span class="stepnum mono">0 / 0</span>
                <label class="speed">Speed
                  <select data-act="speed" aria-label="Animation speed">
                    <option value="0.5">0.5×</option><option value="0.75">0.75×</option><option value="1" selected>1×</option>
                    <option value="1.5">1.5×</option><option value="2">2×</option>
                  </select>
                </label>
              </div>
            </div>
            <div class="card narration" aria-live="polite">
              <div class="n-meta"></div>
              <h2 class="n-title"></h2>
              <div class="n-text"></div>
              <details class="n-deep"><summary>Under the hood</summary><div class="n-deep-body"></div></details>
            </div>
          </div>
          <aside class="side-col">
            <div class="card panel" hidden>
              <div class="panel-head"><span class="panel-title"></span></div>
              <div class="panel-body"></div>
            </div>
            <div class="card tabs">
              <div class="tabbar" role="tablist">
                <button class="tab-btn active" data-tab="pk" role="tab">Packets <span class="pk-count">0</span></button>
                <button class="tab-btn" data-tab="st" role="tab">Steps</button>
              </div>
              <div class="tab tab-pk">
                <div class="plog" role="listbox" aria-label="Packet log"><div class="empty">Packets appear here as they are sent. Click one, or a packet in flight, to inspect it.</div></div>
                <label class="follow"><input type="checkbox" checked> Follow the latest packet</label>
                <div class="inspector"><div class="empty">No packet selected.</div></div>
              </div>
              <div class="tab tab-st" hidden><ol class="steplist"></ol></div>
            </div>
          </aside>
        </div>
        ${s.footer ? `<div class="card lesson-foot">${s.footer}</div>` : ''}`;

      const q = (sel) => this.host.querySelector(sel);
      this.el = {
        optRow: q('.opt-row'), stage: q('.stage'), links: q('.layer-links'), nodes: q('.layer-nodes'),
        pkts: q('.layer-pkts .pkts'), trails: q('.layer-pkts .trails'), over: q('.layer-over'), hud: q('.hud'),
        play: q('[data-act=play]'), bar: q('.progress .bar'), stepnum: q('.stepnum'),
        nMeta: q('.n-meta'), nTitle: q('.n-title'), nText: q('.n-text'), nDeep: q('.n-deep'), nDeepBody: q('.n-deep-body'),
        panel: q('.panel'), panelTitle: q('.panel-title'), panelBody: q('.panel-body'),
        plog: q('.plog'), pkCount: q('.pk-count'), insp: q('.inspector'), follow: q('.follow input'), steplist: q('.steplist'),
      };
      q('[data-act=reset]').onclick = () => this.reset();
      q('[data-act=prev]').onclick = () => this.prev();
      q('[data-act=next]').onclick = () => this.next();
      this.el.play.onclick = () => this.toggle();
      q('[data-act=speed]').onchange = (e) => (this.speed = +e.target.value);
      this.el.follow.onchange = (e) => (this.follow = e.target.checked);
      this.host.querySelectorAll('.tab-btn').forEach((b) => {
        b.onclick = () => this.showTab(b.dataset.tab);
      });
      this.el.progress = q('.progress');
      this.el.progress.onclick = (e) => {
        const r = this.el.progress.getBoundingClientRect();
        const n = this.scene.steps.length;
        this.goto(Math.min(n - 1, Math.floor(((e.clientX - r.left) / r.width) * n)));
      };
      this.renderOptions();
    }

    showTab(t) {
      this.host.querySelectorAll('.tab-btn').forEach((b) => b.classList.toggle('active', b.dataset.tab === t));
      this.host.querySelector('.tab-pk').hidden = t !== 'pk';
      this.host.querySelector('.tab-st').hidden = t !== 'st';
    }

    renderOptions() {
      const row = this.el.optRow;
      row.innerHTML = '';
      for (const o of this.sec.options || []) {
        if (o.visibleIf && !o.visibleIf(this.opts)) continue;
        const wrap = document.createElement('label');
        wrap.className = 'opt opt-' + o.type;
        if (o.type === 'select') {
          wrap.innerHTML = `<span>${o.label}</span><select>${o.choices
            .map(([v, t]) => `<option value="${esc(v)}" ${v === this.opts[o.id] ? 'selected' : ''}>${esc(t)}</option>`)
            .join('')}</select>`;
          wrap.querySelector('select').onchange = (e) => this.setOpt(o.id, e.target.value);
        } else if (o.type === 'check') {
          wrap.innerHTML = `<input type="checkbox" ${this.opts[o.id] ? 'checked' : ''}><span>${o.label}</span>`;
          wrap.querySelector('input').onchange = (e) => this.setOpt(o.id, e.target.checked);
        } else if (o.type === 'segmented') {
          wrap.innerHTML = `<span>${o.label}</span><div class="seg" role="radiogroup">${o.choices
            .map(([v, t]) => `<button type="button" role="radio" aria-checked="${v === this.opts[o.id]}" data-v="${esc(v)}" class="${v === this.opts[o.id] ? 'on' : ''}">${esc(t)}</button>`)
            .join('')}</div>`;
          wrap.querySelectorAll('button').forEach((b) => (b.onclick = (e) => { e.preventDefault(); this.setOpt(o.id, b.dataset.v); }));
        } else if (o.type === 'text') {
          wrap.innerHTML = `<span>${o.label}</span><input type="text" spellcheck="false" autocomplete="off" value="${esc(this.opts[o.id])}" placeholder="${esc(o.placeholder || '')}"><em class="opt-err"></em>`;
          const inp = wrap.querySelector('input');
          const apply = () => {
            const v = inp.value.trim().toLowerCase();
            const err = o.validate ? o.validate(v) : null;
            wrap.querySelector('.opt-err').textContent = err || '';
            inp.classList.toggle('bad', !!err);
            if (!err && v !== this.opts[o.id]) this.setOpt(o.id, v);
          };
          inp.onkeydown = (e) => { if (e.key === 'Enter') apply(); };
          inp.onblur = apply;
        }
        if (o.help) wrap.title = o.help;
        row.appendChild(wrap);
      }
    }

    setOpt(id, v) {
      this.opts[id] = v;
      this.renderOptions();
      this.rebuild();
    }

    /* ------------------------------------------------------------ scene */
    rebuild() {
      this.pause();
      this.token++;
      DV.dns.seed(DV.dns.hashStr(this.sec.id + JSON.stringify(this.opts)) & 0x7fffffff);
      this.scene = this.sec.build(this.opts, this);
      this.renderScene();
      this.reset();
    }

    renderScene() {
      const sc = this.scene;
      this.nodes = {};
      sc.nodes.forEach((n) => (this.nodes[n.id] = n));
      // links & groups
      const L = this.el.links;
      L.innerHTML = '';
      for (const g of sc.groups || []) {
        L.appendChild(svg('rect', { x: g.x, y: g.y, width: g.w, height: g.h, rx: 18, class: 'group ' + (g.cls || '') }));
        const t = svg('text', { x: g.x + 14, y: g.y + 22, class: 'group-label' });
        t.textContent = g.label;
        L.appendChild(t);
      }
      for (const [a, b, cls] of sc.links || []) {
        const A = this.nodes[a], B = this.nodes[b];
        if (!A || !B) continue;
        L.appendChild(svg('line', { x1: A.x, y1: A.y, x2: B.x, y2: B.y, class: 'base-link ' + (cls || ''), 'data-a': a, 'data-b': b }));
      }
      this.el.conns = svg('g', { class: 'conns' });
      L.appendChild(this.el.conns);
      // nodes
      const N = this.el.nodes;
      N.innerHTML = '';
      this.nodeEls = {};
      for (const n of sc.nodes) {
        const d = document.createElement('div');
        d.className = `node tier-${n.tier || 'neutral'} ${n.size ? 'size-' + n.size : ''}`;
        d.style.left = (n.x / W) * 100 + '%';
        d.style.top = (n.y / H) * 100 + '%';
        d.dataset.id = n.id;
        d.innerHTML = `
          <div class="node-badge"></div>
          <div class="node-icon">${DV.icon(n.icon)}</div>
          <div class="node-label">${n.label}</div>
          ${n.sub ? `<div class="node-sub">${n.sub}</div>` : ''}
          <div class="node-cache cache-${n.cacheAt || 'below'}"></div>`;
        N.appendChild(d);
        this.nodeEls[n.id] = d;
      }
      // panel
      if (sc.panel) {
        this.el.panel.hidden = false;
        this.el.panelTitle.innerHTML = sc.panel.title;
      } else this.el.panel.hidden = true;
      // steps list
      this.el.steplist.innerHTML = sc.steps
        .map((s, i) => `<li><button data-i="${i}"><span class="sl-n">${i + 1}</span><span>${s.title}</span></button></li>`)
        .join('');
      this.el.steplist.querySelectorAll('button').forEach((b) => (b.onclick = () => { this.pause(); this.goto(+b.dataset.i); }));
    }

    resetState() {
      clearTimeout(this.dwellTimer);
      this.raf.forEach((id) => cancelAnimationFrame(id));
      this.raf.clear();
      this.el.pkts.innerHTML = '';
      this.el.trails.innerHTML = '';
      this.el.over.innerHTML = '';
      this.el.conns.innerHTML = '';
      this.overlays = {};
      this.conns = {};
      this.caches = {};
      this.time = 0;
      this.lookup = 0;
      this.log = [];
      this.selected = null;
      this.pendingSel = null;
      this.curStep = -1;
      for (const n of this.scene.nodes) {
        const d = this.nodeEls[n.id];
        d.className = `node tier-${n.tier || 'neutral'} ${n.size ? 'size-' + n.size : ''} ${n.hidden ? 'hidden' : ''} ${n.cls || ''}`;
        d.querySelector('.node-badge').className = 'node-badge';
        d.querySelector('.node-badge').textContent = '';
        d.querySelector('.node-cache').innerHTML = '';
      }
      this.el.links.querySelectorAll('.base-link').forEach((l) => {
        const hid = (this.nodes[l.dataset.a] || {}).hidden || (this.nodes[l.dataset.b] || {}).hidden;
        l.classList.toggle('hidden', !!hid);
      });
      if (this.scene.panel) this.el.panelBody.innerHTML = this.scene.panel.html;
      this.el.plog.innerHTML = '<div class="empty">Packets appear here as they are sent. Click one, or a packet in flight, to inspect it.</div>';
      this.el.pkCount.textContent = '0';
      this.el.insp.innerHTML = '<div class="empty">No packet selected.</div>';
      for (const a of this.scene.setup || []) this.execSync(a);
      this.renderHud();
    }

    /* ------------------------------------------------------------ transport controls */
    reset() {
      this.pause();
      this.token++;
      this.animating = false;
      this.resetState();
      this.idx = -1;
      this.updateUI();
    }
    next() {
      if (this.idx < this.scene.steps.length - 1) this.goto(this.idx + 1);
    }
    prev() {
      this.pause();
      if (this.idx > 0) this.goto(this.idx - 1);
      else this.reset();
    }
    toggle() {
      this.playing ? this.pause() : this.play();
    }
    play() {
      this.playing = true;
      this.updatePlayBtn();
      if (this.idx >= this.scene.steps.length - 1) this.goto(0);
      else if (!this.animating) this.goto(this.idx + 1);
    }
    pause() {
      this.playing = false;
      clearTimeout(this.dwellTimer);
      this.updatePlayBtn();
    }
    updatePlayBtn() {
      if (!this.el) return;
      this.el.play.innerHTML = this.playing ? `${DV.icon('pause')}<span>Pause</span>` : `${DV.icon('play')}<span>${this.idx >= this.scene?.steps.length - 1 ? 'Replay' : 'Play'}</span>`;
      this.el.play.setAttribute('aria-label', this.playing ? 'Pause' : 'Play');
    }

    async goto(n) {
      const steps = this.scene.steps;
      n = Math.max(0, Math.min(steps.length - 1, n));
      const tok = ++this.token;
      this.resetState();
      this.animating = true;
      try {
        for (let i = 0; i < n; i++) await this.runStep(i, tok, true);
        if (this.pendingSel) { this.select(this.pendingSel); this.pendingSel = null; }
        this.idx = n;
        this.updateUI();
        await this.runStep(n, tok, false);
      } catch (e) {
        if (e !== ABORT) throw e;
        return;
      }
      if (tok !== this.token) return;
      this.animating = false;
      this.updateFocus(steps[n], true);
      if (this.playing) {
        if (n < steps.length - 1) {
          const len = (steps[n].text || '').replace(/<[^>]+>/g, '').length;
          const dwell = Math.min(7000, 1400 + len * 15) / this.speed;
          this.dwellTimer = setTimeout(() => {
            if (tok === this.token && this.playing) this.goto(n + 1);
          }, dwell);
        } else {
          this.playing = false;
        }
      }
      this.updatePlayBtn();
    }

    async runStep(i, tok, instant) {
      const st = this.scene.steps[i];
      this.curStep = i;
      // step-scoped visuals are cleared at each step start
      for (const id in this.nodeEls) {
        const b = this.nodeEls[id].querySelector('.node-badge');
        if (!b.dataset.sticky) { b.className = 'node-badge'; b.textContent = ''; }
      }
      for (const id in this.overlays) if (!this.overlays[id].keep) this.removeOverlay(id);
      this.updateFocus(st);
      for (const a of st.actions || []) {
        await this.exec(a, tok, instant);
        if (tok !== this.token) throw ABORT;
      }
    }

    updateFocus(st) {
      const f = new Set(st ? st.focus || [] : []);
      for (const id in this.nodeEls) this.nodeEls[id].classList.toggle('active', f.has(id));
    }

    updateUI() {
      const steps = this.scene.steps;
      const i = this.idx;
      this.el.stepnum.textContent = `${Math.max(0, i + 1)} / ${steps.length}`;
      this.el.bar.style.width = ((i + 1) / steps.length) * 100 + '%';
      this.el.steplist.querySelectorAll('li').forEach((li, k) => {
        li.classList.toggle('current', k === i);
        li.classList.toggle('done', k < i);
      });
      const cur = this.el.steplist.querySelector('li.current');
      if (cur && !this.host.querySelector('.tab-st').hidden) cur.scrollIntoView({ block: 'nearest' });
      if (i < 0) {
        this.el.nMeta.textContent = 'Ready';
        this.el.nTitle.textContent = this.scene.introTitle || 'Press Play, or step through with Next →';
        this.el.nText.innerHTML = this.scene.intro || 'Each step animates one part of the exchange. Click any packet to inspect its contents.';
        this.el.nDeep.hidden = true;
      } else {
        const st = steps[i];
        this.el.nMeta.textContent = `Step ${i + 1} of ${steps.length}`;
        this.el.nTitle.innerHTML = st.title;
        this.el.nText.innerHTML = st.text || '';
        this.el.nDeep.hidden = !st.deep;
        this.el.nDeepBody.innerHTML = st.deep || '';
      }
      this.updatePlayBtn();
    }

    /* ------------------------------------------------------------ actions */
    execSync(a) {
      this.exec(a, this.token, true);
    }

    async exec(a, tok, instant) {
      if (a.par) return Promise.all(a.par.map((x) => this.exec(x, tok, instant)));
      if (a.seq) { for (const x of a.seq) await this.exec(x, tok, instant); return; }
      if (a.send) return this.send(a, tok, instant);
      if (a.burst) return this.burst(a, tok, instant);
      if (a.wait) { if (!instant) await this.sleep(a.wait, tok); return; }
      if (a.advance !== undefined) return this.advance(a, tok, instant);
      if ('badge' in a) return this.setBadge(a.badge, a.text, a.tone, a.sticky);
      if (a.cache) return this.cacheOp(a);
      if (a.lookup === 'reset') { this.lookup = 0; this.renderHud(); return; }
      if (a.link) return this.addConn(a, instant);
      if (a.unlink) { const c = this.conns[a.unlink]; if (c) { c.remove(); delete this.conns[a.unlink]; } return; }
      if (a.show) return this.showNodes(a.show, true, instant);
      if (a.hide) return this.showNodes(a.hide, false, instant);
      if (a.cls) { const [id, c] = a.cls; this.nodeEls[id].classList.add(...c.split(' ')); return; }
      if (a.uncls) { const [id, c] = a.uncls; this.nodeEls[id].classList.remove(...c.split(' ')); return; }
      if (a.overlay) return this.overlay(a.overlay, instant);
      if (a.hl) {
        this.el.panelBody.querySelectorAll('.hl').forEach((e) => e.classList.remove('hl'));
        a.hl.forEach((k) => this.el.panelBody.querySelectorAll(`[data-k="${k}"]`).forEach((e) => e.classList.add('hl')));
        this.scrollPanelTo(this.el.panelBody.querySelector('.hl'), instant);
        return;
      }
      if (a.mark) {
        let last = null;
        for (const k in a.mark) this.el.panelBody.querySelectorAll(`[data-k="${k}"]`).forEach((e) => { e.dataset.state = a.mark[k]; last = e; });
        this.scrollPanelTo(last, instant);
        return;
      }
      if (a.panelHtml) { for (const k in a.panelHtml) this.el.panelBody.querySelectorAll(`[data-k="${k}"]`).forEach((e) => (e.innerHTML = a.panelHtml[k])); return; }
      if (a.fn) return a.fn(this, instant);
    }

    scrollPanelTo(el, instant) {
      if (!el || this.el.panel.hidden) return;
      const box = this.el.panelBody;
      const r = el.getBoundingClientRect(), b = box.getBoundingClientRect();
      if (r.top >= b.top && r.bottom <= b.bottom) return;
      box.scrollTo({ top: r.top - b.top + box.scrollTop - 40, behavior: instant ? 'auto' : 'smooth' });
    }

    sleep(ms, tok) {
      return new Promise((res, rej) => {
        const t0 = performance.now();
        const tick = (now) => {
          this.raf.delete(id);
          if (tok !== this.token) return rej(ABORT);
          if (now - t0 >= ms / this.speed) return res();
          id = requestAnimationFrame(tick);
          this.raf.add(id);
        };
        let id = requestAnimationFrame(tick);
        this.raf.add(id);
      });
    }

    animate(dur, fn, tok) {
      return new Promise((res, rej) => {
        const t0 = performance.now();
        const tick = (now) => {
          this.raf.delete(id);
          if (tok !== this.token) return rej(ABORT);
          const t = Math.min(1, (now - t0) / dur);
          fn(t);
          if (t >= 1) return res();
          id = requestAnimationFrame(tick);
          this.raf.add(id);
        };
        let id = requestAnimationFrame(tick);
        this.raf.add(id);
      });
    }

    pos(id) {
      const n = this.nodes[id];
      return { x: n.x, y: n.y };
    }

    makePath(ids, bend) {
      const pts = ids.map((id) => (typeof id === 'string' ? this.pos(id) : id));
      const R = 40;
      let d = '';
      for (let i = 0; i < pts.length - 1; i++) {
        const a = pts[i], b = pts[i + 1];
        const dx = b.x - a.x, dy = b.y - a.y;
        const len = Math.hypot(dx, dy) || 1;
        const ux = dx / len, uy = dy / len;
        const s = i === 0 ? { x: a.x + ux * R, y: a.y + uy * R } : a;
        const e = i === pts.length - 2 ? { x: b.x - ux * R, y: b.y - uy * R } : b;
        const bb = pts.length > 2 ? bend * 0.5 : bend;
        const c = { x: (s.x + e.x) / 2 - uy * bb, y: (s.y + e.y) / 2 + ux * bb };
        if (i === 0) d += `M${s.x.toFixed(1)},${s.y.toFixed(1)}`;
        d += ` Q${c.x.toFixed(1)},${c.y.toFixed(1)} ${e.x.toFixed(1)},${e.y.toFixed(1)}`;
      }
      return d;
    }

    toneOf(a) {
      if (a.tone) return a.tone;
      const p = a.pkt;
      if (!p) return 'q';
      if (p.enc) return 'enc';
      if (p.forged) return 'bad';
      if (p.kind === 'dns') {
        const m = p.dns;
        if (!m.qr) return 'q';
        if (m.rcode === 'SERVFAIL' || m.rcode === 'REFUSED') return 'bad';
        if (m.rcode === 'NXDOMAIN') return 'warn';
        if (!m.an.length && m.ns.some((r) => r.type === 'NS')) return 'ref';
        return 'r';
      }
      return 'gen';
    }

    async send(a, tok, instant) {
      const [from, to] = a.send;
      const tone = this.toneOf(a);
      const pkt = a.pkt;
      const label = a.label || (pkt ? DV.dns.shortLabel(pkt) : '');
      const entry = pkt ? this.logPacket(pkt, tone, label, instant) : null;
      const ms = a.ms || 0;
      if (instant || reduceMotion && a.quick) {
        this.addTime(ms);
        return;
      }
      const d = this.makePath([from, ...(a.via || []), to], a.bend ?? 34);
      const trail = svg('path', { d, class: `trail tone-${tone}` });
      this.el.trails.appendChild(trail);
      const len = trail.getTotalLength();
      trail.style.strokeDasharray = `${len} ${len}`;
      trail.style.strokeDashoffset = len;
      const g = svg('g', { class: `pkt tone-${tone} ${a.big ? 'big' : ''}` });
      g.appendChild(svg('circle', { r: a.big ? 15 : 11, class: 'halo' }));
      g.appendChild(svg('circle', { r: a.big ? 8 : 6, class: 'core' }));
      if (label) {
        const lg = svg('g', { class: 'pk-label' });
        const rect = svg('rect', { rx: 6, ry: 6, height: 22 });
        const text = svg('text', { 'text-anchor': 'middle', dy: '0.35em' });
        text.textContent = ((pkt && pkt.enc) || a.lock ? '🔒 ' : '') + label;
        lg.append(rect, text);
        g.appendChild(lg);
        this.el.pkts.appendChild(g);
        const tw = Math.max(30, text.getComputedTextLength() + 16);
        rect.setAttribute('x', -tw / 2);
        rect.setAttribute('width', tw);
        rect.setAttribute('y', -11);
      } else this.el.pkts.appendChild(g);
      if (pkt) {
        g.style.cursor = 'pointer';
        g.addEventListener('click', () => {
          this.pause();
          this.select(entry);
          this.showTab('pk');
        });
      }
      const dur = (a.dur || Math.max(750, Math.min(2100, 480 + len * 1.9))) / this.speed;
      const t0time = this.time, t0look = this.lookup;
      const lbl = g.querySelector('.pk-label');
      try {
        await this.animate(dur, (t) => {
          const e = ease(t);
          const p = trail.getPointAtLength(e * len);
          g.setAttribute('transform', `translate(${p.x.toFixed(1)},${p.y.toFixed(1)})`);
          if (lbl) lbl.setAttribute('transform', `translate(0,${p.y < 60 ? 26 : -24})`);
          trail.style.strokeDashoffset = len * (1 - e);
          if (ms) { this.time = t0time + ms * t; this.lookup = t0look + ms * t; this.renderHud(); this.renderCaches(); }
        }, tok);
      } catch (e) {
        g.remove(); trail.remove();
        throw e;
      }
      this.time = t0time + ms;
      this.lookup = t0look + ms;
      this.renderHud();
      if (to && this.nodeEls[to]) {
        const n = this.nodeEls[to];
        n.classList.remove('hit');
        void n.offsetWidth;
        n.classList.add('hit');
      }
      g.classList.add('arrived');
      trail.classList.add('fade');
      setTimeout(() => { g.remove(); trail.remove(); }, 900);
    }

    async burst(a, tok, instant) {
      const [from, to] = a.burst;
      const n = a.n || 12;
      const tone = a.tone || 'bad';
      if (a.pkt) this.logPacket(a.pkt, tone, a.logLabel || `${n}× ` + (a.label || DV.dns.shortLabel(a.pkt)), instant);
      if (instant) return;
      const gap = (a.gap || 110) / this.speed;
      const jobs = [];
      for (let i = 0; i < n; i++) {
        jobs.push((async () => {
          await this.sleep(i * gap * this.speed, tok);
          const bend = (a.spread ?? 60) * (((i * 7919) % 17) / 8 - 1);
          const d = this.makePath([a.fromPt ? a.fromPt(i) : from, a.toPt ? a.toPt(i) : to], bend);
          const trail = svg('path', { d, class: `trail thin tone-${tone}` });
          this.el.trails.appendChild(trail);
          const len = trail.getTotalLength();
          trail.style.strokeDasharray = `${len} ${len}`;
          trail.style.strokeDashoffset = len;
          const g = svg('g', { class: `pkt mini tone-${tone} ${a.big ? 'big' : ''}` });
          g.appendChild(svg('circle', { r: a.big ? 10 : 6, class: 'halo' }));
          g.appendChild(svg('circle', { r: a.big ? 6 : 3.5, class: 'core' }));
          const lab = a.labels ? a.labels[i % a.labels.length] : null;
          if (lab) {
            const text = svg('text', { class: 'mini-label', 'text-anchor': 'middle', y: -10 });
            text.textContent = lab;
            g.appendChild(text);
          }
          this.el.pkts.appendChild(g);
          const dur = (a.dur || 1100) / this.speed;
          try {
            await this.animate(dur, (t) => {
              const p = trail.getPointAtLength(ease(t) * len);
              g.setAttribute('transform', `translate(${p.x.toFixed(1)},${p.y.toFixed(1)})`);
              trail.style.strokeDashoffset = len * (1 - ease(t));
            }, tok);
          } finally {
            trail.classList.add('fade');
            g.classList.add(a.dropAt === undefined || i !== a.dropAt ? 'arrived' : 'arrived');
            setTimeout(() => { g.remove(); trail.remove(); }, 700);
          }
        })());
      }
      await Promise.all(jobs);
      const t = this.nodeEls[to];
      if (t) { t.classList.remove('hit'); void t.offsetWidth; t.classList.add('hit'); }
    }

    addTime(ms) {
      this.time += ms;
      this.lookup += ms;
      this.renderHud();
      this.renderCaches();
    }

    async advance(a, tok, instant) {
      const ms = a.advance * 1000;
      if (instant) { this.time += ms; this.renderHud(); this.renderCaches(); return; }
      const t0 = this.time;
      this.el.hud.classList.add('ticking');
      try {
        await this.animate((a.dur || 1800) / this.speed, (t) => {
          this.time = t0 + ms * ease(t);
          this.renderHud();
          this.renderCaches();
        }, tok);
      } finally {
        this.el.hud.classList.remove('ticking');
      }
      this.time = t0 + ms;
      this.renderHud();
      this.renderCaches();
    }

    renderHud() {
      const h = this.scene.hud;
      if (!h) { this.el.hud.hidden = true; return; }
      this.el.hud.hidden = false;
      let s = '';
      if (h === 'clock' || h === 'both') s += `<span>${DV.icon('clock')} Clock <b class="mono">${fmtClock(this.time)}</b></span>`;
      if (h === 'lookup' || h === 'both') s += `<span>Lookup time <b class="mono">${Math.round(this.lookup)} ms</b></span>`;
      this.el.hud.innerHTML = s;
    }

    setBadge(id, text, tone, sticky) {
      const el = this.nodeEls[id];
      if (!el) return;
      const b = el.querySelector('.node-badge');
      if (!text) { b.className = 'node-badge'; b.textContent = ''; delete b.dataset.sticky; return; }
      b.className = `node-badge show tone-${tone || 'info'}`;
      b.innerHTML = text;
      if (sticky) b.dataset.sticky = '1'; else delete b.dataset.sticky;
    }

    cacheOp(a) {
      const id = a.cache;
      const c = (this.caches[id] = this.caches[id] || { title: a.title || 'Cache', rows: [] });
      if (a.title) c.title = a.title;
      if (a.clear) c.rows = [];
      for (const k of a.remove || []) c.rows = c.rows.filter((r) => r.name + ' ' + r.type !== k);
      for (const r of a.add || []) {
        c.rows = c.rows.filter((x) => !(x.name === r.name && x.type === r.type));
        c.rows.push(Object.assign({ t0: this.time - (r.age || 0) * 1000, fresh: true }, r));
      }
      if (a.flash) c.flash = a.flash;
      this.renderCaches(id);
    }

    renderCaches(only) {
      for (const id in this.caches) {
        if (only && id !== only) continue;
        const c = this.caches[id];
        const el = this.nodeEls[id].querySelector('.node-cache');
        if (!c.rows.length && !c.showEmpty) { el.innerHTML = `<div class="cache-box"><div class="cache-title">${DV.icon('database')} ${c.title}</div><div class="cache-empty">empty</div></div>`; continue; }
        el.innerHTML = `<div class="cache-box"><div class="cache-title">${DV.icon('database')} ${c.title}</div><table>${c.rows
          .map((r) => {
            const left = r.ttl - Math.floor((this.time - r.t0) / 1000);
            const frac = Math.max(0, Math.min(1, left / r.ttl));
            const cls = `${left <= 0 ? 'expired' : ''} ${r.tone ? 'tone-' + r.tone : ''}`;
            return `<tr class="${cls}"><td class="c-name">${esc(DV.dns.bare(r.name))}</td><td class="c-type">${esc(r.type)}</td><td class="c-data">${esc(r.data)}</td><td class="c-ttl"><span class="ttlbar"><i style="width:${(frac * 100).toFixed(1)}%"></i></span><span class="mono">${fmtTTL(left)}</span></td></tr>`;
          })
          .join('')}</table></div>`;
      }
    }

    addConn(a, instant) {
      const [x, y] = a.link;
      const A = this.pos(x), B = this.pos(y);
      const g = svg('g', { class: `conn tone-${a.tone || 'tcp'} ${instant ? '' : 'grow'}` });
      g.appendChild(svg('line', { x1: A.x, y1: A.y, x2: B.x, y2: B.y, class: 'conn-tube' }));
      g.appendChild(svg('line', { x1: A.x, y1: A.y, x2: B.x, y2: B.y, class: 'conn-core' }));
      if (a.label) {
        const mx = (A.x + B.x) / 2 + (a.dx || 0), my = (A.y + B.y) / 2 + (a.dy ?? 26);
        const t = svg('text', { x: mx, y: my, class: 'conn-label', 'text-anchor': 'middle' });
        t.textContent = a.label;
        g.appendChild(t);
      }
      const id = a.id || x + '-' + y;
      if (this.conns[id]) this.conns[id].remove();
      this.conns[id] = g;
      this.el.conns.appendChild(g);
    }

    showNodes(ids, show, instant) {
      for (const id of [].concat(ids)) {
        const el = this.nodeEls[id];
        el.classList.toggle('hidden', !show);
        if (show && !instant) { el.classList.remove('pop'); void el.offsetWidth; el.classList.add('pop'); }
        this.el.links.querySelectorAll(`.base-link[data-a="${id}"], .base-link[data-b="${id}"]`).forEach((l) => {
          const other = l.dataset.a === id ? l.dataset.b : l.dataset.a;
          l.classList.toggle('hidden', !show || this.nodeEls[other].classList.contains('hidden'));
        });
      }
    }

    overlay(o, instant) {
      if (o.off) return this.removeOverlay(o.id);
      const id = o.id || 'ov';
      this.removeOverlay(id);
      const d = document.createElement('div');
      d.className = `overlay at-${o.at || 'center'} ${o.cls || ''} ${instant ? '' : 'enter'}`;
      if (o.w) d.style.width = `calc(${o.w} * var(--u))`;
      if (o.x !== undefined) { d.style.left = (o.x / W) * 100 + '%'; d.style.top = (o.y / H) * 100 + '%'; }
      d.innerHTML = (o.title ? `<div class="ov-title">${o.title}</div>` : '') + `<div class="ov-body">${o.html || ''}</div>`;
      if (instant) d.classList.add('instant');
      this.el.over.appendChild(d);
      this.overlays[id] = { el: d, keep: !!o.keep };
    }
    removeOverlay(id) {
      const o = this.overlays[id];
      if (o) { o.el.remove(); delete this.overlays[id]; }
    }

    /* ------------------------------------------------------------ packet log / inspector */
    logPacket(pkt, tone, label, instant) {
      const entry = { pkt, tone, label, step: this.curStep, n: this.log.length + 1 };
      this.log.push(entry);
      if (this.log.length === 1) this.el.plog.innerHTML = '';
      const b = document.createElement('button');
      b.className = `pl-item tone-${tone} ${instant ? '' : 'new'}`;
      b.innerHTML = `<span class="pl-n mono">${entry.n}</span><span class="pl-dot"></span><span class="pl-sum">${esc(DV.dns.summary(pkt))}</span><span class="pl-step">step ${entry.step + 1}</span>`;
      b.onclick = () => {
        this.follow = false;
        this.el.follow.checked = false;
        this.select(entry);
      };
      entry.el = b;
      this.el.plog.appendChild(b);
      this.el.plog.scrollTop = this.el.plog.scrollHeight;
      this.el.pkCount.textContent = this.log.length;
      if (this.follow) {
        if (instant) this.pendingSel = entry;
        else this.select(entry);
      }
      return entry;
    }

    select(entry) {
      if (!entry) return;
      if (this.selected && this.selected.el) this.selected.el.classList.remove('sel');
      this.selected = entry;
      entry.el.classList.add('sel');
      DV.inspector.render(this.el.insp, entry.pkt, entry);
    }
  }

  DV.Player = Player;
})();
