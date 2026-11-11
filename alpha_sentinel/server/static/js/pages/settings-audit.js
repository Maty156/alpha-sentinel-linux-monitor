/* pages/settings-audit.js - the "Log sources" tab (Linux). Shows whether each log
   the detections read exists, is readable and records what is needed. Read-only:
   fix commands are displayed for you to run, nothing is changed from here. */
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};
  S.settingsTabs = S.settingsTabs || {};

  function badge(state) {
    var kind = state === 'ok' ? 'pill-ok' : (state === 'blind' ? 'pill-bad' : 'pill-warn');
    var label = state === 'ok' ? 'Working' : (state === 'blind' ? 'Blind' : 'Unverified');
    return S.ui.pill(kind, label, state === 'blind' ? 'detections that need this log cannot fire' : '');
  }

  function row(src) {
    var body = [
      S.ui.el('div', {}, [S.ui.el('strong', { text: src.name + ' ' }), badge(src.state)]),
      S.ui.el('div', { class: 'caption', text: src.target + (src.detail ? ' - ' + src.detail : '') })
    ];
    if (src.fix) {
      body.push(S.ui.el('div', { class: 'caption', text: 'Fix:' }));
      body.push(S.ui.el('code', { class: 'log-fix', text: src.fix }));
    }
    return S.ui.el('li', {}, body);
  }

  function paint(r) {
    var view = document.getElementById('settingsBody');
    if (!view) { return; }
    S.ui.clear(view);
    var c = r.counts || {};
    var summary = (c.ok || 0) + ' working, ' + (c.blind || 0) + ' blind, ' + (c.unverified || 0) + ' unverified' +
      (r.elevated ? '' : ' (not running as root: some logs may be unreadable)');
    var btn = S.ui.el('button', { class: 'btn', type: 'button', text: 'Re-check' });
    btn.addEventListener('click', function () { load(); });
    view.appendChild(S.ui.el('div', { class: 'card' }, [
      S.ui.el('div', { class: 'card-head' }, [S.ui.el('h2', { text: 'Log sources' }), btn]),
      S.ui.el('div', { class: 'card-body' }, [
        S.ui.el('p', { class: 'caption', text: summary + '. Checked ' + (r.checkedAt || '') }),
        S.ui.el('ul', { class: 'timeline' }, (r.sources || []).map(row))
      ])
    ]));
  }

  function load() {
    return S.api.get('/api/audit', 'settings-audit').then(paint).catch(function (err) {
      var view = document.getElementById('settingsBody');
      if (!view) { return; }
      S.ui.clear(view);
      view.appendChild(S.ui.error(err && err.message ? err.message : 'Could not check the log sources.'));
    });
  }

  S.settingsTabs.audit = { render: function () { load(); } };
})();
