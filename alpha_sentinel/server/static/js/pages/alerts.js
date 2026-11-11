/* pages/alerts.js - OWNER: the Alerts page - filter chips, search, table and the
   drawer (status, ack, contributing events, kill-chain timeline). */
(function () {
  'use strict';
  var S = window.Sentinel = window.Sentinel || {};
  S.pages = S.pages || {};

  var SEVERITIES = ['Critical', 'High', 'Medium', 'Low'];
  var STATUSES = ['New', 'Investigating', 'Resolved', 'False Positive'];
  var filters = { sev: {}, status: {}, ack: 'any', q: '' };
  var data = [];
  var openId = null;

  function isOpen(a) { return a.Status === 'New' || a.Status === 'Investigating' || !a.Status; }

  function visible() {
    return data.filter(function (a) {
      if (a.SelfTest) { return false; }
      var on = false, any = false;
      SEVERITIES.forEach(function (s) { if (filters.sev[s]) { any = true; if (a.Severity === s) { on = true; } } });
      if (any && !on) { return false; }
      on = false; any = false;
      STATUSES.forEach(function (s) { if (filters.status[s]) { any = true; if (a.Status === s) { on = true; } } });
      if (any && !on) { return false; }
      if (filters.ack === 'acked' && !a.Acknowledged) { return false; }
      if (filters.ack === 'open' && a.Acknowledged) { return false; }
      if (filters.q) {
        var hay = [a.Title, a.Description, a.Host, a.Account, a.SourceIp, a.RuleKey, a.Mitre, a.Status].join(' ').toLowerCase();
        if (hay.indexOf(filters.q.toLowerCase()) < 0) { return false; }
      }
      return true;
    });
  }

  function chipGroups(reload) {
    var sevChips = SEVERITIES.map(function (s) {
      return S.ui.chip(s, !!filters.sev[s], function () { filters.sev[s] = !filters.sev[s]; reload(); });
    });
    var statusChips = STATUSES.map(function (s) {
      return S.ui.chip(s, !!filters.status[s], function () { filters.status[s] = !filters.status[s]; reload(); });
    });
    var ackChips = [['any', 'Any ack'], ['open', 'Not acked'], ['acked', 'Acknowledged']].map(function (p) {
      return S.ui.chip(p[1], filters.ack === p[0], function () { filters.ack = p[0]; reload(); });
    });
    return S.ui.el('div', { class: 'filterbar' }, [
      S.ui.el('div', { class: 'chip-group' }, sevChips),
      S.ui.el('span', { class: 'caption', text: '|' }),
      S.ui.el('div', { class: 'chip-group' }, statusChips),
      S.ui.el('span', { class: 'caption', text: '|' }),
      S.ui.el('div', { class: 'chip-group' }, ackChips),
      S.ui.el('span', { class: 'grow spacer' }),
      S.ui.el('span', { class: 'caption', text: 'Acknowledged is a flag, not a status' })
    ]);
  }

  function table(rows) {
    var tbody = S.ui.el('tbody');
    rows.forEach(function (a) {
      var tr = S.ui.el('tr', {}, [
        S.ui.el('td', {}, [S.ui.sevBadge(a.Severity)]),
        S.ui.el('td', {}, [S.ui.el('div', { class: 'alert-title', text: a.Title }), S.ui.el('div', { class: 'caption', text: a.RuleKey + (a.MitreId ? (' - ' + a.MitreId) : '') })]),
        S.ui.el('td', { class: 'cell-dim', text: a.Host || '-' }),
        S.ui.el('td', { class: 'cell-dim', text: a.Account || '-' }),
        S.ui.el('td', { class: 'cell-dim', text: a.SourceIp || '-' }),
        S.ui.el('td', { class: 'cell-mute', text: S.ui.fmtAgo(a.Time) }),
        S.ui.el('td', {}, [S.ui.statusBadge(a.Status)]),
        S.ui.el('td', {}, [a.Acknowledged ? S.ui.el('span', { class: 'badge badge-ack', text: 'Acked' }) : S.ui.el('span', { class: 'caption', text: '-' })]),
        S.ui.el('td', { class: 'num cell-mute', text: String(a.Count || 1) })
      ]);
      tr.addEventListener('click', function () { openDrawer(a.Id); });
      tbody.appendChild(tr);
    });
    return S.ui.el('table', { class: 'data' }, [
      S.ui.el('thead', {}, [S.ui.el('tr', {}, ['Severity', 'Detection', 'Host', 'Account', 'Source IP', 'Time', 'Status', 'Ack', 'Hits'].map(function (h) { return S.ui.el('th', { text: h }); }))]),
      tbody
    ]);
  }

  function drawerHost() {
    var d = document.getElementById('drawer');
    if (d) { return d; }
    d = S.ui.el('aside', { id: 'drawer', class: 'drawer', 'aria-label': 'alert details' });
    document.body.appendChild(d);
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') { closeDrawer(); } });
    return d;
  }

  function closeDrawer() {
    var d = document.getElementById('drawer');
    if (d) { d.classList.remove('open'); }
    var b = document.getElementById('backdrop');
    if (b) { b.hidden = true; }
    openId = null;
  }

  function act(id, action, body) {
    var path = action === 'status' ? ('/api/alerts/' + id + '/status') : ('/api/alerts/' + id + '/' + action);
    return S.api.post(path, body || {}, 'alerts').then(function () {
      S.ui.toast('Alert ' + id + ' ' + (action === 'status' ? 'updated' : action + 'nowledged'), 'ok');
      return load(true);
    }).catch(function (err) { S.ui.toast('Could not update alert ' + id + ': ' + err.message, 'bad'); });
  }

  function renderDrawer(a) {
    var d = drawerHost();
    S.ui.clear(d);
    var contributions = Array.isArray(a.Events) ? a.Events : [];
    var killChain = data.filter(function (x) {
      if (x.Id === a.Id || x.SelfTest) { return false; }
      return (a.Host && x.Host === a.Host) || (a.Account && x.Account === a.Account);
    }).sort(function (p, q) { return String(p.Time).localeCompare(String(q.Time)); }).slice(-8);

    var head = S.ui.el('div', { class: 'drawer-head' }, [
      S.ui.el('div', { class: 'grow' }, [
        S.ui.el('div', { class: 'row' }, [S.ui.sevBadge(a.Severity), S.ui.statusBadge(a.Status), S.ui.ackBadge(a.Acknowledged)]),
        S.ui.el('h2', { style: 'margin-top:8px', text: a.Title }),
        S.ui.el('div', { class: 'caption', text: a.RuleKey + (a.MitreId ? (' - ' + a.MitreId + ' ' + (a.MitreName || '')) : '') })
      ]),
      S.ui.el('button', { class: 'drawer-close', title: 'Close', text: '\u00D7', onclick: null }, [])
    ]);
    head.lastChild.addEventListener('click', closeDrawer);

    var statusSel = S.ui.el('select', { class: 'field' }, STATUSES.map(function (s) {
      var o = S.ui.el('option', { value: s, text: s });
      if (s === a.Status) { o.setAttribute('selected', 'selected'); }
      return o;
    }));
    statusSel.addEventListener('change', function () { act(a.Id, 'status', { status: statusSel.value }); });
    var ackBtn = S.ui.el('button', { class: 'btn btn-sm', text: a.Acknowledged ? 'Un-acknowledge' : 'Acknowledge' });
    ackBtn.addEventListener('click', function () { act(a.Id, a.Acknowledged ? 'unack' : 'ack', {}); });

    var kv = S.ui.el('dl', { class: 'kv' }, [
      S.ui.el('dt', { text: 'Entity' }), S.ui.el('dd', { text: a.Entity || '-' }),
      S.ui.el('dt', { text: 'Host' }), S.ui.el('dd', { text: a.Host || '-' }),
      S.ui.el('dt', { text: 'Account' }), S.ui.el('dd', { text: a.Account || '-' }),
      S.ui.el('dt', { text: 'Source IP' }), S.ui.el('dd', { text: a.SourceIp || '-' }),
      S.ui.el('dt', { text: 'Event' }), S.ui.el('dd', { text: a.EventId || '-' }),
      S.ui.el('dt', { text: 'MITRE' }), S.ui.el('dd', { text: (a.Mitre || '-') + (a.Tactic ? ('  [' + a.Tactic + ']') : '') }),
      S.ui.el('dt', { text: 'First seen' }), S.ui.el('dd', { text: S.ui.fmtDateTime(a.FirstSeen || a.Time) }),
      S.ui.el('dt', { text: 'Last seen' }), S.ui.el('dd', { text: S.ui.fmtDateTime(a.LastSeen || a.Time) }),
      S.ui.el('dt', { text: 'Contributing hits' }), S.ui.el('dd', { text: String(a.Count || 1) }),
      S.ui.el('dt', { text: 'What happened' }), S.ui.el('dd', { text: a.Description || '-' }),
      S.ui.el('dt', { text: 'Remediation' }), S.ui.el('dd', { text: a.Remediation || '-' })
    ]);

    var contribList = S.ui.el('ul', { class: 'timeline' }, contributions.map(function (e) {
      return S.ui.el('li', {}, [S.ui.el('div', { class: 't-time', text: S.ui.fmtDateTime(e.time) }), S.ui.el('div', { text: e.summary || '' })]);
    }));
    var chainList = S.ui.el('ul', { class: 'timeline' }, killChain.map(function (x) {
      return S.ui.el('li', {}, [
        S.ui.el('div', { class: 't-time', text: S.ui.fmtDateTime(x.Time) }),
        S.ui.el('div', { text: x.Title }),
        S.ui.el('div', { class: 't-tactic', text: (x.Tactic || '') + ' - ' + (x.Host || x.Account || '') })
      ]);
    }));

    /* values come from attacker-controlled logs: only embed them in a copy-paste
       shell command when they match a strict shape, otherwise show a placeholder */
    function safeIp(v) {
      v = String(v || '');
      var v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v);
      if (v4) { return v4.slice(1).every(function (o) { return Number(o) <= 255; }) ? v : null; }
      return /^[0-9a-fA-F:]{2,39}$/.test(v) && v.indexOf(':') >= 0 ? v : null;
    }
    function safeUser(v) { v = String(v || ''); return /^[a-z_][a-z0-9_.-]{0,31}$/i.test(v) ? v : null; }

    function buildPlaybook(a) {
      var rk = String(a.RuleKey || '').toLowerCase();
      var acc = safeUser(a.Account) || '<USERNAME>';
      var ip = safeIp(a.SourceIp) || '<ATTACKER_IP>';
      var steps = [];
      if (rk.indexOf('brute') >= 0 || rk.indexOf('after_failures') >= 0) {
        steps.push({ title: '1. Block the attacking IP', cmd: '# ufw\nsudo ufw deny from ' + ip + ' to any port 22\n# or iptables\nsudo iptables -I INPUT -s ' + ip + ' -p tcp --dport 22 -j DROP' });
        steps.push({ title: '2. Check what that IP did', cmd: "sudo grep '" + ip + "' /var/log/auth.log | tail -50\nlast -i | head -20" });
        if (rk.indexOf('after_failures') >= 0) {
          steps.push({ title: '3. Lock the account and kill its sessions', cmd: 'sudo passwd -l ' + acc + '\nsudo pkill -KILL -u ' + acc });
        }
      } else if (rk.indexOf('root_ssh') >= 0) {
        steps.push({ title: '1. Disable direct root SSH login', cmd: "sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config\nsudo systemctl reload sshd" });
        steps.push({ title: '2. Review active root sessions', cmd: 'who -a\nsudo last root | head' });
      } else if (rk.indexOf('authorized_keys') >= 0) {
        steps.push({ title: '1. Inspect the keys', cmd: 'sudo cat /home/' + acc + '/.ssh/authorized_keys' });
        steps.push({ title: '2. Remove unknown keys, then lock the account if needed', cmd: 'sudo passwd -l ' + acc });
      } else if (rk.indexOf('sshd_config') >= 0) {
        steps.push({ title: '1. Review the change', cmd: 'sudo sshd -T | head -40\nsudo ls -l /etc/ssh/sshd_config' });
      } else if (rk.indexOf('user_account') >= 0) {
        steps.push({ title: '1. Review the account', cmd: 'id ' + acc + '\nsudo chage -l ' + acc });
        steps.push({ title: '2. Lock it if it is not expected', cmd: 'sudo usermod -L ' + acc });
      } else if (rk.indexOf('cron') >= 0 || rk.indexOf('systemd') >= 0) {
        steps.push({ title: '1. List scheduled jobs', cmd: 'sudo crontab -l\nls -l /etc/cron.* /etc/cron.d\nsystemctl list-timers --all' });
        steps.push({ title: '2. Look for recently added units', cmd: 'sudo find /etc/systemd /etc/cron* -mtime -2 -type f' });
      } else if (rk.indexOf('sudo') >= 0) {
        steps.push({ title: '1. Review what ' + acc + ' ran with sudo', cmd: "sudo grep 'sudo:' /var/log/auth.log | grep '" + acc + "' | tail -50" });
      } else {
        steps.push({ title: '1. Investigate the source', cmd: 'ss -tnp | grep ' + ip + '\nsudo grep ' + ip + ' /var/log/auth.log | tail -50' });
      }

      var wrap = S.ui.el('div', { class: 'playbook-card' }, [
        S.ui.el('div', { class: 'playbook-title' }, [
          S.ui.el('span', { text: 'Automated Response Playbook' }),
          S.ui.el('span', { class: 'badge', text: 'Shell commands' })
        ])
      ]);

      steps.forEach(function (st) {
        var copyBtn = S.ui.el('button', { class: 'cmd-copy-btn', type: 'button', text: 'Copy' });
        copyBtn.addEventListener('click', function () {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(st.cmd).then(function () {
              S.ui.toast('Copied playbook command to clipboard', 'ok');
            });
          }
        });
        var cmdEl = S.ui.el('pre', { class: 'cmd-box', text: st.cmd });
        cmdEl.appendChild(copyBtn);

        wrap.appendChild(S.ui.el('div', { class: 'playbook-step' }, [
          S.ui.el('div', { class: 'playbook-step-title', text: st.title }),
          cmdEl
        ]));
      });

      return wrap;
    }

    var body = S.ui.el('div', { class: 'drawer-body' }, [
      S.ui.el('div', { class: 'row' }, [S.ui.el('span', { class: 'caption', text: 'Status' }), statusSel, ackBtn]),
      kv,
      S.ui.el('div', {}, [S.ui.el('h2', { text: 'Incident Response Actions' }), buildPlaybook(a)]),
      S.ui.el('div', {}, [S.ui.el('h2', { text: 'Contributing events' }), contributions.length ? contribList : S.ui.empty('No event detail', 'This row has no recorded contributing event.')]),
      S.ui.el('div', {}, [S.ui.el('h2', { text: 'Kill-chain timeline' }), killChain.length ? chainList : S.ui.empty('Nothing else for this host or account', 'Related alerts appear here ordered by time.')])
    ]);
    d.appendChild(head);
    d.appendChild(body);
    d.classList.add('open');
    var b = document.getElementById('backdrop');
    if (!b) { b = S.ui.el('div', { id: 'backdrop', class: 'backdrop' }); document.body.appendChild(b); b.addEventListener('click', closeDrawer); }
    b.hidden = false;
  }

  function openDrawer(id) {
    openId = id;
    var a = data.filter(function (x) { return x.Id === id; })[0];
    if (a) { renderDrawer(a); }
  }

  function paint() {
    var view = document.getElementById('view');
    if (!view || S.router.current() !== 'alerts') { return; }
    var rows = visible();
    S.ui.clear(view);
    view.appendChild(chipGroups(paint));
    var card = S.ui.el('div', { class: 'card' }, [
      S.ui.el('div', { class: 'card-head' }, [S.ui.el('h2', { text: 'Alerts' }), S.ui.el('span', { class: 'grow spacer' }),
        S.ui.el('span', { class: 'caption', text: rows.length + ' of ' + data.filter(function (a) { return !a.SelfTest; }).length + ' shown' })]),
      S.ui.el('div', { class: 'card-body tight' }, [S.ui.el('div', { class: 'table-wrap' }, rows.length ? [table(rows)] : [S.ui.empty('No alerts match', 'Clear a filter, or wait for something to fire.')])])
    ]);
    view.appendChild(card);
    if (openId) { openDrawer(openId); }
  }

  function load(silent) {
    return S.api.get('/api/alerts', 'alerts').then(function (rows) {
      data = Array.isArray(rows) ? rows : [];
      /* publish for the other pages: the Assets drawer labels its links with
         "#id - title (severity)" and should not need its own request to do it */
      S.state.set('alerts', data);
      paint();
    }).catch(function (err) {
      if (silent) { return; }
      var view = document.getElementById('view');
      if (view && S.router.current() === 'alerts') { S.ui.clear(view); view.appendChild(S.ui.error(err.message)); }
    });
  }

  S.pages.alerts = {
    title: 'Alerts',
    subtitle: 'Everything the detection engine has raised.',
    render: function () {
      var view = document.getElementById('view');
      S.ui.clear(view);
      view.appendChild(S.ui.el('div', { class: 'state' }, [S.ui.el('div', { class: 'state-title', text: 'Loading alerts...' })]));
      closeDrawer();
      load();
    },
    refresh: function () { if (S.router.current() === 'alerts') { load(true); } },
    filter: function (q) { filters.q = q || ''; paint(); }
  };
})();
