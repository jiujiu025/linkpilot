/**
 * 本地门户页面
 *
 * 约束（docs/design/02 §4、§12.1）：
 * - 页面上不出现 OpenWrt / sing-box / UUID / 私钥 / 节点地址；
 * - 客户看到的是「线路名 + 地区 + 出口状态」，不是协议细节；
 * - 所有写操作都要二次确认，且提示可能的中断影响。
 *
 * 单文件、零依赖：设备内存有限，门户不应该再拖一个前端构建产物上去。
 */
export function renderPortalHtml(): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>LinkPilot 网络控制台</title>
<style>
  :root {
    --bg: #f5f6f8;
    --card: #ffffff;
    --ink: #14161a;
    --muted: #6b7280;
    --line: #e5e7eb;
    --accent: #2f6fed;
    --ok: #12855a;
    --warn: #b45309;
    --bad: #b42318;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
    background: var(--bg);
    color: var(--ink);
    -webkit-font-smoothing: antialiased;
  }
  .wrap { max-width: 960px; margin: 0 auto; padding: 28px 20px 64px; }
  header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 22px; }
  .brand { display: flex; align-items: center; gap: 10px; font-weight: 650; letter-spacing: .2px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--accent); box-shadow: 0 0 0 4px rgba(47,111,237,.14); }
  .chip { font-size: 12px; color: var(--muted); border: 1px solid var(--line); background: #fff; padding: 5px 10px; border-radius: 999px; }
  .grid { display: grid; gap: 16px; }
  .cols-2 { grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }
  .card { background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 18px 18px 16px; }
  .card h2 { font-size: 13px; font-weight: 600; color: var(--muted); margin: 0 0 12px; letter-spacing: .3px; }
  .stat { font-size: 24px; font-weight: 650; line-height: 1.2; }
  .stat-label { font-size: 11.5px; color: var(--muted); letter-spacing: .3px; margin-bottom: 6px; }
  .stat-block { min-width: 132px; }
  .sub { font-size: 12.5px; color: var(--muted); margin-top: 4px; }
  .row { display: flex; align-items: center; justify-content: space-between; padding: 11px 0; border-bottom: 1px dashed var(--line); }
  .row:last-child { border-bottom: none; }
  .name { font-size: 14px; font-weight: 550; }
  .meta { font-size: 12px; color: var(--muted); margin-top: 2px; }
  .badge { font-size: 11.5px; padding: 3px 8px; border-radius: 999px; border: 1px solid var(--line); color: var(--muted); }
  .badge.ok { color: var(--ok); border-color: rgba(18,133,90,.28); background: rgba(18,133,90,.07); }
  .badge.warn { color: var(--warn); border-color: rgba(180,83,9,.28); background: rgba(180,83,9,.07); }
  button {
    font: inherit; font-size: 13px; padding: 7px 13px; border-radius: 9px; border: 1px solid var(--line);
    background: #fff; color: var(--ink); cursor: pointer;
  }
  button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
  button.ghost { color: var(--muted); }
  button:disabled { opacity: .5; cursor: not-allowed; }
  select, input[type=password], input[type=text] {
    font: inherit; font-size: 13px; padding: 7px 9px; border-radius: 9px; border: 1px solid var(--line); background: #fff; color: var(--ink);
  }
  .toolbar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .notice { font-size: 12.5px; color: var(--warn); background: rgba(180,83,9,.06); border: 1px solid rgba(180,83,9,.2);
    padding: 9px 12px; border-radius: 10px; margin-top: 12px; }
  .empty { font-size: 13px; color: var(--muted); padding: 10px 0; }
  .login { max-width: 360px; margin: 12vh auto 0; }
  .login h1 { font-size: 19px; margin: 0 0 6px; }
  .login p { font-size: 13px; color: var(--muted); margin: 0 0 18px; }
  .field { margin-bottom: 11px; }
  .field label { display: block; font-size: 12.5px; color: var(--muted); margin-bottom: 5px; }
  .field input { width: 100%; }
  .err { color: var(--bad); font-size: 12.5px; margin-top: 10px; min-height: 16px; }
  footer { margin-top: 26px; font-size: 11.5px; color: var(--muted); display: flex; justify-content: space-between; }
  .kpi { display: flex; gap: 26px; flex-wrap: wrap; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand"><span class="dot"></span><span>LinkPilot</span></div>
    <div class="toolbar">
      <span class="chip" id="who">未登录</span>
      <button class="ghost" id="logout" style="display:none">退出</button>
    </div>
  </header>
  <main id="app"></main>
  <footer>
    <span id="footLeft">本页面仅显示已授权线路的概要状态</span>
    <span id="footRight"></span>
  </footer>
</div>
<script>
(function () {
  var state = { snapshot: null, me: null };
  var app = document.getElementById('app');

  function h(html) { return html; }
  function esc(text) {
    return String(text == null ? '' : text).replace(/[&<>"']/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c];
    });
  }
  function api(path, options) {
    options = options || {};
    return fetch(path, {
      method: options.method || 'GET',
      headers: options.body ? { 'content-type': 'application/json' } : {},
      body: options.body ? JSON.stringify(options.body) : undefined,
      credentials: 'same-origin'
    }).then(function (res) {
      return res.json().then(function (data) {
        if (!res.ok) { throw new Error((data.error && data.error.message) || '请求失败'); }
        return data;
      });
    });
  }

  function renderLogin(errorText) {
    app.innerHTML = h(
      '<div class="login card">' +
        '<h1>连接 LinkPilot-WiFi</h1>' +
        '<p>使用分配给你的账号登录，系统会按账号权限展示可用功能。</p>' +
        '<form id="loginForm">' +
          '<div class="field"><label>账号</label><input type="text" id="username" autocomplete="username" /></div>' +
          '<div class="field"><label>密码</label><input type="password" id="password" autocomplete="current-password" /></div>' +
          '<button class="primary" type="submit" style="width:100%">登录</button>' +
        '</form>' +
        '<div class="err" id="loginErr">' + esc(errorText || '') + '</div>' +
      '</div>'
    );
    document.getElementById('loginForm').addEventListener('submit', function (event) {
      event.preventDefault();
      api('/api/portal/login', {
        method: 'POST',
        body: {
          username: document.getElementById('username').value.trim(),
          password: document.getElementById('password').value
        }
      }).then(function () { boot(); }).catch(function (error) {
        document.getElementById('loginErr').textContent = error.message;
      });
    });
  }

  function clientRow(client, isAdmin) {
    var badgeClass = client.state === 'authorized' ? 'ok' : 'warn';
    var badgeText = client.state === 'authorized' ? '已授权' : (client.state === 'revoked' ? '已撤销' : '待授权');
    var profileSelect = '';
    if (client.state !== 'authorized' && state.snapshot.profiles.length > 0) {
      profileSelect = '<select data-profile-for="' + esc(client.id) + '">' +
        state.snapshot.profiles.map(function (p) {
          return '<option value="' + esc(p.id) + '">' + esc(p.name) + '</option>';
        }).join('') + '</select>';
    }
    var action = '';
    if (client.state !== 'authorized') {
      action = profileSelect + ' <button class="primary" data-authorize="' + esc(client.id) + '">授权</button>';
    } else if (isAdmin) {
      var lineOptions = state.snapshot.lines.map(function (line) {
        return '<option value="' + esc(line.id) + '"' + (line.id === client.primaryLineId ? ' selected' : '') + '>' +
          esc(line.name) + ' · ' + esc(line.region) + '</option>';
      }).join('');
      action = '<select data-line-for="' + esc(client.id) + '">' + lineOptions + '</select> ' +
        '<button data-switch="' + esc(client.id) + '">切线路</button>';
    }
    return h(
      '<div class="row">' +
        '<div>' +
          '<div class="name">' + esc(client.label) + '</div>' +
          '<div class="meta">' + esc(client.ip) + ' · ' + esc(client.attach === 'wifi' ? '无线接入' : '有线接入') +
            (client.primaryLine ? ' · 出口 ' + esc(client.primaryLine) : '') +
            (client.standbyLine ? '（备用 ' + esc(client.standbyLine) + '）' : '') + '</div>' +
        '</div>' +
        '<div class="toolbar"><span class="badge ' + badgeClass + '">' + badgeText + '</span>' + action + '</div>' +
      '</div>'
    );
  }

  function renderDashboard() {
    var s = state.snapshot;
    var isAdmin = state.me.role === 'device_admin';
    var authorized = s.clients.filter(function (c) { return c.state === 'authorized'; });
    var pending = s.clients.filter(function (c) { return c.state !== 'authorized'; });

    var html = '<div class="grid cols-2">' +
      '<div class="card">' +
        '<h2>当前出口</h2>' +
        '<div class="kpi">' +
          '<div class="stat-block"><div class="stat-label">线路</div>' +
            '<div class="stat">' + esc(s.exit.lineName || '未启用') + '</div>' +
            '<div class="sub">' + esc(s.exit.region || '等待授权设备') + '</div></div>' +
          '<div class="stat-block"><div class="stat-label">生效版本</div>' +
            '<div class="stat">r' + esc(String(s.device.activeRevision || '—')) + '</div>' +
            '<div class="sub">' + esc(s.device.digestShort || '尚未应用配置') + '</div></div>' +
        '</div>' +
        '<div class="notice" style="' + (s.device.cloudReachable ? 'display:none' : '') + '">' +
          '与云端暂时断开：本地转发、已授权设备与自动策略继续生效，远程运维暂停。</div>' +
      '</div>' +
      '<div class="card">' +
        '<h2>网络</h2>' +
        '<div class="row"><div><div class="name">' + esc(s.wifi.enabled ? s.wifi.ssid : '无线由外部 AP 提供') + '</div>' +
          '<div class="meta">' +
            (s.wifi.enabled
              ? '单 SSID · ' + esc(s.wifi.band) + ' · 未授权设备无法出网'
              : '本机未内置无线模块 · 有线接入同样受门户与隔离策略约束') +
          '</div></div>' +
          (s.wifi.enabled && isAdmin ? '<button data-wifi="1">修改口令</button>'
            : '<span class="badge">' + (s.wifi.enabled ? '仅管理员可改' : '不适用') + '</span>') +
        '</div>' +
        '<div class="row"><div><div class="name">设备 ' + esc(s.device.model) + '</div>' +
          '<div class="meta">' + esc(s.device.lastApply || '尚未应用配置') + '</div></div>' +
          '<span class="badge ' + (s.device.health === 'healthy' ? 'ok' : 'warn') + '">' + esc(s.device.health) + '</span>' +
        '</div>' +
      '</div>' +
    '</div>';

    if (s.access && s.access.mode === 'session') {
      var online = s.access.online || [];
      html += '<div class="card" style="margin-top:16px"><h2>在线用户（' + online.length + '）</h2>' +
        (online.length === 0 ? '<div class="empty">当前没有已登录的终端。客户连上 Wi-Fi 后会自动弹出登录页。</div>' :
          '<table class="list"><tr><th>账号</th><th>出口线路</th><th>地址</th><th>登录时间</th><th></th></tr>' +
          online.map(function (o) {
            return '<tr><td>' + esc(o.username) + (o.pinned ? ' <span class="badge">预授权</span>' : '') +
              '</td><td>' + esc(o.lineName || o.lineId) + '</td><td class="meta">' + esc(o.ip) +
              '</td><td class="meta">' + esc(o.since.replace('T', ' ').slice(0, 16)) + '</td><td>' +
              (isAdmin && !o.pinned ? '<button data-kick="' + esc(o.username) + '">踢下线</button>' : '') +
              '</td></tr>';
          }).join('') + '</table>') +
        '<div class="meta" style="margin-top:8px">一账号一设备，后登踢前登。离线超过 ' + esc(String(s.access.graceMinutes)) +
        ' 分钟后名额释放，但设备记忆保留，回来不需重登。</div>' +
      '</div>';
    }

    html += '<div class="card" style="margin-top:16px"><h2>已授权设备</h2>' +
      (authorized.length === 0 ? '<div class="empty">还没有已授权设备。</div>' :
        authorized.map(function (c) { return clientRow(c, isAdmin); }).join('')) +
      '</div>';

    html += '<div class="card" style="margin-top:16px"><h2>待授权设备</h2>' +
      (pending.length === 0 ? '<div class="empty">没有待授权设备。</div>' :
        pending.map(function (c) { return clientRow(c, isAdmin); }).join('')) +
      '<div class="notice">编码器、摄像机等无浏览器设备先接入网络，再在这里选择线路完成授权，设备本身不需要登录。</div>' +
      '</div>';

    html += '<div class="card" style="margin-top:16px"><h2>诊断</h2>' +
      s.diagnostics.map(function (item) {
        return '<div class="row"><div><div class="name">' + esc(item.name) + '</div>' +
          '<div class="meta">' + esc(item.detail) + '</div></div>' +
          '<span class="badge ' + (item.status === 'ok' ? 'ok' : 'warn') + '">' + esc(item.status) + '</span></div>';
      }).join('') +
      '</div>';

    app.innerHTML = html;
    bindActions();
    document.getElementById('footRight').textContent = '配置 r' + s.device.activeRevision + ' · ' + s.device.digestShort;
  }

  function bindActions() {
    Array.prototype.forEach.call(document.querySelectorAll('[data-authorize]'), function (button) {
      button.addEventListener('click', function () {
        var clientId = button.getAttribute('data-authorize');
        var select = document.querySelector('[data-profile-for="' + clientId + '"]');
        if (!confirm('授权后该设备将立即使用所选线路出网，可能中断当前正在进行的连接。继续？')) return;
        button.disabled = true;
        api('/api/portal/device-bindings', {
          method: 'POST',
          body: { clientId: clientId, routeProfileId: select.value }
        }).then(function () { refresh(); }).catch(function (error) { alert(error.message); button.disabled = false; });
      });
    });
    Array.prototype.forEach.call(document.querySelectorAll('[data-switch]'), function (button) {
      button.addEventListener('click', function () {
        var clientId = button.getAttribute('data-switch');
        var select = document.querySelector('[data-line-for="' + clientId + '"]');
        if (!confirm('立即切换会重建该设备的新连接，正在直播可能中断。继续？')) return;
        button.disabled = true;
        api('/api/portal/line-switch', {
          method: 'POST',
          body: { clientId: clientId, lineId: select.value }
        }).then(function () { refresh(); }).catch(function (error) { alert(error.message); button.disabled = false; });
      });
    });
    Array.prototype.forEach.call(document.querySelectorAll('[data-kick]'), function (btn) {
      btn.addEventListener('click', function () {
        api('/api/portal/access-kick', { method: 'POST', body: { username: btn.getAttribute('data-kick') } })
          .then(refresh).catch(function (error) { alert(error.message); });
      });
    });

    var wifiButton = document.querySelector('[data-wifi]');
    if (wifiButton) {
      wifiButton.addEventListener('click', function () {
        var psk = prompt('新的 Wi-Fi 口令（8~63 位）。修改后无线设备会短暂断开，请保留有线入口。');
        if (!psk) return;
        api('/api/portal/wifi', { method: 'POST', body: { psk: psk } })
          .then(function () { alert('已提交，设备将在下一次同步后生效。'); refresh(); })
          .catch(function (error) { alert(error.message); });
      });
    }
  }

  // 账号接入模式：一个 SSID、输账号密码、按账号给出口线路
  function renderAccess(current) {
    if (current.authed) {
      app.innerHTML = h(
        '<div class="login card">' +
          '<h1>已连接</h1>' +
          '<p>当前账号：<b>' + esc(current.username || '') + '</b></p>' +
          '<p>出口线路：<b>' + esc(current.lineName || current.lineId || '—') + '</b></p>' +
          '<button class="primary" type="button" id="accessLogout" style="width:100%">退出登录</button>' +
        '</div>'
      );
      document.getElementById('accessLogout').addEventListener('click', function () {
        api('/api/portal/access-logout', { method: 'POST' }).then(function () {
          return api('/api/portal/access-state');
        }).then(renderAccess).catch(boot);
      });
      return;
    }
    app.innerHTML = h(
      '<div class="login card">' +
        '<h1>连接 LinkPilot-WiFi</h1>' +
        '<p>输入分配给你的账号和密码，连接后即走该账号对应的出口线路。</p>' +
        '<form id="accessForm">' +
          '<div class="field"><label>账号</label><input type="text" id="accessUser" autocomplete="username" /></div>' +
          '<div class="field"><label>密码</label><input type="password" id="accessPass" autocomplete="current-password" /></div>' +
          '<button class="primary" type="submit" style="width:100%">连接</button>' +
        '</form>' +
        '<div class="err" id="accessErr"></div>' +
      '</div>'
    );
    document.getElementById('accessForm').addEventListener('submit', function (event) {
      event.preventDefault();
      api('/api/portal/access-login', {
        method: 'POST',
        body: {
          username: document.getElementById('accessUser').value.trim(),
          password: document.getElementById('accessPass').value
        }
      }).then(function () {
        return api('/api/portal/access-state');
      }).then(renderAccess).catch(function (error) {
        document.getElementById('accessErr').textContent = error.message;
      });
    });
  }

  function refresh() {
    api('/api/portal/state').then(function (data) {
      state.snapshot = data.snapshot;
      state.me = data.me;
      document.getElementById('who').textContent = data.me.displayName + ' · ' +
        (data.me.role === 'device_admin' ? '设备管理员' : '客户');
      document.getElementById('logout').style.display = 'inline-block';
      renderDashboard();
    }).catch(function () { renderLogin(); });
  }

  function boot() {
    // 先判断是不是账号接入模式：是就整页只做接入登录，不暴露管理功能
    api('/api/portal/access-state').then(function (access) {
      if (access && access.enabled) {
        document.getElementById('who').textContent = '账号接入';
        document.getElementById('logout').style.display = 'none';
        renderAccess(access);
        return;
      }
      adminBoot();
    }).catch(adminBoot);
  }

  function adminBoot() {
    api('/api/portal/me').then(function (data) {
      state.me = data.me;
      refresh();
    }).catch(function () {
      document.getElementById('who').textContent = '未登录';
      document.getElementById('logout').style.display = 'none';
      renderLogin();
    });
  }

  document.getElementById('logout').addEventListener('click', function () {
    api('/api/portal/logout', { method: 'POST' }).then(boot).catch(boot);
  });

  boot();
})();
</script>
</body>
</html>`;
}
