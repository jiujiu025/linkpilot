/**
 * 最小运营后台（单页，无构建步骤）
 *
 * 为什么不做前端工程：这个后台的使用者是运营自己，需求是「改一条线路、开一个账号、
 * 看设备活着没有」。上一套构建工具链的维护成本远大于收益，而且没有构建也就没有
 * 「构建产物和源不一致」这类问题。
 *
 * 安全边界说清楚：管理令牌存在 sessionStorage，页面本身不落任何凭证；
 * 线路凭证只在提交时经过一次，云端立刻加密，之后任何接口都不会再返回明文。
 */
export function renderAdminHtml(): string {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>LinkPilot 运营后台</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; font: 14px/1.6 -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; background: #f5f6f8; color: #1c1f23; }
  header { background: #fff; border-bottom: 1px solid #e5e7eb; padding: 14px 20px; display: flex; gap: 12px; align-items: center; position: sticky; top: 0; z-index: 5; }
  header h1 { font-size: 16px; margin: 0; font-weight: 600; }
  .spacer { flex: 1; }
  input, select, button, textarea { font: inherit; }
  input, select { padding: 7px 9px; border: 1px solid #d0d5dd; border-radius: 6px; background: #fff; }
  button { padding: 7px 14px; border-radius: 6px; border: 1px solid #d0d5dd; background: #fff; cursor: pointer; }
  button.primary { background: #1f6feb; border-color: #1f6feb; color: #fff; }
  button.danger { color: #b42318; border-color: #f3b7b2; }
  main { max-width: 1080px; margin: 0 auto; padding: 20px; display: grid; gap: 16px; }
  section { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 16px 18px; }
  section h2 { font-size: 14px; margin: 0 0 12px; color: #344054; letter-spacing: .02em; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 6px; border-bottom: 1px solid #f0f1f3; vertical-align: middle; }
  th { color: #667085; font-weight: 500; }
  .row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-top: 12px; }
  .row label { color: #667085; font-size: 12px; }
  .hint { color: #667085; font-size: 12px; margin: 8px 0 0; }
  .tag { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px; background: #eef2f6; color: #344054; }
  .tag.ok { background: #e7f6ec; color: #067647; }
  .tag.warn { background: #fff4e5; color: #b54708; }
  .err { color: #b42318; font-size: 12px; min-height: 18px; }
  .muted { color: #98a2b3; }
</style>
</head>
<body>
<header>
  <h1>LinkPilot 运营后台</h1>
  <span class="spacer"></span>
  <input id="token" type="password" placeholder="管理令牌（LP_ADMIN_TOKEN）" style="width:260px" />
  <button class="primary" id="save">连接</button>
</header>
<main>
  <div class="err" id="err"></div>

  <section>
    <h2>设备</h2>
    <div id="devices" class="muted">未加载</div>
  </section>

  <section>
    <h2>线路</h2>
    <div id="lines" class="muted">未加载</div>
    <div class="row">
      <button class="primary" id="probeAll">全部测速</button>
      <span id="probeResult" class="hint"></span>
    </div>
    <p class="hint">
      测的是<b>云端到节点</b>的 TCP/TLS 握手：能证明端口活着、证书与 SNI 对得上，
      <b>不能证明凭证有效，也代表不了客户本地网络</b>。
    </p>
    <div class="row">
      <input id="lineId" placeholder="线路 ID（如 line-us-1）" style="width:190px" />
      <input id="lineName" placeholder="名称（如 美国-洛杉矶-01）" style="width:200px" />
      <input id="lineRegion" placeholder="地区" style="width:100px" />
      <select id="lineKind">
        <option value="shadowsocks">Shadowsocks</option>
        <option value="trojan">Trojan</option>
        <option value="vless">VLESS</option>
        <option value="socks5">SOCKS5</option>
      </select>
      <input id="lineServer" placeholder="服务器地址" style="width:170px" />
      <input id="linePort" placeholder="端口" style="width:80px" value="443" />
    </div>
    <div class="row" id="credFields">
      <label>SS 方法</label><input id="ssMethod" value="aes-256-gcm" style="width:150px" />
      <label>密码 / UUID</label><input id="credSecret" placeholder="SS/Trojan 密码，或 VLESS UUID" style="width:280px" />
      <label>SNI</label><input id="credSni" placeholder="可选" style="width:180px" />
      <label>WS 路径</label><input id="credPath" placeholder="可选，如 /ray" style="width:140px" />
    </div>
    <div class="row"><button class="primary" id="addLine">新增线路</button></div>
    <p class="hint">凭证提交后立即用 master key 加密落盘，之后任何接口都不会再返回明文。改了线路会自动让设备下一轮拉取新版本。</p>
  </section>

  <section>
    <h2>接入账号（单 SSID 登录用）</h2>
    <div id="accounts" class="muted">未加载</div>
    <div class="row">
      <input id="accUser" placeholder="账号" style="width:130px" />
      <input id="accPass" placeholder="密码（≥8 位）" style="width:170px" />
      <input id="accName" placeholder="显示名" style="width:120px" />
      <select id="accLine" style="min-width:180px"></select>
      <input id="accExpire" type="date" style="width:150px" />
      <button class="primary" id="addAcc">开通账号</button>
    </div>
    <p class="hint">一个账号只能同时一台设备在线（后登踢前登），账号绑定的线路就是它的出口 IP。</p>
  </section>

  <section>
    <h2>粘贴分享链接（开一百台手机用这个）</h2>
    <p class="hint">
      支持 <code>ss://</code> <code>vmess://</code> <code>vless://</code> <code>trojan://</code>
      <code>hy2://</code> <code>socks5://</code> <code>http://</code>，一行一条。自动识别协议与地区，
      <b>一条线路开一个账号</b>（jy001、jy002…），导入后自动切到账号登录模式。
    </p>
    <textarea id="nodesText" rows="8" placeholder="ss://YWVzLTI1Ni1nY206cGFzcy0xMjM0NTY=@1.2.3.4:8388#美国-洛杉矶-01&#10;trojan://pass-abcdef@hk.example.com:443?sni=hk.example.com#香港-01&#10;vless://uuid-xxxx@jp.example.com:443?security=tls&type=ws&path=/ray&sni=jp.example.com#日本-东京-01" style="width:100%;font-family:ui-monospace,monospace;padding:8px"></textarea>
    <div class="row">
      <label>账号前缀</label>
      <input id="accPrefix" value="jy" style="width:90px" />
      <button class="primary" id="importNodes">识别并生成线路 + 账号</button>
      <span id="nodeResult" class="hint"></span>
    </div>
    <div id="nodeAccounts"></div>
  </section>

  <section>
    <h2>批量导入（CSV 方式）</h2>
    <p class="hint">
      线路 CSV 列顺序：<code>id,name,region,kind,server,port,secret,sni,wsPath</code>（secret 按协议是密码或 UUID）<br />
      账号 CSV 列顺序：<code>username,password,displayName,lineId,expiresAt</code>（到期日可留空）
    </p>
    <textarea id="linesCsv" rows="5" placeholder="line-us-01,美国-洛杉矶-01,US,shadowsocks,1.2.3.4,8388,your-password,,&#10;line-hk-01,香港-01,HK,trojan,hk.example.com,443,your-password,hk.example.com," style="width:100%;font-family:ui-monospace,monospace;padding:8px"></textarea>
    <div class="row">
      <label><input type="checkbox" id="overwrite" /> 覆盖同 ID 线路</label>
      <button class="primary" id="importLines">导入线路</button>
      <span id="lineResult" class="hint"></span>
    </div>
    <textarea id="accsCsv" rows="5" placeholder="user001,pass-123456,客户001,line-us-01,&nbsp;&#10;user002,pass-123456,客户002,line-us-01,2026-12-31" style="width:100%;font-family:ui-monospace,monospace;padding:8px"></textarea>
    <div class="row">
      <button class="primary" id="importAccs">导入账号</button>
      <span id="accResult" class="hint"></span>
    </div>
  </section>

  <section>
    <h2>接入模式</h2>
    <div id="mode" class="muted">未加载</div>
    <div class="row">
      <button id="toSession">切换为「账号登录」</button>
      <button id="toBinding">切换为「设备预授权」</button>
      <label>宽限期（分钟）</label>
      <input id="grace" type="number" min="1" max="1440" value="5" style="width:90px" />
      <button id="saveGrace">保存宽限期</button>
    </div>
    <p class="hint">切到账号登录前必须先有至少一个启用的账号，否则用户连上网会「Wi-Fi 已连但完全打不开」。</p>
  </section>
</main>
<script>
(function () {
  var tokenInput = document.getElementById('token');
  var errBox = document.getElementById('err');
  var saved = sessionStorage.getItem('lp_admin_token') || '';
  if (saved) tokenInput.value = saved;

  function api(path, options) {
    var opts = options || {};
    return fetch(path, {
      method: opts.method || 'GET',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + tokenInput.value },
      body: opts.body ? JSON.stringify(opts.body) : undefined
    }).then(function (res) {
      return res.json().then(function (data) {
        if (!res.ok) throw new Error((data.error && data.error.message) || ('HTTP ' + res.status));
        return data;
      });
    });
  }

  function esc(value) {
    return String(value == null ? '' : value).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }

  function fail(error) { errBox.textContent = error.message || String(error); }
  function clearErr() { errBox.textContent = ''; }

  function renderDevices(list) {
    var box = document.getElementById('devices');
    if (!list || list.length === 0) { box.textContent = '还没有设备注册'; return; }
    var html = '<table><tr><th>设备</th><th>型号</th><th>版本</th><th>状态</th><th>最近心跳</th></tr>';
    list.forEach(function (d) {
      var state = d.cloudReachable === false ? '离线' : (d.health === 'healthy' ? '正常' : d.health);
      html += '<tr><td>' + esc(d.id) + '</td><td>' + esc(d.model || '-') + '</td><td>r' + esc(d.revision) +
        '</td><td><span class="tag ' + (state === '正常' ? 'ok' : 'warn') + '">' + esc(state) +
        '</span></td><td class="muted">' + esc(d.lastHeartbeatAt || '-') + '</td></tr>';
    });
    box.innerHTML = html + '</table>';
  }

  function renderLines(lines) {
    var box = document.getElementById('lines');
    var select = document.getElementById('accLine');
    if (!lines || lines.length === 0) {
      box.textContent = '还没有线路，先在下面新增一条';
      select.innerHTML = '';
      return;
    }
    var html = '<table><tr><th>ID</th><th>名称</th><th>地区</th><th>协议</th><th>服务器</th><th>延迟</th><th></th></tr>';
    var opts = '';
    lines.forEach(function (l) {
      var probe = l.lastProbe;
      var latency = '<span class="muted">未测</span>';
      if (probe) {
        if (probe.ok) {
          var cls = probe.rttMs != null && probe.rttMs < 200 ? 'ok' : (probe.rttMs != null && probe.rttMs < 500 ? '' : 'warn');
          latency = '<span class="tag ' + cls + '">' + esc(probe.rttMs) + ' ms</span>';
        } else {
          latency = '<span class="tag warn" title="' + esc(probe.error || '') + '">失败</span>';
        }
      }
      html += '<tr><td>' + esc(l.id) + '</td><td>' + esc(l.name) + '</td><td>' + esc(l.region) + '</td><td>' +
        esc(l.kind) + '</td><td class="muted">' + esc(l.server) + ':' + esc(l.port) + '</td><td>' + latency + '</td><td>' +
        (l.enabled ? '<span class="tag ok">启用</span>' : '<span class="tag warn">停用</span>') +
        ' <button data-probe="' + esc(l.id) + '">测速</button></td></tr>';
      opts += '<option value="' + esc(l.id) + '">' + esc(l.name) + '（' + esc(l.region) + '）</option>';
    });
    box.innerHTML = html + '</table>';
    select.innerHTML = opts;
    Array.prototype.forEach.call(box.querySelectorAll('[data-probe]'), function (btn) {
      btn.addEventListener('click', function () {
        btn.textContent = '测试中';
        api('/api/admin/lines/probe', { method: 'POST', body: { ids: [btn.getAttribute('data-probe')] } })
          .then(function (data) {
            document.getElementById('probeResult').textContent = summarizeProbe(data);
            return load();
          }).catch(function (error) { btn.textContent = '测速'; fail(error); });
      });
    });
  }

  function renderAccounts(data) {
    var box = document.getElementById('accounts');
    var list = data.accounts || [];
    var mode = data.accessControl || {};
    var cap = data.capacity || {};
    var capText = '';
    if (cap.dhcpPool) {
      capText = ' · 地址池 ' + cap.dhcpPool + ' / 启用账号 ' + (cap.enabledAccounts || 0) +
        (cap.enough === false ? ' <span class="tag warn">地址池不够，先扩 DHCP 范围</span>' : ' <span class="tag ok">够用</span>');
    }
    if (cap.sharedLines && cap.sharedLines.length) {
      capText += ' · <span class="tag warn">' + cap.sharedLines.length + ' 条线路被多个账号共用（出口 IP 相同）</span>';
    }
    document.getElementById('mode').innerHTML =
      '当前模式：<b>' + (mode.mode === 'session' ? '账号登录' : '设备预授权') + '</b> · 宽限期 ' +
      esc(mode.graceMinutes) + ' 分钟' + capText;
    document.getElementById('grace').value = mode.graceMinutes || 5;
    if (list.length === 0) { box.textContent = '还没有接入账号'; return; }
    var html = '<table><tr><th>账号</th><th>线路</th><th>到期</th><th>状态</th><th></th></tr>';
    list.forEach(function (a) {
      var state = a.revokedAt ? '已撤销' : (a.enabled ? '启用' : '停用');
      html += '<tr><td>' + esc(a.username) + '</td><td>' + esc(a.lineId) + '</td><td class="muted">' +
        esc(a.expiresAt || '长期') + '</td><td><span class="tag ' + (state === '启用' ? 'ok' : 'warn') + '">' +
        state + '</span></td><td><button data-toggle="' + esc(a.id) + '" data-enabled="' + (a.enabled ? '0' : '1') +
        '">' + (a.enabled ? '停用' : '启用') + '</button></td></tr>';
    });
    box.innerHTML = html + '</table>';
    Array.prototype.forEach.call(box.querySelectorAll('[data-toggle]'), function (btn) {
      btn.addEventListener('click', function () {
        api('/api/admin/access-accounts/' + btn.getAttribute('data-toggle'), {
          method: 'PATCH',
          body: { enabled: btn.getAttribute('data-enabled') === '1' }
        }).then(load).catch(fail);
      });
    });
  }

  function load() {
    clearErr();
    sessionStorage.setItem('lp_admin_token', tokenInput.value);
    return Promise.all([
      api('/api/admin/overview'),
      api('/api/admin/lines'),
      api('/api/admin/access-accounts')
    ]).then(function (results) {
      var overview = results[0] || {};
      renderDevices(overview.devices || overview.routers || []);
      renderLines(results[1].lines || []);
      renderAccounts(results[2]);
    }).catch(fail);
  }

  function credential() {
    var kind = document.getElementById('lineKind').value;
    var secret = document.getElementById('credSecret').value.trim();
    var sni = document.getElementById('credSni').value.trim();
    var wsPath = document.getElementById('credPath').value.trim();
    if (kind === 'shadowsocks') {
      return { kind: 'shadowsocks', method: document.getElementById('ssMethod').value.trim(), password: secret };
    }
    if (kind === 'trojan') {
      var trojan = { kind: 'trojan', password: secret, tls: { serverName: sni || document.getElementById('lineServer').value.trim(), alpn: [], allowInsecure: false } };
      return trojan;
    }
    if (kind === 'vless') {
      return {
        kind: 'vless',
        uuid: secret,
        tls: sni ? { serverName: sni, alpn: [], allowInsecure: false } : null,
        transport: wsPath ? { type: 'ws', path: wsPath } : { type: 'tcp' }
      };
    }
    return { kind: 'socks5', username: document.getElementById('accUser').value.trim() || undefined, password: secret || undefined };
  }

  function renderNodeAccounts(data) {
    var box = document.getElementById('nodeAccounts');
    var rows = data.accounts || [];
    if (rows.length === 0) { box.innerHTML = ''; return; }
    var text = rows.map(function (r) { return r.username + ',' + r.password + ',' + r.lineName; }).join('\n');
    var html = '<p class="hint">口令只显示这一次（' + rows.length + ' 个账号），请立刻复制保存：</p>' +
      '<button id="copyAccounts">复制全部（账号,密码,线路）</button>' +
      '<table style="margin-top:8px"><tr><th>账号</th><th>密码</th><th>线路</th></tr>';
    rows.forEach(function (r) {
      html += '<tr><td>' + esc(r.username) + '</td><td>' + esc(r.password) + '</td><td class="muted">' +
        esc(r.lineName) + '</td></tr>';
    });
    box.innerHTML = html + '</table>';
    var copy = document.getElementById('copyAccounts');
    copy.addEventListener('click', function () {
      navigator.clipboard.writeText(text).then(function () {
        copy.textContent = '已复制 ' + rows.length + ' 行';
      }).catch(function () {
        window.prompt('复制下面的内容', text);
      });
    });
  }

  function renderImport(target, data) {
    var box = document.getElementById(target);
    var list = data.results || [];
    var bad = list.filter(function (r) { return r.status === 'error'; });
    var text = '成功 ' + (data.created || 0) + ' 条' + (bad.length ? '，失败 ' + bad.length + ' 条' : '');
    if (bad.length) {
      text += '：' + bad.slice(0, 3).map(function (r) { return '第' + r.line + '行 ' + r.message; }).join('；');
    }
    box.innerHTML = text;
  }

  function summarizeProbe(data) {
    var summary = data.summary || {};
    var failed = (data.results || []).filter(function (r) { return !r.ok; });
    var text = '测完 ' + (summary.total || 0) + ' 条，可达 ' + (summary.reachable || 0) + '，失败 ' + (summary.failed || 0);
    if (failed.length) {
      text += '：' + failed.slice(0, 3).map(function (r) { return r.name + '(' + r.error + ')'; }).join('；');
    }
    return text;
  }

  document.getElementById('probeAll').addEventListener('click', function () {
    var btn = document.getElementById('probeAll');
    btn.disabled = true;
    btn.textContent = '测速中（最多几秒）';
    api('/api/admin/lines/probe', { method: 'POST', body: {} })
      .then(function (data) {
        document.getElementById('probeResult').textContent = summarizeProbe(data);
        return load();
      })
      .catch(fail)
      .then(function () { btn.disabled = false; btn.textContent = '全部测速'; });
  });

  document.getElementById('importNodes').addEventListener('click', function () {
    var text = document.getElementById('nodesText').value;
    if (!text.trim()) { fail(new Error('先粘贴链接')); return; }
    api('/api/admin/import/nodes', {
      method: 'POST',
      body: { text: text, accountPrefix: document.getElementById('accPrefix').value.trim() || 'jy' }
    }).then(function (data) {
      var msg = '识别 ' + data.detected + ' 条，新建线路 ' + data.linesCreated +
        ' 条，复用 ' + data.linesReused + ' 条，账号 ' + data.accounts.length + ' 个';
      if (data.errors.length) msg += '，失败 ' + data.errors.length + ' 条';
      if (data.duplicates.length) msg += '，重复跳过 ' + data.duplicates.length + ' 条';
      document.getElementById('nodeResult').innerHTML = msg;
      if (data.errors.length) {
        document.getElementById('nodeResult').innerHTML += '<br /><span style="color:#b42318">' +
          data.errors.slice(0, 3).map(function (e) { return '第' + e.line + '行 ' + e.message; }).join('<br />') + '</span>';
      }
      renderNodeAccounts(data);
      return load();
    }).catch(fail);
  });

  document.getElementById('importLines').addEventListener('click', function () {
    api('/api/admin/import/lines', {
      method: 'POST',
      body: { csv: document.getElementById('linesCsv').value, overwrite: document.getElementById('overwrite').checked }
    }).then(function (data) { renderImport('lineResult', data); return load(); }).catch(fail);
  });

  document.getElementById('importAccs').addEventListener('click', function () {
    api('/api/admin/import/accounts', {
      method: 'POST',
      body: { csv: document.getElementById('accsCsv').value }
    }).then(function (data) { renderImport('accResult', data); return load(); }).catch(fail);
  });

  document.getElementById('save').addEventListener('click', load);

  document.getElementById('addLine').addEventListener('click', function () {
    var id = document.getElementById('lineId').value.trim();
    if (!id) { fail(new Error('线路 ID 必填')); return; }
    api('/api/admin/lines', {
      method: 'POST',
      body: {
        line: {
          id: id,
          name: document.getElementById('lineName').value.trim() || id,
          region: document.getElementById('lineRegion').value.trim() || '未标注',
          server: document.getElementById('lineServer').value.trim(),
          port: Number(document.getElementById('linePort').value || 443),
          enabled: true
        },
        credential: credential()
      }
    }).then(load).catch(fail);
  });

  document.getElementById('addAcc').addEventListener('click', function () {
    api('/api/admin/access-accounts', {
      method: 'POST',
      body: {
        username: document.getElementById('accUser').value.trim(),
        password: document.getElementById('accPass').value,
        displayName: document.getElementById('accName').value.trim(),
        lineId: document.getElementById('accLine').value,
        expiresAt: document.getElementById('accExpire').value || null
      }
    }).then(load).catch(fail);
  });

  document.getElementById('toSession').addEventListener('click', function () {
    api('/api/admin/access-mode', { method: 'POST', body: { mode: 'session', graceMinutes: Number(document.getElementById('grace').value || 5) } })
      .then(load).catch(fail);
  });
  document.getElementById('toBinding').addEventListener('click', function () {
    api('/api/admin/access-mode', { method: 'POST', body: { mode: 'device_binding' } }).then(load).catch(fail);
  });
  document.getElementById('saveGrace').addEventListener('click', function () {
    api('/api/admin/access-mode', { method: 'POST', body: { mode: 'session', graceMinutes: Number(document.getElementById('grace').value || 5) } })
      .then(load).catch(fail);
  });

  if (tokenInput.value) load();
})();
</script>
</body>
</html>`;
}
