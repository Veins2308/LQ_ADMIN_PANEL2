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
      const key      = request.headers.get('X-Auth-Key') || url.searchParams.get('key');
      const deviceID = request.headers.get('X-Device-ID') || url.searchParams.get('device');

      if (!key) {
        return json(
          { status: 'invalid', message: 'Missing key' },
          corsHeaders
        );
      }

      const raw = await env.KEYS_KV.get(`key:${key}`);

      if (!raw) {
        return json(
          { status: 'deleted', message: 'Key not found' },
          corsHeaders
        );
      }

      let record;

      try {
        record = JSON.parse(raw);
      } catch {
        return json(
          { status: 'invalid', message: 'Corrupt record' },
          corsHeaders
        );
      }

      if (record.status === 'banned') {
        return json(
          {
            status: 'banned',
            message: 'Key is banned',
            role: record.role
          },
          corsHeaders
        );
      }

      const now = new Date();

      if (new Date(record.expiresAt) < now) {
        record.status = 'expired';

        await env.KEYS_KV.put(
          `key:${key}`,
          JSON.stringify(record)
        );

        return json(
          {
            status: 'expired',
            message: 'Key expired',
            role: record.role,
            days_left: 0
          },
          corsHeaders
        );
      }

      // Device management
      const devices = record.devices || [];
      let currentDevice = null;

      if (deviceID) {
        currentDevice = devices.find(d => d.id === deviceID);

        if (!currentDevice) {
          if (devices.length >= record.maxDevices) {
            return json(
              {
                status: 'device_limit',
                message: `Key đã đạt giới hạn ${record.maxDevices} thiết bị`,
                role: record.role
              },
              corsHeaders
            );
          }

          currentDevice = {
            id: deviceID,
            name: '',
            firstSeen: now.toISOString(),
            lastSeen: now.toISOString(),
            blocked_features: []
          };

          devices.push(currentDevice);
        } else {
          currentDevice.lastSeen = now.toISOString();

          if (!currentDevice.blocked_features) {
            currentDevice.blocked_features = [];
          }
        }

        record.devices = devices;

        await env.KEYS_KV.put(
          `key:${key}`,
          JSON.stringify(record)
        );
      }

      const daysLeft = Math.ceil(
        (new Date(record.expiresAt) - now) / 86400000
      );

      const deviceBlocked = currentDevice
        ? (currentDevice.blocked_features || [])
        : [];

      return json(
        {
          status: 'valid',
          role: record.role,
          days_left: daysLeft,
          expires: record.expiresAt,
          blocked_features: deviceBlocked,
          banner_config: record.banner_config || null,
          message: 'OK'
        },
        corsHeaders
      );
    }

    // ── GET /api/admin/list ────────────────────────────────────────────────
    if (url.pathname === '/api/admin/list') {
      const adminToken = request.headers.get('X-Admin-Token');

      if (adminToken !== env.ADMIN_TOKEN) {
        return json(
          { error: 'Unauthorized' },
          corsHeaders,
          401
        );
      }

      // Lấy danh sách online devices
      const onlineListed = await env.KEYS_KV.list({
        prefix: 'online:'
      });

      const onlineSet = new Set();

      for (const item of onlineListed.keys) {
        const raw = await env.KEYS_KV.get(item.name);

        if (raw) {
          try {
            const o = JSON.parse(raw);

            if (o.deviceID) {
              onlineSet.add(o.deviceID);
            }
          } catch {}
        }
      }

      // Lấy unread chat counts
      const chatListed = await env.KEYS_KV.list({
        prefix: 'chat:'
      });

      const unreadMap = {};

      for (const item of chatListed.keys) {
        const raw = await env.KEYS_KV.get(item.name);

        if (!raw) continue;

        try {
          const c = JSON.parse(raw);

          const unread = (c.messages || []).filter(
            m =>
              m.from === 'user' &&
              !m.readByAdmin
          ).length;

          if (unread > 0) {
            unreadMap[c.deviceID] = unread;
          }
        } catch {}
      }

      const listed = await env.KEYS_KV.list({
        prefix: 'key:'
      });

      const allKeys = [];

      for (const item of listed.keys) {
        const raw = await env.KEYS_KV.get(item.name);

        if (!raw) continue;

        try {
          const record = JSON.parse(raw);
          const now = new Date();

          if (
            record.status === 'valid' &&
            new Date(record.expiresAt) < now
          ) {
            record.status = 'expired';

            await env.KEYS_KV.put(
              item.name,
              JSON.stringify(record)
            );
          }

          const devices = (record.devices || []).map(d => ({
            id: d.id,
            name: d.name || '',
            firstSeen: d.firstSeen,
            lastSeen: d.lastSeen,
            blocked_features: d.blocked_features || [],
            online: onlineSet.has(d.id),
            unreadCount: unreadMap[d.id] || 0
          }));

          const onlineDevices = devices.filter(
            d => d.online
          ).length;

          allKeys.push({
            key: record.key,
            role: record.role,
            status: record.status,
            maxDevices: record.maxDevices,
            usedDevices: devices.length,
            onlineDevices,
            devices,
            createdAt: record.createdAt,
            expiresAt: record.expiresAt,
            note: record.note || '',
            banner_config: record.banner_config || null
          });
        } catch {}
      }

      allKeys.sort(
        (a, b) =>
          new Date(b.createdAt) -
          new Date(a.createdAt)
      );

      return json(
        {
          keys: allKeys,
          total: allKeys.length
        },
        corsHeaders
      );
    }

    // ── POST /api/admin/create ─────────────────────────────────────────────
    if (
      url.pathname === '/api/admin/create' &&
      request.method === 'POST'
    ) {
      const adminToken = request.headers.get('X-Admin-Token');

      if (adminToken !== env.ADMIN_TOKEN) {
        return json(
          { error: 'Unauthorized' },
          corsHeaders,
          401
        );
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return json(
          { error: 'Invalid JSON' },
          corsHeaders,
          400
        );
      }

      const {
        key,
        role,
        maxDevices,
        expiresAt,
        note
      } = body;

      if (!key || !expiresAt) {
        return json(
          {
            error:
              'Missing required fields (key, expiresAt)'
          },
          corsHeaders,
          400
        );
      }

      const existing =
        await env.KEYS_KV.get(`key:${key}`);

      if (existing) {
        return json(
          { error: 'Key already exists' },
          corsHeaders,
          409
        );
      }

      const record = {
        key,
        role: role || 'member',
        status: 'valid',
        maxDevices: maxDevices || 1,
        devices: [],
        createdAt: new Date().toISOString(),
        expiresAt,
        note: note || ''
      };

      await env.KEYS_KV.put(
        `key:${key}`,
        JSON.stringify(record)
      );

      return json(
        {
          success: true,
          key
        },
        corsHeaders
      );
    }

    // ── POST /api/admin/ban ────────────────────────────────────────────────
    if (
      url.pathname === '/api/admin/ban' &&
      request.method === 'POST'
    ) {
      const adminToken =
        request.headers.get('X-Admin-Token');

      if (adminToken !== env.ADMIN_TOKEN) {
        return json(
          { error: 'Unauthorized' },
          corsHeaders,
          401
        );
      }

      const { key } = await request.json();

      const raw =
        await env.KEYS_KV.get(`key:${key}`);

      if (!raw) {
        return json(
          { error: 'Not found' },
          corsHeaders,
          404
        );
      }

      const record = JSON.parse(raw);

      record.status = 'banned';

      await env.KEYS_KV.put(
        `key:${key}`,
        JSON.stringify(record)
      );

      return json(
        { success: true },
        corsHeaders
      );
    }

    // ── POST /api/admin/unban ──────────────────────────────────────────────
    if (
      url.pathname === '/api/admin/unban' &&
      request.method === 'POST'
    ) {
      const adminToken =
        request.headers.get('X-Admin-Token');

      if (adminToken !== env.ADMIN_TOKEN) {
        return json(
          { error: 'Unauthorized' },
          corsHeaders,
          401
        );
      }

      const { key } = await request.json();

      const raw =
        await env.KEYS_KV.get(`key:${key}`);

      if (!raw) {
        return json(
          { error: 'Not found' },
          corsHeaders,
          404
        );
      }

      const record = JSON.parse(raw);

      record.status =
        new Date(record.expiresAt) > new Date()
          ? 'valid'
          : 'expired';

      await env.KEYS_KV.put(
        `key:${key}`,
        JSON.stringify(record)
      );

      return json(
        {
          success: true,
          status: record.status
        },
        corsHeaders
      );
    }

    // ── POST /api/admin/delete ─────────────────────────────────────────────
    if (
      url.pathname === '/api/admin/delete' &&
      request.method === 'POST'
    ) {
      const adminToken =
        request.headers.get('X-Admin-Token');

      if (adminToken !== env.ADMIN_TOKEN) {
        return json(
          { error: 'Unauthorized' },
          corsHeaders,
          401
        );
      }

      const { key } = await request.json();

      await env.KEYS_KV.delete(`key:${key}`);

      return json(
        { success: true },
        corsHeaders
      );
    }

    // ── POST /api/admin/renew ──────────────────────────────────────────────
    if (
      url.pathname === '/api/admin/renew' &&
      request.method === 'POST'
    ) {
      const adminToken =
        request.headers.get('X-Admin-Token');

      if (adminToken !== env.ADMIN_TOKEN) {
        return json(
          { error: 'Unauthorized' },
          corsHeaders,
          401
        );
      }

      const { key, addDays } =
        await request.json();

      const raw =
        await env.KEYS_KV.get(`key:${key}`);

      if (!raw) {
        return json(
          { error: 'Not found' },
          corsHeaders,
          404
        );
      }

      const record = JSON.parse(raw);

      const base =
        new Date(record.expiresAt) > new Date()
          ? new Date(record.expiresAt)
          : new Date();

      record.expiresAt =
        new Date(
          base.getTime() +
          addDays * 86400000
        ).toISOString();

      if (record.status === 'expired') {
        record.status = 'valid';
      }

      await env.KEYS_KV.put(
        `key:${key}`,
        JSON.stringify(record)
      );

      return json(
        {
          success: true,
          expiresAt: record.expiresAt
        },
        corsHeaders
      );
    }

    // ── POST /api/offline ──────────────────────────────────────────────────
    if (
      url.pathname === '/api/offline' &&
      request.method === 'POST'
    ) {
      let body;

      try {
        body = await request.json();
      } catch {
        return json(
          { error: 'Invalid JSON' },
          corsHeaders,
          400
        );
      }

      const { deviceID } = body;

      if (!deviceID) {
        return json(
          { error: 'Missing deviceID' },
          corsHeaders,
          400
        );
      }

      await env.KEYS_KV.delete(
        `online:${deviceID}`
      );

      return json(
        { success: true },
        corsHeaders
      );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CHAT — USER → ADMIN
    // ═══════════════════════════════════════════════════════════════════════

    if (
      url.pathname === '/api/chat/send' &&
      request.method === 'POST'
    ) {
      let body;

      try {
        body = await request.json();
      } catch {
        return json(
          { error: 'Invalid JSON' },
          corsHeaders,
          400
        );
      }

      const {
        deviceID,
        key,
        message
      } = body;

      if (!deviceID || !message) {
        return json(
          {
            error:
              'Missing deviceID or message'
          },
          corsHeaders,
          400
        );
      }

      const storageKey =
        `chat:${deviceID}`;

      const raw =
        await env.KEYS_KV.get(storageKey);

      let record;

      try {
        record = raw
          ? JSON.parse(raw)
          : {
              deviceID,
              key: key || '',
              messages: []
            };
      } catch {
        record = {
          deviceID,
          key: key || '',
          messages: []
        };
      }

      if (!Array.isArray(record.messages)) {
        record.messages = [];
      }

      const now = new Date();
      const nowIso = now.toISOString();

      // Tin nhắn thật của user
      record.messages.push({
        id: `${Date.now()}-u-${crypto.randomUUID()}`,
        from: 'user',
        text: message,
        ts: nowIso,

        // Admin chưa đọc
        readByAdmin: false,

        // User không cần "đọc" tin của chính mình
        readByUser: true,

        auto: false
      });

      record.key = key || record.key;

      // ═══════════════════════════════════════════════════════════════════
      // AUTO REPLY
      //
      // Trường hợp 1:
      // Chưa từng có admin trả lời thật -> gửi 1 lần.
      //
      // Trường hợp 2:
      // Admin đã trả lời thật -> sau 30 phút, nếu user nhắn tiếp
      // mà admin chưa trả lời lại -> gửi lại auto reply.
      // ═══════════════════════════════════════════════════════════════════

      const lastRealAdminAt =
        record.lastRealAdminReplyAt
          ? new Date(
              record.lastRealAdminReplyAt
            ).getTime()
          : 0;

      const lastAutoAt =
        record.autoReplySentForUserAt
          ? new Date(
              record.autoReplySentForUserAt
            ).getTime()
          : 0;

      const nowMs = now.getTime();

      let shouldAutoReply = false;

      if (!lastRealAdminAt) {
        // Chưa có admin trả lời thật.
        // Chỉ gửi 1 lần.
        shouldAutoReply =
          lastAutoAt === 0;
      } else {
        const elapsed =
          nowMs - lastRealAdminAt;

        const userAfterAdmin =
          nowMs > lastRealAdminAt;

        const autoAlreadySentAfterAdmin =
          lastAutoAt > lastRealAdminAt;

        shouldAutoReply =
          userAfterAdmin &&
          !autoAlreadySentAfterAdmin &&
          elapsed >= 30 * 60 * 1000;
      }

      if (shouldAutoReply) {
        const autoIso =
          new Date().toISOString();

        record.messages.push({
          id: `${Date.now()}-a-${crypto.randomUUID()}`,
          from: 'admin',
          text:
            '⏳ Vui lòng chờ admin trả lời.',
          ts: autoIso,

          readByAdmin: true,
          readByUser: false,

          // Quan trọng:
          // Đây không phải admin trả lời thật.
          auto: true
        });

        record.autoReplySentForUserAt =
          autoIso;
      }

      // Giới hạn lịch sử
      if (record.messages.length > 200) {
        record.messages =
          record.messages.slice(-200);
      }

      await env.KEYS_KV.put(
        storageKey,
        JSON.stringify(record),
        {
          expirationTtl:
            60 * 60 * 24 * 30
        }
      );

      return json(
        {
          success: true,
          autoReply: shouldAutoReply
        },
        corsHeaders
      );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CHAT — USER GET MESSAGES
    // ═══════════════════════════════════════════════════════════════════════

    if (
      url.pathname === '/api/chat/messages'
    ) {
      const deviceID =
        request.headers.get('X-Device-ID') ||
        url.searchParams.get('device');

      if (!deviceID) {
        return json(
          { error: 'Missing deviceID' },
          corsHeaders,
          400
        );
      }

      const storageKey =
        `chat:${deviceID}`;

      const raw =
        await env.KEYS_KV.get(storageKey);

      if (!raw) {
        return json(
          {
            messages: [],
            hideReadStatus: false
          },
          corsHeaders
        );
      }

      let record;

      try {
        record = JSON.parse(raw);
      } catch {
        return json(
          {
            messages: [],
            hideReadStatus: false
          },
          corsHeaders
        );
      }

      let changed = false;

      // Admin gửi tin thật hoặc auto reply.
      // Khi game nhận được tin thì đánh dấu user đã đọc.
      for (const m of record.messages || []) {
        if (
          m.from === 'admin' &&
          !m.readByUser
        ) {
          m.readByUser = true;
          changed = true;
        }
      }

      if (changed) {
        await env.KEYS_KV.put(
          storageKey,
          JSON.stringify(record),
          {
            expirationTtl:
              60 * 60 * 24 * 30
          }
        );
      }

      return json(
        {
          messages:
            record.messages || [],

          // Đồng bộ trạng thái từ Web → Game
          hideReadStatus:
            record.hideReadStatus === true
        },
        corsHeaders
      );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CHAT — ADMIN GET CHAT
    // ═══════════════════════════════════════════════════════════════════════

    if (
      url.pathname === '/api/admin/chat'
    ) {
      const adminToken =
        request.headers.get(
          'X-Admin-Token'
        );

      if (
        adminToken !==
        env.ADMIN_TOKEN
      ) {
        return json(
          { error: 'Unauthorized' },
          corsHeaders,
          401
        );
      }

      const deviceID =
        url.searchParams.get(
          'device'
        );

      if (!deviceID) {
        return json(
          { error: 'Missing device' },
          corsHeaders,
          400
        );
      }

      const storageKey =
        `chat:${deviceID}`;

      const raw =
        await env.KEYS_KV.get(storageKey);

      if (!raw) {
        return json(
          {
            messages: [],
            hideReadStatus: false
          },
          corsHeaders
        );
      }

      let record;

      try {
        record = JSON.parse(raw);
      } catch {
        return json(
          {
            messages: [],
            hideReadStatus: false
          },
          corsHeaders
        );
      }

      let changed = false;

      // Admin mở chat => user messages được đánh dấu
      // readByAdmin.
      for (const m of record.messages || []) {
        if (
          m.from === 'user' &&
          !m.readByAdmin
        ) {
          m.readByAdmin = true;
          changed = true;
        }
      }

      if (changed) {
        await env.KEYS_KV.put(
          storageKey,
          JSON.stringify(record),
          {
            expirationTtl:
              60 * 60 * 24 * 30
          }
        );
      }

      return json(
        {
          messages:
            record.messages || [],

          hideReadStatus:
            record.hideReadStatus === true
        },
        corsHeaders
      );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CHAT — ADMIN REPLY
    // ═══════════════════════════════════════════════════════════════════════

    if (
      url.pathname ===
        '/api/admin/chat/reply' &&
      request.method === 'POST'
    ) {
      const adminToken =
        request.headers.get(
          'X-Admin-Token'
        );

      if (
        adminToken !==
        env.ADMIN_TOKEN
      ) {
        return json(
          { error: 'Unauthorized' },
          corsHeaders,
          401
        );
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return json(
          { error: 'Invalid JSON' },
          corsHeaders,
          400
        );
      }

      const {
        deviceID,
        message
      } = body;

      if (!deviceID || !message) {
        return json(
          {
            error:
              'Missing deviceID or message'
          },
          corsHeaders,
          400
        );
      }

      const storageKey =
        `chat:${deviceID}`;

      const raw =
        await env.KEYS_KV.get(storageKey);

      let record;

      try {
        record = raw
          ? JSON.parse(raw)
          : {
              deviceID,
              key: '',
              messages: []
            };
      } catch {
        record = {
          deviceID,
          key: '',
          messages: []
        };
      }

      if (!Array.isArray(record.messages)) {
        record.messages = [];
      }

      const nowIso =
        new Date().toISOString();

      // Admin trả lời thật
      record.messages.push({
        id: `${Date.now()}-a-${crypto.randomUUID()}`,
        from: 'admin',
        text: message,
        ts: nowIso,

        readByAdmin: true,
        readByUser: false,

        auto: false
      });

      // Chỉ admin reply thật mới reset trạng thái chờ.
      record.lastRealAdminReplyAt =
        nowIso;

      record.autoReplySentForUserAt =
        null;

      if (record.messages.length > 200) {
        record.messages =
          record.messages.slice(-200);
      }

      await env.KEYS_KV.put(
        storageKey,
        JSON.stringify(record),
        {
          expirationTtl:
            60 * 60 * 24 * 30
        }
      );

      return json(
        { success: true },
        corsHeaders
      );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CHAT — HIDE READ STATUS
    // ═══════════════════════════════════════════════════════════════════════

    if (
      url.pathname ===
        '/api/admin/chat/sethideread' &&
      request.method === 'POST'
    ) {
      const adminToken =
        request.headers.get(
          'X-Admin-Token'
        );

      if (
        adminToken !==
        env.ADMIN_TOKEN
      ) {
        return json(
          { error: 'Unauthorized' },
          corsHeaders,
          401
        );
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return json(
          { error: 'Invalid JSON' },
          corsHeaders,
          400
        );
      }

      const {
        deviceID,
        hideReadStatus
      } = body;

      if (!deviceID) {
        return json(
          { error: 'Missing deviceID' },
          corsHeaders,
          400
        );
      }

      const storageKey =
        `chat:${deviceID}`;

      const raw =
        await env.KEYS_KV.get(storageKey);

      let record;

      try {
        record = raw
          ? JSON.parse(raw)
          : {
              deviceID,
              key: '',
              messages: []
            };
      } catch {
        record = {
          deviceID,
          key: '',
          messages: []
        };
      }

      record.hideReadStatus =
        hideReadStatus === true;

      await env.KEYS_KV.put(
        storageKey,
        JSON.stringify(record),
        {
          expirationTtl:
            60 * 60 * 24 * 30
        }
      );

      return json(
        {
          success: true,
          hideReadStatus:
            record.hideReadStatus
        },
        corsHeaders
      );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CHAT — CLEAR
    // ═══════════════════════════════════════════════════════════════════════

    if (
      url.pathname ===
        '/api/admin/chat/clear' &&
      request.method === 'POST'
    ) {
      const adminToken =
        request.headers.get(
          'X-Admin-Token'
        );

      if (
        adminToken !==
        env.ADMIN_TOKEN
      ) {
        return json(
          { error: 'Unauthorized' },
          corsHeaders,
          401
        );
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return json(
          { error: 'Invalid JSON' },
          corsHeaders,
          400
        );
      }

      const { deviceID } = body;

      if (!deviceID) {
        return json(
          { error: 'Missing deviceID' },
          corsHeaders,
          400
        );
      }

      await env.KEYS_KV.delete(
        `chat:${deviceID}`
      );

      return json(
        { success: true },
        corsHeaders
      );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ADMIN ONLINE DEVICES
    // ═══════════════════════════════════════════════════════════════════════

    if (
      url.pathname ===
      '/api/admin/online'
    ) {
      const adminToken =
        request.headers.get(
          'X-Admin-Token'
        );

      if (
        adminToken !==
        env.ADMIN_TOKEN
      ) {
        return json(
          { error: 'Unauthorized' },
          corsHeaders,
          401
        );
      }

      const listed =
        await env.KEYS_KV.list({
          prefix: 'online:'
        });

      const onlineDevices = [];

      for (
        const item of listed.keys
      ) {
        const raw =
          await env.KEYS_KV.get(
            item.name
          );

        if (raw) {
          try {
            onlineDevices.push(
              JSON.parse(raw)
            );
          } catch {}
        }
      }

      return json(
        {
          onlineDevices,
          total:
            onlineDevices.length
        },
        corsHeaders
      );
    }

    return json(
      {
        error: 'Not found'
      },
      corsHeaders,
      404
    );
  }
};

// ═══════════════════════════════════════════════════════════════════════════
// JSON RESPONSE HELPER
// ═══════════════════════════════════════════════════════════════════════════

function json(
  data,
  headers = {},
  status = 200
) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        'Content-Type':
          'application/json',
        ...headers
      }
    }
  );
}
