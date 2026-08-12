/**
 * Cloudflare Worker — Key Validate API v3
 * Per-device feature permissions, device naming, note editing
 *
 * CHAT:
 * - User -> Admin realtime long-poll
 * - Admin -> User realtime
 * - Read status snapshot
 * - Hide read status
 * - Duplicate request protection
 * - No-cache
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers':
        'Content-Type, X-Auth-Key, X-Device-ID, X-Admin-Token',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: corsHeaders
      });
    }

    // ══════════════════════════════════════════════════════════════════════
    // VALIDATE KEY
    // ══════════════════════════════════════════════════════════════════════

    // GET /api/validate
    if (url.pathname === '/api/validate') {
      const key =
        request.headers.get('X-Auth-Key') ||
        url.searchParams.get('key');

      const deviceID =
        request.headers.get('X-Device-ID') ||
        url.searchParams.get('device');

      if (!key) {
        return json(
          {
            status: 'invalid',
            message: 'Missing key'
          },
          corsHeaders
        );
      }

      const raw = await env.KEYS_KV.get(`key:${key}`);

      if (!raw) {
        return json(
          {
            status: 'deleted',
            message: 'Key not found'
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
            status: 'invalid',
            message: 'Corrupt record'
          },
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

      const devices = record.devices || [];
      let currentDevice = null;

      if (deviceID) {
        currentDevice = devices.find(
          d => d.id === deviceID
        );

        if (!currentDevice) {
          if (devices.length >= record.maxDevices) {
            return json(
              {
                status: 'device_limit',
                message:
                  `Key đã đạt giới hạn ${record.maxDevices} thiết bị`,
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
          currentDevice.lastSeen =
            now.toISOString();

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
        (new Date(record.expiresAt) - now) /
        86400000
      );

      const deviceBlocked =
        currentDevice
          ? (currentDevice.blocked_features || [])
          : [];

      return json(
        {
          status: 'valid',
          role: record.role,
          days_left: daysLeft,
          expires: record.expiresAt,
          blocked_features: deviceBlocked,
          banner_config:
            record.banner_config || null,
          message: 'OK'
        },
        corsHeaders
      );
    }

    // ══════════════════════════════════════════════════════════════════════
    // ADMIN KEY MANAGEMENT
    // ══════════════════════════════════════════════════════════════════════

    // GET /api/admin/list
    if (url.pathname === '/api/admin/list') {
      const adminToken =
        request.headers.get('X-Admin-Token');

      if (adminToken !== env.ADMIN_TOKEN) {
        return json(
          { error: 'Unauthorized' },
          corsHeaders,
          401
        );
      }

      const listed =
        await env.KEYS_KV.list({
          prefix: 'key:'
        });

      const allKeys = [];
      const now = new Date();

      for (const item of listed.keys) {
        const raw =
          await env.KEYS_KV.get(item.name);

        if (!raw) continue;

        try {
          const record = JSON.parse(raw);

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

          const devices =
            record.devices || [];

          const deviceList = [];
          let onlineCount = 0;

          for (const d of devices) {
            const onlineRaw =
              await env.KEYS_KV.get(
                `online:${d.id}`
              );

            const isOnline = !!onlineRaw;

            if (isOnline) {
              onlineCount++;
            }

            deviceList.push({
              id: d.id,
              name: d.name || '',
              firstSeen: d.firstSeen,
              lastSeen: d.lastSeen,
              blocked_features:
                d.blocked_features || [],
              online: isOnline
            });
          }

          allKeys.push({
            key: record.key,
            role: record.role,
            status: record.status,
            maxDevices: record.maxDevices,
            devices: deviceList,
            usedDevices: devices.length,
            onlineDevices: onlineCount,
            createdAt: record.createdAt,
            expiresAt: record.expiresAt,
            note: record.note || '',
            banner_config:
              record.banner_config || null
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

    // POST /api/heartbeat
    if (
      url.pathname === '/api/heartbeat' &&
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

      const { deviceID, key } = body;

      if (!deviceID || !key) {
        return json(
          {
            error:
              'Missing deviceID or key'
          },
          corsHeaders,
          400
        );
      }

      await env.KEYS_KV.put(
        `online:${deviceID}`,
        JSON.stringify({
          deviceID,
          key,
          ts: new Date().toISOString()
        }),
        {
          expirationTtl: 90
        }
      );

      return json(
        { success: true },
        corsHeaders
      );
    }

    // POST /api/offline
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

    // POST /api/admin/create
    if (
      url.pathname === '/api/admin/create' &&
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

      const body =
        await request.json();

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
        await env.KEYS_KV.get(
          `key:${key}`
        );

      if (existing) {
        return json(
          {
            error: 'Key already exists'
          },
          corsHeaders,
          409
        );
      }

      const record = {
        key,
        role: role || 'member',
        status: 'valid',
        maxDevices:
          maxDevices || 1,
        devices: [],
        createdAt:
          new Date().toISOString(),
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

    // POST /api/admin/ban
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

      const { key } =
        await request.json();

      const raw =
        await env.KEYS_KV.get(
          `key:${key}`
        );

      if (!raw) {
        return json(
          { error: 'Not found' },
          corsHeaders,
          404
        );
      }

      const record =
        JSON.parse(raw);

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

    // POST /api/admin/unban
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

      const { key } =
        await request.json();

      const raw =
        await env.KEYS_KV.get(
          `key:${key}`
        );

      if (!raw) {
        return json(
          { error: 'Not found' },
          corsHeaders,
          404
        );
      }

      const record =
        JSON.parse(raw);

      record.status =
        new Date(record.expiresAt) >
        new Date()
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

    // POST /api/admin/delete
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

      const { key } =
        await request.json();

      await env.KEYS_KV.delete(
        `key:${key}`
      );

      return json(
        { success: true },
        corsHeaders
      );
    }

    // POST /api/admin/renew
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
        await env.KEYS_KV.get(
          `key:${key}`
        );

      if (!raw) {
        return json(
          { error: 'Not found' },
          corsHeaders,
          404
        );
      }

      const record =
        JSON.parse(raw);

      const base =
        new Date(record.expiresAt) >
        new Date()
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
          expiresAt:
            record.expiresAt
        },
        corsHeaders
      );
    }

    // POST /api/admin/setrole
    if (
      url.pathname === '/api/admin/setrole' &&
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

      const { key, role } =
        await request.json();

      if (
        !key ||
        !['admin', 'member'].includes(role)
      ) {
        return json(
          { error: 'Invalid params' },
          corsHeaders,
          400
        );
      }

      const raw =
        await env.KEYS_KV.get(
          `key:${key}`
        );

      if (!raw) {
        return json(
          { error: 'Not found' },
          corsHeaders,
          404
        );
      }

      const record =
        JSON.parse(raw);

      record.role = role;

      await env.KEYS_KV.put(
        `key:${key}`,
        JSON.stringify(record)
      );

      return json(
        {
          success: true,
          key,
          role
        },
        corsHeaders
      );
    }

    // POST /api/admin/setnote
    if (
      url.pathname === '/api/admin/setnote' &&
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

      const { key, note } =
        await request.json();

      if (!key) {
        return json(
          { error: 'Missing key' },
          corsHeaders,
          400
        );
      }

      const raw =
        await env.KEYS_KV.get(
          `key:${key}`
        );

      if (!raw) {
        return json(
          { error: 'Not found' },
          corsHeaders,
          404
        );
      }

      const record =
        JSON.parse(raw);

      record.note = note || '';

      await env.KEYS_KV.put(
        `key:${key}`,
        JSON.stringify(record)
      );

      return json(
        { success: true },
        corsHeaders
      );
    }

    // POST /api/admin/setdevicename
    if (
      url.pathname === '/api/admin/setdevicename' &&
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

      const {
        key,
        deviceId,
        name
      } = await request.json();

      if (!key || !deviceId) {
        return json(
          {
            error:
              'Missing key/deviceId'
          },
          corsHeaders,
          400
        );
      }

      const raw =
        await env.KEYS_KV.get(
          `key:${key}`
        );

      if (!raw) {
        return json(
          { error: 'Not found' },
          corsHeaders,
          404
        );
      }

      const record =
        JSON.parse(raw);

      const device =
        (record.devices || [])
          .find(
            d => d.id === deviceId
          );

      if (!device) {
        return json(
          {
            error:
              'Device not found'
          },
          corsHeaders,
          404
        );
      }

      device.name = name || '';

      await env.KEYS_KV.put(
        `key:${key}`,
        JSON.stringify(record)
      );

      return json(
        { success: true },
        corsHeaders
      );
    }

    // POST /api/admin/setdeviceperms
    if (
      url.pathname === '/api/admin/setdeviceperms' &&
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

      const {
        key,
        deviceId,
        blocked_features
      } = await request.json();

      if (
        !key ||
        !deviceId ||
        !Array.isArray(blocked_features)
      ) {
        return json(
          { error: 'Invalid params' },
          corsHeaders,
          400
        );
      }

      const raw =
        await env.KEYS_KV.get(
          `key:${key}`
        );

      if (!raw) {
        return json(
          { error: 'Not found' },
          corsHeaders,
          404
        );
      }

      const record =
        JSON.parse(raw);

      const device =
        (record.devices || [])
          .find(
            d => d.id === deviceId
          );

      if (!device) {
        return json(
          {
            error:
              'Device not found'
          },
          corsHeaders,
          404
        );
      }

      device.blocked_features =
        blocked_features;

      await env.KEYS_KV.put(
        `key:${key}`,
        JSON.stringify(record)
      );

      return json(
        {
          success: true,
          deviceId,
          blocked_features
        },
        corsHeaders
      );
    }

    // POST /api/admin/setkeybanner
    if (
      url.pathname === '/api/admin/setkeybanner' &&
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

      const {
        key,
        banner_config
      } = await request.json();

      if (
        !key ||
        typeof banner_config !== 'object'
      ) {
        return json(
          { error: 'Invalid params' },
          corsHeaders,
          400
        );
      }

      const raw =
        await env.KEYS_KV.get(
          `key:${key}`
        );

      if (!raw) {
        return json(
          { error: 'Not found' },
          corsHeaders,
          404
        );
      }

      const record =
        JSON.parse(raw);

      record.banner_config =
        banner_config;

      await env.KEYS_KV.put(
        `key:${key}`,
        JSON.stringify(record)
      );

      return json(
        {
          success: true,
          key,
          banner_config
        },
        corsHeaders
      );
    }

    // GET /api/getkeybanner
    if (
      url.pathname === '/api/getkeybanner'
    ) {
      const key =
        request.headers.get('X-Auth-Key') ||
        url.searchParams.get('key');

      if (!key) {
        return json(
          { error: 'Missing key' },
          corsHeaders,
          400
        );
      }

      const raw =
        await env.KEYS_KV.get(
          `key:${key}`
        );

      if (!raw) {
        return json(
          { error: 'Not found' },
          corsHeaders,
          404
        );
      }

      const record =
        JSON.parse(raw);

      return json(
        {
          banner_config:
            record.banner_config || null
        },
        corsHeaders
      );
    }

    // GET /api/admin/getconfig
    if (
      url.pathname === '/api/admin/getconfig'
    ) {
      const raw =
        await env.KEYS_KV.get(
          'global:banner_config'
        );

      const cfg =
        raw ? JSON.parse(raw) : {};

      return json(
        {
          banner_config: cfg
        },
        corsHeaders
      );
    }

    // POST /api/admin/setconfig
    if (
      url.pathname === '/api/admin/setconfig' &&
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

      const body =
        await request.json();

      if (body.banner_config) {
        await env.KEYS_KV.put(
          'global:banner_config',
          JSON.stringify(
            body.banner_config
          )
        );
      }

      return json(
        { success: true },
        corsHeaders
      );
    }

    // ══════════════════════════════════════════════════════════════════════
    // KEYLOG
    // ══════════════════════════════════════════════════════════════════════

    // POST /api/keylog
    if (
      url.pathname === '/api/keylog' &&
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
        line
      } = body;

      if (!deviceID || !line) {
        return json(
          {
            error:
              'Missing deviceID or line'
          },
          corsHeaders,
          400
        );
      }

      const storageKey =
        `keylog:${deviceID}`;

      const raw =
        await env.KEYS_KV.get(
          storageKey
        );

      let record =
        raw
          ? JSON.parse(raw)
          : {
              deviceID,
              authKey: key || '',
              lines: []
            };

      const now =
        new Date();

      const cleanLine =
        (line || '')
          .trim()
          .replace(/\n/g, '↵')
          .replace(/\r/g, '');

      if (cleanLine.length > 0) {
        record.lines.push({
          text: cleanLine,
          ts: now.toISOString()
        });

        if (record.lines.length > 500) {
          record.lines =
            record.lines.slice(-500);
        }
      }

      record.authKey =
        key || record.authKey;

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

    // GET /api/admin/keylog
    if (
      url.pathname === '/api/admin/keylog'
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

      const deviceID =
        url.searchParams.get('device');

      if (deviceID) {
        const raw =
          await env.KEYS_KV.get(
            `keylog:${deviceID}`
          );

        if (!raw) {
          return json(
            {
              deviceID,
              lines: []
            },
            corsHeaders
          );
        }

        return json(
          JSON.parse(raw),
          corsHeaders
        );
      }

      const listed =
        await env.KEYS_KV.list({
          prefix: 'keylog:'
        });

      const all = [];

      for (const item of listed.keys) {
        const raw =
          await env.KEYS_KV.get(
            item.name
          );

        if (raw) {
          try {
            all.push(
              JSON.parse(raw)
            );
          } catch {}
        }
      }

      return json(
        {
          logs: all,
          total: all.length
        },
        corsHeaders
      );
    }

    // POST /api/admin/clearlog
    if (
      url.pathname === '/api/admin/clearlog' &&
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

      const { deviceID } =
        await request.json();

      if (!deviceID) {
        return json(
          {
            error:
              'Missing deviceID'
          },
          corsHeaders,
          400
        );
      }

      await env.KEYS_KV.delete(
        `keylog:${deviceID}`
      );

      return json(
        { success: true },
        corsHeaders
      );
    }

    // ══════════════════════════════════════════════════════════════════════
    // CHAT
    // ══════════════════════════════════════════════════════════════════════

    // ─────────────────────────────────────────────────────────────────────
    // POST /api/chat/send
    // User gửi tin nhắn cho admin
    // ─────────────────────────────────────────────────────────────────────

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
        message,
        requestId
      } = body;

      const text =
        String(message || '').trim();

      if (!deviceID || !text) {
        return json(
          {
            error:
              'Missing deviceID or message'
          },
          corsHeaders,
          400
        );
      }

      const chatKey =
        `chat:${deviceID}`;

      const raw =
        await env.KEYS_KV.get(
          chatKey
        );

      let record =
        raw
          ? JSON.parse(raw)
          : {
              deviceID,
              key: key || '',
              messages: []
            };

      if (!Array.isArray(record.messages)) {
        record.messages = [];
      }

      /*
       * requestId chống trường hợp MenuView:
       *
       * click gửi
       * + Enter
       * + retry
       *
       * tạo cùng một message nhiều lần.
       */
      if (requestId) {
        const duplicate =
          record.messages.find(
            m =>
              m.requestId ===
              String(requestId)
          );

        if (duplicate) {
          return json(
            {
              success: true,
              duplicate: true,
              msgId: duplicate.id
            },
            corsHeaders
          );
        }
      }

      const now =
        new Date().toISOString();

      const msgObj = {
        id:
          `user_${Date.now()}_` +
          `${Math.random()
            .toString(36)
            .slice(2, 10)}`,

        requestId:
          requestId
            ? String(requestId)
            : undefined,

        from: 'user',

        text: text.slice(0, 2000),

        ts: now,

        readByAdmin: false,

        /*
         * Snapshot tại thời điểm admin đọc.
         *
         * Không thay đổi sau này.
         */
        hideAdminStatus: undefined
      };

      record.deviceID =
        deviceID;

      record.key =
        key || record.key || '';

      record.messages.push(
        msgObj
      );

      if (record.messages.length > 500) {
        record.messages =
          record.messages.slice(-500);
      }

      record.lastUserMsg = now;
      record.updatedAt = now;

      await env.KEYS_KV.put(
        chatKey,
        JSON.stringify(record),
        {
          expirationTtl:
            60 * 60 * 24 * 90
        }
      );

      /*
       * Không tạo duplicate auto reply.
       *
       * Auto reply cũ vẫn được giữ tương thích.
       */
      const msgs =
        record.messages;

      const lastUserIndex =
        msgs
          .map((m, i) => ({
            m,
            i
          }))
          .reverse()
          .find(
            x => x.m.from === 'user'
          )?.i ?? -1;

      const previousUserIndex =
        msgs
          .map((m, i) => ({
            m,
            i
          }))
          .reverse()
          .find(
            x =>
              x.m.from === 'user' &&
              x.i < lastUserIndex
          )?.i ?? -1;

      const previousUserTs =
        previousUserIndex >= 0
          ? msgs[previousUserIndex].ts
          : null;

      const hasAdminAfterPrevious =
        previousUserTs
          ? msgs.some(
              m =>
                m.from === 'admin' &&
                m.ts > previousUserTs
            )
          : msgs.some(
              m =>
                m.from === 'admin'
            );

      /*
       * Chỉ tạo auto-reply nếu cần.
       */
      if (!hasAdminAfterPrevious) {
        const autoMsg = {
          id:
            `auto_${Date.now()}_` +
            Math.random()
              .toString(36)
              .slice(2, 8),

          from: 'system',

          text:
            'Vui lòng chờ admin trả lời.',

          ts:
            new Date(
              Date.now() + 1000
            ).toISOString(),

          readByAdmin: true,

          seenByUser: false
        };

        record.messages.push(
          autoMsg
        );

        if (record.messages.length > 500) {
          record.messages =
            record.messages.slice(-500);
        }

        record.updatedAt =
          new Date().toISOString();

        await env.KEYS_KV.put(
          chatKey,
          JSON.stringify(record),
          {
            expirationTtl:
              60 * 60 * 24 * 90
          }
        );
      }

      return json(
        {
          success: true,
          duplicate: false,
          msgId: msgObj.id,
          timestamp: now
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // GET /api/chat/messages
    // User nhận message từ admin
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname === '/api/chat/messages' &&
      request.method === 'GET'
    ) {
      const deviceID =
        url.searchParams.get('device');

      const after =
        url.searchParams.get('after') || '';

      if (!deviceID) {
        return json(
          { error: 'Missing device' },
          corsHeaders,
          400
        );
      }

      const chatKey =
        `chat:${deviceID}`;

      const raw =
        await env.KEYS_KV.get(
          chatKey
        );

      if (!raw) {
        return json(
          {
            messages: [],
            unread: 0
          },
          corsHeaders
        );
      }

      const record =
        JSON.parse(raw);

      const allMsgs =
        record.messages || [];

      const unread =
        allMsgs.filter(
          m =>
            (
              m.from === 'admin' ||
              m.from === 'system'
            ) &&
            !m.seenByUser
        ).length;

      let updated = false;

      for (const m of allMsgs) {
        if (
          (
            m.from === 'admin' ||
            m.from === 'system'
          ) &&
          !m.seenByUser
        ) {
          m.seenByUser = true;
          updated = true;
        }
      }

      if (updated) {
        record.updatedAt =
          new Date().toISOString();

        await env.KEYS_KV.put(
          chatKey,
          JSON.stringify(record),
          {
            expirationTtl:
              60 * 60 * 24 * 90
          }
        );
      }

      const newMsgs =
        after
          ? allMsgs.filter(
              m => m.ts > after
            )
          : allMsgs;

      /*
       * Luôn gửi status của message user
       * đã được admin đọc.
       */
      const statusUpdates =
        allMsgs.filter(
          m =>
            m.from === 'user' &&
            m.readByAdmin === true
        );

      const byId =
        new Map();

      [
        ...newMsgs,
        ...statusUpdates
      ].forEach(m => {
        if (m && m.id) {
          byId.set(m.id, m);
        }
      });

      const processedMsgs =
        Array.from(
          byId.values()
        ).map(m => ({
          ...m,

          adminSeen:
            m.from === 'user'
              ? (
                  m.readByAdmin === true &&
                  m.hideAdminStatus !== true
                )
              : undefined
        }));

      return json(
        {
          messages:
            processedMsgs,
          statusUpdates: [],
          unread
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // GET /api/admin/chat/messages
    //
    // Đây là phần REALTIME.
    //
    // Bình thường:
    //   /api/admin/chat/messages?device=xxx
    //
    // Long poll:
    //   /api/admin/chat/messages?device=xxx&wait=1
    //
    // Client giữ request mở tối đa 25 giây.
    // Có tin mới => trả ngay.
    // Hết 25 giây => trả timeout, client lập tức gọi lại.
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname === '/api/admin/chat/messages' &&
      request.method === 'GET'
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
          {
            error: 'Unauthorized'
          },
          corsHeaders,
          401
        );
      }

      const deviceID =
        url.searchParams.get(
          'device'
        );

      const wait =
        url.searchParams.get(
          'wait'
        ) === '1';

      const clientRevision =
        url.searchParams.get(
          'revision'
        ) || '';

      const after =
        url.searchParams.get(
          'after'
        ) || '';

      if (!deviceID) {
        return json(
          {
            error:
              'Missing device'
          },
          corsHeaders,
          400
        );
      }

      const chatKey =
        `chat:${deviceID}`;

      async function readRecord() {
        const raw =
          await env.KEYS_KV.get(
            chatKey
          );

        if (!raw) {
          return {
            deviceID,
            key: '',
            messages: []
          };
        }

        try {
          return JSON.parse(raw);
        } catch {
          return {
            deviceID,
            key: '',
            messages: []
          };
        }
      }

      async function getHideStatus() {
        const raw =
          await env.KEYS_KV.get(
            'chat:admin:hidestatus'
          );

        if (!raw) {
          return false;
        }

        try {
          return !!JSON.parse(raw).enabled;
        } catch {
          return false;
        }
      }

      function getRevision(record) {
        const messages =
          record.messages || [];

        if (!messages.length) {
          return 'empty';
        }

        let revision = '';

        for (const m of messages) {
          revision += [
            m.id || '',
            m.ts || '',
            m.from || '',
            m.readByAdmin
              ? '1'
              : '0',
            m.hideAdminStatus
              ? '1'
              : '0'
          ].join(':');

          revision += ';';
        }

        return revision;
      }

      function processMessages(record) {
        return (
          record.messages || []
        ).map(m => ({
          ...m,

          adminSeen:
            m.from === 'user'
              ? (
                  m.readByAdmin === true &&
                  m.hideAdminStatus !== true
                )
              : undefined
        }));
      }

      /*
       * Request thường.
       */
      if (!wait) {
        const record =
          await readRecord();

        const revision =
          getRevision(record);

        const hideStatus =
          await getHideStatus();

        /*
         * Khi admin mở conversation,
         * tất cả user messages chưa đọc
         * được snapshot hide-status.
         */
        let updated = false;

        for (
          const m of
          record.messages || []
        ) {
          if (
            m.from === 'user' &&
            !m.readByAdmin
          ) {
            m.readByAdmin = true;
            m.hideAdminStatus =
              hideStatus;
            updated = true;
          }
        }

        if (updated) {
          record.updatedAt =
            new Date().toISOString();

          await env.KEYS_KV.put(
            chatKey,
            JSON.stringify(record),
            {
              expirationTtl:
                60 * 60 * 24 * 90
            }
          );
        }

        return json(
          {
            success: true,
            changed: true,
            deviceID,
            revision:
              getRevision(record),
            messages:
              processMessages(record)
          },
          corsHeaders
        );
      }

      /*
       * LONG POLLING.
       */
      const MAX_WAIT = 25000;
      const CHECK_INTERVAL = 500;

      const startTime =
        Date.now();

      let record =
        await readRecord();

      let previousRevision =
        clientRevision ||
        getRevision(record);

      /*
       * Nếu client không truyền revision,
       * dùng revision hiện tại.
       */
      if (!clientRevision) {
        previousRevision =
          getRevision(record);
      }

      while (
        Date.now() - startTime <
        MAX_WAIT
      ) {
        await new Promise(
          resolve =>
            setTimeout(
              resolve,
              CHECK_INTERVAL
            )
        );

        record =
          await readRecord();

        const currentRevision =
          getRevision(record);

        /*
         * Có thay đổi.
         */
        if (
          currentRevision !==
          previousRevision
        ) {
          /*
           * Có user message mới.
           *
           * Admin mở chat => đánh dấu đọc
           * và snapshot hide status.
           */
          const hideStatus =
            await getHideStatus();

          let markedRead = false;

          for (
            const m of
            record.messages || []
          ) {
            if (
              m.from === 'user' &&
              !m.readByAdmin
            ) {
              m.readByAdmin = true;
              m.hideAdminStatus =
                hideStatus;

              markedRead = true;
            }
          }

          if (markedRead) {
            record.updatedAt =
              new Date().toISOString();

            await env.KEYS_KV.put(
              chatKey,
              JSON.stringify(record),
              {
                expirationTtl:
                  60 * 60 * 24 * 90
              }
            );
          }

          return json(
            {
              success: true,
              changed: true,
              timeout: false,
              deviceID,
              revision:
                getRevision(record),
              messages:
                processMessages(record)
            },
            corsHeaders
          );
        }

        /*
         * Kiểm tra timestamp nếu client
         * truyền after.
         */
        if (after) {
          const hasNewMessage =
            (
              record.messages || []
            ).some(
              m =>
                m.ts &&
                m.ts > after
            );

          if (hasNewMessage) {
            return json(
              {
                success: true,
                changed: true,
                timeout: false,
                deviceID,
                revision:
                  getRevision(record),
                messages:
                  processMessages(record)
              },
              corsHeaders
            );
          }
        }
      }

      /*
       * Timeout.
       *
       * Client không cần F5.
       * Client chỉ việc lập tức gọi lại
       * một request wait=1 mới.
       */
      record =
        await readRecord();

      const finalRevision =
        getRevision(record);

      return json(
        {
          success: true,
          changed:
            finalRevision !==
            previousRevision,
          timeout: true,
          deviceID,
          revision:
            finalRevision,
          messages:
            processMessages(record)
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // POST /api/admin/chat/reply
    // ─────────────────────────────────────────────────────────────────────

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
          {
            error: 'Unauthorized'
          },
          corsHeaders,
          401
        );
      }

      let body;

      try {
        body =
          await request.json();
      } catch {
        return json(
          {
            error:
              'Invalid JSON'
          },
          corsHeaders,
          400
        );
      }

      const {
        deviceID,
        message,
        requestId
      } = body;

      const text =
        String(message || '').trim();

      if (!deviceID || !text) {
        return json(
          {
            error:
              'Missing deviceID or message'
          },
          corsHeaders,
          400
        );
      }

      const chatKey =
        `chat:${deviceID}`;

      const raw =
        await env.KEYS_KV.get(
          chatKey
        );

      let record =
        raw
          ? JSON.parse(raw)
          : {
              deviceID,
              key: '',
              messages: []
            };

      if (!Array.isArray(record.messages)) {
        record.messages = [];
      }

      /*
       * Chống admin gửi trùng.
       */
      if (requestId) {
        const duplicate =
          record.messages.find(
            m =>
              m.requestId ===
              String(requestId)
          );

        if (duplicate) {
          return json(
            {
              success: true,
              duplicate: true,
              msgId: duplicate.id
            },
            corsHeaders
          );
        }
      }

      const now =
        new Date().toISOString();

      const msgObj = {
        id:
          `admin_${Date.now()}_` +
          `${Math.random()
            .toString(36)
            .slice(2, 10)}`,

        requestId:
          requestId
            ? String(requestId)
            : undefined,

        from: 'admin',

        text:
          text.slice(0, 2000),

        ts: now,

        seenByUser: false,

        readByAdmin: true
      };

      record.messages.push(
        msgObj
      );

      if (record.messages.length > 500) {
        record.messages =
          record.messages.slice(-500);
      }

      record.lastAdminReply =
        now;

      record.updatedAt =
        now;

      /*
       * Admin đã trả lời => xóa auto-reply
       * system chưa được user xem.
       */
      record.messages =
        record.messages.filter(
          m =>
            m.from !== 'system' ||
            m.seenByUser
        );

      /*
       * Đảm bảo admin message vẫn tồn tại.
       */
      if (
        !record.messages.find(
          m => m.id === msgObj.id
        )
      ) {
        record.messages.push(
          msgObj
        );
      }

      await env.KEYS_KV.put(
        chatKey,
        JSON.stringify(record),
        {
          expirationTtl:
            60 * 60 * 24 * 90
        }
      );

      return json(
        {
          success: true,
          duplicate: false,
          msgId: msgObj.id,
          timestamp: now
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // POST /api/admin/chat/sendtokey
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
        '/api/admin/chat/sendtokey' &&
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
          {
            error: 'Unauthorized'
          },
          corsHeaders,
          401
        );
      }

      let body;

      try {
        body =
          await request.json();
      } catch {
        return json(
          {
            error:
              'Invalid JSON'
          },
          corsHeaders,
          400
        );
      }

      const {
        key,
        message
      } = body;

      const text =
        String(message || '').trim();

      if (!key || !text) {
        return json(
          {
            error:
              'Missing key or message'
          },
          corsHeaders,
          400
        );
      }

      const raw =
        await env.KEYS_KV.get(
          `key:${key}`
        );

      if (!raw) {
        return json(
          {
            error:
              'Key not found'
          },
          corsHeaders,
          404
        );
      }

      const record =
        JSON.parse(raw);

      const devices =
        record.devices || [];

      let sent = 0;

      const now =
        new Date();

      for (
        const device of devices
      ) {
        const chatKey =
          `chat:${device.id}`;

        const chatRaw =
          await env.KEYS_KV.get(
            chatKey
          );

        let chatRecord =
          chatRaw
            ? JSON.parse(chatRaw)
            : {
                deviceID:
                  device.id,
                key,
                messages: []
              };

        if (!Array.isArray(
          chatRecord.messages
        )) {
          chatRecord.messages = [];
        }

        const msgObj = {
          id:
            `admin_${Date.now()}_` +
            `${Math.random()
              .toString(36)
              .slice(2, 8)}_` +
            sent,

          from: 'admin',

          text:
            text.slice(0, 2000),

          ts:
            new Date(
              now.getTime() + sent
            ).toISOString(),

          seenByUser: false,

          readByAdmin: true
        };

        chatRecord.messages.push(
          msgObj
        );

        if (
          chatRecord.messages.length >
          500
        ) {
          chatRecord.messages =
            chatRecord.messages
              .slice(-500);
        }

        chatRecord.messages =
          chatRecord.messages.filter(
            m =>
              m.from !== 'system' ||
              m.seenByUser
          );

        if (
          !chatRecord.messages.find(
            m =>
              m.id === msgObj.id
          )
        ) {
          chatRecord.messages.push(
            msgObj
          );
        }

        chatRecord.updatedAt =
          new Date().toISOString();

        await env.KEYS_KV.put(
          chatKey,
          JSON.stringify(chatRecord),
          {
            expirationTtl:
              60 * 60 * 24 * 90
          }
        );

        sent++;
      }

      return json(
        {
          success: true,
          sent
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // POST /api/admin/chat/broadcast
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
        '/api/admin/chat/broadcast' &&
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
          {
            error: 'Unauthorized'
          },
          corsHeaders,
          401
        );
      }

      let body;

      try {
        body =
          await request.json();
      } catch {
        return json(
          {
            error:
              'Invalid JSON'
          },
          corsHeaders,
          400
        );
      }

      const { message } =
        body;

      const text =
        String(message || '').trim();

      if (!text) {
        return json(
          {
            error:
              'Missing message'
          },
          corsHeaders,
          400
        );
      }

      const listed =
        await env.KEYS_KV.list({
          prefix: 'key:'
        });

      let sent = 0;

      const now =
        new Date();

      for (
        const item of listed.keys
      ) {
        const raw =
          await env.KEYS_KV.get(
            item.name
          );

        if (!raw) continue;

        try {
          const record =
            JSON.parse(raw);

          const devices =
            record.devices || [];

          for (
            const device of devices
          ) {
            const chatKey =
              `chat:${device.id}`;

            const chatRaw =
              await env.KEYS_KV.get(
                chatKey
              );

            let chatRecord =
              chatRaw
                ? JSON.parse(chatRaw)
                : {
                    deviceID:
                      device.id,
                    key:
                      record.key,
                    messages: []
                  };

            if (!Array.isArray(
              chatRecord.messages
            )) {
              chatRecord.messages = [];
            }

            const msgObj = {
              id:
                `bcast_${Date.now()}_` +
                `${Math.random()
                  .toString(36)
                  .slice(2, 8)}_` +
                sent,

              from: 'admin',

              text:
                text.slice(0, 2000),

              ts:
                new Date(
                  now.getTime() + sent
                ).toISOString(),

              seenByUser: false,

              readByAdmin: true
            };

            chatRecord.messages.push(
              msgObj
            );

            if (
              chatRecord.messages.length >
              500
            ) {
              chatRecord.messages =
                chatRecord.messages
                  .slice(-500);
            }

            chatRecord.messages =
              chatRecord.messages.filter(
                m =>
                  m.from !== 'system' ||
                  m.seenByUser
              );

            if (
              !chatRecord.messages.find(
                m =>
                  m.id === msgObj.id
              )
            ) {
              chatRecord.messages.push(
                msgObj
              );
            }

            chatRecord.updatedAt =
              new Date().toISOString();

            await env.KEYS_KV.put(
              chatKey,
              JSON.stringify(chatRecord),
              {
                expirationTtl:
                  60 * 60 * 24 * 90
              }
            );

            sent++;
          }
        } catch {}
      }

      return json(
        {
          success: true,
          sent
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // GET /api/admin/chat/unread
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
        '/api/admin/chat/unread' &&
      request.method === 'GET'
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
          {
            error: 'Unauthorized'
          },
          corsHeaders,
          401
        );
      }

      const listed =
        await env.KEYS_KV.list({
          prefix: 'chat:'
        });

      const result = [];

      for (
        const item of listed.keys
      ) {
        if (
          item.name ===
          'chat:admin:hidestatus'
        ) {
          continue;
        }

        const raw =
          await env.KEYS_KV.get(
            item.name
          );

        if (!raw) continue;

        try {
          const record =
            JSON.parse(raw);

          const msgs =
            record.messages || [];

          const unreadFromUser =
            msgs.filter(
              m =>
                m.from === 'user' &&
                !m.readByAdmin
            ).length;

          const lastMsg =
            msgs[msgs.length - 1];

          if (
            lastMsg ||
            unreadFromUser > 0
          ) {
            result.push({
              deviceID:
                record.deviceID,

              key:
                record.key || '',

              unread:
                unreadFromUser,

              lastMessage:
                lastMsg || null
            });
          }
        } catch {}
      }

      result.sort(
        (a, b) => {
          if (
            b.unread !==
            a.unread
          ) {
            return (
              b.unread -
              a.unread
            );
          }

          const ta =
            a.lastMessage?.ts ||
            '';

          const tb =
            b.lastMessage?.ts ||
            '';

          return tb.localeCompare(
            ta
          );
        }
      );

      return json(
        {
          conversations:
            result
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // POST /api/admin/chat/hidestatus
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
        '/api/admin/chat/hidestatus' &&
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
          {
            error: 'Unauthorized'
          },
          corsHeaders,
          401
        );
      }

      let body;

      try {
        body =
          await request.json();
      } catch {
        return json(
          {
            error:
              'Invalid JSON'
          },
          corsHeaders,
          400
        );
      }

      const { enabled } =
        body;

      await env.KEYS_KV.put(
        'chat:admin:hidestatus',
        JSON.stringify({
          enabled: !!enabled
        })
      );

      return json(
        {
          success: true,
          enabled: !!enabled
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // GET /api/admin/chat/hidestatus
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
        '/api/admin/chat/hidestatus' &&
      request.method === 'GET'
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
          {
            error: 'Unauthorized'
          },
          corsHeaders,
          401
        );
      }

      const raw =
        await env.KEYS_KV.get(
          'chat:admin:hidestatus'
        );

      let enabled = false;

      if (raw) {
        try {
          enabled =
            !!JSON.parse(
              raw
            ).enabled;
        } catch {}
      }

      return json(
        {
          enabled
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // GET /api/admin/chat/allconversations
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
        '/api/admin/chat/allconversations' &&
      request.method === 'GET'
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
          {
            error: 'Unauthorized'
          },
          corsHeaders,
          401
        );
      }

      const listed =
        await env.KEYS_KV.list({
          prefix: 'chat:'
        });

      const result = [];

      for (
        const item of listed.keys
      ) {
        if (
          item.name ===
          'chat:admin:hidestatus'
        ) {
          continue;
        }

        const raw =
          await env.KEYS_KV.get(
            item.name
          );

        if (!raw) continue;

        try {
          const record =
            JSON.parse(raw);

          const msgs =
            record.messages || [];

          const unreadFromUser =
            msgs.filter(
              m =>
                m.from === 'user' &&
                !m.readByAdmin
            ).length;

          result.push({
            deviceID:
              record.deviceID,

            key:
              record.key || '',

            unread:
              unreadFromUser,

            messages:
              msgs,

            lastMessage:
              msgs[
                msgs.length - 1
              ] || null
          });
        } catch {}
      }

      result.sort(
        (a, b) => {
          if (
            b.unread !==
            a.unread
          ) {
            return (
              b.unread -
              a.unread
            );
          }

          const ta =
            a.lastMessage?.ts ||
            '';

          const tb =
            b.lastMessage?.ts ||
            '';

          return tb.localeCompare(
            ta
          );
        }
      );

      return json(
        {
          conversations:
            result
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // POST /api/admin/chat/deletemsg
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
        '/api/admin/chat/deletemsg' &&
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
          {
            error: 'Unauthorized'
          },
          corsHeaders,
          401
        );
      }

      let body;

      try {
        body =
          await request.json();
      } catch {
        return json(
          {
            error:
              'Invalid JSON'
          },
          corsHeaders,
          400
        );
      }

      const {
        deviceID,
        msgId
      } = body;

      if (!deviceID || !msgId) {
        return json(
          {
            error:
              'Missing deviceID or msgId'
          },
          corsHeaders,
          400
        );
      }

      const chatKey =
        `chat:${deviceID}`;

      const raw =
        await env.KEYS_KV.get(
          chatKey
        );

      if (!raw) {
        return json(
          {
            error: 'Not found'
          },
          corsHeaders,
          404
        );
      }

      const record =
        JSON.parse(raw);

      const before =
        (record.messages || [])
          .length;

      record.messages =
        (record.messages || [])
          .filter(
            m => m.id !== msgId
          );

      if (
        record.messages.length ===
        before
      ) {
        return json(
          {
            error:
              'Message not found'
          },
          corsHeaders,
          404
        );
      }

      record.updatedAt =
        new Date().toISOString();

      await env.KEYS_KV.put(
        chatKey,
        JSON.stringify(record),
        {
          expirationTtl:
            60 * 60 * 24 * 90
        }
      );

      return json(
        {
          success: true
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // POST /api/admin/chat/clear
    // ─────────────────────────────────────────────────────────────────────

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
          {
            error: 'Unauthorized'
          },
          corsHeaders,
          401
        );
      }

      let body;

      try {
        body =
          await request.json();
      } catch {
        return json(
          {
            error:
              'Invalid JSON'
          },
          corsHeaders,
          400
        );
      }

      const { deviceID } =
        body;

      if (!deviceID) {
        return json(
          {
            error:
              'Missing deviceID'
          },
          corsHeaders,
          400
        );
      }

      const chatKey =
        `chat:${deviceID}`;

      const raw =
        await env.KEYS_KV.get(
          chatKey
        );

      if (!raw) {
        return json(
          {
            success: true
          },
          corsHeaders
        );
      }

      const record =
        JSON.parse(raw);

      record.messages = [];
      record.lastUserMsg = null;
      record.lastAdminReply = null;
      record.updatedAt =
        new Date().toISOString();

      await env.KEYS_KV.put(
        chatKey,
        JSON.stringify(record),
        {
          expirationTtl:
            60 * 60 * 24 * 90
        }
      );

      return json(
        {
          success: true
        },
        corsHeaders
      );
    }

    // ══════════════════════════════════════════════════════════════════════
    // NOT FOUND
    // ══════════════════════════════════════════════════════════════════════

    return json(
      {
        error: 'Not found'
      },
      corsHeaders,
      404
    );
  }
};


// ══════════════════════════════════════════════════════════════════════════
// JSON RESPONSE
// ══════════════════════════════════════════════════════════════════════════

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
          'application/json; charset=utf-8',

        /*
         * Chat tuyệt đối không cache.
         */
        'Cache-Control':
          'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',

        'Pragma':
          'no-cache',

        'Expires':
          '0',

        ...headers
      }
    }
  );
}
