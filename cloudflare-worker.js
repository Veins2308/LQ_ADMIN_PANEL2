/**
 * Cloudflare Worker — Key Validate API v3
 * Chat / Online / Auto Reply / Hide Read Status
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
        headers: corsHeaders,
      });
    }

    // ─────────────────────────────────────────────────────────────────────
    // VALIDATE KEY
    // ─────────────────────────────────────────────────────────────────────

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
            message: 'Missing key',
          },
          corsHeaders,
          400
        );
      }

      const raw =
        await env.KEYS_KV.get(`key:${key}`);

      if (!raw) {
        return json(
          {
            status: 'deleted',
            message: 'Key not found',
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
            message: 'Corrupt record',
          },
          corsHeaders
        );
      }

      if (record.status === 'banned') {
        return json(
          {
            status: 'banned',
            message: 'Key is banned',
            role: record.role,
          },
          corsHeaders
        );
      }

      const now = new Date();

      if (
        !record.expiresAt ||
        new Date(record.expiresAt) < now
      ) {
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
            days_left: 0,
          },
          corsHeaders
        );
      }

      const devices =
        Array.isArray(record.devices)
          ? record.devices
          : [];

      let currentDevice = null;

      if (deviceID) {
        currentDevice =
          devices.find(
            d => d.id === deviceID
          );

        if (!currentDevice) {
          if (
            devices.length >=
            Number(record.maxDevices || 1)
          ) {
            return json(
              {
                status: 'device_limit',
                message:
                  `Key đã đạt giới hạn ${record.maxDevices} thiết bị`,
                role: record.role,
              },
              corsHeaders
            );
          }

          currentDevice = {
            id: deviceID,
            name: '',
            firstSeen: now.toISOString(),
            lastSeen: now.toISOString(),
            blocked_features: [],
          };

          devices.push(currentDevice);
        } else {
          currentDevice.lastSeen =
            now.toISOString();

          if (
            !Array.isArray(
              currentDevice.blocked_features
            )
          ) {
            currentDevice.blocked_features = [];
          }
        }

        record.devices = devices;

        await env.KEYS_KV.put(
          `key:${key}`,
          JSON.stringify(record)
        );

        // Validate key cũng tính là online.
        await env.KEYS_KV.put(
          `online:${deviceID}`,
          JSON.stringify({
            deviceID,
            key,
            ts: now.toISOString(),
            source: 'validate',
          }),
          {
            expirationTtl: 90,
          }
        );
      }

      const daysLeft = Math.ceil(
        (
          new Date(record.expiresAt) -
          now
        ) / 86400000
      );

      return json(
        {
          status: 'valid',
          role: record.role,
          days_left: Math.max(
            0,
            daysLeft
          ),
          expires: record.expiresAt,
          blocked_features:
            currentDevice
              ? (
                  currentDevice.blocked_features ||
                  []
                )
              : [],
          banner_config:
            record.banner_config || null,
          message: 'OK',
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // ADMIN LIST
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname === '/api/admin/list'
    ) {
      const adminToken =
        request.headers.get(
          'X-Admin-Token'
        );

      if (
        adminToken !== env.ADMIN_TOKEN
      ) {
        return json(
          {
            error: 'Unauthorized',
          },
          corsHeaders,
          401
        );
      }

      const onlineListed =
        await env.KEYS_KV.list({
          prefix: 'online:',
        });

      const onlineMap = new Map();

      for (
        const item of onlineListed.keys
      ) {
        const raw =
          await env.KEYS_KV.get(
            item.name
          );

        if (!raw) continue;

        try {
          const online =
            JSON.parse(raw);

          if (online.deviceID) {
            onlineMap.set(
              online.deviceID,
              online
            );
          }
        } catch {}
      }

      const chatListed =
        await env.KEYS_KV.list({
          prefix: 'chat:',
        });

      const unreadMap = {};

      for (
        const item of chatListed.keys
      ) {
        const raw =
          await env.KEYS_KV.get(
            item.name
          );

        if (!raw) continue;

        try {
          const chat =
            JSON.parse(raw);

          const unread =
            (
              chat.messages || []
            ).filter(
              m =>
                m.from === 'user' &&
                m.readByAdmin !== true
            ).length;

          if (
            unread > 0 &&
            chat.deviceID
          ) {
            unreadMap[
              chat.deviceID
            ] = unread;
          }
        } catch {}
      }

      const listed =
        await env.KEYS_KV.list({
          prefix: 'key:',
        });

      const allKeys = [];

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

          const now = new Date();

          if (
            record.expiresAt &&
            new Date(
              record.expiresAt
            ) < now &&
            record.status === 'valid'
          ) {
            record.status =
              'expired';

            await env.KEYS_KV.put(
              item.name,
              JSON.stringify(record)
            );
          }

          const devices =
            (
              record.devices || []
            ).map(d => {
              const online =
                onlineMap.has(d.id);

              return {
                id: d.id,
                name: d.name || '',
                firstSeen:
                  d.firstSeen || null,
                lastSeen:
                  d.lastSeen || null,
                blocked_features:
                  d.blocked_features ||
                  [],
                online,
                unreadCount:
                  unreadMap[d.id] ||
                  0,
              };
            });

          allKeys.push({
            key: record.key,
            role: record.role,
            status: record.status,
            maxDevices:
              record.maxDevices,
            usedDevices:
              devices.length,
            onlineDevices:
              devices.filter(
                d => d.online
              ).length,
            devices,
            createdAt:
              record.createdAt,
            expiresAt:
              record.expiresAt,
            note:
              record.note || '',
            banner_config:
              record.banner_config ||
              null,
          });
        } catch {}
      }

      allKeys.sort(
        (a, b) =>
          new Date(b.createdAt || 0) -
          new Date(a.createdAt || 0)
      );

      return json(
        {
          keys: allKeys,
          total: allKeys.length,
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // ADMIN CREATE
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
        '/api/admin/create' &&
      request.method === 'POST'
    ) {
      const adminToken =
        request.headers.get(
          'X-Admin-Token'
        );

      if (
        adminToken !== env.ADMIN_TOKEN
      ) {
        return json(
          {
            error: 'Unauthorized',
          },
          corsHeaders,
          401
        );
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return json(
          {
            error: 'Invalid JSON',
          },
          corsHeaders,
          400
        );
      }

      const {
        key,
        role,
        maxDevices,
        expiresAt,
        note,
      } = body;

      if (!key || !expiresAt) {
        return json(
          {
            error:
              'Missing required fields',
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
            error:
              'Key already exists',
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
          Number(maxDevices || 1),
        devices: [],
        createdAt:
          new Date().toISOString(),
        expiresAt,
        note: note || '',
      };

      await env.KEYS_KV.put(
        `key:${key}`,
        JSON.stringify(record)
      );

      return json(
        {
          success: true,
          key,
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // ADMIN BAN
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
        '/api/admin/ban' &&
      request.method === 'POST'
    ) {
      const adminToken =
        request.headers.get(
          'X-Admin-Token'
        );

      if (
        adminToken !== env.ADMIN_TOKEN
      ) {
        return json(
          {
            error: 'Unauthorized',
          },
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
          {
            error: 'Not found',
          },
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
        {
          success: true,
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // ADMIN UNBAN
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
        '/api/admin/unban' &&
      request.method === 'POST'
    ) {
      const adminToken =
        request.headers.get(
          'X-Admin-Token'
        );

      if (
        adminToken !== env.ADMIN_TOKEN
      ) {
        return json(
          {
            error: 'Unauthorized',
          },
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
          {
            error: 'Not found',
          },
          corsHeaders,
          404
        );
      }

      const record =
        JSON.parse(raw);

      record.status =
        record.expiresAt &&
        new Date(
          record.expiresAt
        ) > new Date()
          ? 'valid'
          : 'expired';

      await env.KEYS_KV.put(
        `key:${key}`,
        JSON.stringify(record)
      );

      return json(
        {
          success: true,
          status: record.status,
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // ADMIN DELETE
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
        '/api/admin/delete' &&
      request.method === 'POST'
    ) {
      const adminToken =
        request.headers.get(
          'X-Admin-Token'
        );

      if (
        adminToken !== env.ADMIN_TOKEN
      ) {
        return json(
          {
            error: 'Unauthorized',
          },
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
        {
          success: true,
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // ADMIN RENEW
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
        '/api/admin/renew' &&
      request.method === 'POST'
    ) {
      const adminToken =
        request.headers.get(
          'X-Admin-Token'
        );

      if (
        adminToken !== env.ADMIN_TOKEN
      ) {
        return json(
          {
            error: 'Unauthorized',
          },
          corsHeaders,
          401
        );
      }

      const {
        key,
        addDays,
      } = await request.json();

      const raw =
        await env.KEYS_KV.get(
          `key:${key}`
        );

      if (!raw) {
        return json(
          {
            error: 'Not found',
          },
          corsHeaders,
          404
        );
      }

      const record =
        JSON.parse(raw);

      const base =
        record.expiresAt &&
        new Date(
          record.expiresAt
        ) > new Date()
          ? new Date(
              record.expiresAt
            )
          : new Date();

      record.expiresAt =
        new Date(
          base.getTime() +
          Number(addDays || 0) *
            86400000
        ).toISOString();

      record.status =
        'valid';

      await env.KEYS_KV.put(
        `key:${key}`,
        JSON.stringify(record)
      );

      return json(
        {
          success: true,
          expiresAt:
            record.expiresAt,
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // DEVICE NAME
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
        '/api/admin/setdevicename' &&
      request.method === 'POST'
    ) {
      const adminToken =
        request.headers.get(
          'X-Admin-Token'
        );

      if (
        adminToken !== env.ADMIN_TOKEN
      ) {
        return json(
          {
            error: 'Unauthorized',
          },
          corsHeaders,
          401
        );
      }

      const {
        key,
        deviceId,
        name,
      } = await request.json();

      if (!key || !deviceId) {
        return json(
          {
            error:
              'Missing key/deviceId',
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
            error: 'Not found',
          },
          corsHeaders,
          404
        );
      }

      const record =
        JSON.parse(raw);

      const device =
        (
          record.devices || []
        ).find(
          d => d.id === deviceId
        );

      if (!device) {
        return json(
          {
            error:
              'Device not found',
          },
          corsHeaders,
          404
        );
      }

      device.name =
        String(name || '')
          .slice(0, 100);

      await env.KEYS_KV.put(
        `key:${key}`,
        JSON.stringify(record)
      );

      return json(
        {
          success: true,
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // DEVICE PERMISSIONS
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
        '/api/admin/setdeviceperms' &&
      request.method === 'POST'
    ) {
      const adminToken =
        request.headers.get(
          'X-Admin-Token'
        );

      if (
        adminToken !== env.ADMIN_TOKEN
      ) {
        return json(
          {
            error: 'Unauthorized',
          },
          corsHeaders,
          401
        );
      }

      const {
        key,
        deviceId,
        blocked_features,
      } = await request.json();

      if (
        !key ||
        !deviceId ||
        !Array.isArray(
          blocked_features
        )
      ) {
        return json(
          {
            error:
              'Invalid params',
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
            error: 'Not found',
          },
          corsHeaders,
          404
        );
      }

      const record =
        JSON.parse(raw);

      const device =
        (
          record.devices || []
        ).find(
          d => d.id === deviceId
        );

      if (!device) {
        return json(
          {
            error:
              'Device not found',
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
          blocked_features,
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // KEY BANNER
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
        '/api/admin/setkeybanner' &&
      request.method === 'POST'
    ) {
      const adminToken =
        request.headers.get(
          'X-Admin-Token'
        );

      if (
        adminToken !== env.ADMIN_TOKEN
      ) {
        return json(
          {
            error: 'Unauthorized',
          },
          corsHeaders,
          401
        );
      }

      const {
        key,
        banner_config,
      } = await request.json();

      if (
        !key ||
        !banner_config ||
        typeof banner_config !==
          'object'
      ) {
        return json(
          {
            error:
              'Invalid params',
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
            error: 'Not found',
          },
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
          banner_config,
        },
        corsHeaders
      );
    }

    if (
      url.pathname ===
      '/api/getkeybanner'
    ) {
      const key =
        request.headers.get(
          'X-Auth-Key'
        ) ||
        url.searchParams.get(
          'key'
        );

      if (!key) {
        return json(
          {
            error:
              'Missing key',
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
              'Not found',
          },
          corsHeaders,
          404
        );
      }

      const record =
        JSON.parse(raw);

      return json(
        {
          banner_config:
            record.banner_config ||
            null,
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // GLOBAL CONFIG
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
      '/api/admin/getconfig'
    ) {
      const raw =
        await env.KEYS_KV.get(
          'global:banner_config'
        );

      let cfg = {};

      try {
        cfg = raw
          ? JSON.parse(raw)
          : {};
      } catch {
        cfg = {};
      }

      return json(
        {
          banner_config: cfg,
        },
        corsHeaders
      );
    }

    if (
      url.pathname ===
        '/api/admin/setconfig' &&
      request.method === 'POST'
    ) {
      const adminToken =
        request.headers.get(
          'X-Admin-Token'
        );

      if (
        adminToken !== env.ADMIN_TOKEN
      ) {
        return json(
          {
            error:
              'Unauthorized',
          },
          corsHeaders,
          401
        );
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return json(
          {
            error:
              'Invalid JSON',
          },
          corsHeaders,
          400
        );
      }

      if (
        body.banner_config
      ) {
        await env.KEYS_KV.put(
          'global:banner_config',
          JSON.stringify(
            body.banner_config
          )
        );
      }

      return json(
        {
          success: true,
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // KEYLOG
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
        '/api/keylog' &&
      request.method === 'POST'
    ) {
      let body;

      try {
        body = await request.json();
      } catch {
        return json(
          {
            error:
              'Invalid JSON',
          },
          corsHeaders,
          400
        );
      }

      const {
        deviceID,
        key,
        line,
      } = body;

      if (
        !deviceID ||
        !line
      ) {
        return json(
          {
            error:
              'Missing deviceID or line',
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

      let record;

      try {
        record = raw
          ? JSON.parse(raw)
          : {
              deviceID,
              authKey:
                key || '',
              lines: [],
            };
      } catch {
        record = {
          deviceID,
          authKey: key || '',
          lines: [],
        };
      }

      const cleanLine =
        String(line)
          .trim()
          .replace(
            /\n/g,
            '↵'
          )
          .replace(
            /\r/g,
            ''
          );

      if (cleanLine) {
        record.lines.push({
          text: cleanLine,
          ts:
            new Date().toISOString(),
        });
      }

      if (
        record.lines.length >
        500
      ) {
        record.lines =
          record.lines.slice(-500);
      }

      record.authKey =
        key || record.authKey;

      await env.KEYS_KV.put(
        storageKey,
        JSON.stringify(record),
        {
          expirationTtl:
            60 * 60 * 24 * 30,
        }
      );

      return json(
        {
          success: true,
        },
        corsHeaders
      );
    }

    if (
      url.pathname ===
      '/api/admin/keylog'
    ) {
      const adminToken =
        request.headers.get(
          'X-Admin-Token'
        );

      if (
        adminToken !== env.ADMIN_TOKEN
      ) {
        return json(
          {
            error:
              'Unauthorized',
          },
          corsHeaders,
          401
        );
      }

      const deviceID =
        url.searchParams.get(
          'device'
        );

      if (deviceID) {
        const raw =
          await env.KEYS_KV.get(
            `keylog:${deviceID}`
          );

        if (!raw) {
          return json(
            {
              deviceID,
              lines: [],
            },
            corsHeaders
          );
        }

        try {
          return json(
            JSON.parse(raw),
            corsHeaders
          );
        } catch {
          return json(
            {
              deviceID,
              lines: [],
            },
            corsHeaders
          );
        }
      }

      const listed =
        await env.KEYS_KV.list({
          prefix: 'keylog:',
        });

      const all = [];

      for (
        const item of listed.keys
      ) {
        const raw =
          await env.KEYS_KV.get(
            item.name
          );

        if (!raw) continue;

        try {
          all.push(
            JSON.parse(raw)
          );
        } catch {}
      }

      return json(
        {
          logs: all,
          total: all.length,
        },
        corsHeaders
      );
    }

    if (
      url.pathname ===
        '/api/admin/clearlog' &&
      request.method === 'POST'
    ) {
      const adminToken =
        request.headers.get(
          'X-Admin-Token'
        );

      if (
        adminToken !== env.ADMIN_TOKEN
      ) {
        return json(
          {
            error:
              'Unauthorized',
          },
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
              'Missing deviceID',
          },
          corsHeaders,
          400
        );
      }

      await env.KEYS_KV.delete(
        `keylog:${deviceID}`
      );

      return json(
        {
          success: true,
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // HEARTBEAT
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
        '/api/heartbeat' &&
      request.method === 'POST'
    ) {
      let body;

      try {
        body = await request.json();
      } catch {
        return json(
          {
            error:
              'Invalid JSON',
          },
          corsHeaders,
          400
        );
      }

      const {
        deviceID,
        key,
      } = body;

      if (!deviceID) {
        return json(
          {
            error:
              'Missing deviceID',
          },
          corsHeaders,
          400
        );
      }

      const nowIso =
        new Date().toISOString();

      // Cập nhật device lastSeen
      if (key) {
        const raw =
          await env.KEYS_KV.get(
            `key:${key}`
          );

        if (raw) {
          try {
            const record =
              JSON.parse(raw);

            const device =
              (
                record.devices ||
                []
              ).find(
                d =>
                  d.id ===
                  deviceID
              );

            if (device) {
              device.lastSeen =
                nowIso;

              await env.KEYS_KV.put(
                `key:${key}`,
                JSON.stringify(
                  record
                )
              );
            }
          } catch {}
        }
      }

      // ONLINE TTL = 90s
      await env.KEYS_KV.put(
        `online:${deviceID}`,
        JSON.stringify({
          deviceID,
          key: key || '',
          ts: nowIso,
          source:
            'heartbeat',
        }),
        {
          expirationTtl: 90,
        }
      );

      // Tin admin chưa được user đọc
      let pendingMessages = [];

      const chatRaw =
        await env.KEYS_KV.get(
          `chat:${deviceID}`
        );

      if (chatRaw) {
        try {
          const chat =
            JSON.parse(chatRaw);

          pendingMessages =
            (
              chat.messages ||
              []
            ).filter(
              m =>
                m.from ===
                  'admin' &&
                m.readByUser !==
                  true
            );
        } catch {}
      }

      return json(
        {
          success: true,
          pendingMessages,
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // OFFLINE
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
        '/api/offline' &&
      request.method === 'POST'
    ) {
      let body;

      try {
        body = await request.json();
      } catch {
        return json(
          {
            error:
              'Invalid JSON',
          },
          corsHeaders,
          400
        );
      }

      const {
        deviceID,
      } = body;

      if (!deviceID) {
        return json(
          {
            error:
              'Missing deviceID',
          },
          corsHeaders,
          400
        );
      }

      await env.KEYS_KV.delete(
        `online:${deviceID}`
      );

      return json(
        {
          success: true,
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // CHAT SEND — USER
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
        '/api/chat/send' &&
      request.method === 'POST'
    ) {
      let body;

      try {
        body = await request.json();
      } catch {
        return json(
          {
            error:
              'Invalid JSON',
          },
          corsHeaders,
          400
        );
      }

      const {
        deviceID,
        key,
        message,
      } = body;

      if (
        !deviceID ||
        !message
      ) {
        return json(
          {
            error:
              'Missing deviceID or message',
          },
          corsHeaders,
          400
        );
      }

      const now =
        new Date();

      const nowIso =
        now.toISOString();

      // Gửi chat = ONLINE ngay lập tức
      await env.KEYS_KV.put(
        `online:${deviceID}`,
        JSON.stringify({
          deviceID,
          key: key || '',
          ts: nowIso,
          source:
            'chat',
        }),
        {
          expirationTtl: 90,
        }
      );

      // Update lastSeen
      if (key) {
        const keyRaw =
          await env.KEYS_KV.get(
            `key:${key}`
          );

        if (keyRaw) {
          try {
            const keyRecord =
              JSON.parse(
                keyRaw
              );

            const device =
              (
                keyRecord.devices ||
                []
              ).find(
                d =>
                  d.id ===
                  deviceID
              );

            if (device) {
              device.lastSeen =
                nowIso;

              await env.KEYS_KV.put(
                `key:${key}`,
                JSON.stringify(
                  keyRecord
                )
              );
            }
          } catch {}
        }
      }

      const storageKey =
        `chat:${deviceID}`;

      const raw =
        await env.KEYS_KV.get(
          storageKey
        );

      let record;

      try {
        record = raw
          ? JSON.parse(raw)
          : {
              deviceID,
              key: key || '',
              messages: [],
            };
      } catch {
        record = {
          deviceID,
          key: key || '',
          messages: [],
        };
      }

      if (
        !Array.isArray(
          record.messages
        )
      ) {
        record.messages = [];
      }

      // User message
      record.messages.push({
        id:
          `${Date.now()}-u-${crypto.randomUUID()}`,
        from: 'user',
        text:
          String(message).slice(
            0,
            4000
          ),
        ts: nowIso,

        readByAdmin: false,
        readByUser: true,

        auto: false,
      });

      record.key =
        key || record.key;

      // ────────────────────────────────────────────────────────────────
      // AUTO REPLY
      //
      // Không quan tâm admin đã mở chat hay chưa.
      //
      // Chỉ ADMIN REPLY THẬT mới reset.
      //
      // Nếu chưa từng có admin reply:
      //     user nhắn -> auto reply.
      //
      // Nếu đã có admin reply:
      //     trong 30 phút -> không auto.
      //
      // Sau 30 phút:
      //     user nhắn -> auto reply.
      // ────────────────────────────────────────────────────────────────

      const lastRealAdmin =
        record.lastRealAdminReplyAt
          ? new Date(
              record.lastRealAdminReplyAt
            ).getTime()
          : 0;

      const elapsed =
        lastRealAdmin
          ? now.getTime() -
            lastRealAdmin
          : Infinity;

      const shouldAutoReply =
        !lastRealAdmin ||
        elapsed >=
          30 * 60 * 1000;

      if (shouldAutoReply) {
        record.messages.push({
          id:
            `${Date.now()}-auto-${crypto.randomUUID()}`,
          from: 'admin',
          text:
            '⏳ Vui lòng chờ admin trả lời.',
          ts:
            new Date().toISOString(),

          readByAdmin: true,
          readByUser: false,

          auto: true,
        });

        record.autoReplySentForUserAt =
          new Date().toISOString();
      }

      // Giới hạn chat
      if (
        record.messages.length >
        200
      ) {
        record.messages =
          record.messages.slice(
            -200
          );
      }

      await env.KEYS_KV.put(
        storageKey,
        JSON.stringify(
          record
        ),
        {
          expirationTtl:
            60 * 60 * 24 * 30,
        }
      );

      return json(
        {
          success: true,
          autoReply:
            shouldAutoReply,
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // CHAT MESSAGES — USER
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
      '/api/chat/messages'
    ) {
      const deviceID =
        request.headers.get(
          'X-Device-ID'
        ) ||
        url.searchParams.get(
          'device'
        );

      if (!deviceID) {
        return json(
          {
            error:
              'Missing deviceID',
          },
          corsHeaders,
          400
        );
      }

      const storageKey =
        `chat:${deviceID}`;

      const raw =
        await env.KEYS_KV.get(
          storageKey
        );

      if (!raw) {
        return json(
          {
            messages: [],
            hideReadStatus: false,
            hideReadStatusSince:
              null,
          },
          corsHeaders
        );
      }

      let record;

      try {
        record =
          JSON.parse(raw);
      } catch {
        return json(
          {
            messages: [],
            hideReadStatus: false,
            hideReadStatusSince:
              null,
          },
          corsHeaders
        );
      }

      let changed = false;

      // Tin admin gửi cho user
      for (
        const m of
          record.messages || []
      ) {
        if (
          m.from === 'admin' &&
          m.readByUser !== true
        ) {
          m.readByUser = true;
          changed = true;
        }
      }

      if (changed) {
        await env.KEYS_KV.put(
          storageKey,
          JSON.stringify(
            record
          ),
          {
            expirationTtl:
              60 * 60 * 24 * 30,
          }
        );
      }

      return json(
        {
          messages:
            record.messages ||
            [],

          hideReadStatus:
            record.hideReadStatus ===
            true,

          hideReadStatusSince:
            record.hideReadStatusSince ||
            null,
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // ADMIN CHAT
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
      '/api/admin/chat'
    ) {
      const adminToken =
        request.headers.get(
          'X-Admin-Token'
        );

      if (
        adminToken !== env.ADMIN_TOKEN
      ) {
        return json(
          {
            error:
              'Unauthorized',
          },
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
          {
            error:
              'Missing device',
          },
          corsHeaders,
          400
        );
      }

      const storageKey =
        `chat:${deviceID}`;

      const raw =
        await env.KEYS_KV.get(
          storageKey
        );

      if (!raw) {
        return json(
          {
            messages: [],
            hideReadStatus: false,
            hideReadStatusSince:
              null,
          },
          corsHeaders
        );
      }

      let record;

      try {
        record =
          JSON.parse(raw);
      } catch {
        return json(
          {
            messages: [],
            hideReadStatus: false,
            hideReadStatusSince:
              null,
          },
          corsHeaders
        );
      }

      // Admin mở chat chỉ đánh dấu đã đọc.
      //
      // QUAN TRỌNG:
      // Không đụng tới lastRealAdminReplyAt.
      // Do đó mở chat KHÔNG làm tắt auto reply.
      let changed = false;

      for (
        const m of
          record.messages || []
      ) {
        if (
          m.from === 'user' &&
          m.readByAdmin !== true
        ) {
          m.readByAdmin = true;
          changed = true;
        }
      }

      if (changed) {
        await env.KEYS_KV.put(
          storageKey,
          JSON.stringify(
            record
          ),
          {
            expirationTtl:
              60 * 60 * 24 * 30,
          }
        );
      }

      return json(
        {
          messages:
            record.messages ||
            [],

          hideReadStatus:
            record.hideReadStatus ===
            true,

          hideReadStatusSince:
            record.hideReadStatusSince ||
            null,
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // ADMIN REPLY
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
        adminToken !== env.ADMIN_TOKEN
      ) {
        return json(
          {
            error:
              'Unauthorized',
          },
          corsHeaders,
          401
        );
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return json(
          {
            error:
              'Invalid JSON',
          },
          corsHeaders,
          400
        );
      }

      const {
        deviceID,
        message,
      } = body;

      if (
        !deviceID ||
        !message
      ) {
        return json(
          {
            error:
              'Missing deviceID or message',
          },
          corsHeaders,
          400
        );
      }

      const storageKey =
        `chat:${deviceID}`;

      const raw =
        await env.KEYS_KV.get(
          storageKey
        );

      let record;

      try {
        record = raw
          ? JSON.parse(raw)
          : {
              deviceID,
              key: '',
              messages: [],
            };
      } catch {
        record = {
          deviceID,
          key: '',
          messages: [],
        };
      }

      if (
        !Array.isArray(
          record.messages
        )
      ) {
        record.messages = [];
      }

      const replyTs =
        new Date().toISOString();

      // Đây là ADMIN REPLY THẬT
      record.messages.push({
        id:
          `${Date.now()}-a-${crypto.randomUUID()}`,
        from: 'admin',
        text:
          String(message).slice(
            0,
            4000
          ),
        ts: replyTs,

        readByAdmin: true,
        readByUser: false,

        auto: false,
      });

      // Chỉ chỗ này mới reset auto reply.
      record.lastRealAdminReplyAt =
        replyTs;

      record.autoReplySentForUserAt =
        null;

      if (
        record.messages.length >
        200
      ) {
        record.messages =
          record.messages.slice(
            -200
          );
      }

      await env.KEYS_KV.put(
        storageKey,
        JSON.stringify(
          record
        ),
        {
          expirationTtl:
            60 * 60 * 24 * 30,
        }
      );

      return json(
        {
          success: true,
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // HIDE READ STATUS
    // ─────────────────────────────────────────────────────────────────────

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
        adminToken !== env.ADMIN_TOKEN
      ) {
        return json(
          {
            error:
              'Unauthorized',
          },
          corsHeaders,
          401
        );
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return json(
          {
            error:
              'Invalid JSON',
          },
          corsHeaders,
          400
        );
      }

      const {
        deviceID,
        hideReadStatus,
      } = body;

      if (!deviceID) {
        return json(
          {
            error:
              'Missing deviceID',
          },
          corsHeaders,
          400
        );
      }

      const storageKey =
        `chat:${deviceID}`;

      const raw =
        await env.KEYS_KV.get(
          storageKey
        );

      let record;

      try {
        record = raw
          ? JSON.parse(raw)
          : {
              deviceID,
              key: '',
              messages: [],
            };
      } catch {
        record = {
          deviceID,
          key: '',
          messages: [],
        };
      }

      const nextHide =
        hideReadStatus === true;

      record.hideReadStatus =
        nextHide;

      // Chỉ tin nhắn user gửi SAU
      // thời điểm bật mới bị ẩn.
      //
      // Khi tắt thì reset mốc.
      record.hideReadStatusSince =
        nextHide
          ? new Date().toISOString()
          : null;

      await env.KEYS_KV.put(
        storageKey,
        JSON.stringify(
          record
        ),
        {
          expirationTtl:
            60 * 60 * 24 * 30,
        }
      );

      return json(
        {
          success: true,
          hideReadStatus:
            record.hideReadStatus,
          hideReadStatusSince:
            record.hideReadStatusSince,
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // CLEAR CHAT
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
        adminToken !== env.ADMIN_TOKEN
      ) {
        return json(
          {
            error:
              'Unauthorized',
          },
          corsHeaders,
          401
        );
      }

      const {
        deviceID,
      } = await request.json();

      if (!deviceID) {
        return json(
          {
            error:
              'Missing deviceID',
          },
          corsHeaders,
          400
        );
      }

      await env.KEYS_KV.delete(
        `chat:${deviceID}`
      );

      return json(
        {
          success: true,
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // ADMIN ONLINE
    // ─────────────────────────────────────────────────────────────────────

    if (
      url.pathname ===
      '/api/admin/online'
    ) {
      const adminToken =
        request.headers.get(
          'X-Admin-Token'
        );

      if (
        adminToken !== env.ADMIN_TOKEN
      ) {
        return json(
          {
            error:
              'Unauthorized',
          },
          corsHeaders,
          401
        );
      }

      const listed =
        await env.KEYS_KV.list({
          prefix: 'online:',
        });

      const onlineDevices = [];

      for (
        const item of listed.keys
      ) {
        const raw =
          await env.KEYS_KV.get(
            item.name
          );

        if (!raw) continue;

        try {
          onlineDevices.push(
            JSON.parse(raw)
          );
        } catch {}
      }

      return json(
        {
          onlineDevices,
          total:
            onlineDevices.length,
        },
        corsHeaders
      );
    }

    // ─────────────────────────────────────────────────────────────────────
    // NOT FOUND
    // ─────────────────────────────────────────────────────────────────────

    return json(
      {
        error: 'Not found',
      },
      corsHeaders,
      404
    );
  },
};


// ═══════════════════════════════════════════════════════════════════════════
// JSON RESPONSE
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
        ...headers,
      },
    }
  );
}
