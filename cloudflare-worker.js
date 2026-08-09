/**
 * Cloudflare Worker — Key Validate API
 * v2 — thêm /api/admin/list và /api/admin/unban
 *
 * Setup:
 *  1. Tạo Worker mới trên Cloudflare, paste code này
 *  2. Tạo KV namespace "KEYS_KV" và bind vào Worker (variable name: KEYS_KV)
 *  3. Thêm Environment Variable: ADMIN_TOKEN = your-secret-token
 *  4. Save & Deploy
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
    // iOS app gọi endpoint này để xác thực key
    if (url.pathname === '/api/validate') {
      const key      = request.headers.get('X-Auth-Key')  || url.searchParams.get('key');
      const deviceID = request.headers.get('X-Device-ID') || url.searchParams.get('device');

      if (!key) {
        return json({ status: 'invalid', message: 'Missing key' }, corsHeaders);
      }

      const raw = await env.KEYS_KV.get(`key:${key}`);
      if (!raw) {
        return json({ status: 'deleted', message: 'Key not found' }, corsHeaders);
      }

      let record;
      try { record = JSON.parse(raw); } catch {
        return json({ status: 'invalid', message: 'Corrupt record' }, corsHeaders);
      }

      if (record.status === 'banned') {
        return json({ status: 'banned', message: 'Key is banned', role: record.role }, corsHeaders);
      }

      const now = new Date();
      if (new Date(record.expiresAt) < now) {
        record.status = 'expired';
        await env.KEYS_KV.put(`key:${key}`, JSON.stringify(record));
        return json({ status: 'expired', message: 'Key expired', role: record.role, days_left: 0 }, corsHeaders);
      }

      // Kiểm tra device limit
      if (deviceID) {
        const devices = record.devices || [];
        const knownDevice = devices.find(d => d.id === deviceID);

        if (!knownDevice) {
          if (devices.length >= record.maxDevices) {
            return json({
              status: 'device_limit',
              message: `Key đã đạt giới hạn ${record.maxDevices} thiết bị`,
              role: record.role
            }, corsHeaders);
          }
          devices.push({ id: deviceID, firstSeen: now.toISOString(), lastSeen: now.toISOString() });
        } else {
          knownDevice.lastSeen = now.toISOString();
        }

        record.devices = devices;
        await env.KEYS_KV.put(`key:${key}`, JSON.stringify(record));
      }

      const daysLeft = Math.ceil((new Date(record.expiresAt) - now) / 86400000);

      return json({
        status:           'valid',
        role:             record.role,
        days_left:        daysLeft,
        expires:          record.expiresAt,
        blocked_features: record.blocked_features || [],
        message:   'OK'
      }, corsHeaders);
    }

    // ── GET /api/admin/list ────────────────────────────────────────────────
    // Web admin dùng để load danh sách toàn bộ key
    if (url.pathname === '/api/admin/list') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) {
        return json({ error: 'Unauthorized' }, corsHeaders, 401);
      }

      // List tất cả key trong KV (prefix "key:")
      const listed = await env.KEYS_KV.list({ prefix: 'key:' });
      const allKeys = [];

      for (const item of listed.keys) {
        const raw = await env.KEYS_KV.get(item.name);
        if (!raw) continue;
        try {
          const record = JSON.parse(raw);
          // Kiểm tra và update expired tự động
          const now = new Date();
          if (record.status === 'valid' && new Date(record.expiresAt) < now) {
            record.status = 'expired';
            await env.KEYS_KV.put(item.name, JSON.stringify(record));
          }
          allKeys.push({
            key:        record.key,
            role:       record.role,
            status:     record.status,
            maxDevices: record.maxDevices,
            devices:    record.devices || [],
            createdAt:  record.createdAt,
            expiresAt:  record.expiresAt,
            note:             record.note || '',
            blocked_features: record.blocked_features || []
          });
        } catch {}
      }

      // Sắp xếp mới nhất lên đầu
      allKeys.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

      return json({ keys: allKeys, total: allKeys.length }, corsHeaders);
    }

    // ── POST /api/admin/create ─────────────────────────────────────────────
    if (url.pathname === '/api/admin/create' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) {
        return json({ error: 'Unauthorized' }, corsHeaders, 401);
      }

      const body = await request.json();
      const { key, role, maxDevices, expiresAt, note } = body;

      if (!key || !expiresAt) {
        return json({ error: 'Missing required fields (key, expiresAt)' }, corsHeaders, 400);
      }

      // Kiểm tra key đã tồn tại chưa
      const existing = await env.KEYS_KV.get(`key:${key}`);
      if (existing) {
        return json({ error: 'Key already exists' }, corsHeaders, 409);
      }

      const record = {
        key,
        role:       role || 'member',
        status:     'valid',
        maxDevices: maxDevices || 1,
        devices:    [],
        createdAt:  new Date().toISOString(),
        expiresAt,
        note:       note || ''
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
      const now = new Date();
      record.status = new Date(record.expiresAt) > now ? 'valid' : 'expired';
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
      const base   = new Date(record.expiresAt) > new Date() ? new Date(record.expiresAt) : new Date();
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
      if (!key || !['admin', 'member'].includes(role)) {
        return json({ error: 'Invalid params (key, role must be admin|member)' }, corsHeaders, 400);
      }

      const raw = await env.KEYS_KV.get(`key:${key}`);
      if (!raw) return json({ error: 'Not found' }, corsHeaders, 404);

      const record = JSON.parse(raw);
      record.role = role;
      await env.KEYS_KV.put(`key:${key}`, JSON.stringify(record));
      return json({ success: true, key, role }, corsHeaders);
    }


    // ── POST /api/admin/setperms ───────────────────────────────────────────
    // Lưu danh sách features bị block cho một key cụ thể
    if (url.pathname === '/api/admin/setperms' && request.method === 'POST') {
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) return json({ error: 'Unauthorized' }, corsHeaders, 401);

      const { key, blocked_features } = await request.json();
      if (!key || !Array.isArray(blocked_features)) {
        return json({ error: 'Invalid params (key, blocked_features[])' }, corsHeaders, 400);
      }

      const raw = await env.KEYS_KV.get(`key:${key}`);
      if (!raw) return json({ error: 'Not found' }, corsHeaders, 404);

      const record = JSON.parse(raw);
      record.blocked_features = blocked_features;
      await env.KEYS_KV.put(`key:${key}`, JSON.stringify(record));
      return json({ success: true, key, blocked_features }, corsHeaders);
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
