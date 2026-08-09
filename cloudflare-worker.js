/**
 * Cloudflare Worker — Key Validate API
 * Deploy lên Cloudflare Workers (miễn phí) để tạo endpoint thật:
 *   POST/GET https://your-worker.your-name.workers.dev/api/validate
 *
 * iOS app gọi: GET endpoint?key=XXX&device=YYY
 * Worker đọc KV store (KEYS_KV) -> trả JSON
 *
 * Setup:
 *  1. Tạo Cloudflare account (miễn phí)
 *  2. Tạo Worker mới, paste code này
 *  3. Tạo KV namespace tên "KEYS_KV"
 *  4. Bind KV vào Worker
 *  5. Upload keys qua Workers KV API hoặc dashboard
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Auth-Key, X-Device-ID',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // ── GET /api/validate ──────────────────────────────────────────────────
    if (url.pathname === '/api/validate') {
      const key      = request.headers.get('X-Auth-Key')   || url.searchParams.get('key');
      const deviceID = request.headers.get('X-Device-ID')  || url.searchParams.get('device');

      if (!key) {
        return json({ status: 'invalid', message: 'Missing key' }, corsHeaders);
      }

      // Đọc key từ KV
      const raw = await env.KEYS_KV.get(`key:${key}`);
      if (!raw) {
        return json({ status: 'deleted', message: 'Key not found' }, corsHeaders);
      }

      let record;
      try { record = JSON.parse(raw); } catch {
        return json({ status: 'invalid', message: 'Corrupt record' }, corsHeaders);
      }

      // Kiểm tra ban
      if (record.status === 'banned') {
        return json({ status: 'banned', message: 'Key is banned', role: record.role }, corsHeaders);
      }

      // Kiểm tra hết hạn
      const now = new Date();
      if (new Date(record.expiresAt) < now) {
        record.status = 'expired';
        await env.KEYS_KV.put(`key:${key}`, JSON.stringify(record));
        return json({ status: 'expired', message: 'Key expired', role: record.role, days_left: 0 }, corsHeaders);
      }

      // Kiểm tra giới hạn thiết bị
      if (deviceID) {
        const devices = record.devices || [];
        const knownDevice = devices.find(d => d.id === deviceID);

        if (!knownDevice) {
          if (devices.length >= record.maxDevices) {
            // Đã đủ thiết bị
            return json({
              status: 'device_limit',
              message: `Key đã đạt giới hạn ${record.maxDevices} thiết bị`,
              role: record.role
            }, corsHeaders);
          }
          // Thêm thiết bị mới
          devices.push({ id: deviceID, firstSeen: now.toISOString(), lastSeen: now.toISOString() });
        } else {
          // Update lastSeen
          knownDevice.lastSeen = now.toISOString();
        }

        record.devices = devices;
        await env.KEYS_KV.put(`key:${key}`, JSON.stringify(record));
      }

      const daysLeft = Math.ceil((new Date(record.expiresAt) - now) / 86400000);

      return json({
        status:    'valid',
        role:      record.role,
        days_left: daysLeft,
        expires:   record.expiresAt,
        message:   'OK'
      }, corsHeaders);
    }

    // ── POST /api/admin/create ─────────────────────────────────────────────
    if (url.pathname === '/api/admin/create' && request.method === 'POST') {
      // Xác thực admin token
      const adminToken = request.headers.get('X-Admin-Token');
      if (adminToken !== env.ADMIN_TOKEN) {
        return json({ error: 'Unauthorized' }, corsHeaders, 401);
      }

      const body = await request.json();
      const { key, role, maxDevices, expiresAt, note } = body;

      if (!key || !expiresAt) {
        return json({ error: 'Missing required fields' }, corsHeaders, 400);
      }

      const record = {
        key, role: role || 'member',
        status:    'valid',
        maxDevices: maxDevices || 1,
        devices:   [],
        createdAt: new Date().toISOString(),
        expiresAt,
        note: note || ''
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

    return json({ error: 'Not found' }, corsHeaders, 404);
  }
};

function json(data, headers = {}, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers }
  });
}
