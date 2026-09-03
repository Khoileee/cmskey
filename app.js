/* ============================================================
   CMS Quản trị khóa — bản tối giản, 1 người dùng (anh Tộ)
   Không phê duyệt · không phân quyền · không SLA

   Trạng thái (5):
     Chưa xong bàn giao → Đang hiệu lực → Tạm khóa / Thu hồi / Hết hiệu lực
   Khóa nội bộ bỏ qua bước bàn giao, tạo xong là Đang hiệu lực.

   Dữ liệu giả lập, không kết nối OpenBao thật.
   ============================================================ */

const TODAY = new Date(2026, 7, 27); // 27/08/2026

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const d = (iso) => { const [y, m, dd] = iso.split('-').map(Number); return new Date(y, m - 1, dd); };
const iso = (dt) => dt.getFullYear() + '-' + String(dt.getMonth() + 1).padStart(2, '0') + '-' + String(dt.getDate()).padStart(2, '0');
const fmt = (s) => s ? s.split('-').reverse().join('/') : '—';
const days = (s) => s ? Math.round((d(s) - TODAY) / 86400000) : null;
const addHours = (h) => iso(new Date(TODAY.getTime() + h * 3600000));
const nowStamp = () => '27/08/2026 ' + new Date().toTimeString().slice(0, 5);
const TODAY_ISO = iso(TODAY);

const ST = {
  CHUA_XONG: { l: 'Chưa xong bàn giao', c: 'st-warn' },
  HIEU_LUC: { l: 'Đang hiệu lực', c: 'st-ok' },
  TAM_KHOA: { l: 'Tạm khóa', c: 'st-warn' },
  THU_HOI: { l: 'Thu hồi', c: 'st-bad' },
  HET_HAN: { l: 'Hết hiệu lực', c: 'st-idle' },
};
const stBadge = (k) => `<span class="st ${ST[k].c}">${ST[k].l}</span>`;

/* ---- Đối tượng sử dụng khóa (menu Danh mục đối tượng) ---- */
const OBJS = [
  { code: 'FIA', n: 'Ngân hàng Đối tác A', ext: true },
  { code: 'FIB', n: 'Công ty Tài chính B', ext: true },
  { code: 'FIC', n: 'Ngân hàng Đối tác C', ext: true },
  { code: 'FID', n: 'Ngân hàng Đối tác D', ext: true },
  { code: 'FIE', n: 'Công ty Tài chính E', ext: true },
  { code: 'DPY', n: 'Đối tác dữ liệu Y', ext: true },
  { code: 'CDNX', n: 'Nhà cung cấp CDN X', ext: true },
  { code: 'SCOREHUB', n: 'ScoreHub Backend', ext: false },
  { code: 'AIRFLOW', n: 'Airflow', ext: false },
  { code: 'SPARK', n: 'Cụm Spark', ext: false },
  { code: 'REPORT', n: 'Report Service', ext: false },
  { code: 'INGEST', n: 'Ingest Pipeline', ext: false },
];
const OBJ = (n) => OBJS.find(o => o.n === n) || { code: 'NA', n, ext: false };

/* ============================================================
   LOẠI KHÓA — mỗi loại có bộ Thời hạn RIÊNG, đúng bản chất engine
   ============================================================ */
const M1 = 730, M3 = 2190, M6 = 4380, M12 = 8760; // giờ
const KEY_TYPES = [
  {
    code: 'SIGN', name: 'Khóa ký dữ liệu', engine: 'Transit',
    algos: ['rsa-2048', 'rsa-3072', 'rsa-4096', 'ecdsa-p256', 'ecdsa-p384', 'ed25519'],
    ttl: [{ h: M1, l: '1 tháng' }, { h: M3, l: '3 tháng' }, { h: M6, l: '6 tháng' }, { h: M12, l: '12 tháng (trần)' }],
    ttlDef: M12, ttlField: 'auto_rotate_period',
    autoExpire: false,
    ttlNote: 'OpenBao <b>không tự chặn</b> khi hết hạn — chỉ sinh bản mới. CMS phải chủ động chặn bản cũ.',
  },
  {
    code: 'ENC', name: 'Khóa mã hóa', engine: 'Transit',
    algos: ['aes256-gcm96', 'chacha20-poly1305', 'rsa-2048', 'rsa-4096'],
    ttl: [{ h: M1, l: '1 tháng' }, { h: M3, l: '3 tháng' }, { h: M6, l: '6 tháng' }, { h: M12, l: '12 tháng (trần)' }],
    ttlDef: M12, ttlField: 'auto_rotate_period',
    autoExpire: false,
    ttlNote: 'OpenBao <b>không tự chặn</b> khi hết hạn — chỉ sinh bản mới. CMS phải chủ động chặn bản cũ.',
  },
  {
    code: 'CERT', name: 'Chứng thư TLS', engine: 'PKI',
    algos: ['rsa/2048', 'rsa/4096', 'ec/256', 'ec/384'],
    ttl: [{ h: M1, l: '1 tháng' }, { h: M3, l: '3 tháng' }, { h: M6, l: '6 tháng' }, { h: M12, l: '12 tháng (trần)' }],
    ttlDef: M12, ttlField: 'ttl',
    autoExpire: true,
    ttlNote: 'Chứng thư <b>hết hạn là tự vô hiệu</b> — bên nhận tự từ chối, không cần ai làm gì.',
  },
  {
    code: 'DBC', name: 'Credential CSDL', engine: 'Database',
    algos: ['— engine tự sinh user/password'],
    ttl: [{ h: 1, l: '1 giờ' }, { h: 24, l: '24 giờ' }, { h: 168, l: '7 ngày' }, { h: 720, l: '30 ngày (trần)' }],
    ttlDef: 720, ttlField: 'default_ttl',
    autoExpire: true,
    ttlNote: 'Loại này sinh ra để <b>sống ngắn</b>. Hết hạn OpenBao <b>tự xóa user</b> khỏi CSDL. Không có tùy chọn tính bằng tháng.',
  },
  {
    code: 'SEC', name: 'API secret / keytab', engine: 'KV v2',
    algos: ['— chỉ lưu dữ liệu, không có thuật toán'],
    ttl: [{ h: M3, l: '3 tháng' }, { h: M6, l: '6 tháng' }, { h: M12, l: '12 tháng' }],
    ttlDef: M6, ttlField: null,
    autoExpire: false,
    ttlNote: 'KV v2 <b>không có TTL</b>. Ô này <b>không gửi xuống OpenBao</b> — chỉ để CMS nhắc anh Tộ tự thay.',
  },
];
const KT = (c) => KEY_TYPES.find(k => k.code === c) || KEY_TYPES[0];
const ttlLabel = (t, h) => (t.ttl.find(x => x.h === h) || { l: h + 'h' }).l;

const extTag = (ext) => ext
  ? '<span class="tag-type tag-B">Bên ngoài</span>'
  : '<span class="tag-type tag-A">Nội bộ</span>';

function expCell(s, status) {
  if (!s) return '<span class="muted">không có hạn</span>';
  const n = days(s);
  if (status === 'THU_HOI' || status === 'HET_HAN') return `<span class="muted">${fmt(s)}</span>`;
  if (n < 0) return `<span class="st st-idle">${fmt(s)} (quá hạn)</span>`;
  if (n <= 30) return `<span class="st st-bad">${fmt(s)} (còn ${n} ngày)</span>`;
  if (n <= 90) return `<span class="st st-warn">${fmt(s)} (còn ${n} ngày)</span>`;
  return `${fmt(s)} <span class="muted">(còn ${n} ngày)</span>`;
}

/* ============================================================
   DỮ LIỆU
   ============================================================ */
const DB = {
  keys: [
    { id: 'KEY-2026-0014', obj: 'Ngân hàng Đối tác A', kt: 'SIGN', dossier: 'HĐ-2025/SCOREHUB/012', algo: 'rsa-2048', ttlH: M12, ver: 1, activeVer: 1, status: 'HIEU_LUC', eff: '2025-11-02', exp: '2026-11-02', bao: 'transit/keys/scorehub-fia-sign-2025', lockReason: '', sentAt: '2025-10-28', channel: 'SFTP + biên bản giấy', cfAt: '2025-11-01', cfBy: 'Ban CNTT đối tác' },
    { id: 'KEY-2026-0021', obj: 'Công ty Tài chính B', kt: 'ENC', dossier: 'HĐ-2025/SCOREHUB/019', algo: 'aes256-gcm96', ttlH: M12, ver: 2, activeVer: 2, status: 'HIEU_LUC', eff: '2025-09-15', exp: '2026-09-15', bao: 'transit/keys/scorehub-fib-enc-2025', lockReason: '', sentAt: '', channel: '', cfAt: '', cfBy: '' },
    { id: 'KEY-2026-0033', obj: 'Ngân hàng Đối tác C', kt: 'SIGN', dossier: 'HĐ-2025/SCOREHUB/027', algo: 'ecdsa-p256', ttlH: M12, ver: 1, activeVer: 1, status: 'TAM_KHOA', eff: '2025-10-08', exp: '2026-10-08', bao: 'transit/keys/scorehub-fic-sign-2025', lockReason: '[Mức 3] Nghi ngờ lộ khóa — đang xác minh theo PYC-2026-0871', sentAt: '2025-10-01', channel: 'Portal', cfAt: '2025-10-06', cfBy: 'Phòng CNTT đối tác' },
    { id: 'KEY-2026-0002', obj: 'Ngân hàng Đối tác D', kt: 'SIGN', dossier: 'HĐ-2026/SCOREHUB/003', algo: 'rsa-2048', ttlH: M12, ver: 1, activeVer: 1, status: 'CHUA_XONG', eff: '', exp: '', bao: 'transit/keys/scorehub-fid-sign-2026', lockReason: '', sentAt: '2026-08-20', channel: 'Portal đối tượng', cfAt: '', cfBy: '' },
    { id: 'KEY-2026-0005', obj: 'Công ty Tài chính E', kt: 'ENC', dossier: 'HĐ-2026/SCOREHUB/008', algo: 'rsa-4096', ttlH: M12, ver: 1, activeVer: 1, status: 'CHUA_XONG', eff: '', exp: '', bao: 'transit/keys/scorehub-fie-enc-2026', lockReason: '', sentAt: '', channel: '', cfAt: '', cfBy: '' },
    { id: 'KEY-2026-0041', obj: 'Công ty Tài chính B', kt: 'SIGN', dossier: 'HĐ-2025/SCOREHUB/019', algo: 'ecdsa-p256', ttlH: M12, ver: 2, activeVer: 2, status: 'HIEU_LUC', eff: '2025-11-30', exp: '2026-11-30', bao: 'transit/keys/scorehub-fib-sign-2025', lockReason: '', sentAt: '2026-08-05', channel: 'Email ký số', cfAt: '2026-08-12', cfBy: 'Phòng CNTT đối tác' },
    { id: 'KEY-2026-0007', obj: 'Nhà cung cấp CDN X', kt: 'CERT', dossier: 'HĐ-MS-2026/041', algo: 'rsa/2048', ttlH: M12, ver: 1, activeVer: 1, status: 'HIEU_LUC', eff: '2026-03-01', exp: '2027-03-01', bao: 'pki/issue/scorehub-public-api', lockReason: '', sentAt: '2026-02-26', channel: 'Email ký số', cfAt: '2026-02-28', cfBy: 'Vận hành CDN' },
    { id: 'KEY-2025-0018', obj: 'Ngân hàng Đối tác C', kt: 'SIGN', dossier: 'HĐ-2024/SCOREHUB/031', algo: 'rsa-2048', ttlH: M12, ver: 1, activeVer: 1, status: 'HET_HAN', eff: '2024-06-30', exp: '2026-06-30', bao: 'transit/keys/scorehub-fic-sign-2024', lockReason: '', sentAt: '2024-06-25', channel: 'SFTP', cfAt: '2024-06-28', cfBy: 'Phòng CNTT đối tác' },
    { id: 'KEY-2025-0009', obj: 'Ngân hàng Đối tác A', kt: 'SIGN', dossier: 'HĐ-2024/SCOREHUB/012', algo: 'rsa-2048', ttlH: M12, ver: 2, activeVer: 2, status: 'THU_HOI', eff: '2024-11-02', exp: '2025-11-02', bao: 'transit/keys/scorehub-fia-sign-2024', lockReason: 'Thu hồi theo lịch xoay khóa 2025', sentAt: '2024-10-28', channel: 'SFTP', cfAt: '2024-11-01', cfBy: 'Ban CNTT đối tác' },

    { id: 'CRED-2026-0001', obj: 'ScoreHub Backend', kt: 'DBC', dossier: '', algo: '—', ttlH: 720, ver: 27, activeVer: 27, status: 'HIEU_LUC', eff: '2026-08-02', exp: '2026-09-01', bao: 'database/roles/scorehub-oracle', lockReason: '', sentAt: '', channel: '', cfAt: '', cfBy: '' },
    { id: 'CRED-2026-0003', obj: 'Airflow', kt: 'DBC', dossier: '', algo: '—', ttlH: 720, ver: 9, activeVer: 9, status: 'HIEU_LUC', eff: '2026-07-30', exp: '2026-08-29', bao: 'database/roles/airflow-pg', lockReason: '', sentAt: '', channel: '', cfAt: '', cfBy: '' },
    { id: 'CRED-2026-0004', obj: 'Cụm Spark', kt: 'SEC', dossier: '', algo: '—', ttlH: M12, ver: 4, activeVer: 4, status: 'TAM_KHOA', eff: '2026-02-01', exp: '2027-02-01', bao: 'kv/data/scorehub/spark-keytab', lockReason: '[Mức 2] Cụm Spark đang bảo trì — tạm dừng cấp phát', sentAt: '', channel: '', cfAt: '', cfBy: '' },
    { id: 'CRED-2026-0005', obj: 'Report Service', kt: 'DBC', dossier: 'YCNB-2026/207', algo: '—', ttlH: 720, ver: 15, activeVer: 15, status: 'HIEU_LUC', eff: '2026-06-01', exp: '2026-07-01', bao: 'database/roles/report-mysql', lockReason: '', sentAt: '', channel: '', cfAt: '', cfBy: '' },
    { id: 'CRED-2026-0006', obj: 'Ingest Pipeline', kt: 'SEC', dossier: 'YCNB-2026/188', algo: '—', ttlH: M6, ver: 3, activeVer: 3, status: 'HIEU_LUC', eff: '2026-04-20', exp: '2026-10-20', bao: 'kv/data/scorehub/kafka-secret', lockReason: '', sentAt: '', channel: '', cfAt: '', cfBy: '' },
  ],
  audit: [
    { at: '24/08/2026 16:02', act: 'Tạo khóa trên OpenBao', obj: 'KEY-2026-0005', reason: 'POST /v1/transit/keys — type=rsa-4096' },
    { at: '20/08/2026 10:47', act: 'Cập nhật bàn giao', obj: 'KEY-2026-0002', reason: 'Đã gửi qua Portal đối tượng' },
    { at: '19/08/2026 08:20', act: 'TẠM KHÓA', obj: 'KEY-2026-0033', reason: 'Mức 3 — Nghi ngờ lộ khóa, PYC-2026-0871' },
    { at: '16/08/2026 00:05', act: 'Cảnh báo hết hạn T-30', obj: 'KEY-2026-0021', reason: 'Lịch xoay khóa hằng năm' },
    { at: '12/08/2026 14:31', act: 'Ghi nhận đối tác xác nhận → kích hoạt', obj: 'KEY-2026-0041', reason: 'Phòng CNTT đối tác' },
  ],
};

const EXTRA = {
  'KEY-2026-0014': { latest: 3, minDec: 2, minEnc: 0 },
  'KEY-2026-0021': { latest: 2, minDec: 1, minEnc: 0 },
  'KEY-2026-0033': { latest: 1, minDec: 1, minEnc: 2 },
  'KEY-2026-0002': { latest: 1, minDec: 1, minEnc: 0 },
  'KEY-2026-0005': { latest: 1, minDec: 1, minEnc: 0 },
  'KEY-2026-0041': { latest: 2, minDec: 2, minEnc: 0 },
  'KEY-2026-0007': { pkiRole: 'scorehub-public-api', cn: 'api.scorehub.example.vn', allowed: 'scorehub.example.vn', serial: '4a:1f:9c:22:e0:75:b3:8d:11:6f' },
  'KEY-2025-0018': { latest: 1, minDec: 2, minEnc: 2 },
  'KEY-2025-0009': { latest: 2, minDec: 3, minEnc: 3 },
  'CRED-2026-0001': { dbRole: 'scorehub-oracle', leaseId: 'database/creds/scorehub-oracle/7Hk2mQ', leaseDur: '720h' },
  'CRED-2026-0003': { dbRole: 'airflow-pg', leaseId: 'database/creds/airflow-pg/2Bd8nL', leaseDur: '720h' },
  'CRED-2026-0004': { kvPath: 'scorehub/spark-keytab', kvVersion: 4 },
  'CRED-2026-0005': { dbRole: 'report-mysql', leaseId: 'database/creds/report-mysql/5Xz1vT', leaseDur: '720h' },
  'CRED-2026-0006': { kvPath: 'scorehub/kafka-secret', kvVersion: 3 },
};
const EX = (id) => EXTRA[id] || {};

/* ============================================================
   NỘI DUNG POPOVER (i) — bấm để mở
   ============================================================ */
const TIP = {
  f_obj: {
    t: 'Đối tượng sử dụng khóa',
    d: 'Ai sẽ dùng khóa này. Danh sách lấy từ menu <b>Danh mục đối tượng</b>. <br><b>Không có ô "Nội bộ / Bên ngoài" riêng</b> — phạm vi là thuộc tính của chính đối tượng, chọn xong là biết.',
    vd: '<code>Ngân hàng Đối tác D</code> (mã <code>FID</code>, Bên ngoài) · <code>Airflow</code> (mã <code>AIRFLOW</code>, Nội bộ)',
    anh: [
      '<b>Bên ngoài</b> → sau khi tạo, khóa vào trạng thái <b>Chưa xong bàn giao</b>; ô <b>Hồ sơ ràng buộc</b> thành <b>bắt buộc</b>',
      '<b>Nội bộ</b> → tạo xong là <b>Đang hiệu lực</b> ngay; ô <b>Hồ sơ ràng buộc</b> thành <b>tùy chọn</b>',
      'Mã đối tượng được ghép vào <b>tên khóa trong OpenBao</b>',
    ],
    map: [['Mã đối tượng', 'ghép vào <code>:name</code> trên URL, không gửi thành trường riêng']],
    json: 'POST /v1/transit/keys/scorehub-fid-sign-2026\n                       └───┬────┘\n                      mã đối tượng FID (viết thường)',
  },
  f_kt: {
    t: 'Loại khóa',
    d: 'Quyết định <b>engine OpenBao</b> sẽ gọi. Chỉ có 4 engine, không thêm được cái thứ 5. Hai loại đầu dùng chung engine Transit, chỉ khác trường <code>type</code>.',
    vd: '5 loại khóa ↔ 4 engine: Khóa ký + Khóa mã hóa cùng dùng <b>Transit</b>',
    anh: [
      '<b>Danh sách thuật toán</b> đổi hoàn toàn',
      '<b>Các mốc Thời hạn</b> đổi hoàn toàn — Credential CSDL tính bằng <b>giờ/ngày</b>, không phải tháng',
      '<b>Endpoint và toàn bộ payload</b> đổi',
      '<b>Cách hết hạn</b> đổi — xem (i) ở ô Thời hạn',
    ],
    map: [
      ['Khóa ký', 'Transit · <code>POST /v1/transit/keys/:name</code>'],
      ['Khóa mã hóa', 'Transit · cùng endpoint, khác <code>type</code>'],
      ['Chứng thư TLS', 'PKI · <code>POST /v1/pki/issue/:role</code>'],
      ['Credential CSDL', 'Database · <code>POST /v1/database/roles/:name</code>'],
      ['API secret', 'KV v2 · <code>POST /v1/kv/data/:path</code>'],
    ],
    json: null,
  },
  f_ttl: {
    t: 'Thời hạn hiệu lực',
    d: 'Khóa sống bao lâu. <b>Các mốc chọn được và cách hết hạn KHÁC NHAU theo từng loại khóa</b> — không phải loại nào cũng 1/3/6/12 tháng.',
    vd: 'Chọn <code>12 tháng</code> với Khóa ký → gửi xuống <code>auto_rotate_period: "8760h"</code>',
    anh: [
      '<b>Khóa ký / mã hóa (Transit)</b> — 1/3/6/12 tháng → <code>auto_rotate_period</code>. <span class="warn">OpenBao KHÔNG tự chặn khi hết hạn, chỉ sinh bản mới. CMS phải chủ động chặn.</span>',
      '<b>Chứng thư TLS (PKI)</b> — 1/3/6/12 tháng → <code>ttl</code>. <span class="ok">Hết hạn tự vô hiệu thật.</span>',
      '<b>Credential CSDL (Database)</b> — 1 giờ / 24 giờ / 7 ngày / 30 ngày → <code>default_ttl</code>. <span class="ok">Hết hạn OpenBao tự xóa user.</span>',
      '<b>API secret (KV v2)</b> — 3/6/12 tháng nhưng <span class="warn">KHÔNG gửi xuống OpenBao</span>. KV không có TTL, ô này chỉ để CMS nhắc.',
    ],
    map: [
      ['Transit', '<code>auto_rotate_period</code>'],
      ['PKI', '<code>ttl</code> (khi cấp) + <code>max_ttl</code> (trên role)'],
      ['Database', '<code>default_ttl</code> + <code>max_ttl</code>'],
      ['KV v2', 'không có — CMS tự quản'],
    ],
    json: '// OpenBao chỉ nhận đơn vị s / m / h — không nhận "tháng"\n1 tháng  = "730h"      1 giờ   = "1h"\n3 tháng  = "2190h"     24 giờ  = "24h"\n6 tháng  = "4380h"     7 ngày  = "168h"\n12 tháng = "8760h"     30 ngày = "720h"',
  },
  f_dossier: {
    t: 'Hồ sơ ràng buộc',
    d: 'Căn cứ pháp lý để cấp khóa. <b>Kiểm toán đối chiếu đúng trường này</b> — hỏi "cấp khóa cho ngân hàng này theo cái gì".',
    vd: '<code>HĐ-2026/SCOREHUB/003</code> · <code>YCNB-2026/207</code>',
    anh: [
      'Đối tượng <b>Bên ngoài</b> → <b>bắt buộc</b> nhập',
      'Đối tượng <b>Nội bộ</b> → tùy chọn (nội bộ thường không có hợp đồng)',
      'Validate: phải có ít nhất 1 chữ số và dài từ 6 ký tự',
    ],
    map: [['Hồ sơ ràng buộc', '<b>KHÔNG gửi xuống OpenBao</b> — chỉ nằm trong sổ CMS']],
    json: null,
  },
  f_algo: {
    t: 'Thuật toán',
    d: 'Mặc định theo loại khóa, hiếm khi phải đổi. Danh sách chỉ hiện đúng giá trị mà engine đang chọn chấp nhận — <b>gõ sai một ký tự là API trả lỗi</b>.',
    vd: '<code>rsa-2048</code> (Transit) · <code>rsa/2048</code> (PKI, tách thành 2 trường)',
    anh: [
      'Với <b>Khóa mã hóa</b>: chọn <code>aes256-gcm96</code> hoặc <code>chacha20-poly1305</code> thì khóa <b>không có public key</b> → <span class="warn">không bàn giao ra ngoài được</span>',
      'Chọn <code>rsa-*</code> thì mới có cặp public/private để bàn giao',
    ],
    map: [
      ['Transit', '<code>type</code> — một trường'],
      ['PKI', '<code>key_type</code> + <code>key_bits</code> — hai trường'],
      ['Database / KV v2', 'không có khái niệm này'],
    ],
    json: '// Transit\n{ "type": "rsa-2048" }\n\n// PKI (trên role)\n{ "key_type": "rsa", "key_bits": 2048 }',
  },
  f_deliv: {
    t: 'Bàn giao & xác nhận',
    d: 'Hai việc xảy ra <b>ngoài hệ thống</b> — anh Tộ gửi public key qua email/portal, đối tác gọi lại báo đã cài xong. CMS chỉ <b>ghi chép lại</b>.<br>Điền đủ <b>cả hai dòng</b> → khóa tự chuyển sang <b>Đang hiệu lực</b>.',
    vd: 'Gửi 20/08 qua Portal → đối tác báo nhận 22/08 → khóa hiệu lực từ 22/08',
    anh: [
      'Chỉ hiện với đối tượng <b>Bên ngoài</b>',
      'Xóa trắng ô ngày = <b>hoàn tác</b>, khóa quay lại Chưa xong bàn giao',
      'Đối tác báo cài lỗi → sửa lại ngày gửi, ghi chú vào ô người xác nhận',
      'Đối tác từ chối hẳn → dùng nút <b>Thu hồi</b>',
    ],
    map: [['Cả hai dòng', '<b>KHÔNG gọi API nào</b> — thuần ghi sổ']],
    json: null,
  },
  f_lockLevel: {
    t: 'Mức tạm khóa',
    d: 'Anh Tú chỉ nói cần "khóa ở mức từng khóa riêng lẻ", <b>không nói mấy mức</b>. Chia 3 mức là đề xuất, chờ anh Tộ chốt.',
    vd: 'Nghi lộ khóa → chọn Mức 3 để chặn thật ngay',
    anh: [
      '<b>Mức 1</b> — chỉ đánh dấu trên sổ. Không gọi API. Nghiệp vụ vẫn chạy',
      '<b>Mức 2</b> — chặn xoay / cấp thêm / bàn giao. Chặn ở tầng CMS',
      '<b>Mức 3</b> — chặn thật. Gọi API xuống OpenBao, mọi lệnh ký bị từ chối ngay',
    ],
    map: [
      ['Mức 3 — cách A', '<code>min_encryption_version</code> = latest + 1'],
      ['Mức 3 — cách B ⭐', '<b>soft delete</b> của OpenBao 2.0 — chặn dùng và chặn xoay, giữ nguyên khóa, khôi phục được'],
    ],
    json: 'POST /v1/transit/keys/scorehub-fid-sign-2026/config\n{ "min_encryption_version": 2 }   // latest_version(1) + 1\n\n// Mở khóa lại:\n{ "min_encryption_version": 0 }   // 0 = dùng bản mới nhất',
  },
  f_lockReason: {
    t: 'Lý do',
    d: 'Bắt buộc nhập. <b>Kiểm toán chắc chắn hỏi tới</b> khi rà soát vì sao khóa bị dừng giữa chừng.',
    vd: '<code>Nghi ngờ lộ khóa theo PYC-2026-0871</code>',
    anh: ['Lưu vào nhật ký cùng thời điểm bấm', 'Không gửi xuống OpenBao'],
    map: null, json: null,
  },
  f_rotate: {
    t: 'Xoay khóa',
    d: 'Chỉ <b>thêm một bản mới</b> vào chùm khóa. <b>KHÔNG xóa bản cũ, không hủy bản cũ</b> — bản cũ vẫn nằm trong OpenBao để xác thực dữ liệu đã ký từ trước.<br>Đây là "đổi khóa hằng năm" theo yêu cầu #1 của anh Tộ.',
    vd: 'Chùm đang có <code>{v1}</code> → xoay → <code>{v1, v2}</code>. v1 vẫn nguyên.',
    anh: [
      '<b>Đối tượng Bên ngoài</b> — sinh v2 nhưng <b>con trỏ giữ ở v1</b>, ứng dụng vẫn ký bằng v1 → <span class="ok">không gián đoạn</span>. Gửi public key v2 cho đối tác, họ xác nhận xong thì CMS mới đổi con trỏ sang v2',
      '<b>Đối tượng Nội bộ</b> — đổi con trỏ ngay, không ai bên ngoài giữ public key nên không cần chờ',
      '<b>Không có bước "hủy bản cũ"</b> trong luồng thường. Bản cũ tự nghỉ hưu khi con trỏ chuyển đi',
      '<span class="warn">Khai tử hẳn bản cũ chỉ làm khi có sự cố lộ khóa</span> — dùng nút Thu hồi, không phải nút này',
    ],
    map: [
      ['Transit', '<code>POST /v1/transit/keys/:name/rotate</code> (không có body)'],
      ['PKI', 'không có rotate — phải <b>cấp chứng thư mới</b>, serial mới'],
      ['Database / KV v2', 'không có khái niệm xoay khóa'],
    ],
    json: '// Bước 1 — sinh bản mới, con trỏ GIỮ NGUYÊN\nPOST /v1/transit/keys/scorehub-fid-sign-2026/rotate\n→ chùm khóa: { v1, v2 }   con trỏ vẫn = 1\n\n// Bước 2 — gửi public key v2 cho đối tác, chờ xác nhận\n\n// Bước 3 — đối tác xác nhận xong, ĐỔI CON TRỎ\nPOST /v1/kv/data/keyref/fid-sign\n{ "data": { "key_version": 2 } }\n→ từ giờ ứng dụng ký bằng v2. v1 vẫn còn trong OpenBao.',
  },
  f_revoke: {
    t: 'Thu hồi',
    d: 'Vĩnh viễn, không mở lại được. <b>Mỗi engine thu hồi một kiểu khác nhau.</b>',
    vd: 'Xác định đã lộ khóa / chấm dứt hợp đồng / cấp nhầm',
    anh: [
      '<span class="warn">Transit KHÔNG có lệnh "revoke"</span> — phải đẩy <code>min_decryption_version</code> lên để vô hiệu mọi phiên bản',
      'Xóa hẳn chỉ được khi bật <code>deletion_allowed</code>, mà CMS cố ý để <code>false</code> vì nghiệp vụ cần giữ để đối soát',
    ],
    map: [
      ['Transit', '<code>config</code> · <code>min_decryption_version</code> = latest + 1'],
      ['PKI', '<code>POST /v1/pki/revoke</code> · <code>serial_number</code>'],
      ['Database', '<code>POST /v1/sys/leases/revoke</code> · <code>lease_id</code>'],
      ['KV v2', '<code>DELETE /v1/kv/metadata/:path</code>'],
    ],
    json: '// PKI\nPOST /v1/pki/revoke\n{ "serial_number": "4a:1f:9c:22:e0:75:b3:8d:11:6f" }\n\n// Database\nPOST /v1/sys/leases/revoke\n{ "lease_id": "database/creds/scorehub-oracle/7Hk2mQ" }',
  },
  f_baoname: {
    t: 'Tên khóa trong OpenBao',
    d: 'Định danh kỹ thuật, <b>CMS tự sinh, người dùng không bao giờ nhập</b>. Nó chính là đoạn đường dẫn trên URL gọi API.',
    vd: '<code>scorehub-fid-sign-2026</code>',
    anh: [
      'Quy tắc: <code>&lt;hệ-thống&gt;-&lt;mã-đối-tượng&gt;-&lt;mục-đích&gt;-&lt;năm&gt;</code>',
      'Chỉ dùng <code>a-z</code>, <code>0-9</code>, dấu <code>-</code> — vì nó nằm thẳng trong URL',
      '<span class="warn">Đặt trùng tên = ghi đè lên khóa đang chạy</span> → phải định nghĩa quy tắc trong SRS',
    ],
    map: [['Tên khóa', 'đoạn <code>:name</code> / <code>:role</code> / <code>:path</code> trên URL']],
    json: 'POST /v1/transit/keys/scorehub-fid-sign-2026\n                      └──────────┬─────────┘\n                        tên khóa nằm trên URL',
  },

  /* ---------- Public key & con trỏ phiên bản ---------- */
  f_pubkey: {
    t: 'Public key',
    d: 'Nửa <b>công khai</b> của cặp khóa. Sinh ra để đưa cho đối tác — <b>không phải bí mật</b>, gửi qua email cũng được.<br>Đối tác dùng nó để <b>xác thực chữ ký</b> của mình. Không có nó, họ không tin được dữ liệu mình gửi.',
    vd: 'Copy chuỗi PEM → dán vào email → gửi cho phòng CNTT ngân hàng',
    anh: [
      'CMS <b>không tự gửi</b> — anh Tộ vẫn gửi bằng email / portal như bình thường',
      'CMS chỉ có nhiệm vụ <b>đưa được nội dung ra</b> để copy',
      'Sau khi xoay khóa, phải gửi public key của <b>bản mới</b>, không phải bản cũ',
      'Private key thì <b>không bao giờ</b> hiện ở đây, kể cả anh Tộ cũng không xem được',
    ],
    map: [['Lấy từ đâu', '<code>GET /v1/transit/keys/:name</code> → trường <code>keys[N].public_key</code>']],
    json: 'GET /v1/transit/keys/scorehub-fid-sign-2026\n\n{ "data": {\n    "latest_version": 2,\n    "keys": {\n      "1": { "public_key": "-----BEGIN PUBLIC KEY-----\\n..." },\n      "2": { "public_key": "-----BEGIN PUBLIC KEY-----\\n..." }\n    } } }',
  },
  f_version: {
    t: 'Phiên bản khóa',
    d: 'Mỗi lần xoay khóa, OpenBao <b>thêm một bản mới</b> vào chùm và <b>giữ nguyên các bản cũ</b>. Không có bản nào bị xóa.',
    vd: 'v1 → xoay khóa → chùm có { v1, v2 }. v1 vẫn nằm đó.',
    anh: [
      'Bản cũ giữ lại để <b>xác thực / giải mã dữ liệu đã ký từ trước</b>',
      'Xóa bản cũ đi = <b>dữ liệu cũ không đọc được nữa</b> → không bao giờ làm trong luồng thường',
      'Chỉ khi có <b>sự cố lộ khóa</b> mới dùng nút Thu hồi để khai tử bản cũ',
    ],
    map: [['Bản mới nhất', '<code>latest_version</code> — OpenBao trả về']],
    json: null,
  },
  f_pointer: {
    t: 'Con trỏ phiên bản (đang ký bằng bản nào)',
    d: 'Một bản ghi bé ghi <b>“hiện đang dùng bản mấy để ký”</b>. Đây là thứ giúp xoay khóa <b>không gây gián đoạn</b>.',
    vd: 'OpenBao có v1 và v2, nhưng con trỏ = 1 → ứng dụng vẫn ký bằng v1',
    anh: [
      '<b>Bấm Xoay khóa</b> → sinh bản mới nhưng con trỏ <b>giữ nguyên</b> → giao dịch không đứt',
      '<b>Bàn giao xong</b> → CMS đổi con trỏ sang bản mới → từ đó mới ký bằng bản mới',
      'Khóa <b>nội bộ</b> thì đổi con trỏ ngay khi xoay, không cần chờ ai',
    ],
    map: [
      ['CMS ghi', '<code>kv/data/keyref/&lt;khóa&gt;</code>'],
      ['Ứng dụng đọc', 'rồi truyền vào <code>key_version</code> khi gọi lệnh ký'],
    ],
    json: '// CMS ghi con trỏ\nPOST /v1/kv/data/keyref/fid-sign\n{ "data": { "key_version": 1 } }\n\n// Ứng dụng ký — PHẢI nói rõ bản nào\nPOST /v1/transit/sign/scorehub-fid-sign-2026\n{ "input": "<base64>", "key_version": 1 }\n\n// Không truyền key_version → OpenBao tự dùng bản MỚI NHẤT\n// → đối tác chưa có public key bản mới → XÁC THỰC HỎNG',
  },

  /* ---------- Tiêu đề cột trên bảng Danh mục khóa ---------- */
  th_id: {
    t: 'Mã khóa',
    d: 'Mã do <b>CMS tự sinh</b>, người dùng không nhập. Dùng để tra cứu và đối chiếu với nhật ký.',
    vd: '<code>KEY-2026-0042</code> (khóa mật mã) · <code>CRED-2026-0101</code> (credential / secret)',
    anh: ['Khác với <b>tên khóa trong OpenBao</b> — cái đó là định danh kỹ thuật nằm trên URL'],
    map: [['Mã khóa', '<b>KHÔNG gửi xuống OpenBao</b> — chỉ nằm trong sổ CMS']], json: null,
  },
  th_kt: {
    t: 'Loại khóa',
    d: 'Quyết định <b>engine OpenBao</b> nào được gọi, và toàn bộ payload gửi xuống.',
    vd: 'Khóa ký dữ liệu → engine Transit → <code>POST /v1/transit/keys/:name</code>',
    anh: [
      'Dòng nhỏ bên dưới hiện <b>thuật toán · phiên bản · engine</b>',
      '5 loại khóa nhưng chỉ 4 engine — Khóa ký và Khóa mã hóa dùng chung Transit',
    ],
    map: [['Transit', 'khóa ký, khóa mã hóa'], ['PKI', 'chứng thư TLS'], ['Database', 'credential CSDL'], ['KV v2', 'API secret / keytab']],
    json: null,
  },
  th_obj: {
    t: 'Đối tượng sử dụng / hồ sơ',
    d: 'Ai đang dùng khóa này, và <b>căn cứ nào</b> để cấp. Đây là hai cột kiểm toán hỏi tới nhiều nhất.',
    vd: '<code>Ngân hàng Đối tác D</code> · <span class="ok">Bên ngoài</span> · <code>HĐ-2026/SCOREHUB/003</code>',
    anh: [
      'Nhãn <b>Bên ngoài</b> → khóa có bước bàn giao, hồ sơ bắt buộc',
      'Nhãn <b>Nội bộ</b> → không bàn giao, hồ sơ tùy chọn',
      'Danh sách đối tượng khai ở menu <b>Danh mục đối tượng</b>',
    ],
    map: null, json: null,
  },
  th_ttl: {
    t: 'Thời hạn',
    d: 'Khóa dự kiến sống bao lâu. <b>Mốc chọn được khác nhau theo loại khóa</b> — không phải loại nào cũng tính bằng tháng.',
    vd: 'Khóa ký: 12 tháng · Credential CSDL: 30 ngày',
    anh: [
      'Transit → <code>auto_rotate_period</code>. <span class="warn">OpenBao không tự chặn khi hết hạn</span>',
      'PKI → <code>ttl</code>. <span class="ok">Hết hạn tự vô hiệu thật</span>',
      'Database → <code>default_ttl</code>. <span class="ok">Hết hạn tự xóa user</span>',
      'KV v2 → <span class="warn">không gửi xuống OpenBao</span>, chỉ để CMS nhắc',
    ],
    map: null, json: null,
  },
  th_exp: {
    t: 'Ngày hết hạn',
    d: 'Tính bằng <b>ngày hiệu lực + thời hạn</b>. Ngày hiệu lực là ngày đối tác xác nhận (khóa ngoài) hoặc ngày tạo (khóa nội bộ).',
    vd: 'Xác nhận 03/01 + 1 tháng → hết hạn 03/02',
    anh: [
      'Còn ≤ 90 ngày → nền vàng',
      'Còn ≤ 30 ngày → nền đỏ',
      '<span class="warn">Với khóa Transit và KV v2, đến ngày này OpenBao KHÔNG tự làm gì</span> — CMS phải chủ động xoay khóa',
      'Với PKI và Database thì hết hạn là tự vô hiệu thật',
    ],
    map: null, json: null,
  },
  th_status: {
    t: 'Trạng thái — cả 5 giá trị',
    d: 'Trạng thái <b>nghiệp vụ</b> do CMS quản. OpenBao không biết các trạng thái này.',
    vd: 'Dòng nhỏ bên dưới hiện tiến độ: <code>✓ đã gửi 20/08 · ○ chờ xác nhận</code>',
    anh: [
      '<b>Chưa xong bàn giao</b> — khóa ĐÃ có trong OpenBao, chờ ghi nhận đã gửi + đối tác xác nhận',
      '<b>Đang hiệu lực</b> — đang được dùng để ký / mã hóa',
      '<b>Tạm khóa</b> — tạm dừng, còn mở lại được',
      '<b>Thu hồi</b> — vĩnh viễn, không quay lại',
      '<b>Hết hiệu lực</b> — quá ngày hết hạn, CMS tự đổi',
    ],
    map: [['Lưu ý', '<b>Chưa xong bàn giao</b> chỉ là ghi sổ — nó KHÔNG chặn ứng dụng dùng khóa']],
    json: null,
  },
  th_act: {
    t: 'Cột Thao tác — nút nào hiện khi nào',
    d: 'Nút hiện ra <b>theo trạng thái của từng dòng</b>. Không phải dòng nào cũng có đủ nút.',
    vd: 'Dòng Đang hiệu lực → thấy Tạm khóa / Xoay khóa / Thu hồi',
    anh: [
      '<b>Chi tiết</b> — luôn có. Xem hồ sơ, tham số OpenBao, nhật ký',
      '<b>👁 Public key</b> — khóa bên ngoài. Xem và copy để gửi đối tác',
      '<b>Cập nhật bàn giao</b> — chỉ khi <i>Chưa xong bàn giao</i>. Điền 2 ngày là khóa vào hiệu lực',
      '<b>Tạm khóa</b> — chỉ khi <i>Đang hiệu lực</i>. Có 3 mức',
      '<b>Mở khóa</b> — chỉ khi <i>Tạm khóa</i>',
      '<b>Xoay khóa</b> — chỉ khi <i>Đang hiệu lực</i>. Sinh bản mới, con trỏ giữ nguyên',
      '<b>Thu hồi</b> — vĩnh viễn. Không có ở dòng đã Thu hồi / Hết hiệu lực',
    ],
    map: null, json: null,
  },
  qf_bar: {
    t: 'Bộ lọc nhanh',
    d: 'Bốn nhóm việc cần để mắt. Con số là <b>số khóa đang rơi vào nhóm đó</b>. Đây là thứ thay cho việc phải có nhiều menu riêng.',
    vd: '<code>Chưa xong bàn giao 2</code> → còn 2 khóa chưa gửi hoặc chưa được xác nhận',
    anh: [
      '<b>Chưa xong bàn giao</b> — việc còn dở, cần đi hỏi đối tác',
      '<b>Sắp hết hạn ≤90 ngày</b> — cần bắt đầu chuẩn bị xoay khóa',
      '<b>Đang tạm khóa</b> — đang có sự cố chưa xử lý dứt điểm',
    ],
    map: null, json: null,
  },
  btn_new: {
    t: 'Tạo khóa mới',
    d: 'Bấm là CMS <b>gọi OpenBao sinh khóa ngay</b> — không có bước phê duyệt, vì công cụ chỉ có một người dùng.',
    vd: 'Khai 4 ô → bấm Tạo khóa → khóa tồn tại thật trong OpenBao',
    anh: [
      'Đối tượng <b>Bên ngoài</b> → trạng thái <i>Chưa xong bàn giao</i>',
      'Đối tượng <b>Nội bộ</b> → <i>Đang hiệu lực</i> ngay',
      '<span class="warn">Khóa dùng được ngay từ lúc tạo</span> — trạng thái “Chưa xong bàn giao” không chặn gì',
    ],
    map: null, json: null,
  },
  menu_grp: {
    t: 'Công cụ này làm gì',
    d: 'OpenBao đã lo phần lõi bảo mật. Công cụ này chỉ làm <b>3 việc OpenBao không làm được</b>.',
    vd: null,
    anh: [
      '<b>1. Quyển sổ</b> — khóa nào cấp cho ai, theo hồ sơ nào, hết hạn khi nào',
      '<b>2. Nút Tạm khóa</b> — trạng thái tạm dừng có thể khôi phục, OpenBao không có',
      '<b>3. Nhật ký &amp; báo cáo</b> — để trả lời kiểm toán',
    ],
    map: [['Nguyên tắc', 'CMS <b>không nằm trên đường chạy</b> nghiệp vụ hằng ngày. CMS sập, giao dịch vẫn chạy']],
    json: null,
  },
  th_obj_code: {
    t: 'Mã đối tượng',
    d: 'Viết <b>HOA, không dấu, không khoảng trắng</b>. Vì mã này được ghép thẳng vào tên khóa trong OpenBao, mà tên đó nằm trên URL.',
    vd: '<code>FID</code> → tên khóa <code>transit/keys/scorehub-fid-sign-2026</code>',
    anh: ['Có dấu tiếng Việt hoặc khoảng trắng là gọi API hỏng'],
    map: null, json: null,
  },
  th_obj_scope: {
    t: 'Phạm vi',
    d: 'Quyết định khóa cấp cho đối tượng này có phải <b>bàn giao ra ngoài</b> hay không. Đây là thuộc tính của đối tượng, không phải của từng khóa.',
    vd: '<code>Ngân hàng Đối tác D</code> → Bên ngoài · <code>Airflow</code> → Nội bộ',
    anh: [
      '<b>Bên ngoài</b> → có bước bàn giao · hồ sơ bắt buộc · xoay khóa phải phối hợp',
      '<b>Nội bộ</b> → không bàn giao · hồ sơ tùy chọn · xoay khóa trong suốt',
    ],
    map: null, json: null,
  },
  th_log: {
    t: 'Nhật ký thao tác',
    d: 'Ghi lại <b>mọi thao tác đổi trạng thái</b>, kèm lý do người dùng nhập và tham số thật đã gửi xuống OpenBao.',
    vd: '<code>TẠM KHÓA · KEY-2026-0033 · Mức 3 — min_encryption_version = 2 · Nghi lộ khóa PYC-2026-0871</code>',
    anh: [
      'Cột <b>Lý do / tham số</b> ghi cả hai: vì sao làm, và đã gọi lệnh gì',
      '<span class="warn">Đã bỏ cột Tài khoản vì chỉ 1 người dùng</span> — nếu sau này thêm người thì dữ liệu cũ không truy hồi được',
    ],
    map: null, json: null,
  },
  rpt_type: {
    t: 'Kết xuất báo cáo',
    d: 'Đầu ra cho kiểm toán. <b>Các cột cần có phải chốt ngay từ đầu</b> — sau này đòi thêm cột mà hệ thống chưa ghi thì không truy hồi được.',
    vd: 'Báo cáo <i>Tuân thủ trần hiệu lực</i> → liệt kê khóa nào đang vượt 12 tháng',
    anh: ['🔴 Chưa chốt: kiểm toán cần đúng những cột nào'],
    map: null, json: null,
  },
  tab_api: {
    t: 'Tab Tham số OpenBao',
    d: 'Chỗ tra cứu cho dev: <b>chính xác</b> những trường CMS gửi xuống và những trường OpenBao trả về.',
    vd: null,
    anh: [
      'Tên trường do <b>OpenBao quy định</b>, không đổi được',
      'Giá trị do <b>nghiệp vụ quyết</b>, CMS tự dịch từ hồ sơ',
      'Dòng nền đỏ = <b>khóa cứng</b>, không cho người dùng sửa',
      'Bảng dưới = trường OpenBao trả về, <b>CMS bắt buộc lưu</b>',
    ],
    map: null, json: null,
  },
};

/* thêm từ điển trường API cho tab kỹ thuật */
const API_DOC = {
  name: 'Tên khóa, cũng là đường dẫn <code>/transit/keys/&lt;name&gt;</code>. CMS sinh tự động.',
  type: 'Thuật toán. Chỉ nhận: <b>aes128-gcm96, aes256-gcm96, chacha20-poly1305, ed25519, ecdsa-p256/384/521, rsa-2048/3072/4096, hmac</b>.',
  auto_rotate_period: 'Chu kỳ tự sinh bản mới. <code>"0"</code> = tắt. <span class="warn">Không nhận giá trị ngắn hơn 1 giờ. Đây KHÔNG phải hạn dùng — bản cũ vẫn sống.</span>',
  exportable: 'Cho phép xuất private key ra ngoài. <span class="warn">Bật rồi KHÔNG TẮT ĐƯỢC — CMS khóa cứng ở false.</span>',
  allow_plaintext_backup: 'Cho phép backup khóa dạng rõ. <span class="warn">Bật rồi KHÔNG TẮT ĐƯỢC — khóa cứng ở false.</span>',
  min_encryption_version: 'Phiên bản tối thiểu được dùng để ký/mã hóa. <b>Đây là cách thực hiện Tạm khóa Mức 3.</b>',
  min_decryption_version: 'Phiên bản tối thiểu còn được giải mã/xác thực. <b>Đây là cách cắt bản cũ khi hết hạn, và cách thu hồi khóa Transit.</b>',
  deletion_allowed: 'Cho phép xóa hẳn khóa. <b>KHÔNG phải tham số lúc tạo</b> — chỉ đặt được ở <code>POST /transit/keys/:name/config</code>. Khóa mới sinh <b>mặc định đã là <code>false</code></b> nên CMS không cần gửi gì. Nghiệp vụ giữ nguyên false để còn đối soát.',
  latest_version: '<b>OpenBao trả về.</b> Phiên bản mới nhất đang giữ.',
  role: 'Role PKI quy định chứng thư nào được phép cấp.',
  allowed_domains: 'Danh sách tên miền role được phép cấp chứng thư. Đặt ở <b>Bước A</b>, khi tạo role.',
  allow_subdomains: 'Cho phép cấp cho tên miền con của <code>allowed_domains</code>. Đặt ở <b>Bước A</b>.',
  common_name: 'CN của chứng thư. Đặt ở <b>Bước B</b>, mỗi lần cấp. Phải nằm trong <code>allowed_domains</code> của role.',
  ttl: 'Thời hạn chứng thư. <span class="warn">Không vượt được <code>max_ttl</code> của role.</span>',
  max_ttl: 'Trần thời hạn trên role. <b>Chỗ ép chính sách "tối đa 12 tháng" xuống kỹ thuật.</b>',
  key_type: 'Loại khóa PKI: <code>rsa</code> / <code>ec</code> / <code>ed25519</code>.',
  key_bits: 'Độ dài khóa: RSA 2048/3072/4096 · EC 224/256/384/521 · bỏ qua với ed25519.',
  format: 'Định dạng trả về: <code>pem</code> / <code>der</code> / <code>pem_bundle</code>.',
  no_store: 'Không lưu chứng thư đã cấp. <span class="warn">Đặt true thì không thu hồi bằng serial được — phải để false.</span>',
  serial_number: '<b>OpenBao trả về, bắt buộc lưu.</b> PKI chỉ thu hồi được bằng serial.',
  expiration: '<b>OpenBao trả về.</b> Thời điểm chứng thư hết hạn.',
  db_name: 'Tên kết nối CSDL đã khai trong OpenBao.',
  creation_statements: 'Câu lệnh SQL tạo user tạm. DBA soạn.',
  default_ttl: 'Thời hạn mặc định của credential. Hết hạn OpenBao <b>tự xóa user</b>.',
  lease_id: '<b>OpenBao trả về, phải lưu.</b> Thu hồi credential đang phát phải gọi theo lease_id.',
  lease_duration: 'Thời gian còn lại của lease.',
  path: 'Đường dẫn <code>/kv/data/&lt;path&gt;</code>. KV v2 không có schema.',
  data: 'Nội dung tùy ý. <span class="warn">KV v2 KHÔNG có TTL, KHÔNG tự xoay.</span>',
  version: '<b>OpenBao trả về.</b> Số phiên bản dữ liệu.',
};

/* Tạm khóa Mức 3 — mỗi engine một cơ chế khác nhau.
   PKI KHÔNG tạm dừng được: chứng thư đã cấp chỉ có thể thu hồi vĩnh viễn. */
const LOCK3 = {
  Transit: {
    ok: true,
    label: 'Mức 3 — Vô hiệu thật: chặn ký và giải mã',
    cmd: (k, e) => `POST /v1/transit/keys/${k.bao.split('/').pop()}/config { "min_encryption_version": ${(e.latest || 0) + 1} }`,
    effect: 'Gọi API xuống OpenBao — <code>min_encryption_version</code> = latest + 1. Mọi lệnh ký bị từ chối ngay, không phải sửa ứng dụng.',
  },
  PKI: {
    ok: false,
    why: 'Chứng thư đã cấp <b>không tạm dừng được</b>. OpenBao PKI chỉ có thu hồi vĩnh viễn bằng <code>serial_number</code>, không có trạng thái tạm dừng khôi phục được.',
  },
  Database: {
    ok: true,
    label: 'Mức 3 — Vô hiệu thật: thu hồi lease + chặn cấp mới',
    cmd: (k, e) => `POST /v1/sys/leases/revoke { "lease_id": "${e.leaseId || '—'}" } + gỡ policy đọc database/creds/${e.dbRole || '—'}`,
    effect: 'Thu hồi lease đang phát (user bị xóa khỏi CSDL) <b>và</b> gỡ policy để ứng dụng không xin được credential mới. <span class="warn">Không dùng min_encryption_version — engine Database không có tham số đó.</span>',
  },
  'KV v2': {
    ok: true,
    label: 'Mức 3 — Vô hiệu thật: gỡ quyền đọc',
    cmd: (k, e) => `gỡ policy đọc kv/data/${e.kvPath || '—'}`,
    effect: 'Gỡ policy đọc đường dẫn đó. <span class="warn">KV v2 không có min_encryption_version — chặn bằng phân quyền là cách duy nhất.</span>',
  },
};

const DANGER = { exportable: 1, allow_plaintext_backup: 1, no_store: 1 };
const tt = (f) => (TIP[f] || API_DOC[f]) ? `<i class="tt ${DANGER[f] ? 'danger' : ''}" data-tip="${esc(f)}" tabindex="0">i</i>` : '';
const lb = (text, f, req) => `<label>${text}${req ? ' <span class="req-mark">*</span>' : ''}${tt(f)}</label>`;

function tipHtml(f) {
  if (API_DOC[f] && !TIP[f]) return { head: f, body: `<p>${API_DOC[f]}</p>` };
  const p = TIP[f]; if (!p) return null;
  let h = `<p>${p.d}</p>`;
  if (p.vd) h += `<h6>Ví dụ</h6><p>${p.vd}</p>`;
  if (p.anh && p.anh.length) h += `<h6>Chọn ô này ảnh hưởng tới</h6><ul>${p.anh.map(x => `<li>${x}</li>`).join('')}</ul>`;
  if (p.map) h += `<h6>Gửi xuống OpenBao</h6><table><tbody>${p.map.map(m => `<tr><td>${m[0]}</td><td>${m[1]}</td></tr>`).join('')}</tbody></table>`;
  if (p.json) h += `<h6>JSON mẫu</h6><pre>${esc(p.json)}</pre>`;
  return { head: p.t, body: h };
}

/* ---- Tham số API suy ra từ hồ sơ ---- */
function apiParams(k) {
  const t = KT(k.kt), e = EX(k.id), req = [], res = [];
  const P = (n, v, lock, grp) => req.push({ n, v, lock, grp });
  const R = (n, v) => res.push({ n, v });
  if (t.engine === 'Transit') {
    P('name', k.bao.split('/').pop()); P('type', k.algo);
    P('auto_rotate_period', k.ttlH + 'h');
    P('exportable', 'false', 1); P('allow_plaintext_backup', 'false', 1);
    R('latest_version', e.latest); R('min_decryption_version', e.minDec);
    R('deletion_allowed', 'false  (mặc định, CMS không đổi)');
    R('min_encryption_version', e.minEnc + (e.minEnc > 0 ? '  ← đang bị chặn' : ''));
  } else if (t.engine === 'PKI') {
    const A = 'Bước A — POST /v1/pki/roles/' + (e.pkiRole || ':role') + '  (chạy MỘT LẦN khi thiết lập)';
    const B = 'Bước B — POST /v1/pki/issue/' + (e.pkiRole || ':role') + '  (chạy MỖI LẦN cấp chứng thư)';
    P('allowed_domains', e.allowed || '—', 0, A);
    P('allow_subdomains', 'true', 0, A);
    P('key_type', (k.algo || '/').split('/')[0], 0, A);
    P('key_bits', (k.algo || '/').split('/')[1] || '—', 0, A);
    P('max_ttl', k.ttlH + 'h', 0, A);
    P('no_store', 'false', 1, A);
    P('common_name', e.cn || '—', 0, B);
    P('ttl', k.ttlH + 'h', 0, B);
    P('format', 'pem', 0, B);
    R('serial_number', e.serial || '—'); R('expiration', fmt(k.exp));
  } else if (t.engine === 'Database') {
    P('db_name', e.dbRole || '—'); P('default_ttl', k.ttlH + 'h'); P('max_ttl', k.ttlH + 'h');
    P('creation_statements', '(DBA soạn)', 1);
    R('lease_id', e.leaseId || '—'); R('lease_duration', e.leaseDur || '—');
  } else {
    P('path', 'kv/data/' + (e.kvPath || '—')); P('data', '(nội dung tùy ý)');
    R('version', e.kvVersion || '—');
  }
  return { req, res, engine: t.engine };
}

/* ---- Nút thao tác theo trạng thái ---- */
function actionsFor(k) {
  const a = [`<a data-act="detail" data-id="${k.id}">Chi tiết</a>`];
  if (OBJ(k.obj).ext && KT(k.kt).engine !== 'Database') a.push(`<a data-act="pubkey" data-id="${k.id}"><i class="fa fa-eye"></i> Public key</a>`);
  if (k.status === 'CHUA_XONG') a.push(`<a data-act="deliv" data-id="${k.id}">Cập nhật bàn giao</a>`, `<a data-act="revoke" data-id="${k.id}" class="danger">Thu hồi</a>`);
  else if (k.status === 'HIEU_LUC') {
    if (LOCK3[KT(k.kt).engine].ok) a.push(`<a data-act="lock" data-id="${k.id}">Tạm khóa</a>`);
    else a.push(`<span class="muted" style="font-size:12.5px;margin-right:9px" title="Chứng thư không tạm dừng được">Tạm khóa —</span>`);
    a.push(`<a data-act="rotate" data-id="${k.id}">Xoay khóa</a>`, `<a data-act="revoke" data-id="${k.id}" class="danger">Thu hồi</a>`);
  }
  else if (k.status === 'TAM_KHOA') a.push(`<a data-act="unlock" data-id="${k.id}">Mở khóa</a>`, `<a data-act="revoke" data-id="${k.id}" class="danger">Thu hồi</a>`);
  return a.join('');
}

/* ---------------- MENU ---------------- */
const NAV = [
  { group: 'Chức năng hiện có của SQLWF' },
  { icon: 'fa-database', label: 'Quản lý dữ liệu', disabled: true },
  { icon: 'fa-check-double', label: 'Data Quality', disabled: true },
  { icon: 'fa-users-cog', label: 'Quản trị hệ thống', disabled: true },
  { group: 'Quản trị khóa (đề xuất mới)', isNew: true },
  { icon: 'fa-key', label: 'Danh mục khóa', route: 'keys' },
  { icon: 'fa-address-book', label: 'Danh mục đối tượng', route: 'objs' },
  { icon: 'fa-file-alt', label: 'Nhật ký & báo cáo', route: 'audit' },
];
const TITLES = { keys: 'Danh mục khóa', objs: 'Danh mục đối tượng', audit: 'Nhật ký & báo cáo' };

function renderNav() {
  const cur = route();
  $('#nav').innerHTML = NAV.map(n => {
    if (n.group) return `<li class="nav-group ${n.isNew ? 'new' : ''}">${esc(n.group)}${n.isNew ? tt('menu_grp') : ''}</li>`;
    if (n.disabled) return `<li><a class="disabled-link"><i class="fa ${n.icon}"></i>${esc(n.label)}</a></li>`;
    return `<li><a href="#/${n.route}" class="${cur === n.route ? 'active' : ''}"><i class="fa ${n.icon}"></i>${esc(n.label)}</a></li>`;
  }).join('');
}

let SHOW_NOTES = true;
const note = (t, kind) => SHOW_NOTES ? `<div class="hint ${kind || ''}"><b><i class="fa fa-comment-dots"></i> Ghi chú nghiệp vụ:</b> ${t}</div>` : '';

/* ============================================================
   MÀN 1 — DANH MỤC KHÓA
   ============================================================ */
const QF = [
  { k: '', l: 'Tất cả', f: () => true },
  { k: 'bangiao', l: 'Chưa xong bàn giao', f: (x) => x.status === 'CHUA_XONG' },
  { k: 'hethan', l: 'Sắp hết hạn ≤90 ngày', f: (x) => x.status === 'HIEU_LUC' && x.exp && days(x.exp) <= 90 },
  { k: 'khoa', l: 'Đang tạm khóa', f: (x) => x.status === 'TAM_KHOA' },
];

function viewKeys() {
  const f = window.__f || { q: '', ext: '', qf: '' };
  const qf = QF.find(q => q.k === f.qf) || QF[0];
  const list = DB.keys.filter(x => qf.f(x)
    && (!f.q || (x.id + x.obj + x.dossier).toLowerCase().includes(f.q.toLowerCase()))
    && (!f.ext || String(OBJ(x.obj).ext) === f.ext));

  const rows = list.map((x, i) => {
    const t = KT(x.kt), ext = OBJ(x.obj).ext;
    let sub = '';
    if (x.status === 'CHUA_XONG') {
      sub = `<div class="muted" style="font-size:11.5px">
        ${x.sentAt ? '<span class="done-tick">✓</span> đã gửi ' + fmt(x.sentAt) : '<span class="wait-tick">○</span> chưa gửi'} ·
        ${x.cfAt ? '<span class="done-tick">✓</span> đã xác nhận' : '<span class="wait-tick">○</span> chờ xác nhận'}</div>`;
    } else if (x.lockReason) {
      sub = `<div class="muted" style="font-size:11.5px;max-width:200px">${esc(x.lockReason)}</div>`;
    }
    return `<tr>
      <td class="text-center">${i + 1}</td>
      <td class="mono">${esc(x.id)}</td>
      <td>${esc(t.name)}
        <div class="muted" style="font-size:11.5px">${esc(x.algo)} · ${esc(t.engine)}</div>
        <div style="font-size:11.5px">OpenBao có <b>v1…v${x.ver}</b> ·
          ${x.activeVer === x.ver
        ? `đang ký <b>v${x.activeVer}</b>`
        : `<span class="req-mark">đang ký v${x.activeVer}, chưa chuyển sang v${x.ver}</span>`}</div></td>
      <td>${esc(x.obj)} ${extTag(ext)}
        <div class="muted" style="font-size:11.5px">${x.dossier ? esc(x.dossier) : '<i>không có hồ sơ</i>'}</div></td>
      <td class="nowrap">${ttlLabel(t, x.ttlH)}</td>
      <td class="nowrap">${expCell(x.exp, x.status)}</td>
      <td>${stBadge(x.status)}${sub}</td>
      <td class="actions nowrap">${actionsFor(x)}</td>
    </tr>`;
  }).join('');

  return `
  ${note('Một danh sách duy nhất. Bấm <b>Tạo khóa mới</b> là CMS gọi OpenBao sinh khóa ngay — không có bước phê duyệt.<br>Khóa cho đối tượng <b>Bên ngoài</b> vào trạng thái <b>Chưa xong bàn giao</b>; điền đủ ngày gửi và ngày đối tác xác nhận thì <b>tự chuyển</b> sang Đang hiệu lực. Khóa <b>Nội bộ</b> dùng được ngay.')}

  <div class="qf">
    ${QF.map(q => `<a data-act="qf" data-id="${q.k}" class="${f.qf === q.k ? 'on' : ''}">${esc(q.l)}
      <span class="cnt">${DB.keys.filter(q.f).length}</span></a>`).join('')}
    <span style="align-self:center">${tt('qf_bar')}</span>
  </div>

  <div class="card">
    <div class="card-header">Thông tin tìm kiếm</div>
    <div class="card-body font-size-14">
      <div class="row">
        <div class="col-md-6 form-group"><label>Mã khóa / đối tượng / hồ sơ</label>
          <input class="form-control" id="fq" value="${esc(f.q)}" placeholder="Nhập từ khóa..."></div>
        <div class="col-md-3 form-group"><label>Phạm vi</label>
          <select class="form-control" id="fext"><option value="">Tất cả</option>
            <option value="true" ${f.ext === 'true' ? 'selected' : ''}>Bên ngoài</option>
            <option value="false" ${f.ext === 'false' ? 'selected' : ''}>Nội bộ</option></select></div>
      </div>
      <div class="text-center mt-2">
        <button class="btn btn-secondary" id="btnReset"><i class="fa fa-times"></i> Bỏ tìm kiếm</button>
        <button class="btn btn-primary ml-3" id="btnSearch"><i class="fa fa-search"></i> Tìm kiếm</button>
        <button class="btn btn-primary ml-3" data-act="new"><i class="fa fa-plus"></i> Tạo khóa mới</button>
        <span class="ml-2">${tt('btn_new')}</span>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-header">Kết quả tra cứu${f.qf ? ' — ' + esc(qf.l) : ''}</div>
    <div class="card-body font-size-14">
      <div class="ui-table"><table>
        <thead><tr><th style="width:52px">STT</th>
          <th>Mã khóa${tt('th_id')}</th>
          <th>Loại khóa${tt('th_kt')}</th>
          <th>Đối tượng / hồ sơ${tt('th_obj')}</th>
          <th>Thời hạn${tt('th_ttl')}</th>
          <th>Hết hạn${tt('th_exp')}</th>
          <th>Trạng thái${tt('th_status')}</th>
          <th style="width:290px">Thao tác${tt('th_act')}</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="8" class="text-center muted">Không có dữ liệu</td></tr>'}</tbody>
      </table></div>
      <div class="paginator"><span>Bản ghi 1 đến ${list.length} trong ${list.length} bản ghi</span>
        <span class="pages"><span class="cur">1</span></span></div>
    </div>
  </div>`;
}

/* ---------------- MÀN 2 — DANH MỤC ĐỐI TƯỢNG ---------------- */
function viewObjs() {
  const rows = OBJS.map((o, i) => `<tr>
    <td class="text-center">${i + 1}</td>
    <td class="mono">${esc(o.code)}</td>
    <td>${esc(o.n)}</td>
    <td>${extTag(o.ext)}</td>
    <td class="muted" style="font-size:12px">${o.ext ? 'Có bước bàn giao · hồ sơ bắt buộc' : 'Không bàn giao · hồ sơ tùy chọn'}</td>
    <td class="text-center">${DB.keys.filter(k => k.obj === o.n).length}</td>
  </tr>`).join('');

  return `
  ${note('SQLWF <b>không có</b> menu Quản lý đối tác dùng chung — mình đã kiểm tra lại code: <code>PartnerComponent</code> chỉ nằm trong module Backtest (<code>backtest-management/partner</code>). Nên tool này phải tự có danh mục riêng.<br><b>Mã đối tượng</b> viết hoa không dấu vì nó được ghép vào tên khóa trong OpenBao.')}
  <div class="card">
    <div class="card-header">Danh mục đối tượng sử dụng khóa</div>
    <div class="card-body font-size-14">
      <div class="text-right mb-2"><button class="btn btn-primary btn-sm" data-act="addobj"><i class="fa fa-plus"></i> Thêm đối tượng</button></div>
      <div class="ui-table"><table>
        <thead><tr><th style="width:52px">STT</th>
          <th style="width:140px">Mã${tt('th_obj_code')}</th><th>Tên đối tượng</th>
          <th style="width:140px">Phạm vi${tt('th_obj_scope')}</th><th>Hệ quả</th><th style="width:90px">Số khóa</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
    </div>
  </div>`;
}

/* ---------------- MÀN 3 — NHẬT KÝ ---------------- */
function viewAudit() {
  const rows = DB.audit.map((a, i) => `<tr>
      <td class="text-center">${i + 1}</td>
      <td class="nowrap mono">${esc(a.at)}</td>
      <td>${(a.act.indexOf('TẠM KHÓA') === 0 || a.act.indexOf('Thu hồi') >= 0) ? `<b class="req-mark">${esc(a.act)}</b>` : esc(a.act)}</td>
      <td class="mono">${esc(a.obj)}</td>
      <td>${a.reason ? esc(a.reason) : '<span class="muted">—</span>'}</td>
    </tr>`).join('');

  return `
  ${note('Đầu ra cho kiểm toán. Đã bỏ cột <i>Tài khoản</i> vì chỉ một người dùng.<span class="d-block mt-2"><b class="req-mark">Cần quyết sớm:</b> nếu sau này có người dùng thứ hai thì phải có lại cột đó, mà dữ liệu quá khứ <b>không truy hồi được</b>.</span>')}
  <div class="card">
    <div class="card-header">Kết xuất báo cáo</div>
    <div class="card-body font-size-14">
      <div class="row">
        <div class="col-md-6 form-group"><label>Loại báo cáo${tt('rpt_type')}</label>
          <select class="form-control">
            <option>Danh mục khóa đang hiệu lực</option>
            <option>Khóa sắp hết hạn / quá hạn</option>
            <option>Lịch sử tạm khóa &amp; thu hồi</option>
            <option>Nhật ký bàn giao và xác nhận</option>
            <option>Tuân thủ trần hiệu lực</option>
          </select></div>
        <div class="col-md-4 form-group"><label>Khoảng thời gian</label>
          <input class="form-control" value="01/08/2026 - 27/08/2026"></div>
        <div class="col-md-2 form-group d-flex align-items-end pb-3">
          <button class="btn btn-primary" data-act="export"><i class="fa fa-file-excel"></i> Kết xuất</button></div>
      </div>
    </div>
  </div>
  <div class="card">
    <div class="card-header">Nhật ký thao tác</div>
    <div class="card-body font-size-14">
      <div class="ui-table"><table>
        <thead><tr><th style="width:52px">STT</th><th style="width:165px">Thời điểm</th>
          <th>Hành động${tt('th_log')}</th><th>Khóa</th><th>Lý do / tham số</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
    </div>
  </div>`;
}

/* ---------------- MODAL ---------------- */
const modal = (h) => { $('#modalRoot').innerHTML = h; };
const closeModal = () => { $('#modalRoot').innerHTML = ''; hideTip(); };
const shell = (title, body, foot, size) => `<div class="modal-backdrop-x" data-close="1">
  <div class="modal-x ${size || ''}">
    <div class="m-head"><span>${title}</span><span class="close-x" data-close="1"><i class="fa fa-times"></i></span></div>
    <div class="m-body">${body}</div><div class="m-foot">${foot}</div></div></div>`;

function openNew() {
  modal(shell('<i class="fa fa-plus"></i> Tạo khóa mới', `
    <div class="hint">Bấm vào <i class="tt">i</i> cạnh mỗi ô để mở giải thích đầy đủ: ô đó là gì, chọn nó thì <b>trường nào bị đổi theo</b>, và <b>JSON gửi xuống OpenBao</b>. Bấm ra ngoài để tắt.</div>
    <div class="row">
      <div class="col-md-7 form-group">${lb('Đối tượng sử dụng khóa', 'f_obj', 1)}
        <select class="form-control" id="nObj">
          <optgroup label="Bên ngoài tổ chức">${OBJS.filter(o => o.ext).map(o => `<option>${esc(o.n)}</option>`).join('')}</optgroup>
          <optgroup label="Nội bộ">${OBJS.filter(o => !o.ext).map(o => `<option>${esc(o.n)}</option>`).join('')}</optgroup>
        </select>
        <div id="nObjAffect"></div></div>
      <div class="col-md-5 form-group">${lb('Loại khóa', 'f_kt', 1)}
        <select class="form-control" id="nKt">${KEY_TYPES.map(t => `<option value="${t.code}">${esc(t.name)}</option>`).join('')}</select>
        <div class="src-note" id="nKtNote"></div></div>

      <div class="col-md-5 form-group">${lb('Thời hạn hiệu lực', 'f_ttl', 1)}
        <select class="form-control" id="nTtl"></select>
        <div id="nTtlAffect"></div></div>
      <div class="col-md-7 form-group" id="nDosWrap">
        <div id="nDosLbl"></div>
        <input class="form-control" id="nDos" placeholder="Ví dụ: HĐ-2026/SCOREHUB/003">
        <div class="src-note" id="nDosNote"></div></div>

      <div class="col-12"><span class="linkish" data-act="advToggle"><i class="fa fa-cog"></i> Tuỳ chỉnh thuật toán (ít khi cần)</span>
        <div id="nAdv" style="display:none" class="mt-2">
          ${lb('Thuật toán', 'f_algo')}
          <select class="form-control" id="nAlgo"></select>
          <div class="src-note" id="nAlgoNote"></div></div></div>

      <div class="col-12 mt-2"><div class="hint" id="nSummary"></div></div>
    </div>
  `, `<button class="btn btn-secondary" data-close="1">Hủy</button>
      <button class="btn btn-primary ml-2" data-act="doNew"><i class="fa fa-key"></i> Tạo khóa</button>`));
  syncNew();
}

/** Toàn bộ quy tắc phụ thuộc giữa các ô nằm ở đây. */
function syncNew() {
  const sO = $('#nObj'), sK = $('#nKt'), sT = $('#nTtl'), sA = $('#nAlgo');
  if (!sO || !sK || !sT || !sA) return;
  const o = OBJ(sO.value), t = KT(sK.value);

  // 1. Đối tượng → phạm vi → luồng + hồ sơ bắt buộc hay không
  $('#nObjAffect').innerHTML = `<div class="affect">${extTag(o.ext)}
    ${o.ext
      ? '<b>→ có bước bàn giao.</b> Tạo xong khóa vào <b>Chưa xong bàn giao</b>. Hồ sơ ràng buộc <b>bắt buộc</b>.'
      : '<b>→ không có bàn giao.</b> Tạo xong là <b>Đang hiệu lực</b> ngay. Hồ sơ ràng buộc <b>tùy chọn</b>.'}</div>`;
  $('#nDosLbl').innerHTML = lb('Hồ sơ ràng buộc', 'f_dossier', o.ext ? 1 : 0)
    + (o.ext ? '' : ' <span class="muted" style="font-size:12px">(tùy chọn)</span>');
  $('#nDosNote').innerHTML = o.ext
    ? 'Bắt buộc — kiểm toán đối chiếu trường này. Phải có số hiệu, tối thiểu 6 ký tự.'
    : 'Không bắt buộc với đối tượng nội bộ.';

  // 2. Loại khóa → engine + danh sách thuật toán + danh sách thời hạn
  $('#nKtNote').innerHTML = `engine <b>${esc(t.engine)}</b>`;
  const keepA = sA.value;
  sA.innerHTML = t.algos.map(a => `<option ${a === keepA ? 'selected' : ''}>${esc(a)}</option>`).join('');
  const keepT = +sT.value;
  sT.innerHTML = t.ttl.map(x => `<option value="${x.h}" ${x.h === (t.ttl.some(y => y.h === keepT) ? keepT : t.ttlDef) ? 'selected' : ''}>${esc(x.l)}</option>`).join('');

  // 3. Thời hạn → trường API + cách hết hạn
  const h = +sT.value;
  $('#nTtlAffect').innerHTML = `<div class="affect">
    ${t.ttlField
      ? `<b>→ gửi xuống <code>${t.ttlField}: "${h}h"</code></b>`
      : '<b>→ KHÔNG gửi xuống OpenBao.</b> KV v2 không có TTL.'}
    <br>${t.ttlNote}</div>`;

  // 4. Thuật toán → trường API
  $('#nAlgoNote').innerHTML = t.engine === 'Transit' ? `→ <code>type=${esc(sA.value)}</code>`
    : t.engine === 'PKI' ? `→ <code>key_type=${esc(sA.value.split('/')[0])}</code>, <code>key_bits=${esc(sA.value.split('/')[1])}</code>`
      : `engine <b>${esc(t.engine)}</b> không dùng thuật toán`;

  // 5. Tóm tắt: tên khóa tự sinh + ngày hết hạn
  const bao = baoName(o, t);
  const exp = t.ttlField || t.code === 'SEC' ? addHours(h) : '';
  $('#nSummary').innerHTML = `<b>CMS sẽ tự sinh:</b>
    <table style="width:100%;margin-top:6px;font-size:13px">
      <tr><td style="width:190px;color:#767574">Mã khóa</td><td class="mono">KEY-2026-0xxx</td></tr>
      <tr><td style="color:#767574">Tên trong OpenBao ${tt('f_baoname')}</td><td class="mono">${esc(bao)}</td></tr>
      <tr><td style="color:#767574">Ngày hết hạn</td><td>${fmt(exp)} <span class="muted">(hôm nay + ${ttlLabel(t, h)})</span></td></tr>
      <tr><td style="color:#767574">Trạng thái sau khi tạo</td><td>${stBadge(o.ext ? 'CHUA_XONG' : 'HIEU_LUC')}</td></tr>
    </table>`;
}

function baoName(o, t) {
  const purpose = { SIGN: 'sign', ENC: 'enc', CERT: 'tls', DBC: 'db', SEC: 'secret' }[t.code];
  const prefix = t.engine === 'PKI' ? 'pki/issue/' : t.engine === 'Database' ? 'database/roles/' : t.engine === 'KV v2' ? 'kv/data/' : 'transit/keys/';
  return prefix + 'scorehub-' + o.code.toLowerCase() + '-' + purpose + '-2026';
}

function openDeliv(id) {
  const k = DB.keys.find(x => x.id === id);
  modal(shell(`<i class="fa fa-paper-plane"></i> Cập nhật bàn giao — ${esc(k.id)}`, `
    <div class="hint">Hai việc này xảy ra <b>ngoài hệ thống</b>. CMS chỉ ghi chép lại.
      Điền đủ <b>cả hai dòng</b> → khóa <b>tự chuyển sang Đang hiệu lực</b>. Xóa trắng ô ngày = hoàn tác.
      ${tt('f_deliv')}</div>
    <div class="deliv-box mb-3">
      <div class="row-lbl"><b>1. Mình đã gửi public key cho đối tác</b></div>
      <div class="row">
        <div class="col-md-5 form-group mb-0"><label>Ngày gửi</label>
          <input class="form-control" id="dSent" value="${k.sentAt ? fmt(k.sentAt) : ''}" placeholder="dd/mm/yyyy"></div>
        <div class="col-md-7 form-group mb-0"><label>Kênh gửi</label>
          <select class="form-control" id="dCh">
            ${['', 'Portal đối tượng', 'Email ký số', 'SFTP + biên bản giấy'].map(c => `<option ${c === k.channel ? 'selected' : ''}>${esc(c || '— chọn kênh —')}</option>`).join('')}
          </select></div>
      </div>
    </div>
    <div class="deliv-box">
      <div class="row-lbl"><b>2. Đối tác báo đã nhận và cài đặt xong</b></div>
      <div class="row">
        <div class="col-md-5 form-group mb-0"><label>Ngày xác nhận</label>
          <input class="form-control" id="dCfAt" value="${k.cfAt ? fmt(k.cfAt) : ''}" placeholder="dd/mm/yyyy"></div>
        <div class="col-md-7 form-group mb-0"><label>Người / bộ phận xác nhận</label>
          <input class="form-control" id="dCfBy" value="${esc(k.cfBy)}" placeholder="Ví dụ: Phòng CNTT đối tác"></div>
      </div>
    </div>
    <div class="src-note mt-3">Bước này <b>không gọi API nào xuống OpenBao</b> — khóa đã tồn tại từ lúc bấm Tạo khóa.</div>
  `, `<button class="btn btn-secondary" data-close="1">Hủy</button>
      <button class="btn btn-primary ml-2" data-act="doDeliv" data-id="${id}">Lưu</button>`));
}

/* ---- Public key giả lập, khác nhau theo mã khóa + phiên bản ---- */
function fakePem(id, v) {
  const seed = (id + 'v' + v).split('').reduce((a, ch) => (a * 31 + ch.charCodeAt(0)) >>> 0, 7);
  const CH = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let s = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA', r = seed;
  for (let i = 0; i < 348; i++) { r = (r * 1103515245 + 12345) >>> 0; s += CH[r % 64]; }
  const lines = s.match(/.{1,64}/g).join('\n');
  return '-----BEGIN PUBLIC KEY-----\n' + lines + '\nIDAQAB\n-----END PUBLIC KEY-----';
}

function openPubkey(id) {
  const k = DB.keys.find(x => x.id === id), t = KT(k.kt);
  const v = window.__pkv || k.ver;
  const vers = []; for (let i = 1; i <= k.ver; i++) vers.push(i);
  const pem = fakePem(k.id, v);
  const needSend = k.status === 'CHUA_XONG' && v === k.ver;

  modal(shell(`<i class="fa fa-eye"></i> Public key — ${esc(k.id)}`, `
    <div class="hint"><b>Đây là nửa công khai của cặp khóa — gửi cho đối tác được, không phải bí mật.</b>
      Private key nằm trong OpenBao, CMS không bao giờ nhìn thấy. ${tt('f_pubkey')}</div>

    <div class="form-group"><label>Chọn phiên bản${tt('f_version')}</label>
      <select class="form-control" id="pkVer" style="max-width:340px">
        ${vers.reverse().map(i => `<option value="${i}" ${i === v ? 'selected' : ''}>v${i}${i === k.ver ? ' — mới nhất' : ''}${i === k.activeVer ? ' · ĐANG DÙNG ĐỂ KÝ' : ''}</option>`).join('')}
      </select></div>

    ${needSend ? `<div class="hint warn"><b>Đây là bản cần gửi cho đối tác.</b>
      Con trỏ vẫn đang ở <b>v${k.activeVer}</b> nên giao dịch chưa bị ảnh hưởng.
      Gửi xong và đối tác xác nhận thì mới đổi con trỏ sang v${k.ver}.</div>` : ''}

    <div class="pem-box" id="pemBox">${esc(pem)}</div>
    <div class="mt-2">
      <button class="btn btn-primary btn-sm" data-act="copyPem"><i class="fa fa-copy"></i> Copy</button>
      <span class="src-note ml-2" id="copyMsg"></span>
    </div>
    <div class="src-note mt-3">CMS lấy trực tiếp từ OpenBao mỗi lần mở:
      <code>GET /v1/${esc(t.engine === 'PKI' ? 'pki/cert/&lt;serial&gt;' : k.bao)}</code> — không lưu bản sao để tránh lệch.</div>
  `, `<button class="btn btn-secondary" data-close="1">Đóng</button>`));
  window.__pkId = id;
}

function openRotate(id) {
  const k = DB.keys.find(x => x.id === id), t = KT(k.kt), ext = OBJ(k.obj).ext;
  modal(shell(`<i class="fa fa-sync-alt"></i> Xoay khóa — ${esc(k.id)}`, `
    <div class="hint">Xoay khóa = <b>sinh thêm bản mới</b>, không xóa bản cũ. ${tt('f_rotate')}</div>

    <table style="width:100%;font-size:13.5px;margin-bottom:14px">
      <tr><td style="width:220px;color:#767574;padding:5px 0">Trong OpenBao hiện có</td>
          <td><b>v1 … v${k.ver}</b></td></tr>
      <tr><td style="color:#767574;padding:5px 0">Đang dùng để ký${tt('f_pointer')}</td>
          <td><b>v${k.activeVer}</b> <span class="muted">(con trỏ <code>kv/data/keyref/…</code>)</span></td></tr>
      <tr><td style="color:#767574;padding:5px 0">Sau khi bấm sẽ có</td>
          <td><b>v1 … v${k.ver + 1}</b></td></tr>
      <tr><td style="color:#767574;padding:5px 0">Sau khi bấm sẽ ký bằng</td>
          <td>${ext
      ? `<b class="req-mark">v${k.activeVer}</b> <span class="muted">— giữ nguyên, KHÔNG đổi</span>`
      : `<b>v${k.ver + 1}</b> <span class="muted">— đổi ngay</span>`}</td></tr>
    </table>

    ${ext
      ? `<div class="hint"><b>Đối tượng bên ngoài — 3 bước, không gián đoạn:</b>
          <ol style="margin:8px 0 0 0;padding-left:20px">
            <li>Bấm nút dưới → OpenBao sinh <b>v${k.ver + 1}</b>. <b>Con trỏ giữ ở v${k.activeVer}</b> nên giao dịch vẫn chạy bình thường</li>
            <li>Bấm <b>👁 Xem public key</b> → chọn v${k.ver + 1} → copy → gửi đối tác</li>
            <li>Đối tác xác nhận → <b>Cập nhật bàn giao</b> → CMS đổi con trỏ sang v${k.ver + 1}</li>
          </ol>
          <div class="mt-2"><b>Không có bước "hủy bản cũ".</b> v${k.activeVer} vẫn nằm trong OpenBao để xác thực dữ liệu ký từ trước.</div>
        </div>`
      : `<div class="hint">Đối tượng <b>nội bộ</b> — không ai bên ngoài giữ public key, nên đổi con trỏ ngay. Ứng dụng tự dùng bản mới, <b>không gián đoạn</b>.</div>`}

    ${t.engine !== 'Transit' ? `<div class="hint warn"><b>Lưu ý engine ${esc(t.engine)}:</b>
      ${t.engine === 'PKI' ? 'PKI không có lệnh <code>rotate</code> — phải <b>cấp chứng thư mới</b> (serial mới). Chứng thư cũ vẫn sống tới ngày hết hạn.'
        : t.engine === 'Database' ? 'Database không có khái niệm xoay khóa — credential tự hết hạn rồi ứng dụng xin cái mới.'
          : 'KV v2 không có <code>rotate</code> — chỉ ghi đè giá trị mới, <code>version</code> tăng lên.'}</div>` : ''}
  `, `<button class="btn btn-secondary" data-close="1">Hủy</button>
      <button class="btn btn-primary ml-2" data-act="doRotate" data-id="${id}"><i class="fa fa-sync-alt"></i> Xoay khóa</button>`));
}

function openDetail(id) {
  const k = DB.keys.find(x => x.id === id), t = KT(k.kt), ext = OBJ(k.obj).ext;
  const tab = window.__tab || 'info';
  const T = (i2, l) => `<div class="${tab === i2 ? 'active' : ''}" data-act="tab" data-id="${i2}">${l}</div>`;
  let body;

  if (tab === 'info') {
    body = `<div class="kv">
      <div class="k">Mã khóa</div><div class="v mono">${esc(k.id)}</div>
      <div class="k">Đối tượng sử dụng</div><div class="v">${esc(k.obj)} ${extTag(ext)}</div>
      <div class="k">Hồ sơ ràng buộc</div><div class="v">${k.dossier ? esc(k.dossier) : '<span class="muted">không có</span>'}</div>
      <div class="k">Loại khóa</div><div class="v">${esc(t.name)} <span class="muted">→ engine ${esc(t.engine)}</span></div>
      <div class="k">Thuật toán</div><div class="v">${esc(k.algo)}</div>
      <div class="k">Phiên bản trong OpenBao ${tt('f_version')}</div><div class="v">v1 … v${k.ver}</div>
      <div class="k">Đang ký bằng ${tt('f_pointer')}</div><div class="v">${k.activeVer === k.ver
        ? `v${k.activeVer}`
        : `<span class="req-mark">v${k.activeVer}</span> <span class="muted">— chưa chuyển sang v${k.ver}, chờ đối tác xác nhận</span>`}</div>
      <div class="k">Public key ${tt('f_pubkey')}</div><div class="v"><span class="linkish" data-act="pubkey" data-id="${k.id}"><i class="fa fa-eye"></i> Xem &amp; copy</span></div>
      <div class="k">Thời hạn</div><div class="v">${ttlLabel(t, k.ttlH)} <span class="muted">(${k.ttlH}h)</span></div>
      <div class="k">Hiệu lực</div><div class="v">${fmt(k.eff)} → ${fmt(k.exp)}</div>
      <div class="k">Trạng thái</div><div class="v">${stBadge(k.status)}</div>
      ${k.lockReason ? `<div class="k">Lý do</div><div class="v" style="font-weight:400">${esc(k.lockReason)}</div>` : ''}
      ${ext ? `<div class="k">Đã gửi</div><div class="v" style="font-weight:400">${k.sentAt ? `${fmt(k.sentAt)} · ${esc(k.channel)}` : '<span class="muted">chưa</span>'}</div>
      <div class="k">Đối tác xác nhận</div><div class="v" style="font-weight:400">${k.cfAt ? `${fmt(k.cfAt)} · ${esc(k.cfBy)}` : '<span class="muted">chưa</span>'}</div>` : ''}
      <div class="k">Tên trong OpenBao ${tt('f_baoname')}</div><div class="v mono">${esc(k.bao)}</div>
    </div>
    <div class="hint mt-3"><b><i class="fa fa-lock"></i></b> Màn hình này <b>không bao giờ hiển thị private key</b>.</div>`;
  } else if (tab === 'api') {
    const p = apiParams(k);
    body = `<div class="hint">Trường do <b>OpenBao quy định</b> — tên không đổi được. CMS tự dịch từ hồ sơ. Bấm <i class="tt">i</i> để xem chi tiết từng trường.
      ${p.engine === 'Transit' ? '<div class="src-note mt-2" style="color:#33415c"><b>Lưu ý:</b> <code>deletion_allowed</code> và <code>min_*_version</code> <b>không đặt được lúc tạo khóa</b> — chỉ có ở endpoint <code>/config</code>. Chúng nằm ở bảng dưới.</div>' : ''}</div>
    <div class="api-tbl"><table style="width:100%;border-collapse:collapse">
      <thead><tr><th style="width:38%">Trường gửi xuống API</th><th>Giá trị</th><th style="width:22%">Nguồn</th></tr></thead>
      <tbody>${p.req.map((r, i) => {
        const head = r.grp && (i === 0 || p.req[i - 1].grp !== r.grp)
          ? `<tr><td colspan="3" style="background:#eff6fc;color:#005A9E;font-weight:600;font-size:12.5px;padding:7px 10px">${esc(r.grp)}</td></tr>` : '';
        return head + `<tr class="${r.lock ? 'locked' : ''}">
        <td class="fname">${esc(r.n)}${tt(r.n)}</td><td class="fval">${esc(String(r.v))}</td>
        <td class="muted" style="font-size:12px">${r.lock ? '<b class="req-mark">Khóa cứng</b>' : 'Hồ sơ'}</td></tr>`;
      }).join('')}
      </tbody></table></div>
    <h6 class="mt-4" style="font-size:14px;font-weight:600">OpenBao trả về — CMS bắt buộc lưu</h6>
    <div class="api-tbl"><table style="width:100%;border-collapse:collapse"><tbody>
      ${p.res.map(r => `<tr><td class="fname" style="width:38%">${esc(r.n)}${tt(r.n)}</td><td class="fval">${esc(String(r.v))}</td></tr>`).join('')}
    </tbody></table></div>`;
  } else {
    const items = DB.audit.filter(a => a.obj.indexOf(k.id) >= 0)
      .concat(k.eff ? [{ at: fmt(k.eff), act: 'Kích hoạt khóa', reason: '' }] : []);
    body = `<ul class="timeline">${items.map(a => `<li><div><b>${esc(a.act)}</b></div>
      <div class="tl-time">${esc(a.at)}${a.reason ? ' · ' + esc(a.reason) : ''}</div></li>`).join('')
      || '<li class="muted">Chưa có thao tác nào</li>'}</ul>`;
  }

  modal(shell(`<i class="fa fa-key"></i> ${esc(k.id)}`,
    `<div class="tabs">${T('info', 'Thông tin')}${T('api', 'Tham số OpenBao' + tt('tab_api'))}${T('log', 'Nhật ký')}</div>${body}`,
    `<button class="btn btn-secondary" data-close="1">Đóng</button>`));
  window.__detailId = id;
}

function openLock(id) {
  const k = DB.keys.find(x => x.id === id), e = EX(k.id), eng = KT(k.kt).engine, L3 = LOCK3[eng];

  if (!L3.ok) {
    modal(shell(`<i class="fa fa-lock"></i> Tạm khóa — ${esc(id)}`, `
      <div class="hint bad"><b>Engine ${esc(eng)} không hỗ trợ tạm khóa.</b><br>${L3.why}</div>
      <div class="hint">Nếu cần dừng khóa này thì chỉ có <b>Thu hồi</b> — vĩnh viễn, không khôi phục được.</div>
    `, `<button class="btn btn-secondary" data-close="1">Đóng</button>`, 'sm'));
    return;
  }

  modal(shell(`<i class="fa fa-lock"></i> Tạm khóa — ${esc(id)}`, `
    <div class="src-note mb-2">Engine <b>${esc(eng)}</b> — cơ chế chặn thật khác nhau theo engine.</div>
    <div class="form-group">${lb('Mức tạm khóa', 'f_lockLevel', 1)}
      <select class="form-control" id="lockLevel">
        <option value="1">Mức 1 — Hành chính: chỉ đánh dấu trên sổ</option>
        <option value="2">Mức 2 — Chặn xoay / cấp thêm / bàn giao</option>
        <option value="3" selected>${esc(L3.label)}</option>
      </select></div>
    <div id="lockEffect" data-eng="${esc(eng)}"></div>
    <div class="form-group">${lb('Lý do tạm khóa', 'f_lockReason', 1)}
      <textarea class="form-control" id="lockReason" rows="3" placeholder="Nghi ngờ lộ khóa theo PYC-… / hợp đồng tạm dừng / hệ thống bảo trì"></textarea></div>
    <div class="src-note">Đường dẫn: <code>${esc(k.bao)}</code>${e.latest ? ' · latest_version = <code>' + e.latest + '</code>' : ''}</div>
  `, `<button class="btn btn-secondary" data-close="1">Hủy</button>
      <button class="btn btn-primary ml-2" data-act="doLock" data-id="${id}"><i class="fa fa-lock"></i> Xác nhận</button>`, 'sm'));
  window.__lockEng = eng;
  lockEffect();
}
function lockEffect() {
  const el = $('#lockEffect'); if (!el) return;
  const L3 = LOCK3[window.__lockEng] || LOCK3.Transit;
  const m = {
    '1': ['hint', '<b>Không gọi API.</b> Nghiệp vụ vẫn chạy bình thường, chỉ đánh dấu trên sổ.'],
    '2': ['hint warn', '<b>Không gọi API.</b> Chặn ở tầng CMS: không cho xoay / cấp thêm / bàn giao. Khóa vẫn dùng được.'],
    '3': ['hint bad', L3.effect],
  };
  const [c, t] = m[$('#lockLevel').value] || m['3'];
  el.innerHTML = `<div class="${c}">${t}</div>`;
}

function openRevoke(id) {
  const k = DB.keys.find(x => x.id === id), t = KT(k.kt);
  const how = { Transit: '<code>config</code> · <code>min_decryption_version</code> = latest + 1', PKI: '<code>POST /v1/pki/revoke</code> · <code>serial_number</code>', Database: '<code>POST /v1/sys/leases/revoke</code> · <code>lease_id</code>', 'KV v2': '<code>DELETE /v1/kv/metadata/:path</code>' }[t.engine];
  modal(shell(`<i class="fa fa-ban"></i> Thu hồi — ${esc(id)}`, `
    <div class="hint bad"><b>Thu hồi là vĩnh viễn.</b> Muốn tạm dừng mà còn khôi phục được thì dùng <b>Tạm khóa</b>. ${tt('f_revoke')}</div>
    <div class="form-group">${lb('Lý do thu hồi', 'f_lockReason', 1)}
      <textarea class="form-control" id="revReason" rows="3" placeholder="Đã xác định lộ khóa / chấm dứt hợp đồng / cấp nhầm"></textarea></div>
    <div class="src-note">Engine <b>${esc(t.engine)}</b> → CMS sẽ gọi: ${how}</div>
  `, `<button class="btn btn-secondary" data-close="1">Hủy</button>
      <button class="btn btn-danger ml-2" data-act="doRevoke" data-id="${id}">Xác nhận thu hồi</button>`, 'sm'));
}

function openAddObj() {
  modal(shell('<i class="fa fa-plus"></i> Thêm đối tượng', `
    <div class="hint"><b>Mã đối tượng</b> viết hoa, không dấu, không khoảng trắng — vì nó được ghép vào tên khóa trong OpenBao. ${tt('f_baoname')}</div>
    <div class="row">
      <div class="col-md-4 form-group"><label>Mã <span class="req-mark">*</span></label>
        <input class="form-control" id="aoCode" placeholder="VD: INSUR"></div>
      <div class="col-md-8 form-group"><label>Tên đối tượng <span class="req-mark">*</span></label>
        <input class="form-control" id="aoName" placeholder="VD: Doanh nghiệp bảo hiểm Z"></div>
      <div class="col-12 form-group"><label>Phạm vi <span class="req-mark">*</span></label>
        <select class="form-control" id="aoExt">
          <option value="1">Bên ngoài tổ chức — có bước bàn giao, hồ sơ bắt buộc</option>
          <option value="0">Nội bộ — không bàn giao, hồ sơ tùy chọn</option></select></div>
    </div>
  `, `<button class="btn btn-secondary" data-close="1">Hủy</button>
      <button class="btn btn-primary ml-2" data-act="doAddObj">Lưu</button>`, 'sm'));
}

/* ============================================================
   POPOVER (i) — bấm mở, bấm ngoài tắt
   ============================================================ */
let TIP_OPEN = null;
function showTip(el) {
  const box = $('#tipbox'); if (!box) return;
  const c = tipHtml(el.dataset.tip); if (!c) return;
  if (TIP_OPEN === el) { hideTip(); return; }
  hideTip();
  box.innerHTML = `<div class="tp-head"><span>${esc(c.head)}</span><span class="x" data-tipclose="1">✕</span></div>
    <div class="tp-body">${c.body}</div>`;
  box.style.display = 'block';
  const r = el.getBoundingClientRect(), b = box.getBoundingClientRect();
  const vw = document.documentElement.clientWidth, vh = document.documentElement.clientHeight;
  const left = Math.max(10, Math.min(r.left + r.width / 2 - b.width / 2, vw - b.width - 10));
  let top = r.bottom + 10;
  if (top + b.height > vh - 10) top = Math.max(10, r.top - b.height - 10);
  box.style.left = left + 'px'; box.style.top = top + 'px';
  el.classList.add('on');
  TIP_OPEN = el;
}
function hideTip() {
  const b = $('#tipbox'); if (b) b.style.display = 'none';
  if (TIP_OPEN && TIP_OPEN.classList) TIP_OPEN.classList.remove('on');
  TIP_OPEN = null;
}

/* ---------------- ROUTER ---------------- */
const route = () => (location.hash.replace('#/', '') || 'keys');
function render() {
  const r = route();
  const fn = { keys: viewKeys, objs: viewObjs, audit: viewAudit }[r] || viewKeys;
  $('#crumb').innerHTML = `<div style="display:flex;align-items:center;justify-content:space-between">
    <span><i class="fa fa-home"></i> Trang chủ <span class="sep">/</span> Quản trị khóa <span class="sep">/</span> <b>${esc(TITLES[r] || '')}</b></span>
    <span><label style="margin:0;cursor:pointer;user-select:none">
      <input type="checkbox" id="tgNotes" ${SHOW_NOTES ? 'checked' : ''}> Hiện ghi chú nghiệp vụ</label></span></div>`;
  $('#view').innerHTML = fn();
  renderNav(); hideTip(); window.scrollTo(0, 0);
}

/* ---------------- SỰ KIỆN ---------------- */
const log = (act, obj, reason) => DB.audit.unshift({ at: nowStamp(), act, obj, reason: reason || '' });
const parseD = (s) => {
  const m = (s || '').trim().match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  return m ? `${m[3]}-${m[2].padStart(2, '0')}-${m[1].padStart(2, '0')}` : '';
};

document.addEventListener('click', (e) => {
  // popover
  const tipEl = e.target.closest && e.target.closest('[data-tip]');
  if (tipEl) { e.preventDefault(); showTip(tipEl); return; }
  if (e.target.closest && e.target.closest('[data-tipclose]')) { hideTip(); return; }
  if (TIP_OPEN && !(e.target.closest && e.target.closest('#tipbox'))) hideTip();

  const t = e.target.closest('[data-act],[data-close],#btnSearch,#btnReset,#btnCollapse');
  if (!t) return;
  if (t.id === 'btnCollapse') { $('#sidebar').classList.toggle('collapsed'); return; }
  if (t.dataset.close) { if (t.classList.contains('modal-backdrop-x') && e.target !== t) return; closeModal(); return; }
  if (t.id === 'btnSearch') { window.__f = Object.assign({}, window.__f, { q: $('#fq').value, ext: $('#fext').value }); render(); return; }
  if (t.id === 'btnReset') { window.__f = null; render(); return; }

  const id = t.dataset.id;
  const K = () => DB.keys.find(x => x.id === id);
  switch (t.dataset.act) {
    case 'qf': window.__f = Object.assign({}, window.__f, { qf: id }); render(); break;
    case 'detail': window.__tab = 'info'; openDetail(id); break;
    case 'tab': window.__tab = id; openDetail(window.__detailId); break;
    case 'new': openNew(); break;
    case 'deliv': openDeliv(id); break;
    case 'pubkey': window.__pkv = null; openPubkey(id); break;
    case 'copyPem': {
      const txt = $('#pemBox').textContent || '';
      const done = () => { const m = $('#copyMsg'); if (m) m.innerHTML = '<span style="color:#1b7a4b"><i class="fa fa-check"></i> Đã copy — dán vào email gửi đối tác</span>'; };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(txt).then(done, done);
      else {
        const ta = document.createElement('textarea');
        ta.value = txt; document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); } catch (err) { /* trình duyệt chặn */ }
        document.body.removeChild(ta); done();
      }
      break;
    }
    case 'lock': openLock(id); break;
    case 'revoke': openRevoke(id); break;
    case 'addobj': openAddObj(); break;
    case 'advToggle': { const a = $('#nAdv'); a.style.display = a.style.display === 'none' ? 'block' : 'none'; break; }

    case 'rotate': openRotate(id); break;
    case 'doRotate': {
      const k = K(), t2 = KT(k.kt), ext = OBJ(k.obj).ext;
      k.ver++;
      if (EXTRA[k.id]) EXTRA[k.id].latest = k.ver;
      if (ext) {
        // CON TRỎ GIỮ NGUYÊN ở bản cũ → ứng dụng vẫn ký bằng bản cũ, không đứt
        k.status = 'CHUA_XONG'; k.sentAt = ''; k.channel = ''; k.cfAt = ''; k.cfBy = '';
        log('Xoay khóa', k.id, `${t2.engine === 'PKI' ? 'POST /v1/pki/issue/…' : 'POST /v1/transit/keys/…/rotate'} → sinh v${k.ver}. Con trỏ GIỮ NGUYÊN ở v${k.activeVer} — chưa đứt giao dịch`);
      } else {
        k.activeVer = k.ver; k.exp = addHours(k.ttlH);
        log('Xoay khóa', k.id, `POST /v1/transit/keys/…/rotate → v${k.ver}. Nội bộ: đổi con trỏ ngay sang v${k.ver}`);
      }
      closeModal(); render(); break;
    }
    case 'unlock': {
      const k = K();
      if (!confirm(`Mở khóa ${k.id}?\n\nCMS sẽ gọi: min_encryption_version = 0`)) return;
      k.status = 'HIEU_LUC'; k.lockReason = '';
      if (EXTRA[k.id]) EXTRA[k.id].minEnc = 0;
      log('MỞ KHÓA', k.id, 'min_encryption_version = 0'); render(); break;
    }
    case 'doLock': {
      const r = $('#lockReason').value.trim();
      if (!r) { alert('Lý do là bắt buộc — kiểm toán sẽ hỏi tới trường này.'); return; }
      const lv = +$('#lockLevel').value, k = K(), e = EX(k.id), L3 = LOCK3[KT(k.kt).engine];
      if (lv === 3 && !L3.ok) { alert('Engine này không tạm khóa được. Chỉ có thể Thu hồi.'); return; }
      k.status = 'TAM_KHOA'; k.lockReason = `[Mức ${lv}] ${r}`;
      if (lv === 3 && KT(k.kt).engine === 'Transit' && EXTRA[k.id] && EXTRA[k.id].latest) {
        EXTRA[k.id].minEnc = EXTRA[k.id].latest + 1;
      }
      log('TẠM KHÓA', k.id, lv === 3 ? `Mức 3 — ${L3.cmd(k, e)} · ${r}` : `Mức ${lv} (không gọi API) — ${r}`);
      closeModal(); render(); break;
    }
    case 'doRevoke': {
      const r = $('#revReason').value.trim();
      if (!r) { alert('Lý do thu hồi là bắt buộc.'); return; }
      const k = K(), t2 = KT(k.kt), e = EX(k.id);
      k.status = 'THU_HOI'; k.lockReason = r;
      const how = t2.engine === 'Transit' ? `min_decryption_version = ${(e.latest || 0) + 1}`
        : t2.engine === 'PKI' ? `POST /v1/pki/revoke · serial_number=${e.serial || '—'}`
          : t2.engine === 'Database' ? `POST /v1/sys/leases/revoke · lease_id=${e.leaseId || '—'}`
            : `DELETE /v1/kv/metadata/${e.kvPath || '—'}`;
      log('Thu hồi khóa', k.id, `${how} · ${r}`);
      closeModal(); render(); break;
    }
    case 'doDeliv': {
      const k = K();
      const s = parseD($('#dSent').value), c = parseD($('#dCfAt').value);
      if ($('#dSent').value.trim() && !s) { alert('Ngày gửi sai định dạng. Nhập dd/mm/yyyy.'); return; }
      if ($('#dCfAt').value.trim() && !c) { alert('Ngày xác nhận sai định dạng. Nhập dd/mm/yyyy.'); return; }
      if (c && !s) { alert('Chưa ghi ngày gửi thì không thể có ngày xác nhận.'); return; }
      const ch = $('#dCh').value.indexOf('chọn kênh') >= 0 ? '' : $('#dCh').value;
      k.sentAt = s; k.channel = ch; k.cfAt = c; k.cfBy = $('#dCfBy').value.trim();
      if (s && c) {
        const moved = k.activeVer !== k.ver;
        k.status = 'HIEU_LUC'; k.eff = c; k.exp = addHours(k.ttlH);
        k.activeVer = k.ver; // ĐỔI CON TRỎ — từ giờ ứng dụng ký bằng bản mới
        log('Bàn giao xong → kích hoạt', k.id,
          `gửi ${fmt(s)} qua ${ch || '—'} · xác nhận ${fmt(c)}`
          + (moved ? ` · ĐỔI CON TRỎ sang v${k.ver} (kv/data/keyref)` : ''));
      } else {
        k.status = 'CHUA_XONG'; k.eff = ''; k.exp = '';
        log('Cập nhật bàn giao', k.id, s ? `đã gửi ${fmt(s)}, chờ xác nhận` : 'hoàn tác — chưa gửi');
      }
      closeModal(); render(); break;
    }
    case 'doNew': {
      const o = OBJ($('#nObj').value), t2 = KT($('#nKt').value);
      const dos = $('#nDos').value.trim(), h = +$('#nTtl').value;
      if (o.ext && (!/\d/.test(dos) || dos.length < 6)) {
        $('#nDos').classList.add('invalid');
        $('#nDosNote').innerHTML = '<span class="req-mark">Đối tượng bên ngoài bắt buộc có hồ sơ: phải có số hiệu, tối thiểu 6 ký tự.</span>';
        return;
      }
      const nid = (t2.engine === 'Database' || t2.engine === 'KV v2' ? 'CRED-2026-0' : 'KEY-2026-0') + (100 + DB.keys.length);
      DB.keys.unshift({
        id: nid, obj: o.n, kt: t2.code, dossier: dos, algo: $('#nAlgo').value, ttlH: h, ver: 1, activeVer: 1,
        status: o.ext ? 'CHUA_XONG' : 'HIEU_LUC',
        eff: o.ext ? '' : TODAY_ISO, exp: o.ext ? '' : addHours(h),
        bao: baoName(o, t2), lockReason: '', sentAt: '', channel: '', cfAt: '', cfBy: '',
      });
      EXTRA[nid] = { latest: 1, minDec: 1, minEnc: 0 };
      log('Tạo khóa trên OpenBao', nid,
        `POST /v1/${baoName(o, t2)} · ${t2.ttlField ? t2.ttlField + '=' + h + 'h' : 'không có TTL'}`);
      closeModal(); window.__f = { q: '', ext: '', qf: o.ext ? 'bangiao' : '' }; render(); break;
    }
    case 'doAddObj': {
      const code = ($('#aoCode').value || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
      const name = ($('#aoName').value || '').trim();
      if (!code || !name) { alert('Vui lòng nhập mã và tên.'); return; }
      if (OBJS.some(x => x.code === code)) { alert('Mã này đã tồn tại.'); return; }
      OBJS.push({ code, n: name, ext: $('#aoExt').value === '1' });
      log('Thêm đối tượng', code, name); closeModal(); render(); break;
    }
    case 'export': alert('Kết xuất báo cáo ra Excel.\n\n(Báo cáo kiểm toán cần đúng những cột nào — phải chốt sớm.)'); break;
  }
});

document.addEventListener('change', (e) => {
  const el = e.target;
  if (el.id === 'tgNotes') { SHOW_NOTES = el.checked; render(); return; }
  if (el.id === 'lockLevel') { lockEffect(); return; }
  if (el.id === 'pkVer') { window.__pkv = +el.value; openPubkey(window.__pkId); return; }
  if (['nObj', 'nKt', 'nTtl', 'nAlgo'].indexOf(el.id) >= 0) syncNew();
});

window.addEventListener('hashchange', render);
render();
