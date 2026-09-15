/* ============================================================
   CMS Quản trị khóa — bản tối giản, 1 người dùng (anh Tộ)
   Không phê duyệt · không phân quyền · không SLA

   Trạng thái (5):
     Chưa xong bàn giao → Đang hiệu lực → Thu hồi / Hết hiệu lực
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
    create: [{ v: 'gen', l: 'OpenBao sinh khóa mới', ep: 'POST /v1/transit/keys/:name' }],
    noImport: 'Transit có nhập khóa sẵn (BYOK) nhưng phải tự bọc khóa bằng wrapping key 4096-bit của OpenBao, và <b>khóa đã nhập thì chỉ xoay được nếu bật <code>allow_rotation</code> lúc nhập; xoay rồi là không nhập thêm bản nào được nữa</b> — đá nhau với yêu cầu xoay khóa hằng năm.',
    dl: 'public', role: false,
    ttl: [{ h: M1, l: '1 tháng' }, { h: M3, l: '3 tháng' }, { h: M6, l: '6 tháng' }, { h: M12, l: '12 tháng (trần)' }],
    ttlDef: M12, ttlField: 'auto_rotate_period',
    autoExpire: false,
    ttlNote: 'OpenBao <b>không tự chặn</b> khi hết hạn — chỉ sinh bản mới. CMS phải chủ động chặn bản cũ.',
  },
  {
    code: 'ENC', name: 'Khóa mã hóa', engine: 'Transit',
    algos: ['aes256-gcm96', 'chacha20-poly1305', 'rsa-2048', 'rsa-4096'],
    create: [{ v: 'gen', l: 'OpenBao sinh khóa mới', ep: 'POST /v1/transit/keys/:name' }],
    noImport: 'Giống khóa ký — nhập sẵn phải qua BYOK phức tạp và làm hỏng khả năng xoay khóa.',
    dl: 'public-if-rsa', role: false,
    ttl: [{ h: M1, l: '1 tháng' }, { h: M3, l: '3 tháng' }, { h: M6, l: '6 tháng' }, { h: M12, l: '12 tháng (trần)' }],
    ttlDef: M12, ttlField: 'auto_rotate_period',
    autoExpire: false,
    ttlNote: 'OpenBao <b>không tự chặn</b> khi hết hạn — chỉ sinh bản mới. CMS phải chủ động chặn bản cũ.',
  },
  {
    code: 'CERT', name: 'Chứng thư TLS', engine: 'PKI',
    algos: ['rsa/2048', 'rsa/4096', 'ec/256', 'ec/384'],
    create: [
      { v: 'gen', l: 'OpenBao sinh cặp khóa và cấp chứng thư', ep: 'POST /v1/pki/issue/:role' },
      { v: 'csr', l: 'Mình tự sinh khóa, chỉ nộp CSR để ký', ep: 'POST /v1/pki/sign/:role' },
    ],
    dl: 'cert', role: 'PKI',
    ttl: [{ h: M1, l: '1 tháng' }, { h: M3, l: '3 tháng' }, { h: M6, l: '6 tháng' }, { h: M12, l: '12 tháng (trần)' }],
    ttlDef: M12, ttlField: 'ttl',
    autoExpire: true,
    ttlNote: 'Chứng thư <b>hết hạn là tự vô hiệu</b> — bên nhận tự từ chối, không cần ai làm gì.',
  },
  {
    code: 'DBC', name: 'Credential CSDL', engine: 'Database',
    algos: ['— engine tự sinh user/password'],
    create: [{ v: 'gen', l: 'OpenBao tự sinh user/password', ep: 'GET /v1/database/creds/:role' }],
    noImport: 'Không nhập được. Credential do chính OpenBao tạo trên CSDL thật rồi tự xóa khi hết hạn — nhập tay thì mất toàn bộ ý nghĩa.',
    dl: '', role: 'DATABASE',
    ttl: [{ h: 1, l: '1 giờ' }, { h: 24, l: '24 giờ' }, { h: 168, l: '7 ngày' }, { h: 720, l: '30 ngày (trần)' }],
    ttlDef: 720, ttlField: 'default_ttl',
    autoExpire: true,
    ttlNote: 'Loại này sinh ra để <b>sống ngắn</b>. Hết hạn OpenBao <b>tự xóa user</b> khỏi CSDL. Không có tùy chọn tính bằng tháng.',
  },
  {
    code: 'SEC', name: 'API secret / keytab', engine: 'KV v2',
    algos: ['— chỉ lưu dữ liệu, không có thuật toán'],
    create: [
      { v: 'input', l: 'Nhập giá trị sẵn có', ep: 'POST /v1/kv/data/:path' },
      { v: 'gen', l: 'Sinh chuỗi ngẫu nhiên rồi lưu', ep: 'POST /v1/kv/data/:path' },
    ],
    dl: '', role: false,
    ttl: [{ h: M3, l: '3 tháng' }, { h: M6, l: '6 tháng' }, { h: M12, l: '12 tháng' }],
    ttlDef: M6, ttlField: null,
    autoExpire: false,
    ttlNote: 'KV v2 <b>không có TTL</b>. Ô này <b>không gửi xuống OpenBao</b> — chỉ để CMS nhắc anh Tộ tự thay.',
  },
];
const KT = (c) => KEY_TYPES.find(k => k.code === c) || KEY_TYPES[0];

/* Role do ADMIN tạo trước trong OpenBao — màn tạo khóa chỉ được CHỌN, không tạo mới.
   Role là hàng rào bảo mật: nó chặn sẵn domain và trần thời hạn, không phụ thuộc UI kiểm tra đúng hay sai. */
const ROLES = [
  { type: 'PKI', name: 'scorehub-public-api', desc: 'Chứng thư cho cổng API công khai', domains: 'scorehub.example.vn', maxTtlH: M12 },
  { type: 'PKI', name: 'scorehub-internal-mtls', desc: 'Chứng thư mTLS nội bộ giữa các service', domains: 'svc.internal', maxTtlH: M3 },
  { type: 'DATABASE', name: 'scorehub-oracle-ro', desc: 'Chỉ đọc Oracle ScoreHub', conn: 'scorehub-oracle', maxTtlH: 720 },
  { type: 'DATABASE', name: 'airflow-pg-rw', desc: 'Đọc ghi PostgreSQL Airflow', conn: 'airflow-pg', maxTtlH: 720 },
  { type: 'DATABASE', name: 'report-mysql-ro', desc: 'Chỉ đọc MySQL báo cáo', conn: 'report-mysql', maxTtlH: 720 },
];
const rolesOf = (t) => ROLES.filter(r => r.type === t);
const ROLE = (n) => ROLES.find(r => r.name === n) || null;

/* Mount = chỗ engine được gắn vào OpenBao. Mỗi mount có trần riêng max_lease_ttl.
   MẶC ĐỊNH CỦA OPENBAO LÀ 768h (32 NGÀY) — không tune thì chọn "12 tháng" sẽ bị từ chối,
   kể cả khi role cho phép. Đây là trần dễ quên nhất. Nguồn: openbao.org/docs/configuration. */
const SYS_MAX_LEASE_H = 768;
const MOUNTS = [
  { engine: 'Transit', path: 'transit/', tuned: true, maxLeaseH: 87600, note: 'Transit không phát lease nên trần này không chặn việc tạo khóa.' },
  { engine: 'PKI', path: 'pki/', tuned: true, maxLeaseH: M12, note: 'Đã tune lên 8760h. Nếu để mặc định 768h thì không cấp nổi chứng thư 12 tháng.' },
  { engine: 'Database', path: 'database/', tuned: false, maxLeaseH: SYS_MAX_LEASE_H, note: 'Để mặc định 768h — vẫn thoải mái vì credential CSDL dài nhất chỉ 30 ngày.' },
  { engine: 'KV v2', path: 'kv/', tuned: false, maxLeaseH: 0, note: 'KV v2 không phát lease, không có trần thời hạn.' },
];
const MOUNT = (e) => MOUNTS.find(m => m.engine === e) || null;

/* Kết nối CSDL do admin khai một lần — role Database bắt buộc trỏ vào một kết nối có sẵn */
const CONNS = [
  { name: 'scorehub-oracle', plugin: 'oracle-database-plugin', url: 'oracle://{{username}}:{{password}}@db-scorehub:1521/ORCL', roles: 'scorehub-oracle-ro' },
  { name: 'airflow-pg', plugin: 'postgresql-database-plugin', url: 'postgresql://{{username}}:{{password}}@pg-airflow:5432/airflow', roles: 'airflow-pg-rw' },
  { name: 'report-mysql', plugin: 'mysql-database-plugin', url: '{{username}}:{{password}}@tcp(mysql-report:3306)/', roles: 'report-mysql-ro' },
];

/* Trả về trần thấp nhất đang áp cho lựa chọn hiện tại, hoặc null nếu không vướng trần nào */
function ttlCeiling(t, roleName, h) {
  const m = MOUNT(t.engine), r = ROLE(roleName);
  if (r && h > r.maxTtlH) return { kind: 'role', name: r.name, limitH: r.maxTtlH };
  if (m && m.maxLeaseH && h > m.maxLeaseH) return { kind: 'mount', name: m.path, limitH: m.maxLeaseH, tuned: m.tuned };
  return null;
}
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
    { id: 'KEY-2026-0033', obj: 'Ngân hàng Đối tác C', kt: 'SIGN', dossier: 'HĐ-2025/SCOREHUB/027', algo: 'ecdsa-p256', ttlH: M12, ver: 1, activeVer: 1, status: 'THU_HOI', eff: '2025-10-08', exp: '2026-10-08', bao: 'transit/keys/scorehub-fic-sign-2025', lockReason: 'Xác định lộ khóa theo PYC-2026-0871 — thu hồi vĩnh viễn', sentAt: '2025-10-01', channel: 'Portal', cfAt: '2025-10-06', cfBy: 'Phòng CNTT đối tác' },
    { id: 'KEY-2026-0002', obj: 'Ngân hàng Đối tác D', kt: 'SIGN', dossier: 'HĐ-2026/SCOREHUB/003', algo: 'rsa-2048', ttlH: M12, ver: 1, activeVer: 1, status: 'CHUA_XONG', eff: '', exp: '', bao: 'transit/keys/scorehub-fid-sign-2026', lockReason: '', sentAt: '2026-08-20', channel: 'Portal đối tượng', cfAt: '', cfBy: '' },
    { id: 'KEY-2026-0005', obj: 'Công ty Tài chính E', kt: 'ENC', dossier: 'HĐ-2026/SCOREHUB/008', algo: 'rsa-4096', ttlH: M12, ver: 1, activeVer: 1, status: 'CHUA_XONG', eff: '', exp: '', bao: 'transit/keys/scorehub-fie-enc-2026', lockReason: '', sentAt: '', channel: '', cfAt: '', cfBy: '' },
    { id: 'KEY-2026-0041', obj: 'Công ty Tài chính B', kt: 'SIGN', dossier: 'HĐ-2025/SCOREHUB/019', algo: 'ecdsa-p256', ttlH: M12, ver: 2, activeVer: 2, status: 'HIEU_LUC', eff: '2025-11-30', exp: '2026-11-30', bao: 'transit/keys/scorehub-fib-sign-2025', lockReason: '', sentAt: '2026-08-05', channel: 'Email ký số', cfAt: '2026-08-12', cfBy: 'Phòng CNTT đối tác' },
    { id: 'KEY-2026-0007', obj: 'Nhà cung cấp CDN X', kt: 'CERT', dossier: 'HĐ-MS-2026/041', algo: 'rsa/2048', ttlH: M12, ver: 1, activeVer: 1, status: 'HIEU_LUC', eff: '2026-03-01', exp: '2027-03-01', bao: 'pki/issue/scorehub-public-api', role: 'scorehub-public-api', createMode: 'gen', lockReason: '', sentAt: '2026-02-26', channel: 'Email ký số', cfAt: '2026-02-28', cfBy: 'Vận hành CDN' },
    { id: 'KEY-2025-0018', obj: 'Ngân hàng Đối tác C', kt: 'SIGN', dossier: 'HĐ-2024/SCOREHUB/031', algo: 'rsa-2048', ttlH: M12, ver: 1, activeVer: 1, status: 'HET_HAN', eff: '2024-06-30', exp: '2026-06-30', bao: 'transit/keys/scorehub-fic-sign-2024', lockReason: '', sentAt: '2024-06-25', channel: 'SFTP', cfAt: '2024-06-28', cfBy: 'Phòng CNTT đối tác' },
    { id: 'KEY-2025-0009', obj: 'Ngân hàng Đối tác A', kt: 'SIGN', dossier: 'HĐ-2024/SCOREHUB/012', algo: 'rsa-2048', ttlH: M12, ver: 2, activeVer: 2, status: 'THU_HOI', eff: '2024-11-02', exp: '2025-11-02', bao: 'transit/keys/scorehub-fia-sign-2024', lockReason: 'Thu hồi theo lịch xoay khóa 2025', sentAt: '2024-10-28', channel: 'SFTP', cfAt: '2024-11-01', cfBy: 'Ban CNTT đối tác' },

    { id: 'CRED-2026-0001', obj: 'ScoreHub Backend', kt: 'DBC', dossier: '', algo: '—', ttlH: 720, ver: 27, activeVer: 27, status: 'HIEU_LUC', eff: '2026-08-02', exp: '2026-09-01', bao: 'database/creds/scorehub-oracle-ro', role: 'scorehub-oracle-ro', createMode: 'gen', lockReason: '', sentAt: '', channel: '', cfAt: '', cfBy: '' },
    { id: 'CRED-2026-0003', obj: 'Airflow', kt: 'DBC', dossier: '', algo: '—', ttlH: 720, ver: 9, activeVer: 9, status: 'HIEU_LUC', eff: '2026-07-30', exp: '2026-08-29', bao: 'database/creds/airflow-pg-rw', role: 'airflow-pg-rw', createMode: 'gen', lockReason: '', sentAt: '', channel: '', cfAt: '', cfBy: '' },
    { id: 'CRED-2026-0004', obj: 'Cụm Spark', kt: 'SEC', dossier: '', algo: '—', ttlH: M12, ver: 4, activeVer: 4, status: 'HIEU_LUC', eff: '2026-02-01', exp: '2027-02-01', bao: 'kv/data/scorehub/spark-keytab', lockReason: '', sentAt: '', channel: '', cfAt: '', cfBy: '' },
    { id: 'CRED-2026-0005', obj: 'Report Service', kt: 'DBC', dossier: 'YCNB-2026/207', algo: '—', ttlH: 720, ver: 15, activeVer: 15, status: 'HIEU_LUC', eff: '2026-06-01', exp: '2026-07-01', bao: 'database/creds/report-mysql-ro', role: 'report-mysql-ro', createMode: 'gen', lockReason: '', sentAt: '', channel: '', cfAt: '', cfBy: '' },
    { id: 'CRED-2026-0006', obj: 'Ingest Pipeline', kt: 'SEC', dossier: 'YCNB-2026/188', algo: '—', ttlH: M6, ver: 3, activeVer: 3, status: 'HIEU_LUC', eff: '2026-04-20', exp: '2026-10-20', bao: 'kv/data/scorehub/kafka-secret', lockReason: '', sentAt: '', channel: '', cfAt: '', cfBy: '' },
  ],
  audit: [
    { at: '24/08/2026 16:02', act: 'Tạo khóa trên OpenBao', obj: 'KEY-2026-0005', reason: 'POST /v1/transit/keys — type=rsa-4096' },
    { at: '20/08/2026 10:47', act: 'Cập nhật bàn giao', obj: 'KEY-2026-0002', reason: 'Đã gửi qua Portal đối tượng' },
    { at: '19/08/2026 08:20', act: 'Thu hồi khóa', obj: 'KEY-2026-0033', reason: 'POST /v1/transit/keys/…/config · min_decryption_version = 2 · Xác định lộ khóa theo PYC-2026-0871' },
    { at: '18/08/2026 15:40', act: 'Tải xuống', obj: 'KEY-2026-0007', reason: 'certificate + ca_chain · tệp key-2026-0007-certificate.pem' },
    { at: '17/08/2026 09:12', act: 'Tạo khóa trên OpenBao', obj: 'KEY-2026-0007', reason: 'POST /v1/pki/issue/scorehub-public-api · ttl=8760h · private key trả về MỘT LẦN' },
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
  'CRED-2026-0001': { dbRole: 'scorehub-oracle-ro', conn: 'scorehub-oracle', leaseId: 'database/creds/scorehub-oracle-ro/7Hk2mQ', leaseDur: '720h' },
  'CRED-2026-0003': { dbRole: 'airflow-pg-rw', conn: 'airflow-pg', leaseId: 'database/creds/airflow-pg-rw/2Bd8nL', leaseDur: '720h' },
  'CRED-2026-0004': { kvPath: 'scorehub/spark-keytab', kvVersion: 4 },
  'CRED-2026-0005': { dbRole: 'report-mysql-ro', conn: 'report-mysql', leaseId: 'database/creds/report-mysql-ro/5Xz1vT', leaseDur: '720h' },
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
  f_ttlcap: {
    t: 'Vì sao thời hạn hay bị từ chối',
    d: 'Thời hạn mình chọn phải lọt qua <b>ba cái trần chồng lên nhau</b>. Vướng bất kỳ cái nào là OpenBao từ chối — <span class="warn">không phải cứ role cho phép là chạy được.</span>',
    vd: 'Role cho <code>8760h</code> nhưng mount để mặc định <code>768h</code> → chọn 12 tháng vẫn <b>lỗi</b>',
    anh: [
      '<b>Trần 1 — hệ thống.</b> <code>max_lease_ttl</code> trong file cấu hình OpenBao, mặc định <code>768h</code> (~32 ngày).',
      '<b>Trần 2 — mount.</b> Mỗi engine gắn ở một mount, tune riêng được: <code>POST /v1/sys/mounts/pki/tune</code>. <span class="warn">Không tune thì vẫn là 768h.</span>',
      '<b>Trần 3 — role.</b> <code>max_ttl</code> trên từng role. Đây là trần duy nhất anh Tộ nhìn thấy trên màn hình.',
      'Ngoài ra chứng thư <b>không sống lâu hơn CA</b> cấp ra nó. CA còn 3 tháng thì không cấp nổi chứng thư 12 tháng.',
      '<span class="ok">CMS chặn trước cả ba</span> để không phải gửi request rồi mới biết lỗi.',
    ],
    map: [
      ['Trần hệ thống', '<code>max_lease_ttl</code> — file cấu hình, mặc định <code>768h</code>'],
      ['Trần mount', '<code>POST /v1/sys/mounts/:path/tune</code>'],
      ['Trần role', '<code>max_ttl</code> trên <code>pki/roles/:name</code>, <code>database/roles/:name</code>'],
      ['Trần CA', 'hạn của chính chứng thư CA — không có tham số nào chỉnh được'],
    ],
    json: '# Admin nới trần mount (làm một lần)\nPOST /v1/sys/mounts/pki/tune\n{ "max_lease_ttl": "8760h" }\n\n# Xem trần hiện tại\nGET /v1/sys/mounts/pki/tune\n→ { "max_lease_ttl": 8760, "default_lease_ttl": 0 }\n\n# Thứ tự áp dụng: lấy giá trị NHỎ NHẤT trong\n#   ttl yêu cầu · max_ttl của role · max_lease_ttl của mount\n#   · max_lease_ttl hệ thống · hạn còn lại của CA',
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
  f_lockReason: {
    t: 'Lý do thu hồi',
    d: 'Bắt buộc nhập. <b>Kiểm toán chắc chắn hỏi tới</b> khi rà soát vì sao khóa bị khai tử.<br>OpenBao thu hồi được nhưng <b>không ghi lại vì sao</b> — đó là việc của CMS.',
    vd: '<code>Xác định lộ khóa theo PYC-2026-0871</code> · <code>Chấm dứt hợp đồng HĐ-2025/012</code>',
    anh: [
      'Lưu vào nhật ký cùng thời điểm bấm và mã khóa',
      'Không gửi xuống OpenBao — chỉ nằm trong sổ CMS',
      '<span class="warn">Thu hồi là vĩnh viễn. Không có thao tác hoàn tác.</span>',
    ],
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

  /* ---------- Cách tạo khóa · Role · Tải xuống ---------- */
  f_create: {
    t: 'Cách tạo khóa',
    d: 'Mỗi engine hỗ trợ cách khác nhau — <b>không phải loại nào cũng có đủ hai lựa chọn "sinh mới" và "nhập sẵn"</b>. Danh sách bên dưới chỉ hiện đúng cách mà engine đang chọn thật sự làm được.',
    vd: 'Chứng thư TLS có <b>hai cách thật sự</b>: để OpenBao sinh cả cặp khóa, hoặc mình tự sinh khóa rồi chỉ nộp CSR.',
    anh: [
      '<b>Khóa ký / mã hóa (Transit)</b> — chỉ sinh mới. Nhập sẵn phải qua BYOK: tự bọc khóa bằng wrapping key 4096-bit, và <span class="warn">khóa đã nhập thì xoay khóa bị hạn chế</span>',
      '<b>Chứng thư TLS (PKI)</b> — có cả hai. Nộp CSR thì <span class="ok">private key không bao giờ rời khỏi máy mình</span>',
      '<b>Credential CSDL</b> — chỉ OpenBao sinh. Nhập tay thì mất hết ý nghĩa vì credential phải tự xóa khi hết hạn',
      '<b>API secret (KV v2)</b> — <span class="ok">nhập sẵn là cách chính</span>. API key của bên thứ ba thì mình đâu tự sinh được',
    ],
    map: [
      ['Transit', '<code>POST /v1/transit/keys/:name</code>'],
      ['PKI — sinh mới', '<code>POST /v1/pki/issue/:role</code>'],
      ['PKI — nộp CSR', '<code>POST /v1/pki/sign/:role</code>'],
      ['Database', '<code>GET /v1/database/creds/:role</code>'],
      ['KV v2', '<code>POST /v1/kv/data/:path</code>'],
    ],
    json: null,
  },
  f_csr: {
    t: 'Nộp CSR thay vì để OpenBao sinh khóa',
    d: '<b>CSR</b> = Certificate Signing Request. Mình tự sinh cặp khóa trên máy mình, rồi chỉ gửi <b>nửa công khai kèm chữ ký chứng minh mình giữ nửa bí mật</b> sang cho OpenBao ký.',
    vd: '<code>openssl req -new -newkey rsa:2048 -nodes -keyout svc.key -out svc.csr</code>',
    anh: [
      '<span class="ok">Private key không bao giờ đi qua mạng</span> — đây là cách tài liệu OpenBao khuyến nghị',
      'Role vẫn chặn được domain và trần thời hạn: CA quyết định lấy trường nào từ CSR, không phải cứ nộp gì là được nấy',
      '<span class="warn">Đừng nhầm với <code>pki/sign-verbatim</code></span> — endpoint đó bỏ qua mọi ràng buộc của role, tài liệu OpenBao xếp vào nhóm nguy hiểm, chỉ operator mới được gọi',
    ],
    map: [['Ký CSR', '<code>POST /v1/pki/sign/:role</code> · tham số <code>csr</code>']],
    json: 'POST /v1/pki/sign/scorehub-public-api\n{\n  "csr": "-----BEGIN CERTIFICATE REQUEST-----\\n...",\n  "common_name": "api.scorehub.example.vn",\n  "ttl": "8760h"\n}\n\n// Trả về certificate + issuing_ca + ca_chain\n// KHÔNG có private_key — vì OpenBao chưa từng thấy nó',
  },
  f_role: {
    t: 'Role — do admin tạo trước',
    d: 'Role là <b>hàng rào bảo mật do quản trị viên duyệt trước</b>. Màn tạo khóa <b>chỉ được chọn</b> role có sẵn, không tạo role mới.',
    vd: '<code>scorehub-public-api</code> — chỉ cấp chứng thư cho <code>scorehub.example.vn</code>, trần 12 tháng',
    anh: [
      'Role chặn sẵn <b>domain được phép</b> và <b>trần thời hạn</b>',
      'Không có role thì người dùng có thể xin chứng thư cho <b>domain bất kỳ</b>, biến CA nội bộ thành công cụ giả mạo',
      'Chặn ở tầng OpenBao — <b>không phụ thuộc UI kiểm tra đúng hay sai</b>',
      '<span class="warn">Đây là lỗi bản trước:</span> demo từng sinh một role riêng cho mỗi khóa. Sai — role dùng chung cho nhiều khóa',
    ],
    map: [
      ['Role PKI', '<code>POST /v1/pki/roles/:name</code> — <code>allowed_domains</code>, <code>max_ttl</code>'],
      ['Role Database', '<code>POST /v1/database/roles/:name</code> — <code>db_name</code>, <code>creation_statements</code>'],
    ],
    json: '// Admin tạo MỘT LẦN\nPOST /v1/pki/roles/scorehub-public-api\n{\n  "allowed_domains": "scorehub.example.vn",\n  "allow_subdomains": true,\n  "max_ttl": "8760h",\n  "key_type": "rsa",\n  "key_bits": 2048\n}\n\n// Sau đó cấp bao nhiêu chứng thư cũng dùng chung role này',
  },
  f_conn: {
    t: 'Kết nối CSDL',
    d: 'OpenBao <b>tự đăng nhập vào CSDL thật</b> để tạo và xóa tài khoản. Muốn thế thì phải khai trước đường kết nối và một tài khoản quản trị cho nó dùng.',
    vd: '<code>scorehub-oracle</code> → <code>oracle://…@db-scorehub:1521/ORCL</code>',
    anh: [
      'Chỉ engine <b>Database</b> cần bước này. PKI không cần.',
      '<code>{{username}}</code> và <code>{{password}}</code> trong URL là <b>chỗ OpenBao thay tài khoản quản trị vào</b>, không phải chỗ để gõ mật khẩu thật',
      '<span class="warn">Tài khoản đó phải có quyền <code>CREATE USER</code> / <code>DROP USER</code></span> trên CSDL thật. Chỉ cấp quyền đọc thì xin credential sẽ lỗi ngay ở phía CSDL, không phải lỗi OpenBao',
      '<code>allowed_roles</code> giới hạn role nào được dùng kết nối này — <b>thiếu tên role trong đây là bị từ chối</b>',
    ],
    map: [
      ['Khai kết nối', '<code>POST /v1/database/config/:name</code>'],
      ['Tham số bắt buộc', '<code>plugin_name</code>, <code>connection_url</code>, <code>allowed_roles</code>'],
    ],
    json: 'POST /v1/database/config/scorehub-oracle\n{\n  "plugin_name": "oracle-database-plugin",\n  "connection_url": "oracle://{{username}}:{{password}}@db-scorehub:1521/ORCL",\n  "allowed_roles": "scorehub-oracle-ro",\n  "username": "BAO_ADMIN",\n  "password": "..."\n}\n\n// Sau đó role mới trỏ vào được\nPOST /v1/database/roles/scorehub-oracle-ro\n{ "db_name": "scorehub-oracle", "creation_statements": "...", "default_ttl": "24h", "max_ttl": "720h" }',
  },
  f_prereq: {
    t: 'Điều kiện tiên quyết',
    d: 'CMS chỉ là lớp vỏ gọi API. <b>Thiếu bất kỳ điều kiện nào dưới đây thì OpenBao trả lỗi chứ không tự tạo giúp</b> — và lỗi sẽ hiện ra ở màn tạo khóa dù người dùng không làm gì sai.',
    vd: 'Token còn hạn nhưng thiếu policy trên <code>pki/issue/*</code> → <code>403 permission denied</code>',
    anh: [
      'Toàn bộ do <b>admin hạ tầng</b> làm trực tiếp trên OpenBao, <b>làm một lần lúc dựng hệ thống</b>',
      'Phân biệt hai loại TTL dễ nhầm: <b>TTL của token</b> (để gọi API) và <b>TTL của khóa</b> (thời hạn nghiệp vụ). Token hết hạn thì mọi thứ dừng, không liên quan khóa còn hạn hay không',
      '<span class="warn">Bật engine không phải việc của CMS.</span> CMS không nên có nút "bật Transit" — quyền <code>sys/mounts</code> là quyền quản trị toàn hệ thống',
      'Đề nghị: CMS có một màn <b>kiểm tra kết nối</b> chạy lúc khởi động để báo sớm, thay vì để người dùng bấm tạo khóa rồi mới lỗi',
    ],
    map: [
      ['Unseal', '<code>PUT /v1/sys/unseal</code> — hoặc auto-unseal'],
      ['Bật engine', '<code>POST /v1/sys/mounts/:path</code> — quyền admin'],
      ['Xem trạng thái', '<code>GET /v1/sys/health</code> · <code>GET /v1/sys/seal-status</code>'],
      ['Token', 'header <code>X-Vault-Token</code> trên mọi request'],
      ['Namespace', 'header <code>X-Vault-Namespace</code> nếu có dùng'],
    ],
    json: '# CMS kiểm tra lúc khởi động\nGET /v1/sys/health\n→ { "initialized": true, "sealed": false, "standby": false }\n\n# Bật engine — ADMIN làm một lần, không phải việc của CMS\nPOST /v1/sys/mounts/transit   { "type": "transit" }\nPOST /v1/sys/mounts/pki       { "type": "pki" }\nPOST /v1/sys/mounts/database  { "type": "database" }\nPOST /v1/sys/mounts/kv        { "type": "kv", "options": { "version": "2" } }\n\n# Nới trần thời hạn cho mount PKI\nPOST /v1/sys/mounts/pki/tune  { "max_lease_ttl": "8760h" }',
  },
  f_kvvalue: {
    t: 'Giá trị secret',
    d: 'KV v2 <b>chỉ là kho lưu trữ</b> — không mã hóa nghiệp vụ, không sinh gì cả. Gõ giá trị vào, OpenBao cất giữ có phiên bản.',
    vd: 'API key của bên thứ ba, token bot, nội dung tệp keytab mã hóa base64',
    anh: [
      'Đây là loại <b>duy nhất mà nhập tay là bình thường</b> — secret của bên thứ ba thì mình không tự sinh được',
      'Ghi đè giá trị mới thì <code>version</code> tăng lên, bản cũ vẫn còn để rollback',
      '<span class="warn">KV v2 không có TTL, không tự xoay</span> — CMS phải tự nhắc thay',
    ],
    map: [['Ghi', '<code>POST /v1/kv/data/:path</code> · body <code>{ "data": { ... } }</code>']],
    json: 'POST /v1/kv/data/scorehub/kafka-secret\n{ "data": { "sasl_password": "..." } }\n\n→ { "data": { "version": 1, "created_time": "..." } }',
  },
  f_download: {
    t: 'Tải xuống',
    d: 'Xuất ra tệp để mang đi cài lên nơi cần dùng. <b>Chỉ tải được thứ được phép ra ngoài</b> — nút sẽ không hiện với loại khóa không có gì để tải.',
    vd: 'Tải <code>public-key.pem</code> gửi cho ngân hàng đối tác để họ xác thực chữ ký của mình',
    anh: [
      '<b>Khóa ký</b> → tải <b>public key</b>. An toàn, đưa cho ai cũng được',
      '<b>Chứng thư TLS</b> → tải <b>certificate + CA chain</b>',
      '<b>Khóa mã hóa đối xứng</b> (<code>aes256-gcm96</code>, <code>chacha20</code>) → <span class="warn">không có gì để tải</span>, vì không có nửa công khai',
      '<b>Credential CSDL · API secret</b> → <span class="warn">không cho tải</span>, đó là giá trị bí mật, ứng dụng phải tự lấy',
      'Mỗi lần tải đều <b>ghi vào nhật ký</b> — kiểm toán truy được ai tải, lúc nào',
    ],
    map: [['Lấy từ đâu', '<code>GET /v1/transit/keys/:name</code> hoặc dữ liệu chứng thư đã lưu']],
    json: null,
  },
  f_pkikey: {
    t: '⚠️ Private key của chứng thư — chỉ trả về MỘT LẦN',
    d: 'Khác hẳn Transit. Khi dùng <code>pki/issue</code>, <b>OpenBao sinh cặp khóa rồi trả cả private key về cho mình và KHÔNG giữ lại</b>. Mất là mất luôn, phải cấp chứng thư mới.',
    vd: 'Cấp chứng thư cho Nginx → phải lưu ngay <code>.crt</code> và <code>.key</code> vào máy chủ đó',
    anh: [
      '<span class="warn">Không có endpoint nào đọc lại private key sau đó</span>',
      'Màn Chi tiết của chứng thư <b>chỉ hiện metadata</b>, không hiện lại được key',
      '<span class="ok">Muốn private key không bao giờ ra khỏi máy mình thì dùng cách nộp CSR</span> — <code>pki/sign</code> thay cho <code>pki/issue</code>',
      'Đây là chỗ <b>quy tắc BR-01 của tài liệu bản trước viết sai</b> — nói tuyệt đối rằng private key không bao giờ rời OpenBao, nhưng điều đó chỉ đúng với Transit',
    ],
    map: [
      ['<code>pki/issue</code>', 'trả về <code>certificate</code>, <code>private_key</code>, <code>ca_chain</code>, <code>serial_number</code>'],
      ['<code>pki/sign</code>', 'chỉ trả <code>certificate</code> — không có private key'],
    ],
    json: null,
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
      '<b>Thu hồi</b> — vĩnh viễn, không quay lại',
      '<b>Hết hiệu lực</b> — quá ngày hết hạn, CMS tự đổi',
    ],
    map: [['Lưu ý', '<b>Chưa xong bàn giao</b> chỉ là ghi sổ — nó KHÔNG chặn ứng dụng dùng khóa']],
    json: null,
  },
  th_act: {
    t: 'Cột Thao tác — nút nào hiện khi nào',
    d: 'Nút hiện ra <b>theo trạng thái của từng dòng</b>. Không phải dòng nào cũng có đủ nút.',
    vd: 'Dòng Đang hiệu lực → thấy Xoay khóa / Thu hồi',
    anh: [
      '<b>Chi tiết</b> — luôn có. Xem hồ sơ, tham số OpenBao, nhật ký',
      '<b>Public key / Chứng thư</b> — xem, copy, <b>tải xuống tệp .pem</b>. Chỉ hiện với loại khóa có thứ đưa ra ngoài được',
      '<b>Cập nhật bàn giao</b> — chỉ khi <i>Chưa xong bàn giao</i>. Điền 2 ngày là khóa vào hiệu lực',
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
      '<b>Đã thu hồi</b> — khóa đã khai tử, giữ lại để đối soát với kiểm toán',
      '<span class="warn">Không có nhóm "tạm khóa"</span> — OpenBao không hỗ trợ trạng thái tạm dừng, nghiệp vụ chỉ có dùng hoặc khai tử',
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
      '<b>2. Thu hồi có lý do</b> — OpenBao thu hồi được nhưng không ghi vì sao',
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
    vd: '<code>Thu hồi khóa · KEY-2026-0033 · min_decryption_version = 2 · Xác định lộ khóa theo PYC-2026-0871</code>',
    anh: [
      'Cột <b>Lý do / tham số</b> ghi cả hai: vì sao làm, và <b>đã gọi lệnh gì xuống OpenBao</b>',
      'Ghi cả thao tác <b>Tải xuống</b> — kiểm toán truy được ai lấy public key, lúc nào',
      'OpenBao có audit log riêng nhưng <b>chỉ ghi lệnh kỹ thuật, không ghi vì sao</b> — lý do chỉ có ở CMS',
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
  min_encryption_version: 'Phiên bản tối thiểu được dùng để ký/mã hóa. <code>0</code> = dùng bản mới nhất.',
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
    P('db_name', e.conn || '—'); P('default_ttl', k.ttlH + 'h'); P('max_ttl', k.ttlH + 'h');
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
  if (dlOf(k)) a.push(`<a data-act="pubkey" data-id="${k.id}"><i class="fa fa-download"></i> ${KT(k.kt).engine === 'PKI' ? 'Chứng thư' : 'Public key'}</a>`);
  if (k.status === 'CHUA_XONG') a.push(`<a data-act="deliv" data-id="${k.id}">Cập nhật bàn giao</a>`, `<a data-act="revoke" data-id="${k.id}" class="danger">Thu hồi</a>`);
  else if (k.status === 'HIEU_LUC') a.push(
    `<a data-act="rotate" data-id="${k.id}">Xoay khóa</a>`,
    `<a data-act="revoke" data-id="${k.id}" class="danger">Thu hồi</a>`);
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
  { icon: 'fa-sliders-h', label: 'Thiết lập hạ tầng', route: 'setup' },
  { icon: 'fa-file-alt', label: 'Nhật ký & báo cáo', route: 'audit' },
];
const TITLES = {
  keys: 'Danh mục khóa', objs: 'Danh mục đối tượng',
  setup: 'Thiết lập hạ tầng', audit: 'Nhật ký & báo cáo',
};

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
  { k: 'thuhoi', l: 'Đã thu hồi', f: (x) => x.status === 'THU_HOI' },
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

/* ---------------- MÀN 3 — THIẾT LẬP HẠ TẦNG (chỉ đọc) ----------------
   Màn này KHÔNG phải để anh Tộ khai báo. Nó trả lời đúng một câu hỏi:
   "cái dropdown Role lúc tạo khóa ở đâu ra, và vì sao thời hạn bị chặn".
   Mọi thứ ở đây do admin hạ tầng làm trực tiếp trên OpenBao. */
function viewSetup() {
  const mountRows = MOUNTS.map(m => `<tr>
    <td><b>${esc(m.engine)}</b></td>
    <td class="mono">${esc(m.path)}</td>
    <td class="mono">${m.maxLeaseH
      ? `${m.maxLeaseH}h` + (m.tuned ? '' : ` <span class="req-mark">(mặc định)</span>`)
      : '<span class="muted">không áp dụng</span>'}</td>
    <td class="text-center">${m.tuned
      ? '<span class="st st-ok">đã tune</span>'
      : '<span class="st st-idle">để mặc định</span>'}</td>
    <td class="muted" style="font-size:12px">${m.note}</td>
  </tr>`).join('');

  const roleRows = ROLES.map(r => `<tr>
    <td class="mono">${esc(r.name)}</td>
    <td><span class="tag-type ${r.type === 'PKI' ? 'tag-B' : 'tag-A'}">${esc(r.type)}</span></td>
    <td>${esc(r.desc)}</td>
    <td class="mono" style="font-size:12px">${r.domains
      ? 'allowed_domains=' + esc(r.domains)
      : 'kết nối ' + esc(r.conn)}</td>
    <td class="mono">${r.maxTtlH}h</td>
    <td class="text-center">${DB.keys.filter(k => k.role === r.name).length}</td>
  </tr>`).join('');

  const connRows = CONNS.map(c => `<tr>
    <td class="mono">${esc(c.name)}</td>
    <td class="mono" style="font-size:12px">${esc(c.plugin)}</td>
    <td class="mono" style="font-size:12px">${esc(c.url)}</td>
    <td class="mono" style="font-size:12px">${esc(c.roles)}</td>
  </tr>`).join('');

  return `
  ${note('Màn này <b>chỉ để xem</b>, không sửa được gì. Toàn bộ do <b>admin hạ tầng</b> làm trực tiếp trên OpenBao trước khi anh Tộ tạo khóa.<br>Dựng màn này vì hai lý do: (1) giải thích cái dropdown <b>Role</b> lúc tạo khóa ở đâu ra, (2) khi thời hạn bị từ chối thì biết ngay vướng trần nào mà đi hỏi ai.')}

  <div class="card">
    <div class="card-header">Thiết lập hạ tầng OpenBao <span class="ro-badge">CHỈ ĐỌC</span></div>
    <div class="card-body font-size-14">

      <div class="setup-sec">
        <h4>1. Engine đã bật và trần thời hạn của mount ${tt('f_ttlcap')}</h4>
        <div class="sub">Mount là chỗ engine được gắn vào OpenBao. <b>Trần <code>max_lease_ttl</code> mặc định là ${SYS_MAX_LEASE_H}h (~32 ngày)</b> — không tune thì không cấp nổi chứng thư 12 tháng dù role có cho phép.</div>
        <div class="ui-table"><table>
          <thead><tr><th style="width:110px">Engine</th><th style="width:100px">Mount path</th>
            <th style="width:150px">max_lease_ttl</th><th style="width:110px">Trạng thái</th><th>Ghi chú</th></tr></thead>
          <tbody>${mountRows}</tbody>
        </table></div>
      </div>

      <div class="setup-sec">
        <h4>2. Role do admin tạo sẵn ${tt('f_role')}</h4>
        <div class="sub">Chỉ <b>PKI</b> và <b>Database</b> cần role. Role là hàng rào thật nằm dưới OpenBao — nó chặn domain và trần thời hạn, <b>không phụ thuộc vào việc CMS kiểm tra đúng hay sai</b>. Màn tạo khóa chỉ được <b>chọn</b>, không tạo mới.</div>
        <div class="ui-table"><table>
          <thead><tr><th style="width:200px">Tên role</th><th style="width:100px">Engine</th><th>Mục đích</th>
            <th>Ràng buộc</th><th style="width:90px">max_ttl</th><th style="width:90px">Đang dùng</th></tr></thead>
          <tbody>${roleRows}</tbody>
        </table></div>
      </div>

      <div class="setup-sec">
        <h4>3. Kết nối CSDL ${tt('f_conn')}</h4>
        <div class="sub">Chỉ engine <b>Database</b> cần. Mỗi role Database phải trỏ vào một kết nối có sẵn. Tài khoản OpenBao dùng để kết nối <b>phải có quyền tạo/xóa user</b> trên CSDL thật, nếu không thì xin credential sẽ lỗi ngay ở phía CSDL.</div>
        <div class="ui-table"><table>
          <thead><tr><th style="width:170px">Tên kết nối</th><th style="width:210px">plugin_name</th>
            <th>connection_url</th><th style="width:180px">allowed_roles</th></tr></thead>
          <tbody>${connRows}</tbody>
        </table></div>
      </div>

      <div class="setup-sec" style="margin-bottom:0">
        <h4>4. Điều kiện chung — thiếu là mọi API đều lỗi ${tt('f_prereq')}</h4>
        <div class="ui-table"><table>
          <thead><tr><th style="width:260px">Điều kiện</th><th style="width:120px">Lỗi nếu thiếu</th><th>Giải thích</th></tr></thead>
          <tbody>
            <tr><td><b>OpenBao đã unseal</b></td><td class="mono">503</td>
              <td class="muted" style="font-size:12px">Mới khởi động là trạng thái sealed, phải mở khóa bằng unseal key hoặc auto-unseal trước khi nhận bất kỳ request nào.</td></tr>
            <tr><td><b>Token còn hạn</b></td><td class="mono">403</td>
              <td class="muted" style="font-size:12px">Gắn ở header <code>X-Vault-Token</code>. Đây là TTL của <b>token</b>, khác TTL của khóa — token hết hạn thì mọi thứ dừng.</td></tr>
            <tr><td><b>Policy cho đúng path</b></td><td class="mono">403</td>
              <td class="muted" style="font-size:12px">Token còn hạn vẫn bị chặn nếu policy không cấp quyền trên <code>transit/keys/*</code>, <code>pki/issue/*</code>…</td></tr>
            <tr><td><b>Đúng namespace</b></td><td class="mono">404</td>
              <td class="muted" style="font-size:12px">Nếu hệ thống chia namespace mà thiếu header <code>X-Vault-Namespace</code> thì tìm nhầm chỗ, báo không tồn tại.</td></tr>
            <tr><td><b>PKI: đã có CA</b></td><td class="mono">400</td>
              <td class="muted" style="font-size:12px">Chưa sinh/ký CA thì <code>pki/issue</code> lỗi. Chứng thư cũng <b>không sống lâu hơn CA</b> cấp ra nó.</td></tr>
          </tbody>
        </table></div>
      </div>

    </div>
  </div>`;
}

/* ---------------- MÀN 4 — NHẬT KÝ ---------------- */
function viewAudit() {
  const rows = DB.audit.map((a, i) => `<tr>
      <td class="text-center">${i + 1}</td>
      <td class="nowrap mono">${esc(a.at)}</td>
      <td>${a.act.indexOf('Thu hồi') >= 0 ? `<b class="req-mark">${esc(a.act)}</b>` : esc(a.act)}</td>
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

      <div class="col-12 form-group">${lb('Cách tạo khóa', 'f_create', 1)}
        <select class="form-control" id="nCreate"></select>
        <div id="nCreateAffect"></div></div>

      <div class="col-12 form-group" id="nRoleWrap" style="display:none">
        ${lb('Role', 'f_role', 1)}
        <select class="form-control" id="nRole"></select>
        <div class="src-note" id="nRoleNote"></div></div>

      <div class="col-12 form-group" id="nCsrWrap" style="display:none">
        ${lb('CSR', 'f_csr', 1)}
        <textarea class="form-control" id="nCsr" rows="3" placeholder="-----BEGIN CERTIFICATE REQUEST-----&#10;..."></textarea>
        <div class="src-note">Tự sinh bằng: <code>openssl req -new -newkey rsa:2048 -nodes -keyout svc.key -out svc.csr</code></div></div>

      <div class="col-12 form-group" id="nValWrap" style="display:none">
        ${lb('Giá trị secret', 'f_kvvalue', 1)}
        <input class="form-control mono" id="nValKey" placeholder="Tên trường, ví dụ: api_key" style="margin-bottom:6px">
        <textarea class="form-control mono" id="nVal" rows="2" placeholder="Dán giá trị vào đây"></textarea>
        <div class="src-note" id="nValNote"></div></div>

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
  const sO = $('#nObj'), sK = $('#nKt'), sT = $('#nTtl'), sA = $('#nAlgo'), sC = $('#nCreate');
  if (!sO || !sK || !sT || !sA || !sC) return;
  const o = OBJ(sO.value), t = KT(sK.value);

  // 0. Loại khóa → các cách tạo mà engine THẬT SỰ hỗ trợ
  const keepC = sC.value;
  const modes = t.create || [{ v: 'gen', l: 'OpenBao sinh khóa mới', ep: '' }];
  sC.innerHTML = modes.map(m => `<option value="${m.v}" ${m.v === keepC ? 'selected' : ''}>${esc(m.l)}</option>`).join('');
  if (!modes.some(m => m.v === sC.value)) sC.value = modes[0].v;
  const mode = modes.find(m => m.v === sC.value) || modes[0];

  $('#nCreateAffect').innerHTML = `<div class="affect">
    <b>→ gọi <code>${esc(mode.ep)}</code></b>
    ${modes.length === 1
      ? `<br><b>Loại khóa này chỉ có một cách.</b> ${t.noImport || ''}`
      : `<br>Loại khóa này có <b>${modes.length} cách</b>, chọn cách nào thì form bên dưới đổi theo.`}
    ${mode.v === 'csr' ? '<br><span style="color:#1b7a4b">Private key không rời khỏi máy mình — OpenBao chỉ ký CSR.</span>' : ''}
    ${mode.v === 'gen' && t.code === 'CERT' ? '<br><span class="req-mark">OpenBao trả private key về MỘT LẦN duy nhất, sau đó không lấy lại được.</span>' : ''}
  </div>`;

  // 0b. Role — chỉ hiện với PKI và Database, do admin tạo trước
  const rw = $('#nRoleWrap'), sR = $('#nRole');
  if (t.role) {
    rw.style.display = '';
    const list = rolesOf(t.role), keepR = sR.value;
    sR.innerHTML = list.map(r => `<option value="${esc(r.name)}" ${r.name === keepR ? 'selected' : ''}>${esc(r.name)} — ${esc(r.desc)}</option>`).join('');
    const r = ROLE(sR.value) || list[0];
    $('#nRoleNote').innerHTML = r
      ? `Do admin tạo sẵn · ${r.domains ? 'chỉ cấp cho <code>' + esc(r.domains) + '</code>' : 'kết nối <code>' + esc(r.conn) + '</code>'} · trần <b>${ttlLabel(t, r.maxTtlH) || r.maxTtlH + 'h'}</b>`
      : '';
  } else { rw.style.display = 'none'; }

  // 0c. CSR — chỉ khi chọn cách nộp CSR
  $('#nCsrWrap').style.display = mode.v === 'csr' ? '' : 'none';

  // 0d. Giá trị secret — chỉ với KV v2
  const vw = $('#nValWrap');
  vw.style.display = t.engine === 'KV v2' ? '' : 'none';
  if (t.engine === 'KV v2') {
    $('#nVal').disabled = mode.v === 'gen';
    $('#nValNote').innerHTML = mode.v === 'gen'
      ? 'CMS sinh chuỗi ngẫu nhiên rồi ghi vào KV. Ô giá trị để trống.'
      : '<b>Đây là loại duy nhất nhập tay là bình thường</b> — API key bên thứ ba thì mình không tự sinh được.';
  }

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

  // 3. Thời hạn → trường API + cách hết hạn + các trần đang chặn
  const h = +sT.value;
  const mnt = MOUNT(t.engine), cap = ttlCeiling(t, sR ? sR.value : '', h);
  const capLine = cap
    ? `<div class="affect bad"><b>⛔ Vượt trần ${cap.kind === 'role' ? 'của role' : 'của mount'} —
        ${esc(cap.name)} chỉ cho tối đa <code>${cap.limitH}h</code>.</b>
        ${cap.kind === 'mount' && !cap.tuned
        ? ` Mount này đang để mặc định <code>${SYS_MAX_LEASE_H}h</code> của OpenBao.`
        : ''} OpenBao sẽ từ chối request. ${tt('f_ttlcap')}</div>`
    : (t.ttlField && mnt && mnt.maxLeaseH
      ? `<div class="affect ok">✔ Lọt trần: role, mount <code>${esc(mnt.path)}</code>
          (<code>max_lease_ttl ${mnt.maxLeaseH}h</code>) và hệ thống. ${tt('f_ttlcap')}</div>`
      : '');
  $('#nTtlAffect').innerHTML = `<div class="affect">
    ${t.ttlField
      ? `<b>→ gửi xuống <code>${t.ttlField}: "${h}h"</code></b>`
      : '<b>→ KHÔNG gửi xuống OpenBao.</b> KV v2 không có TTL.'}
    <br>${t.ttlNote}</div>${capLine}`;

  // 4. Thuật toán → trường API
  $('#nAlgoNote').innerHTML = t.engine === 'Transit' ? `→ <code>type=${esc(sA.value)}</code>`
    : t.engine === 'PKI' ? `→ <code>key_type=${esc(sA.value.split('/')[0])}</code>, <code>key_bits=${esc(sA.value.split('/')[1])}</code>`
      : `engine <b>${esc(t.engine)}</b> không dùng thuật toán`;

  // 5. Tóm tắt: tên khóa tự sinh + ngày hết hạn + tải được gì
  const bao = baoName(o, t, sR ? sR.value : '');
  const exp = t.ttlField || t.code === 'SEC' ? addHours(h) : '';
  const dl = dlLabel(t, sA.value);
  $('#nSummary').innerHTML = `<b>CMS sẽ tự sinh:</b>
    <table style="width:100%;margin-top:6px;font-size:13px">
      <tr><td style="width:210px;color:#767574">Mã khóa</td><td class="mono">KEY-2026-0xxx</td></tr>
      <tr><td style="color:#767574">Đường dẫn trong OpenBao ${tt('f_baoname')}</td><td class="mono">${esc(bao)}</td></tr>
      <tr><td style="color:#767574">Ngày hết hạn</td><td>${fmt(exp)} <span class="muted">(hôm nay + ${ttlLabel(t, h)})</span></td></tr>
      <tr><td style="color:#767574">Trạng thái sau khi tạo</td><td>${stBadge(o.ext ? 'CHUA_XONG' : 'HIEU_LUC')}</td></tr>
      <tr><td style="color:#767574">Tải xuống được ${tt('f_download')}</td><td>${dl
      ? esc(dl)
      : '<span class="muted">không có gì để tải — đây là giá trị bí mật, ứng dụng phải tự lấy</span>'}</td></tr>
    </table>`;
}

/** Tải xuống được gì — phụ thuộc engine và thuật toán. */
function dlLabel(t, algo) {
  if (t.dl === 'public') return 'Public key (.pem)';
  if (t.dl === 'cert') return 'Certificate + CA chain (.pem)';
  if (t.dl === 'public-if-rsa') return /^rsa/.test(algo || '') ? 'Public key (.pem)' : '';
  return '';
}

/** Đường dẫn thật trong OpenBao.
 *  PKI và Database dùng ROLE do admin tạo sẵn — KHÔNG sinh role riêng cho từng khóa. */
function baoName(o, t, roleName) {
  if (t.engine === 'PKI') return 'pki/issue/' + (roleName || ':role');
  if (t.engine === 'Database') return 'database/creds/' + (roleName || ':role');
  const purpose = { SIGN: 'sign', ENC: 'enc', SEC: 'secret' }[t.code] || 'key';
  const prefix = t.engine === 'KV v2' ? 'kv/data/' : 'transit/keys/';
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

/** Serial giả lập cho chứng thư PKI — dạng hex ngăn bằng dấu hai chấm như OpenBao trả về. */
function randSerial(seedStr) {
  let r = seedStr.split('').reduce((a, ch) => (a * 33 + ch.charCodeAt(0)) >>> 0, 5381);
  const b = [];
  for (let i = 0; i < 10; i++) { r = (r * 1103515245 + 12345) >>> 0; b.push(('0' + (r % 256).toString(16)).slice(-2)); }
  return b.join(':');
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

/** Loại khóa này tải xuống được gì — rỗng nghĩa là không có gì để tải. */
function dlOf(k) { return dlLabel(KT(k.kt), k.algo); }

function openPubkey(id) {
  const k = DB.keys.find(x => x.id === id), t = KT(k.kt), e = EX(k.id);
  const isCert = t.engine === 'PKI';
  const what = dlOf(k);

  if (!what) {
    modal(shell(`<i class="fa fa-ban"></i> ${esc(k.id)}`, `
      <div class="hint bad"><b>Loại khóa này không có gì để tải xuống.</b> ${tt('f_download')}
        <div class="mt-2">${t.engine === 'Transit'
        ? `Thuật toán <code>${esc(k.algo)}</code> là <b>khóa đối xứng</b> — chỉ có một khóa duy nhất, không có nửa công khai để đưa ra ngoài.`
        : t.engine === 'Database'
          ? 'Credential CSDL là <b>user/password bí mật</b>. Ứng dụng tự gọi <code>GET /v1/database/creds/:role</code> để lấy, mỗi lần một bộ mới.'
          : 'Giá trị trong KV v2 là <b>bí mật</b>. Ứng dụng tự đọc <code>GET /v1/kv/data/:path</code>, không tải qua CMS.'}</div></div>
    `, `<button class="btn btn-secondary" data-close="1">Đóng</button>`, 'sm'));
    return;
  }

  const v = window.__pkv || k.ver;
  const vers = []; for (let i = 1; i <= k.ver; i++) vers.push(i);
  const body = isCert ? fakeCert(k.id, e.serial) : fakePem(k.id, v);
  const needSend = k.status === 'CHUA_XONG' && v === k.ver;

  modal(shell(`<i class="fa fa-eye"></i> ${isCert ? 'Chứng thư' : 'Public key'} — ${esc(k.id)}`, `
    <div class="hint"><b>${isCert
      ? 'Chứng thư và chuỗi CA — gửi ra ngoài được, không phải bí mật.'
      : 'Đây là nửa công khai của cặp khóa — gửi cho đối tác được, không phải bí mật.'}</b>
      ${isCert ? tt('f_pkikey') : 'Private key nằm trong OpenBao, CMS không bao giờ nhìn thấy. ' + tt('f_pubkey')}</div>

    ${isCert ? `<div class="hint warn"><b>Private key thì KHÔNG hiện ở đây.</b>
      ${k.createMode === 'csr'
        ? 'Khóa này tạo bằng cách <b>nộp CSR</b> — private key vẫn nằm trên máy người xin, OpenBao chưa từng thấy nó.'
        : 'Khóa này để <b>OpenBao sinh</b> — private key đã trả về đúng một lần lúc cấp và không lưu lại ở đâu. Mất là phải cấp chứng thư mới.'}</div>`
      : `<div class="form-group"><label>Chọn phiên bản${tt('f_version')}</label>
      <select class="form-control" id="pkVer" style="max-width:340px">
        ${vers.reverse().map(i => `<option value="${i}" ${i === v ? 'selected' : ''}>v${i}${i === k.ver ? ' — mới nhất' : ''}${i === k.activeVer ? ' · ĐANG DÙNG ĐỂ KÝ' : ''}</option>`).join('')}
      </select></div>`}

    ${needSend && !isCert ? `<div class="hint warn"><b>Đây là bản cần gửi cho đối tác.</b>
      Con trỏ vẫn đang ở <b>v${k.activeVer}</b> nên giao dịch chưa bị ảnh hưởng.
      Gửi xong và đối tác xác nhận thì mới đổi con trỏ sang v${k.ver}.</div>` : ''}

    <div class="pem-box" id="pemBox">${esc(body)}</div>
    <div class="mt-2">
      <button class="btn btn-primary btn-sm" data-act="copyPem"><i class="fa fa-copy"></i> Copy</button>
      <button class="btn btn-primary btn-sm ml-2" data-act="dlPem" data-id="${k.id}"><i class="fa fa-download"></i> Tải xuống</button>
      <span class="ml-2">${tt('f_download')}</span>
      <span class="src-note ml-2" id="copyMsg"></span>
    </div>
    <div class="src-note mt-3">CMS lấy trực tiếp từ OpenBao mỗi lần mở:
      <code>GET /v1/${esc(isCert ? 'pki/cert/' + (e.serial || '&lt;serial&gt;') : k.bao)}</code> — không lưu bản sao để tránh lệch.</div>
  `, `<button class="btn btn-secondary" data-close="1">Đóng</button>`));
  window.__pkId = id;
}

/** Chứng thư giả lập — để demo nút tải xuống. */
function fakeCert(id, serial) {
  return '-----BEGIN CERTIFICATE-----\n' + fakePem(id + 'cert', 1)
    .replace(/-----(BEGIN|END) PUBLIC KEY-----\n?/g, '')
    + '\n-----END CERTIFICATE-----\n'
    + '\n# serial_number: ' + (serial || '—')
    + '\n\n-----BEGIN CERTIFICATE-----\n' + fakePem(id + 'ca', 1)
      .replace(/-----(BEGIN|END) PUBLIC KEY-----\n?/g, '')
    + '\n-----END CERTIFICATE-----\n# ↑ issuing_ca';
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
      <div class="k">Cách tạo ${tt('f_create')}</div><div class="v" style="font-weight:400">${esc(
      ((t.create || []).find(m => m.v === (k.createMode || 'gen')) || { l: 'OpenBao sinh khóa mới' }).l)}</div>
      ${k.role ? `<div class="k">Role ${tt('f_role')}</div><div class="v mono">${esc(k.role)}
        <span class="muted" style="font-weight:400;font-family:inherit"> — do admin tạo sẵn</span></div>` : ''}
      <div class="k">Thuật toán</div><div class="v">${esc(k.algo)}</div>
      ${t.engine === 'Transit' ? `<div class="k">Phiên bản trong OpenBao ${tt('f_version')}</div><div class="v">v1 … v${k.ver}</div>
      <div class="k">Đang ký bằng ${tt('f_pointer')}</div><div class="v">${k.activeVer === k.ver
        ? `v${k.activeVer}`
        : `<span class="req-mark">v${k.activeVer}</span> <span class="muted">— chưa chuyển sang v${k.ver}, chờ đối tác xác nhận</span>`}</div>` : ''}
      ${dlOf(k)
      ? `<div class="k">${t.engine === 'PKI' ? 'Chứng thư' : 'Public key'} ${tt(t.engine === 'PKI' ? 'f_pkikey' : 'f_pubkey')}</div>
         <div class="v"><span class="linkish" data-act="pubkey" data-id="${k.id}"><i class="fa fa-download"></i> Xem · copy · tải xuống</span></div>`
      : `<div class="k">Tải xuống ${tt('f_download')}</div><div class="v muted" style="font-weight:400">không có gì đưa ra ngoài được</div>`}
      <div class="k">Thời hạn</div><div class="v">${ttlLabel(t, k.ttlH)} <span class="muted">(${k.ttlH}h)</span></div>
      <div class="k">Hiệu lực</div><div class="v">${fmt(k.eff)} → ${fmt(k.exp)}</div>
      <div class="k">Trạng thái</div><div class="v">${stBadge(k.status)}</div>
      ${k.lockReason ? `<div class="k">Lý do</div><div class="v" style="font-weight:400">${esc(k.lockReason)}</div>` : ''}
      ${ext ? `<div class="k">Đã gửi</div><div class="v" style="font-weight:400">${k.sentAt ? `${fmt(k.sentAt)} · ${esc(k.channel)}` : '<span class="muted">chưa</span>'}</div>
      <div class="k">Đối tác xác nhận</div><div class="v" style="font-weight:400">${k.cfAt ? `${fmt(k.cfAt)} · ${esc(k.cfBy)}` : '<span class="muted">chưa</span>'}</div>` : ''}
      <div class="k">Tên trong OpenBao ${tt('f_baoname')}</div><div class="v mono">${esc(k.bao)}</div>
    </div>
    <div class="hint mt-3"><b><i class="fa fa-lock"></i></b> ${t.engine === 'PKI'
      ? `Màn hình này <b>không hiển thị private key</b> — và với chứng thư thì <b>không nơi nào hiển thị lại được</b>. ${tt('f_pkikey')}`
      : t.engine === 'Transit'
        ? 'Private key <b>chưa bao giờ rời khỏi OpenBao</b>. CMS chỉ gửi dữ liệu sang để OpenBao ký hộ.'
        : 'Giá trị bí mật không đi qua CMS — ứng dụng tự gọi OpenBao để lấy.'}</div>`;
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

function openRevoke(id) {
  const k = DB.keys.find(x => x.id === id), t = KT(k.kt);
  const how = { Transit: '<code>config</code> · <code>min_decryption_version</code> = latest + 1', PKI: '<code>POST /v1/pki/revoke</code> · <code>serial_number</code>', Database: '<code>POST /v1/sys/leases/revoke</code> · <code>lease_id</code>', 'KV v2': '<code>DELETE /v1/kv/metadata/:path</code>' }[t.engine];
  modal(shell(`<i class="fa fa-ban"></i> Thu hồi — ${esc(id)}`, `
    <div class="hint bad"><b>Thu hồi là vĩnh viễn — không có thao tác hoàn tác.</b>
      Công cụ <b>không có chức năng tạm dừng</b>: OpenBao không hỗ trợ trạng thái đó, nên nghiệp vụ chỉ có dùng hoặc khai tử. ${tt('f_revoke')}</div>
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
  const fn = { keys: viewKeys, objs: viewObjs, setup: viewSetup, audit: viewAudit }[r] || viewKeys;
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
    case 'dlPem': {
      const k = K(), t2 = KT(k.kt);
      const txt = $('#pemBox').textContent || '';
      const isCert = t2.engine === 'PKI';
      const fname = k.id.toLowerCase() + (isCert ? '-certificate.pem' : '-public-key.pem');
      try {
        const blob = new Blob([txt], { type: 'application/x-pem-file' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = fname;
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
      } catch (err) { alert('Trình duyệt chặn tải tệp. Dùng nút Copy thay thế.'); return; }
      const m = $('#copyMsg');
      if (m) m.innerHTML = `<span style="color:#1b7a4b"><i class="fa fa-check"></i> Đã tải <b>${esc(fname)}</b></span>`;
      log('Tải xuống', k.id, `${isCert ? 'certificate + ca_chain' : 'public key'} · tệp ${fname}`);
      break;
    }
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
      const mode = $('#nCreate').value, roleName = t2.role ? $('#nRole').value : '';

      if (o.ext && (!/\d/.test(dos) || dos.length < 6)) {
        $('#nDos').classList.add('invalid');
        $('#nDosNote').innerHTML = '<span class="req-mark">Đối tượng bên ngoài bắt buộc có hồ sơ: phải có số hiệu, tối thiểu 6 ký tự.</span>';
        return;
      }
      if (mode === 'csr' && !/BEGIN CERTIFICATE REQUEST/.test($('#nCsr').value)) {
        alert('Chọn cách nộp CSR thì phải dán nội dung CSR vào.\n\nSinh bằng:\nopenssl req -new -newkey rsa:2048 -nodes -keyout svc.key -out svc.csr');
        return;
      }
      if (t2.engine === 'KV v2' && mode === 'input' && !$('#nVal').value.trim()) {
        alert('Chọn cách nhập sẵn thì phải dán giá trị secret vào.'); return;
      }
      // Thời hạn bị chặn bởi NHIỀU trần chồng nhau — CMS phải chặn trước và nói rõ vướng trần nào
      const cap = ttlCeiling(t2, roleName, h);
      if (cap) {
        const lim = ttlLabel(t2, cap.limitH) || cap.limitH + 'h';
        alert(cap.kind === 'role'
          ? `Role "${cap.name}" có trần ${lim} (max_ttl).\n\n`
            + 'Role là hàng rào do admin dựng sẵn — CMS không vượt qua được.\n'
            + 'Muốn dài hơn thì phải nhờ admin sửa role, hoặc chọn role khác.'
          : `Mount "${cap.name}" có trần ${lim} (max_lease_ttl).\n\n`
            + (cap.tuned
              ? 'Admin đã tune mount này nhưng vẫn chưa đủ dài.'
              : `Mount này đang để MẶC ĐỊNH của OpenBao là ${SYS_MAX_LEASE_H}h (~32 ngày).`)
            + '\n\nĐây là trần dễ quên nhất: role cho phép không có nghĩa là mount cho phép.\n'
            + `Admin phải chạy: POST /v1/sys/mounts/${cap.name}tune  { "max_lease_ttl": "${h}h" }`);
        return;
      }

      const nid = (t2.engine === 'Database' || t2.engine === 'KV v2' ? 'CRED-2026-0' : 'KEY-2026-0') + (100 + DB.keys.length);
      const bao = baoName(o, t2, roleName);
      DB.keys.unshift({
        id: nid, obj: o.n, kt: t2.code, dossier: dos, algo: $('#nAlgo').value, ttlH: h, ver: 1, activeVer: 1,
        status: o.ext ? 'CHUA_XONG' : 'HIEU_LUC',
        eff: o.ext ? '' : TODAY_ISO, exp: o.ext ? '' : addHours(h),
        bao, lockReason: '', sentAt: '', channel: '', cfAt: '', cfBy: '', createMode: mode, role: roleName,
      });
      EXTRA[nid] = { latest: 1, minDec: 1, minEnc: 0 };
      if (t2.engine === 'PKI') { EXTRA[nid].pkiRole = roleName; EXTRA[nid].cn = (ROLE(roleName) || {}).domains || '—'; EXTRA[nid].serial = randSerial(nid); }
      if (t2.engine === 'Database') { EXTRA[nid].dbRole = roleName; EXTRA[nid].leaseId = bao + '/' + nid.slice(-6); EXTRA[nid].leaseDur = h + 'h'; }
      if (t2.engine === 'KV v2') { EXTRA[nid].kvPath = bao.replace('kv/data/', ''); EXTRA[nid].kvVersion = 1; }

      const modeObj = (t2.create || []).find(m => m.v === mode) || { ep: '' };
      log('Tạo khóa trên OpenBao', nid,
        `${modeObj.ep.replace(':role', roleName || ':role').replace(':name', bao.split('/').pop()).replace(':path', bao.replace('kv/data/', ''))}`
        + ` · ${t2.ttlField ? t2.ttlField + '=' + h + 'h' : 'KV v2 không có TTL'}`
        + (mode === 'csr' ? ' · ký CSR, private key không rời máy người dùng' : '')
        + (mode === 'gen' && t2.engine === 'PKI' ? ' · private key trả về MỘT LẦN' : ''));

      closeModal(); window.__f = { q: '', ext: '', qf: o.ext ? 'bangiao' : '' }; render();

      if (t2.engine === 'PKI' && mode === 'gen') {
        alert('Chứng thư đã cấp.\n\n'
          + 'OpenBao vừa trả về private key và KHÔNG giữ lại bản nào.\n'
          + 'Phải tải xuống ngay — sau khi đóng màn này sẽ không lấy lại được.');
      }
      break;
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
  if (el.id === 'pkVer') { window.__pkv = +el.value; openPubkey(window.__pkId); return; }
  if (['nObj', 'nKt', 'nTtl', 'nAlgo', 'nCreate', 'nRole'].indexOf(el.id) >= 0) syncNew();
});

window.addEventListener('hashchange', render);
render();
