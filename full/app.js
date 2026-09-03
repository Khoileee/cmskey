/* ============================================================
   CMS Quản trị khóa — nguyên mẫu tương tác (dữ liệu giả lập)
   Mô hình LOẠI-ĐỐI-TƯỢNG ĐỘNG: không hardcode "đối tác FI".
   Không kết nối OpenBao. Thao tác chỉ đổi state trong bộ nhớ.
   ============================================================ */

const TODAY = new Date(2026, 7, 26); // 26/08/2026

/* ---------------- helpers ---------------- */
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const d = (iso) => { const [y, m, dd] = iso.split('-').map(Number); return new Date(y, m - 1, dd); };
const fmt = (iso) => iso ? iso.split('-').reverse().join('/') : '—';
const days = (iso) => iso ? Math.round((d(iso) - TODAY) / 86400000) : null;
const nowStamp = () => '26/08/2026 ' + new Date().toTimeString().slice(0, 5);

const ST = {
  DE_NGHI: { l: 'Chờ duyệt', c: 'st-info' },
  DA_DUYET: { l: 'Đã duyệt', c: 'st-info' },
  DA_SINH: { l: 'Đã sinh khóa', c: 'st-info' },
  DA_BAN_GIAO: { l: 'Chờ xác nhận', c: 'st-info' },
  HIEU_LUC: { l: 'Đang hiệu lực', c: 'st-ok' },
  TAM_KHOA: { l: 'Tạm khóa', c: 'st-warn' },
  THU_HOI: { l: 'Thu hồi', c: 'st-bad' },
  HET_HAN: { l: 'Hết hiệu lực', c: 'st-idle' },
};
const stBadge = (k) => `<span class="st ${ST[k].c}">${ST[k].l}</span>`;

/* ============================================================
   DANH MỤC CẤU HÌNH ĐỘNG
   Đây là phần thay thế cho cách chia cứng "Loại A / Loại B".
   Thêm một loại đối tượng mới = thêm một dòng, không sửa code.
   ============================================================ */
const CFG = {
  subjects: [
    { code: 'FI', name: 'Đối tác tài chính', external: true, dossier: 'Hợp đồng / phụ lục', levels: 2, delivery: true, confirm: true, lockLevel: 3, alerts: 'T-90 · T-60 · T-30 · T-7', active: true },
    { code: 'DATA', name: 'Đối tác dữ liệu', external: true, dossier: 'Thỏa thuận chia sẻ dữ liệu', levels: 2, delivery: true, confirm: true, lockLevel: 3, alerts: 'T-90 · T-30 · T-7', active: true },
    { code: 'VENDOR', name: 'Nhà cung cấp dịch vụ', external: true, dossier: 'Hợp đồng mua sắm', levels: 1, delivery: true, confirm: false, lockLevel: 2, alerts: 'T-60 · T-15', active: true },
    { code: 'REGU', name: 'Cơ quan quản lý', external: true, dossier: 'Văn bản yêu cầu', levels: 2, delivery: true, confirm: true, lockLevel: 3, alerts: 'T-90 · T-30', active: false },
    { code: 'SYS', name: 'Hệ thống nội bộ', external: false, dossier: '—', levels: 0, delivery: false, confirm: false, lockLevel: 2, alerts: 'T-15 · T-3', active: true },
    { code: 'APP', name: 'Ứng dụng nội bộ', external: false, dossier: 'Phiếu yêu cầu nội bộ', levels: 1, delivery: false, confirm: false, lockLevel: 2, alerts: 'T-30 · T-7', active: true },
  ],
  keyTypes: [
    { code: 'SIGN', name: 'Khóa ký dữ liệu', engine: 'Transit', algos: 'rsa-2048/3072/4096, ecdsa-p256/384/521, ed25519', maxMonths: 12, auto: false, rotate: 'Theo lệnh — giữ nhiều phiên bản', active: true },
    { code: 'ENC', name: 'Khóa mã hóa', engine: 'Transit', algos: 'aes256-gcm96, rsa-2048/4096, chacha20-poly1305', maxMonths: 12, auto: false, rotate: 'Theo lệnh — giữ nhiều phiên bản', active: true },
    { code: 'CERT', name: 'Chứng thư TLS', engine: 'PKI', algos: 'rsa (2048/3072/4096), ec (256/384/521), ed25519', maxMonths: 12, auto: false, rotate: 'Cấp chứng thư mới trước khi hết hạn', active: true },
    { code: 'DBC', name: 'Credential CSDL', engine: 'Database', algos: '— (engine sinh user/password)', maxMonths: 1, auto: true, rotate: 'Tự động theo TTL của lease', active: true },
    { code: 'KTAB', name: 'Keytab Kerberos', engine: 'KV v2', algos: '— (chỉ lưu tệp như dữ liệu)', maxMonths: 12, auto: false, rotate: 'Thủ công — CMS phải tự nhắc và thay', active: true },
    { code: 'SEC', name: 'API secret', engine: 'KV v2', algos: '— (chỉ lưu chuỗi như dữ liệu)', maxMonths: 6, auto: false, rotate: 'Thủ công — KV v2 KHÔNG tự xoay', active: true },
  ],
};

const SUBJ = (c) => CFG.subjects.find(s => s.code === c) || { code: c, name: c, external: false, levels: 0, delivery: false, confirm: false, lockLevel: 1, dossier: '—', alerts: '—' };
const KT = (c) => CFG.keyTypes.find(k => k.code === c) || { code: c, name: c, engine: '—', algos: '—', maxMonths: 12, auto: false };
const isExt = (k) => SUBJ(k.subj).external;

/* ============================================================
   TỪ ĐIỂN TRƯỜNG API OPENBAO
   Nguồn: openbao.org/api-docs/secret/{transit,pki,databases}
   Mọi trường ở đây là TÊN DO OPENBAO QUY ĐỊNH, không đổi được.
   ============================================================ */
const API_DOC = {
  // --- Transit ---
  name: ['Transit', 'Tên khóa, cũng là đường dẫn <code>/transit/keys/&lt;name&gt;</code>. CMS sinh tự động từ mã khóa nghiệp vụ — không cho gõ tay để tránh trùng và tránh ký tự lạ.'],
  type: ['Transit', 'Thuật toán khóa. Chỉ nhận đúng danh sách OpenBao định nghĩa: <b>aes128-gcm96, aes256-gcm96, chacha20-poly1305, ed25519, ecdsa-p256/p384/p521, rsa-2048/3072/4096, hmac</b>. Gõ sai một ký tự là API trả lỗi.'],
  auto_rotate_period: ['Transit', 'Chu kỳ tự xoay khóa, dạng duration (<code>8760h</code> = 12 tháng). <code>"0"</code> = tắt tự xoay. <span class="warn">OpenBao không nhận giá trị ngắn hơn 1 giờ.</span> CMS suy ra từ trần hiệu lực nghiệp vụ.'],
  exportable: ['Transit', 'Cho phép <b>xuất private key ra khỏi OpenBao</b>. <span class="warn">Bật rồi KHÔNG TẮT ĐƯỢC. Bật là mất cam kết "chìa bí mật không rời hệ thống" của anh Tộ — CMS khóa cứng ở false.</span>'],
  allow_plaintext_backup: ['Transit', 'Cho phép backup khóa ở dạng rõ. <span class="warn">Bật rồi KHÔNG TẮT ĐƯỢC — CMS khóa cứng ở false.</span>'],
  min_encryption_version: ['Transit', 'Phiên bản tối thiểu được dùng để <b>ký / mã hóa</b>. <code>0</code> = dùng bản mới nhất. <b>Đặt giá trị này lớn hơn latest_version chính là cách CMS thực hiện “Tạm khóa Mức 3”</b> — chặn thật, không cần sửa ứng dụng.'],
  min_decryption_version: ['Transit', 'Phiên bản tối thiểu còn được <b>giải mã / xác thực chữ ký</b>. Sau khi xoay khóa và hết cửa sổ song song, CMS nâng số này lên để vô hiệu bản cũ.'],
  deletion_allowed: ['Transit', 'Có cho phép xóa hẳn khóa khỏi OpenBao hay không. Nghiệp vụ chỉ <b>thu hồi</b> chứ không xóa (còn phải giữ để đối soát) → luôn để <code>false</code>.'],
  latest_version: ['Transit', 'Phiên bản mới nhất OpenBao đang giữ. <b>OpenBao trả về, CMS phải lưu lại</b> để đối chiếu với cột “Phiên bản” trên hồ sơ nghiệp vụ.'],
  // --- PKI ---
  role: ['PKI', 'Tên role quy định chứng thư nào được phép cấp. Endpoint cấp là <code>/pki/issue/&lt;role&gt;</code>.'],
  common_name: ['PKI', 'CN của chứng thư — tên miền chính. Bắt buộc, và phải nằm trong <code>allowed_domains</code> của role, nếu không API từ chối.'],
  alt_names: ['PKI', 'Các tên miền phụ (SAN), phân tách bằng dấu phẩy.'],
  ttl: ['PKI', 'Thời hạn chứng thư, dạng duration. <span class="warn">Không được vượt max_ttl của role và max lease TTL của mount.</span>'],
  format: ['PKI', 'Định dạng trả về: <code>pem</code> · <code>der</code> · <code>pem_bundle</code>. CMS dùng <code>pem</code> để bàn giao cho bên nhận.'],
  private_key_format: ['PKI', 'Định dạng private key trả về. Chỉ dùng khi OpenBao sinh cả cặp khóa.'],
  key_type: ['PKI', 'Loại khóa của chứng thư: <code>rsa</code> · <code>ec</code> · <code>ed25519</code>. Khác với Transit — PKI tách thành 2 trường key_type và key_bits.'],
  key_bits: ['PKI', 'Độ dài khóa: RSA 2048/3072/4096, EC 256/384/521.'],
  max_ttl: ['PKI', 'Trần thời hạn của role. <b>Đây chính là chỗ chính sách “tối đa 12 tháng” của anh Tộ được ép xuống kỹ thuật</b> — đặt <code>8760h</code> thì không ai cấp được chứng thư dài hơn.'],
  allowed_domains: ['PKI', 'Danh sách tên miền role được phép cấp. Kèm <code>allow_subdomains</code>.'],
  no_store: ['PKI', 'Không lưu chứng thư đã cấp để tăng throughput. <span class="warn">Đặt true thì KHÔNG THU HỒI được bằng serial — nghiệp vụ cần thu hồi nên phải để false.</span>'],
  serial_number: ['PKI', '<b>OpenBao trả về, bắt buộc phải lưu.</b> PKI của OpenBao chỉ thu hồi được bằng serial. Không lưu serial = không bao giờ thu hồi được chứng thư đó.'],
  expiration: ['PKI', 'Thời điểm hết hạn OpenBao trả về. CMS đối chiếu với ngày hết hạn trên hồ sơ.'],
  issuing_ca: ['PKI', 'Chứng thư CA đã ký. Bàn giao kèm cho bên nhận để họ dựng được chuỗi tin cậy.'],
  ca_chain: ['PKI', 'Chuỗi CA đầy đủ. Bàn giao kèm cùng issuing_ca.'],
  // --- Database ---
  db_name: ['Database', 'Tên kết nối CSDL đã khai trong OpenBao. Một db_name có thể phục vụ nhiều role.'],
  creation_statements: ['Database', 'Câu lệnh SQL OpenBao chạy để tạo user tạm. Do DBA soạn, không phải người dùng nghiệp vụ.'],
  default_ttl: ['Database', 'Thời hạn mặc định của credential. Hết hạn OpenBao tự thu hồi user — đây là lý do Loại credential CSDL không cần quy trình bàn giao.'],
  rotation_period: ['Database', 'Chu kỳ xoay của static role. Chỉ áp cho user cố định, khác với credential động.'],
  lease_id: ['Database', '<b>OpenBao trả về, phải lưu.</b> Muốn thu hồi credential đang phát ra thì gọi revoke theo lease_id này.'],
  lease_duration: ['Database', 'Thời gian còn hiệu lực của lease (giây). CMS dùng để tính thời điểm ứng dụng phải lấy credential mới.'],
  username: ['Database', 'User OpenBao vừa sinh trong CSDL. Lưu lại để đối soát log truy cập của DBA.'],
  // --- KV v2 ---
  path: ['KV v2', 'Đường dẫn lưu dữ liệu: <code>/kv/data/&lt;path&gt;</code>. KV v2 <b>không có schema</b> — lưu gì cũng được.'],
  data: ['KV v2', 'Nội dung tùy ý (chuỗi, tệp keytab mã hóa base64...). <span class="warn">KV v2 KHÔNG có TTL và KHÔNG tự xoay — CMS phải tự nhắc và tự thay.</span>'],
  version: ['KV v2', 'Số phiên bản dữ liệu OpenBao trả về sau khi ghi.'],
};

/* ============================================================
   GIẢI THÍCH CHO TỪNG Ô NHẬP TRÊN FORM
   Gộp luôn: nghĩa nghiệp vụ + trường này có xuống OpenBao không.
   ============================================================ */
const SRC = (t) => `<span class="src">Căn cứ: ${t}</span>`;
const MINE = (t) => `<span class="src mine"><b>Mình đề xuất — chưa ai yêu cầu.</b> ${t}</span>`;

const FORM_DOC = {
  f_subj: ['Loại đối tượng', 'Nhóm đối tượng được cấp khóa: đối tác tài chính, đối tác dữ liệu, nhà cung cấp, hệ thống nội bộ… <br>Chọn cái nào thì <b>quy trình đổi theo cái đó</b>: số cấp duyệt, có bàn giao không, có xác nhận không, mức lock mặc định.<span class="api">Trường nghiệp vụ — OpenBao không biết trường này.</span>' + SRC('anh Tú — “hồ sơ khóa gắn với đối tác”, cộng yêu cầu mô hình động.')],
  f_kt: ['Loại khóa', 'Cần khóa để làm gì: ký dữ liệu, mã hóa, chứng thư TLS, credential CSDL…<br>Quyết định <b>engine OpenBao</b> sẽ dùng và <b>trần hiệu lực</b>.<span class="api">→ Quyết định endpoint gọi xuống: <code>/transit/</code>, <code>/pki/</code>, <code>/database/</code> hay <code>/kv/</code>.</span>' + SRC('bắt buộc kỹ thuật — không biết loại thì không biết gọi engine nào.')],
  f_obj: ['Đối tượng cụ thể', 'Tên đích danh bên sẽ dùng khóa, ví dụ <i>Ngân hàng Đối tác D</i> hoặc <i>Report Service</i>.<span class="api">→ CMS dùng để sinh đường dẫn khóa, gửi xuống trường <code>name</code> (Transit) hoặc <code>role</code> (PKI). Người dùng không gõ tên kỹ thuật.</span>' + SRC('anh Tú — “hồ sơ khóa gắn với đối tác/hợp đồng”.')],
  f_dossier: ['Hồ sơ ràng buộc', 'Hợp đồng / thỏa thuận / phiếu yêu cầu làm căn cứ cấp khóa. <b>Kiểm toán sẽ đối chiếu đúng trường này</b> — không có hồ sơ thì không được cấp khóa.<span class="api">Trường nghiệp vụ — OpenBao không biết.</span>' + SRC('anh Tú — “hồ sơ khóa gắn với đối tác/hợp đồng”.')],
  f_name: ['Tên khóa', 'Tên gợi nhớ cho người dùng đọc. <b>Không phải</b> tên khóa trong OpenBao — tên kỹ thuật do CMS tự sinh để tránh trùng và tránh ký tự lạ.<span class="api">Trường nghiệp vụ — OpenBao không biết.</span>' + SRC('tối thiểu — không có tên thì không tra cứu được.')],
  f_algo: ['Thuật toán', 'Danh sách chỉ hiện đúng giá trị mà engine đang chọn chấp nhận — sai một ký tự là API trả lỗi.<span class="api">→ Gửi thẳng xuống OpenBao: Transit dùng <code>type</code> (<code>rsa-2048</code>, <code>ecdsa-p256</code>…); PKI tách thành <code>key_type</code> + <code>key_bits</code>; Database và KV v2 không có khái niệm này.</span>' + SRC('OpenBao bắt buộc trường <code>type</code>.')],
  f_ttl: ['Thời hạn hiệu lực', 'Khóa sống bao lâu trước khi phải xoay. Trần tối đa 12 tháng theo yêu cầu ATTT.<span class="api">→ Gửi xuống OpenBao thành <code>auto_rotate_period</code> (Transit) hoặc <code>ttl</code> + <code>max_ttl</code> trên role (PKI). Không vượt được trần của loại khóa.</span>' + SRC('anh Tộ yêu cầu #1 — “tối đa 12 tháng, xoay hằng năm”.')],

  f_env: ['Môi trường', 'PROD / UAT / DEV. Tách khóa thật khỏi khóa thử, và lọc khi xuất báo cáo.' + MINE('Bỏ được nếu CMS chỉ quản khóa PROD.')],
  f_contact: ['Đầu mối liên hệ', 'Người phía đối tượng sẽ nhận khóa và ký biên bản. Dùng ở bước bàn giao và khi gửi cảnh báo sắp hết hạn.' + MINE('Suy từ “bàn giao cho FI và xác nhận đã nhận”. Bỏ được nếu đầu mối lấy từ hệ thống quản lý đối tác sẵn có.')],
  f_sys: ['Hệ thống sử dụng khóa', 'Ứng dụng nào sẽ gọi OpenBao để dùng khóa này (ScoreHub Backend, Airflow, Spark…).' + MINE('Cần khi tạm khóa để biết hệ thống nào bị ảnh hưởng. Bỏ được nếu chấp nhận không biết trước tác động.')],
  f_purpose: ['Mục đích sử dụng', 'Mô tả khóa dùng vào việc gì.' + MINE('Kiểm toán thường hỏi tính cần thiết của khóa, nhưng anh Tộ chưa nêu. Bỏ được.')],
  f_lockLevel: ['Mức tạm khóa', '<b>Mức 1</b> chỉ đánh dấu hồ sơ, nghiệp vụ vẫn chạy.<br><b>Mức 2</b> chặn xoay/cấp thêm/bàn giao.<br><b>Mức 3</b> chặn thật mọi thao tác ký và giải mã.<span class="api">→ Mức 3 thực hiện bằng cách đặt <code>min_encryption_version</code> lớn hơn phiên bản hiện tại, hoặc gỡ policy truy cập.</span>'],
  f_lockReason: ['Lý do tạm khóa', 'Bắt buộc nhập. Đây là trường <b>kiểm toán chắc chắn hỏi tới</b> khi rà soát vì sao khóa bị dừng.<span class="api">Trường nghiệp vụ — OpenBao không biết.</span>'],
  f_channel: ['Kênh bàn giao', 'Cách chuyển public key / chứng thư sang bên nhận. <b>Chỉ public key được gửi đi</b>, private key ở lại OpenBao.<span class="warn">Chọn kênh nào còn đang chờ chốt với anh Tộ.</span>'],
  f_confirmType: ['Hình thức xác nhận', 'Bằng chứng bên nhận đã nhận và cài đặt xong khóa.<span class="warn">Câu hỏi D4 chưa chốt: bấm nút trên portal đã đủ giá trị pháp lý chưa, hay bắt buộc biên bản ký đóng dấu.</span>'],
};

const DANGER_FIELDS = { exportable: 1, allow_plaintext_backup: 1, no_store: 1 };

/** (i) đặt ngay cạnh nhãn trường. Nội dung vẽ ở #tipbox nên không bị bảng cắt mất. */
function tt(field) {
  if (!API_DOC[field] && !FORM_DOC[field]) return '';
  return `<i class="tt ${DANGER_FIELDS[field] ? 'danger' : ''}" data-tip="${esc(field)}" tabindex="0">i</i>`;
}

/** Nội dung tooltip: ưu tiên từ điển form, sau đó tới từ điển API. */
function tipHtml(field) {
  if (FORM_DOC[field]) return `<span class="tip-h">${esc(FORM_DOC[field][0])}</span>${FORM_DOC[field][1]}`;
  const a = API_DOC[field];
  if (!a) return '';
  return `<span class="tip-h">${esc(a[0])} · ${esc(field)}</span>${a[1]}`;
}

/** Nhãn form kèm (i) */
const lb = (text, field, req) =>
  `<label>${text}${req ? ' <span class="req-mark">*</span>' : ''}${tt(field)}</label>`;

/* ---- Thông tin nghiệp vụ mở rộng + giá trị OpenBao trả về ---- */
const EXTRA = {
  'KEY-2025-014': { env: 'PROD', sys: 'ScoreHub Backend', contact: 'Ng. Q. Huy · huy@fi-a.example · 0912 345 678', createdAt: '2025-10-20', createdBy: 'nguyenvana', approvedBy: 'lead.tool → giamdoc.dvu', approvedAt: '2025-10-27', ticket: 'YC-2025-088', apiType: 'rsa-2048', latest: 3, minDec: 2, minEnc: 0 },
  'KEY-2025-021': { env: 'PROD', sys: 'Job đối soát hằng ngày', contact: 'Tr. V. Nam · nam@fi-b.example', createdAt: '2025-09-01', createdBy: 'tranthib', approvedBy: 'lead.tool → giamdoc.dvu', approvedAt: '2025-09-10', ticket: 'YC-2025-071', apiType: 'rsa-2048', latest: 2, minDec: 1, minEnc: 0 },
  'KEY-2025-033': { env: 'PROD', sys: 'API Gateway', contact: 'L. T. Mai · mai@fi-c.example', createdAt: '2025-09-25', createdBy: 'levanc', approvedBy: 'lead.tool → attt', approvedAt: '2025-10-01', ticket: 'YC-2025-079', apiType: 'ecdsa-p256', latest: 1, minDec: 1, minEnc: 99 },
  'KEY-2026-002': { env: 'PROD', sys: 'ScoreHub Backend', contact: 'Đ. M. Tuấn · tuan@fi-d.example', createdAt: '2026-08-11', createdBy: 'nguyenvana', approvedBy: 'lead.tool → giamdoc.dvu', approvedAt: '2026-08-18', ticket: 'YC-2026-016', apiType: 'rsa-2048', latest: 1, minDec: 1, minEnc: 0 },
  'KEY-2026-005': { env: 'UAT', sys: 'Kênh SFTP', contact: 'chưa cung cấp', createdAt: '2026-08-24', createdBy: 'tranthib', approvedBy: '—', approvedAt: '', ticket: 'YC-2026-018', apiType: 'rsa-4096', latest: 0, minDec: 0, minEnc: 0 },
  'KEY-2025-041': { env: 'PROD', sys: 'Report Service', contact: 'Tr. V. Nam · nam@fi-b.example', createdAt: '2025-11-20', createdBy: 'tranthib', approvedBy: 'lead.tool → giamdoc.dvu', approvedAt: '2025-11-26', ticket: 'YC-2025-093', apiType: 'ecdsa-p256', latest: 2, minDec: 2, minEnc: 0 },
  'KEY-2024-018': { env: 'PROD', sys: 'API Gateway', contact: 'L. T. Mai · mai@fi-c.example', createdAt: '2024-06-10', createdBy: 'levanc', approvedBy: 'lead.tool', approvedAt: '2024-06-20', ticket: 'YC-2024-044', apiType: 'rsa-2048', latest: 1, minDec: 1, minEnc: 0 },
  'KEY-2024-009': { env: 'PROD', sys: 'ScoreHub Backend', contact: 'Ng. Q. Huy · huy@fi-a.example', createdAt: '2024-10-15', createdBy: 'nguyenvana', approvedBy: 'lead.tool', approvedAt: '2024-10-25', ticket: 'YC-2024-061', apiType: 'rsa-2048', latest: 2, minDec: 3, minEnc: 99 },
  'KEY-2026-004': { env: 'PROD', sys: 'Pipeline chia sẻ dữ liệu', contact: 'P. H. Sơn · son@partner-y.example', createdAt: '2025-10-28', createdBy: 'phamthid', approvedBy: 'lead.tool → giamdoc.dvu', approvedAt: '2025-11-05', ticket: 'YC-2025-090', apiType: 'ecdsa-p256', latest: 1, minDec: 1, minEnc: 0 },
  'KEY-2026-007': { env: 'PROD', sys: 'Cổng API public', contact: 'Bộ phận vận hành CDN X', createdAt: '2026-02-20', createdBy: 'hatang', approvedBy: 'lead.hatang', approvedAt: '2026-02-24', ticket: 'YC-2026-013', pkiRole: 'public-api', cn: 'api.scorehub.example.vn', san: 'www.api.scorehub.example.vn', serial: '4a:1f:9c:22:e0:75:b3:8d:11:6f', keyType: 'rsa', keyBits: 2048 },
  'CRED-DB-001': { env: 'PROD', sys: 'ScoreHub Backend', contact: 'DBA Oracle', createdAt: '2026-08-02', createdBy: 'devops', approvedBy: 'tự động (0 cấp)', approvedAt: '2026-08-02', ticket: '—', dbName: 'scorehub-oracle', leaseId: 'database/creds/scorehub-oracle/7Hk2mQ', leaseDur: '720h', dbUser: 'v-approle-scorehu-9fK3xQ' },
  'CRED-DB-003': { env: 'PROD', sys: 'Airflow', contact: 'DBA PostgreSQL', createdAt: '2026-07-30', createdBy: 'devops', approvedBy: 'tự động (0 cấp)', approvedAt: '2026-07-30', ticket: '—', dbName: 'airflow-pg', leaseId: 'database/creds/airflow-pg/2Bd8nL', leaseDur: '720h', dbUser: 'v-approle-airflow-4Lm7pR' },
  'CRED-RDS-002': { env: 'PROD', sys: 'ScoreHub Backend', contact: 'Vận hành hạ tầng', createdAt: '2026-03-10', createdBy: 'devops', approvedBy: 'tự động (0 cấp)', approvedAt: '2026-03-10', ticket: '—', kvPath: 'scorehub/redis', kvVersion: 12 },
  'CRED-HDFS-004': { env: 'PROD', sys: 'Cụm Spark', contact: 'Vận hành Big Data', createdAt: '2026-02-01', createdBy: 'devops', approvedBy: 'tự động (0 cấp)', approvedAt: '2026-02-01', ticket: '—', kvPath: 'spark/keytab', kvVersion: 4 },
  'CRED-DB-005': { env: 'UAT', sys: 'Report Service', contact: 'DBA MySQL', createdAt: '2026-06-01', createdBy: 'devops', approvedBy: 'lead.tool', approvedAt: '2026-06-03', ticket: 'YCNB-2026/207', dbName: 'report-mysql', leaseId: 'database/creds/report-mysql/5Xz1vT', leaseDur: '4320h', dbUser: 'v-approle-report-8Qw2sN' },
  'CRED-KAFKA-006': { env: 'DEV', sys: 'Ingest Pipeline', contact: 'Vận hành hạ tầng', createdAt: '2026-04-20', createdBy: 'devops', approvedBy: 'lead.tool', approvedAt: '2026-04-22', ticket: 'YCNB-2026/188', kvPath: 'ingest/kafka', kvVersion: 3 },
};
const EX = (id) => EXTRA[id] || { env: 'DEV', sys: '—', contact: '—', createdAt: '', createdBy: '—', approvedBy: '—', approvedAt: '', ticket: '—' };

const hours = (months) => (months * 730) + 'h';

/** Trường API chính của từng engine — dùng cho bảng cấu hình loại khóa. */
const ENGINE_FIELDS = {
  Transit: ['name', 'type', 'auto_rotate_period', 'min_encryption_version'],
  PKI: ['role', 'common_name', 'ttl', 'key_type', 'key_bits', 'serial_number'],
  Database: ['db_name', 'default_ttl', 'lease_id'],
  'KV v2': ['path', 'data', 'version'],
};

/**
 * Suy tham số API từ hồ sơ nghiệp vụ.
 * Đây là điểm mấu chốt: người dùng KHÔNG gõ các trường này,
 * CMS dịch từ lựa chọn nghiệp vụ rồi hiển thị read-only để đối chiếu.
 */
function apiParams(k) {
  const t = KT(k.kt), e = EX(k.id);
  const req = [], res = [];
  const P = (n, v, locked) => req.push({ n, v, locked });
  const R = (n, v) => res.push({ n, v });

  if (t.engine === 'Transit') {
    P('name', k.path.split('/').pop());
    P('type', e.apiType || '—');
    P('auto_rotate_period', hours(t.maxMonths));
    P('exportable', 'false', true);
    P('allow_plaintext_backup', 'false', true);
    P('deletion_allowed', 'false', true);
    R('latest_version', e.latest);
    R('min_decryption_version', e.minDec);
    R('min_encryption_version', e.minEnc + (e.minEnc === 99 ? '  ← đang bị chặn ký (lock Mức 3)' : ''));
  } else if (t.engine === 'PKI') {
    P('role', e.pkiRole || '—');
    P('common_name', e.cn || '—');
    P('alt_names', e.san || '');
    P('ttl', hours(t.maxMonths));
    P('format', 'pem');
    P('key_type', e.keyType || '—');
    P('key_bits', e.keyBits || '—');
    P('max_ttl', hours(t.maxMonths) + '  (đặt trên role)');
    P('no_store', 'false', true);
    R('serial_number', e.serial || '—');
    R('expiration', fmt(k.exp));
    R('issuing_ca', '(PEM chứng thư CA)');
    R('ca_chain', '(PEM chuỗi CA)');
  } else if (t.engine === 'Database') {
    P('db_name', e.dbName || '—');
    P('default_ttl', hours(t.maxMonths));
    P('max_ttl', hours(t.maxMonths));
    P('creation_statements', '(do DBA soạn, không sửa trên CMS)', true);
    R('lease_id', e.leaseId || '—');
    R('lease_duration', e.leaseDur || '—');
    R('username', e.dbUser || '—');
  } else {
    P('path', 'kv/data/' + (e.kvPath || '—'));
    P('data', '(nội dung tùy ý — KV v2 không có schema)');
    R('version', e.kvVersion || '—');
  }
  return { req, res, engine: t.engine };
}

/** Quy trình áp dụng được suy ra từ cấu hình, không viết cứng ở đâu cả. */
function flowOf(subjCode) {
  const s = SUBJ(subjCode);
  const steps = ['Đề nghị'];
  steps.push(s.levels === 0 ? 'Tự động (không cần duyệt)' : `Duyệt ${s.levels} cấp`);
  steps.push('Sinh khóa trên OpenBao');
  if (s.delivery) steps.push('Bàn giao');
  if (s.confirm) steps.push('Đối tượng xác nhận');
  steps.push('Kích hoạt & theo dõi hạn');
  return steps;
}

const subjTag = (code) => {
  const s = SUBJ(code);
  return `<span class="tag-type ${s.external ? 'tag-B' : 'tag-A'}">${esc(s.name)}</span>`;
};

function expCell(iso, status) {
  if (!iso) return '<span class="muted">—</span>';
  const n = days(iso);
  if (status === 'THU_HOI' || status === 'HET_HAN') return `<span class="muted">${fmt(iso)}</span>`;
  let cls = '', tail = '';
  if (n < 0) { cls = 'st st-idle'; tail = ' (quá hạn)'; }
  else if (n <= 30) { cls = 'st st-bad'; tail = ` (còn ${n} ngày)`; }
  else if (n <= 90) { cls = 'st st-warn'; tail = ` (còn ${n} ngày)`; }
  else { return `${fmt(iso)} <span class="muted">(còn ${n} ngày)</span>`; }
  return `<span class="${cls}">${fmt(iso)}${tail}</span>`;
}

/* ---------------- DỮ LIỆU GIẢ LẬP ---------------- */
const DB = {
  keys: [
    { id: 'KEY-2025-014', name: 'Khóa ký dữ liệu điểm tín dụng', subj: 'FI', obj: 'Ngân hàng Đối tác A', kt: 'SIGN', dossier: 'HĐ-2025/SCOREHUB/012', algo: 'RSA-2048', purpose: 'Ký dữ liệu trả về đối tác', ver: 'v3', status: 'HIEU_LUC', eff: '2025-11-02', exp: '2026-11-02', owner: 'Nguyễn Văn A', path: 'transit/keys/scorehub-fi-a', lockReason: '' },
    { id: 'KEY-2025-021', name: 'Khóa mã hóa file đối soát', subj: 'FI', obj: 'Công ty Tài chính B', kt: 'ENC', dossier: 'HĐ-2025/SCOREHUB/019', algo: 'RSA-2048', purpose: 'Mã hóa file đối soát hằng ngày', ver: 'v2', status: 'HIEU_LUC', eff: '2025-09-15', exp: '2026-09-15', owner: 'Trần Thị B', path: 'transit/keys/scorehub-fi-b', lockReason: '' },
    { id: 'KEY-2025-033', name: 'Khóa ký API truy vấn điểm', subj: 'FI', obj: 'Ngân hàng Đối tác C', kt: 'SIGN', dossier: 'HĐ-2025/SCOREHUB/027', algo: 'EC P-256', purpose: 'Ký request/response API', ver: 'v1', status: 'TAM_KHOA', eff: '2025-10-08', exp: '2026-10-08', owner: 'Lê Văn C', path: 'transit/keys/scorehub-fi-c', lockReason: 'Nghi ngờ lộ khóa — đang xác minh theo PYC-2026-0871' },
    { id: 'KEY-2026-002', name: 'Khóa ký dữ liệu điểm tín dụng', subj: 'FI', obj: 'Ngân hàng Đối tác D', kt: 'SIGN', dossier: 'HĐ-2026/SCOREHUB/003', algo: 'RSA-2048', purpose: 'Ký dữ liệu trả về đối tác', ver: 'v1', status: 'DA_BAN_GIAO', eff: '', exp: '2027-08-20', owner: 'Nguyễn Văn A', path: 'transit/keys/scorehub-fi-d', lockReason: '' },
    { id: 'KEY-2026-005', name: 'Khóa mã hóa kênh SFTP', subj: 'FI', obj: 'Công ty Tài chính E', kt: 'ENC', dossier: 'HĐ-2026/SCOREHUB/008', algo: 'RSA-4096', purpose: 'Mã hóa kênh truyền SFTP', ver: '—', status: 'DE_NGHI', eff: '', exp: '', owner: 'Trần Thị B', path: '—', lockReason: '' },
    { id: 'KEY-2025-041', name: 'Khóa ký báo cáo định kỳ', subj: 'FI', obj: 'Công ty Tài chính B', kt: 'SIGN', dossier: 'HĐ-2025/SCOREHUB/019', algo: 'EC P-256', purpose: 'Ký báo cáo tháng gửi đối tác', ver: 'v2', status: 'HIEU_LUC', eff: '2025-11-30', exp: '2026-11-30', owner: 'Trần Thị B', path: 'transit/keys/scorehub-fi-b-rpt', lockReason: '' },
    { id: 'KEY-2024-018', name: 'Khóa ký API truy vấn điểm (cũ)', subj: 'FI', obj: 'Ngân hàng Đối tác C', kt: 'SIGN', dossier: 'HĐ-2024/SCOREHUB/031', algo: 'RSA-2048', purpose: 'Ký request/response API', ver: 'v1', status: 'HET_HAN', eff: '2024-06-30', exp: '2026-06-30', owner: 'Lê Văn C', path: 'transit/keys/scorehub-fi-c-old', lockReason: '' },
    { id: 'KEY-2024-009', name: 'Khóa ký dữ liệu điểm tín dụng (v2)', subj: 'FI', obj: 'Ngân hàng Đối tác A', kt: 'SIGN', dossier: 'HĐ-2024/SCOREHUB/012', algo: 'RSA-2048', purpose: 'Ký dữ liệu trả về đối tác', ver: 'v2', status: 'THU_HOI', eff: '2024-11-02', exp: '2025-11-02', owner: 'Nguyễn Văn A', path: 'transit/keys/scorehub-fi-a', lockReason: 'Thu hồi theo lịch xoay khóa 2025' },

    { id: 'KEY-2026-004', name: 'Khóa ký gói dữ liệu chia sẻ', subj: 'DATA', obj: 'Đối tác dữ liệu Y', kt: 'SIGN', dossier: 'TT-CSDL-2026/014', algo: 'EC P-256', purpose: 'Ký gói dữ liệu trao đổi hai chiều', ver: 'v1', status: 'HIEU_LUC', eff: '2025-11-10', exp: '2026-11-10', owner: 'Phạm Thị D', path: 'transit/keys/share-y', lockReason: '' },
    { id: 'KEY-2026-007', name: 'Chứng thư TLS cổng API công khai', subj: 'VENDOR', obj: 'Nhà cung cấp CDN X', kt: 'CERT', dossier: 'HĐ-MS-2026/041', algo: 'RSA-2048', purpose: 'TLS cho cổng API public', ver: 'v1', status: 'HIEU_LUC', eff: '2026-03-01', exp: '2027-03-01', owner: 'Hạ tầng', path: 'pki/issue/public-api', lockReason: '' },

    { id: 'CRED-DB-001', name: 'Kết nối Oracle ScoreHub', subj: 'SYS', obj: 'ScoreHub Backend', kt: 'DBC', dossier: '—', algo: '—', purpose: 'ScoreHub Backend → Oracle', ver: 'v27', status: 'HIEU_LUC', eff: '2026-08-02', exp: '2026-09-01', owner: 'DevOps', path: 'database/creds/scorehub-oracle', lockReason: '' },
    { id: 'CRED-DB-003', name: 'Kết nối PostgreSQL Airflow', subj: 'SYS', obj: 'Airflow', kt: 'DBC', dossier: '—', algo: '—', purpose: 'Airflow → PostgreSQL', ver: 'v9', status: 'HIEU_LUC', eff: '2026-07-30', exp: '2026-08-29', owner: 'DevOps', path: 'database/creds/airflow-pg', lockReason: '' },
    { id: 'CRED-RDS-002', name: 'Kết nối Redis cache', subj: 'SYS', obj: 'ScoreHub Backend', kt: 'SEC', dossier: '—', algo: '—', purpose: 'ScoreHub Backend → Redis', ver: 'v12', status: 'HIEU_LUC', eff: '2026-03-10', exp: '2026-09-10', owner: 'DevOps', path: 'kv/scorehub/redis', lockReason: '' },
    { id: 'CRED-HDFS-004', name: 'Keytab Kerberos cho Spark', subj: 'SYS', obj: 'Cụm Spark', kt: 'KTAB', dossier: '—', algo: '—', purpose: 'Spark job → HDFS', ver: 'v4', status: 'TAM_KHOA', eff: '2026-02-01', exp: '2027-02-01', owner: 'DevOps', path: 'kv/spark/keytab', lockReason: 'Cụm Spark đang bảo trì — tạm dừng cấp phát' },
    { id: 'CRED-DB-005', name: 'Kết nối MySQL báo cáo', subj: 'APP', obj: 'Report Service', kt: 'DBC', dossier: 'YCNB-2026/207', algo: '—', purpose: 'Report service → MySQL', ver: 'v15', status: 'HIEU_LUC', eff: '2026-06-01', exp: '2026-12-01', owner: 'DevOps', path: 'database/creds/report-mysql', lockReason: '' },
    { id: 'CRED-KAFKA-006', name: 'SASL Kafka ingest', subj: 'APP', obj: 'Ingest Pipeline', kt: 'SEC', dossier: 'YCNB-2026/188', algo: '—', purpose: 'Ingest pipeline → Kafka', ver: 'v3', status: 'HIEU_LUC', eff: '2026-04-20', exp: '2026-10-20', owner: 'DevOps', path: 'kv/ingest/kafka', lockReason: '' },
  ],

  requests: [
    { id: 'YC-2026-018', kind: 'Cấp mới', keyName: 'Khóa mã hóa kênh SFTP', subj: 'FI', obj: 'Công ty Tài chính E', algo: 'RSA-4096', by: 'Trần Thị B', at: '2026-08-24', status: 'DE_NGHI', step: 1, note: '' },
    { id: 'YC-2026-017', kind: 'Xoay khóa', keyName: 'Khóa mã hóa file đối soát (KEY-2025-021)', subj: 'FI', obj: 'Công ty Tài chính B', algo: 'RSA-2048', by: 'Hệ thống (cảnh báo T-30)', at: '2026-08-16', status: 'DE_NGHI', step: 2, note: 'Sinh tự động từ lịch xoay khóa hằng năm' },
    { id: 'YC-2026-016', kind: 'Cấp mới', keyName: 'Khóa ký dữ liệu điểm tín dụng (KEY-2026-002)', subj: 'FI', obj: 'Ngân hàng Đối tác D', algo: 'RSA-2048', by: 'Nguyễn Văn A', at: '2026-08-11', status: 'DA_SINH', step: 0, note: '' },
    { id: 'YC-2026-015', kind: 'Thu hồi', keyName: 'Khóa ký API truy vấn điểm (KEY-2025-033)', subj: 'FI', obj: 'Ngân hàng Đối tác C', algo: 'EC P-256', by: 'Lê Văn C', at: '2026-08-19', status: 'DE_NGHI', step: 2, note: 'Kèm PYC-2026-0871 nghi ngờ lộ khóa' },
    { id: 'YC-2026-013', kind: 'Cấp mới', keyName: 'Chứng thư TLS cổng API công khai', subj: 'VENDOR', obj: 'Nhà cung cấp CDN X', algo: 'RSA-2048', by: 'Hạ tầng', at: '2026-02-20', status: 'DA_SINH', step: 0, note: 'Chỉ 1 cấp duyệt theo cấu hình loại đối tượng' },
    { id: 'YC-2026-014', kind: 'Cấp mới', keyName: 'Khóa ký dữ liệu bổ sung', subj: 'FI', obj: 'Ngân hàng Đối tác A', algo: 'RSA-2048', by: 'Nguyễn Văn A', at: '2026-07-30', status: 'TU_CHOI', step: 0, note: 'Chưa có phụ lục hợp đồng cho phạm vi mới' },
  ],

  deliveries: [
    { id: 'BG-2026-010', keyId: 'KEY-2025-021', subj: 'FI', obj: 'Công ty Tài chính B', channel: 'Chưa chọn', sentAt: '', dueAt: '2026-09-05', status: 'CHO_BAN_GIAO', receiver: '', note: 'Khóa v3 sẽ sinh sau khi YC-2026-017 được duyệt' },
    { id: 'BG-2026-009', keyId: 'KEY-2026-002', subj: 'FI', obj: 'Ngân hàng Đối tác D', channel: 'Portal đối tượng', sentAt: '2026-08-20', dueAt: '2026-08-27', status: 'CHO_XAC_NHAN', receiver: '', note: '' },
    { id: 'BG-2026-006', keyId: 'KEY-2026-007', subj: 'VENDOR', obj: 'Nhà cung cấp CDN X', channel: 'Email ký số', sentAt: '2026-02-26', dueAt: '2026-03-01', status: 'DA_BAN_GIAO_KXN', receiver: '', note: 'Loại đối tượng này không yêu cầu bước xác nhận' },
    { id: 'BG-2026-008', keyId: 'KEY-2025-041', subj: 'FI', obj: 'Công ty Tài chính B', channel: 'Email ký số', sentAt: '2026-08-05', dueAt: '2026-08-12', status: 'DA_XAC_NHAN', receiver: 'Phòng CNTT — 12/08/2026', note: '' },
    { id: 'BG-2026-007', keyId: 'KEY-2025-014', subj: 'FI', obj: 'Ngân hàng Đối tác A', channel: 'SFTP + biên bản giấy', sentAt: '2025-10-28', dueAt: '2025-11-02', status: 'DA_XAC_NHAN', receiver: 'Ban CNTT — 01/11/2025', note: '' },
  ],

  audit: [
    { at: '26/08/2026 09:14', user: 'hangttm9', act: 'Xem danh mục khóa', obj: '—', reason: '', ip: '10.60.12.44' },
    { at: '24/08/2026 16:02', user: 'tranthib', act: 'Tạo yêu cầu cấp khóa', obj: 'YC-2026-018', reason: 'Tích hợp mới với Công ty Tài chính E', ip: '10.60.12.51' },
    { at: '20/08/2026 10:47', user: 'nguyenvana', act: 'Bàn giao khóa', obj: 'BG-2026-009 / KEY-2026-002', reason: 'Theo YC-2026-016', ip: '10.60.12.33' },
    { at: '19/08/2026 08:20', user: 'levanc', act: 'TẠM KHÓA', obj: 'KEY-2025-033', reason: 'Nghi ngờ lộ khóa — PYC-2026-0871', ip: '10.60.12.77' },
    { at: '16/08/2026 00:05', user: 'system', act: 'Cảnh báo hết hạn T-30', obj: 'KEY-2025-021', reason: 'Lịch xoay khóa hằng năm', ip: '—' },
    { at: '12/08/2026 14:31', user: 'FI-B', act: 'Xác nhận đã nhận khóa', obj: 'BG-2026-008', reason: '', ip: 'portal' },
    { at: '05/08/2026 09:00', user: 'tranthib', act: 'Sinh khóa trên OpenBao', obj: 'KEY-2025-041 v2', reason: 'Xoay khóa định kỳ', ip: '10.60.12.51' },
    { at: '30/07/2026 11:12', user: 'lead.tool', act: 'Từ chối yêu cầu', obj: 'YC-2026-014', reason: 'Chưa có phụ lục hợp đồng', ip: '10.60.12.10' },
  ],
};

let SHOW_NOTES = true;

/* ---------------- MENU ---------------- */
const NAV = [
  { group: 'Chức năng hiện có của SQLWF' },
  { icon: 'fa-database', label: 'Quản lý dữ liệu', disabled: true },
  { icon: 'fa-check-double', label: 'Data Quality', disabled: true },
  { icon: 'fa-book', label: 'Data Dictionary', disabled: true },
  { icon: 'fa-project-diagram', label: 'Data Lineage', disabled: true },
  { icon: 'fa-handshake', label: 'Quản lý đối tác', disabled: true },
  { icon: 'fa-users-cog', label: 'Quản trị hệ thống', disabled: true },
  { group: 'Quản trị khóa (đề xuất mới)', isNew: true },
  { icon: 'fa-chart-pie', label: 'Tổng quan', route: 'dashboard' },
  { icon: 'fa-key', label: 'Danh mục khóa', route: 'keys' },
  { icon: 'fa-inbox', label: 'Yêu cầu & phê duyệt', route: 'requests' },
  { icon: 'fa-paper-plane', label: 'Bàn giao khóa', route: 'delivery' },
  { icon: 'fa-sync-alt', label: 'Lịch xoay khóa', route: 'rotation' },
  { icon: 'fa-sliders-h', label: 'Cấu hình danh mục', route: 'config' },
  { icon: 'fa-file-alt', label: 'Nhật ký & báo cáo', route: 'audit' },
];

const TITLES = {
  dashboard: 'Tổng quan', keys: 'Danh mục khóa', requests: 'Yêu cầu & phê duyệt',
  delivery: 'Bàn giao khóa', rotation: 'Lịch xoay khóa', config: 'Cấu hình danh mục',
  audit: 'Nhật ký & báo cáo',
};

function renderNav() {
  const cur = route();
  $('#nav').innerHTML = NAV.map(n => {
    if (n.group) return `<li class="nav-group ${n.isNew ? 'new' : ''}">${esc(n.group)}</li>`;
    if (n.disabled) return `<li><a class="disabled-link"><i class="fa ${n.icon}"></i>${esc(n.label)}</a></li>`;
    return `<li><a href="#/${n.route}" class="${cur === n.route ? 'active' : ''}"><i class="fa ${n.icon}"></i>${esc(n.label)}</a></li>`;
  }).join('');
}

function note(text, kind) {
  if (!SHOW_NOTES) return '';
  return `<div class="hint ${kind || ''}"><b><i class="fa fa-comment-dots"></i> Ghi chú nghiệp vụ:</b> ${text}</div>`;
}

/* ---------------- VIEWS ---------------- */
function viewDashboard() {
  const k = DB.keys;
  const active = k.filter(x => x.status === 'HIEU_LUC');
  const soon = active.filter(x => x.exp && days(x.exp) <= 90);
  const urgent = active.filter(x => x.exp && days(x.exp) <= 30);
  const locked = k.filter(x => x.status === 'TAM_KHOA');
  const pending = DB.requests.filter(r => r.status === 'DE_NGHI');
  const waitCf = DB.deliveries.filter(x => x.status === 'CHO_XAC_NHAN');
  const nExt = k.filter(isExt).length;

  const bySubj = CFG.subjects.filter(s => s.active).map(s => {
    const n = k.filter(x => x.subj === s.code).length;
    return `<tr><td>${subjTag(s.code)}</td><td class="text-center">${n}</td>
      <td>${s.external ? '<span class="st st-info">Bên ngoài tổ chức</span>' : '<span class="st st-idle">Nội bộ</span>'}</td>
      <td class="muted" style="font-size:12.5px">${esc(flowOf(s.code).join('  →  '))}</td></tr>`;
  }).join('');

  const rows = soon.sort((a, b) => days(a.exp) - days(b.exp)).map((x, i) => `
    <tr>
      <td class="text-center">${i + 1}</td>
      <td class="mono">${esc(x.id)}</td>
      <td>${esc(x.name)}</td>
      <td>${subjTag(x.subj)}<div class="muted" style="font-size:12px">${esc(x.obj)}</div></td>
      <td class="nowrap">${expCell(x.exp, x.status)}</td>
      <td class="actions nowrap"><a data-act="detail" data-id="${x.id}">Chi tiết</a><a data-act="rotate" data-id="${x.id}">Xoay khóa</a></td>
    </tr>`).join('');

  return `
  ${note('Màn hình này trả lời câu hỏi của kiểm toán: <b>“có bao nhiêu khóa, cấp cho ai, cái nào sắp hết hạn, cái nào đang bị khóa”</b> — thứ OpenBao không tự tổng hợp được.')}
  <div class="tiles">
    <div class="tile"><div class="t-label">Tổng số khóa đang quản lý</div><div class="t-value">${k.length}</div><div class="t-sub">${nExt} bên ngoài · ${k.length - nExt} nội bộ</div></div>
    <div class="tile ok"><div class="t-label">Đang hiệu lực</div><div class="t-value">${active.length}</div><div class="t-sub">tuân thủ trần 12 tháng</div></div>
    <div class="tile warn"><div class="t-label">Sắp hết hạn ≤ 90 ngày</div><div class="t-value">${soon.length}</div><div class="t-sub">trong đó ${urgent.length} khóa ≤ 30 ngày</div></div>
    <div class="tile bad"><div class="t-label">Đang tạm khóa</div><div class="t-value">${locked.length}</div><div class="t-sub">cần xử lý dứt điểm</div></div>
    <div class="tile"><div class="t-label">Yêu cầu chờ duyệt</div><div class="t-value">${pending.length}</div><div class="t-sub"><a href="#/requests">Xem hàng đợi</a></div></div>
    <div class="tile warn"><div class="t-label">Chờ xác nhận</div><div class="t-value">${waitCf.length}</div><div class="t-sub"><a href="#/delivery">Xem bàn giao</a></div></div>
  </div>

  ${urgent.length ? `<div class="hint bad"><b><i class="fa fa-exclamation-triangle"></i> Cảnh báo đỏ:</b> ${urgent.length} khóa còn dưới 30 ngày hiệu lực. Với các loại đối tượng có bước bàn giao, cần khởi động quy trình ngay vì bên nhận cần thời gian cài đặt.</div>` : ''}

  <div class="card">
    <div class="card-header">Phân bổ khóa theo loại đối tượng &amp; quy trình áp dụng</div>
    <div class="card-body font-size-14">
      ${note('Cột <b>Quy trình áp dụng</b> không viết cứng ở đâu cả — nó được suy ra từ cấu hình ở màn <a href="#/config">Cấu hình danh mục</a>. Đổi cấu hình thì cột này đổi theo ngay.')}
      <div class="ui-table"><table>
        <thead><tr><th style="width:220px">Loại đối tượng</th><th style="width:90px">Số khóa</th><th style="width:180px">Phạm vi</th><th>Quy trình áp dụng</th></tr></thead>
        <tbody>${bySubj}</tbody>
      </table></div>
    </div>
  </div>

  <div class="card">
    <div class="card-header">Khóa sắp hết hạn trong 90 ngày</div>
    <div class="card-body font-size-14">
      <div class="ui-table"><table>
        <thead><tr><th style="width:60px">STT</th><th>Mã khóa</th><th>Tên khóa</th><th>Đối tượng sử dụng</th><th>Ngày hết hạn</th><th style="width:170px">Thao tác</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="6" class="text-center muted">Không có dữ liệu</td></tr>'}</tbody>
      </table></div>
    </div>
  </div>`;
}

function viewKeys() {
  const f = window.__kf || { q: '', subj: '', kt: '', status: '', env: '' };
  const list = DB.keys.filter(x =>
    (!f.q || (x.id + x.name + x.obj).toLowerCase().includes(f.q.toLowerCase())) &&
    (!f.subj || x.subj === f.subj) && (!f.kt || x.kt === f.kt) &&
    (!f.env || EX(x.id).env === f.env) &&
    (!f.status || x.status === f.status));

  const rows = list.map((x, i) => `
    <tr>
      <td class="text-center">${i + 1}</td>
      <td class="mono">${esc(x.id)}</td>
      <td>${esc(x.name)}<div class="muted" style="font-size:12px">${esc(x.purpose)}</div>
          <div style="font-size:11.5px;margin-top:3px"><span class="env-badge env-${esc(EX(x.id).env)}">${esc(EX(x.id).env)}</span>
          <span class="muted"> · ${esc(EX(x.id).sys)}</span></div></td>
      <td>${subjTag(x.subj)}<div style="font-size:12.5px;margin-top:3px">${esc(x.obj)}</div>
          <div class="muted" style="font-size:11.5px">${esc(x.dossier)}</div></td>
      <td class="nowrap">${esc(KT(x.kt).name)}<div class="muted" style="font-size:12px">${esc(x.algo)} · ${esc(x.ver)}</div>
          <div class="muted" style="font-size:11.5px">engine ${esc(KT(x.kt).engine)}</div></td>
      <td class="nowrap">${expCell(x.exp, x.status)}</td>
      <td>${stBadge(x.status)}${x.lockReason ? `<div class="muted" style="font-size:11.5px;max-width:190px">${esc(x.lockReason)}</div>` : ''}</td>
      <td class="actions nowrap">
        <a data-act="detail" data-id="${x.id}">Chi tiết</a>
        ${x.status === 'HIEU_LUC' ? `<a data-act="lock" data-id="${x.id}">Tạm khóa</a>` : ''}
        ${x.status === 'TAM_KHOA' ? `<a data-act="unlock" data-id="${x.id}">Mở khóa</a>` : ''}
        ${(x.status === 'HIEU_LUC' || x.status === 'TAM_KHOA') ? `<a data-act="revoke" data-id="${x.id}" class="danger">Thu hồi</a>` : ''}
      </td>
    </tr>`).join('');

  return `
  ${note('Đây là <b>“quyển sổ cái”</b> OpenBao không có. Hai bộ lọc <b>Loại đối tượng</b> và <b>Loại khóa</b> được nạp từ danh mục cấu hình — thêm loại mới ở màn <a href="#/config">Cấu hình danh mục</a> thì hai dropdown này tự có thêm lựa chọn.')}
  <div class="card">
    <div class="card-header">Thông tin tìm kiếm</div>
    <div class="card-body font-size-14">
      <div class="row">
        <div class="col-md-3 form-group"><label>Mã khóa / tên khóa / đối tượng</label>
          <input class="form-control" id="fq" value="${esc(f.q)}" placeholder="Nhập từ khóa..."></div>
        <div class="col-md-3 form-group"><label>Loại đối tượng</label>
          <select class="form-control" id="fsubj"><option value="">Tất cả</option>
            ${CFG.subjects.filter(s => s.active).map(s => `<option value="${s.code}" ${f.subj === s.code ? 'selected' : ''}>${esc(s.name)}</option>`).join('')}
          </select></div>
        <div class="col-md-3 form-group"><label>Loại khóa</label>
          <select class="form-control" id="fkt"><option value="">Tất cả</option>
            ${CFG.keyTypes.filter(s => s.active).map(s => `<option value="${s.code}" ${f.kt === s.code ? 'selected' : ''}>${esc(s.name)}</option>`).join('')}
          </select></div>
        <div class="col-md-3 form-group"><label>Trạng thái</label>
          <select class="form-control" id="fstatus"><option value="">Tất cả</option>
            ${Object.keys(ST).map(s => `<option value="${s}" ${f.status === s ? 'selected' : ''}>${ST[s].l}</option>`).join('')}
          </select></div>
        <div class="col-md-3 form-group"><label>Môi trường</label>
          <select class="form-control" id="fenv"><option value="">Tất cả</option>
            ${['PROD', 'UAT', 'DEV'].map(v => `<option value="${v}" ${f.env === v ? 'selected' : ''}>${v}</option>`).join('')}
          </select></div>
      </div>
      <div class="text-center mt-3">
        <button class="btn btn-secondary" id="btnReset"><i class="fa fa-times"></i> Bỏ tìm kiếm</button>
        <button class="btn btn-primary ml-3" id="btnSearch"><i class="fa fa-search"></i> Tìm kiếm</button>
        <button class="btn btn-primary ml-3" data-act="newreq"><i class="fa fa-plus"></i> Tạo yêu cầu cấp khóa</button>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-header">Kết quả tra cứu</div>
    <div class="card-body font-size-14">
      <div class="ui-table"><table>
        <thead><tr>
          <th style="width:55px">STT</th><th>Mã khóa</th><th>Tên khóa</th>
          <th>Đối tượng sử dụng / hồ sơ</th><th>Loại khóa</th><th>Ngày hết hạn</th><th>Trạng thái</th><th style="width:210px">Thao tác</th>
        </tr></thead>
        <tbody>${rows || '<tr><td colspan="8" class="text-center muted">Không có dữ liệu</td></tr>'}</tbody>
      </table></div>
      <div class="paginator">
        <span>Bản ghi 1 đến ${list.length} trong ${list.length} bản ghi</span>
        <span class="pages"><span class="cur">1</span></span>
      </div>
    </div>
  </div>`;
}

function viewRequests() {
  const rows = DB.requests.map((r, i) => {
    const s = SUBJ(r.subj);
    const lv = r.status === 'DE_NGHI'
      ? (s.levels === 0 ? 'Không cần duyệt' : `Chờ duyệt cấp ${r.step}/${s.levels}`)
      : (r.status === 'TU_CHOI' ? 'Từ chối' : 'Đã duyệt · đã sinh khóa');
    return `
    <tr>
      <td class="text-center">${i + 1}</td>
      <td class="mono">${esc(r.id)}</td>
      <td>${esc(r.kind)}</td>
      <td>${esc(r.keyName)}<div style="font-size:12.5px;margin-top:3px">${subjTag(r.subj)} ${esc(r.obj)}</div></td>
      <td class="nowrap">${esc(r.by)}<div class="muted" style="font-size:12px">${fmt(r.at)}</div></td>
      <td><span class="st ${r.status === 'DE_NGHI' ? 'st-info' : r.status === 'TU_CHOI' ? 'st-bad' : 'st-ok'}">${esc(lv)}</span>
        <div class="muted" style="font-size:11.5px">quy trình ${esc(s.levels)} cấp theo loại đối tượng</div>
        ${r.note ? `<div class="muted" style="font-size:11.5px;max-width:230px">${esc(r.note)}</div>` : ''}</td>
      <td class="actions nowrap">
        ${r.status === 'DE_NGHI' ? `<a data-act="approve" data-id="${r.id}">Duyệt</a><a data-act="reject" data-id="${r.id}" class="danger">Từ chối</a>` : '<span class="muted">—</span>'}
      </td>
    </tr>`;
  }).join('');

  return `
  ${note('Số cấp duyệt <b>không cố định</b> — mỗi loại đối tượng có số cấp riêng, lấy từ cấu hình. Ví dụ <b>Đối tác tài chính</b> đang là 2 cấp, <b>Nhà cung cấp dịch vụ</b> chỉ 1 cấp, <b>Hệ thống nội bộ</b> không cần duyệt. Con số cụ thể vẫn <b class="req-mark">chờ lãnh đạo chốt</b>.')}
  <div class="card">
    <div class="card-header">Hàng đợi yêu cầu</div>
    <div class="card-body font-size-14">
      <div class="text-right mb-3"><button class="btn btn-primary" data-act="newreq"><i class="fa fa-plus"></i> Tạo yêu cầu cấp khóa</button></div>
      <div class="ui-table"><table>
        <thead><tr><th style="width:55px">STT</th><th>Mã yêu cầu</th><th>Loại yêu cầu</th><th>Khóa / đối tượng</th><th>Người đề nghị</th><th>Trạng thái duyệt</th><th style="width:150px">Thao tác</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
    </div>
  </div>`;
}

function viewDelivery() {
  const DS = {
    CHO_BAN_GIAO: { l: 'Chờ bàn giao', c: 'st-idle' },
    CHO_XAC_NHAN: { l: 'Chờ xác nhận', c: 'st-warn' },
    DA_BAN_GIAO_KXN: { l: 'Đã bàn giao (không cần xác nhận)', c: 'st-ok' },
    DA_XAC_NHAN: { l: 'Đã xác nhận', c: 'st-ok' },
  };
  const rows = DB.deliveries.map((x, i) => {
    const late = x.status === 'CHO_XAC_NHAN' && days(x.dueAt) <= 3;
    return `
    <tr>
      <td class="text-center">${i + 1}</td>
      <td class="mono">${esc(x.id)}</td>
      <td class="mono">${esc(x.keyId)}</td>
      <td>${subjTag(x.subj)}<div style="font-size:12.5px;margin-top:3px">${esc(x.obj)}</div></td>
      <td>${esc(x.channel)}</td>
      <td class="nowrap">${x.sentAt ? fmt(x.sentAt) : '<span class="muted">chưa gửi</span>'}</td>
      <td class="nowrap">${SUBJ(x.subj).confirm ? (x.dueAt ? fmt(x.dueAt) : '—') : '<span class="muted">không yêu cầu</span>'}${late ? ` <span class="st st-bad">còn ${days(x.dueAt)} ngày</span>` : ''}</td>
      <td><span class="st ${DS[x.status].c}">${DS[x.status].l}</span>${x.receiver ? `<div class="muted" style="font-size:11.5px">${esc(x.receiver)}</div>` : ''}
        ${x.note ? `<div class="muted" style="font-size:11.5px;max-width:200px">${esc(x.note)}</div>` : ''}</td>
      <td class="actions nowrap">
        ${x.status === 'CHO_BAN_GIAO' ? `<a data-act="send" data-id="${x.id}">Bàn giao</a>` : ''}
        ${x.status === 'CHO_XAC_NHAN' ? `<a data-act="confirm" data-id="${x.id}">Ghi nhận xác nhận</a><a data-act="remind" data-id="${x.id}">Nhắc</a>` : ''}
        ${(x.status === 'DA_XAC_NHAN' || x.status === 'DA_BAN_GIAO_KXN') ? `<a data-act="bienban" data-id="${x.id}">Xem biên bản</a>` : ''}
      </td>
    </tr>`;
  }).join('');

  const withDelivery = CFG.subjects.filter(s => s.active && s.delivery).map(s => s.name).join(', ');
  const without = CFG.subjects.filter(s => s.active && !s.delivery).map(s => s.name).join(', ');

  return `
  ${note(`Phần <b>“delivery”</b> anh Tú nhờ làm rõ. Bước bàn giao <b>không gắn cứng với đối tác tài chính</b> — nó bật/tắt theo cờ cấu hình của từng loại đối tượng.<br>
    Đang bật bàn giao: <b>${esc(withDelivery)}</b>. Không bàn giao: <b>${esc(without)}</b>.`)}
  ${SHOW_NOTES ? `<div class="hint warn"><b><i class="fa fa-question-circle"></i> Ba điểm còn treo:</b>
    <b>(1)</b> Chiều cấp khóa — demo đang giả định mình sinh và bàn giao ra ngoài.
    <b>(2)</b> Kênh bàn giao — cột “Kênh” đang liệt kê 3 phương án, chưa chốt.
    <b>(3)</b> Hình thức xác nhận — bấm nút trên portal hay biên bản ký đóng dấu.</div>` : ''}
  <div class="card">
    <div class="card-header">Theo dõi bàn giao khóa</div>
    <div class="card-body font-size-14">
      <div class="ui-table"><table>
        <thead><tr><th style="width:55px">STT</th><th>Mã bàn giao</th><th>Mã khóa</th><th>Đối tượng nhận</th><th>Kênh bàn giao</th><th>Ngày gửi</th><th>Hạn xác nhận</th><th>Trạng thái</th><th style="width:200px">Thao tác</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
    </div>
  </div>`;
}

function viewRotation() {
  const sel = window.__rotSel || 'KEY-2025-021';
  const k = DB.keys.find(x => x.id === sel) || DB.keys[1];
  const overlapDays = window.__overlap || 30;
  const pct = (dd) => (dd / 365 * 100).toFixed(2);
  const marks = [
    { d: 365 - 90, label: 'T-90 · cảnh báo' },
    { d: 365 - 60, label: 'T-60 · duyệt & sinh bản mới' },
    { d: 365 - overlapDays, label: `T-${overlapDays} · bàn giao` },
    { d: 365, label: 'T-0 · cắt bản cũ' },
  ];

  const list = DB.keys.filter(x => x.status === 'HIEU_LUC' && x.exp)
    .sort((a, b) => days(a.exp) - days(b.exp))
    .map((x, i) => {
      const s = SUBJ(x.subj), t = KT(x.kt);
      return `
      <tr ${x.id === sel ? 'style="background:#eff6fc"' : ''}>
        <td class="text-center">${i + 1}</td>
        <td class="mono">${esc(x.id)}</td>
        <td>${esc(x.name)}</td>
        <td>${subjTag(x.subj)}<div class="muted" style="font-size:12px">${esc(x.obj)}</div></td>
        <td class="nowrap">${fmt(x.eff)}</td>
        <td class="nowrap">${expCell(x.exp, x.status)}</td>
        <td>${s.delivery ? '<span class="st st-warn">Phải bàn giao lại cho bên nhận</span>'
          : (t.auto ? '<span class="st st-ok">Xoay tự động</span>' : '<span class="st st-idle">Xoay nội bộ, không gián đoạn</span>')}</td>
        <td class="actions"><a data-act="rotsel" data-id="${x.id}">Xem dải thời gian</a></td>
      </tr>`;
    }).join('');

  return `
  ${note('Ảnh hưởng khi xoay khóa <b>suy ra từ cấu hình</b>: loại đối tượng nào có bước bàn giao thì mỗi lần xoay đều phải chạy lại quy trình với bên nhận; loại nào không thì xoay tự động, không ai biết.')}

  <div class="card">
    <div class="card-header">Dải thời gian xoay khóa — ${esc(k.id)} · ${esc(k.name)} <span class="muted">(${esc(SUBJ(k.subj).name)})</span></div>
    <div class="card-body font-size-14">
      <div class="row mb-2">
        <div class="col-md-5 form-group">
          <label>Cửa sổ song song (2 bản khóa cùng hiệu lực)</label>
          <select class="form-control" id="selOverlap">
            ${[7, 14, 30, 60].map(v => `<option value="${v}" ${v === overlapDays ? 'selected' : ''}>${v} ngày</option>`).join('')}
          </select>
        </div>
        <div class="col-md-7 d-flex align-items-end pb-3">
          <span class="muted">Con số này <b class="req-mark">chưa chốt</b> — nên là thuộc tính cấu hình theo từng đối tượng, không đặt cứng toàn hệ thống.</span>
        </div>
      </div>

      <div class="rot-bar">
        <div class="rot-overlap" style="left:${pct(365 - overlapDays)}%;width:${pct(overlapDays)}%"></div>
        <div class="rot-seg rot-v1" style="left:0;width:${pct(365)}%">Bản ${esc(k.ver)} — đang hiệu lực (${fmt(k.eff)} → ${fmt(k.exp)})</div>
        <div class="rot-seg rot-v2" style="left:${pct(365 - overlapDays)}%;right:0">Bản mới — 12 tháng tiếp theo</div>
      </div>
      <div class="rot-axis">
        ${marks.map(m => `<div class="rot-tick" style="left:${pct(m.d)}%"><span>${esc(m.label)}</span></div>`).join('')}
      </div>
      <div class="legend">
        <span><i style="background:#e3f2ea;border:1px solid #1b7a4b"></i>Bản hiện tại</span>
        <span><i style="background:#deecf9;border:1px solid #005A9E"></i>Bản mới</span>
        <span><i style="background:rgba(217,164,65,.35);border:1px dashed #d9a441"></i>Cửa sổ song song</span>
      </div>

      ${SUBJ(k.subj).delivery ? `<div class="hint bad mt-3"><b><i class="fa fa-exclamation-triangle"></i> Rủi ro cần quyết:</b>
        loại đối tượng này <b>có bước bàn giao</b>. Nếu đến T-0 mà bên nhận chưa xác nhận cài xong bản mới, cắt bản cũ sẽ <b>đứt luồng nghiệp vụ</b>.
        Đề xuất: <b>không tự cắt</b>, nâng cảnh báo đỏ và để người có thẩm quyền quyết định gia hạn có kiểm soát.</div>`
      : `<div class="hint mt-3"><b>Loại đối tượng này không có bước bàn giao</b> — xoay khóa diễn ra hoàn toàn nội bộ, ứng dụng tự lấy bản mới từ OpenBao, không có rủi ro gián đoạn với bên ngoài.</div>`}
    </div>
  </div>

  <div class="card">
    <div class="card-header">Lịch xoay khóa — sắp xếp theo hạn gần nhất</div>
    <div class="card-body font-size-14">
      <div class="ui-table"><table>
        <thead><tr><th style="width:55px">STT</th><th>Mã khóa</th><th>Tên khóa</th><th>Đối tượng</th><th>Hiệu lực từ</th><th>Hết hạn</th><th>Ảnh hưởng khi xoay</th><th style="width:160px">Thao tác</th></tr></thead>
        <tbody>${list}</tbody>
      </table></div>
    </div>
  </div>`;
}

/* ---------- MÀN CẤU HÌNH DANH MỤC ĐỘNG ---------- */
function viewConfig() {
  const sRows = CFG.subjects.map((s, i) => `
    <tr>
      <td class="text-center">${i + 1}</td>
      <td class="mono">${esc(s.code)}</td>
      <td>${esc(s.name)}</td>
      <td><select class="form-control form-control-sm" data-cfg="external" data-id="${s.code}">
            <option value="1" ${s.external ? 'selected' : ''}>Bên ngoài tổ chức</option>
            <option value="0" ${!s.external ? 'selected' : ''}>Nội bộ</option></select></td>
      <td>${esc(s.dossier)}</td>
      <td><select class="form-control form-control-sm" data-cfg="levels" data-id="${s.code}">
            ${[0, 1, 2, 3].map(v => `<option value="${v}" ${s.levels === v ? 'selected' : ''}>${v === 0 ? 'Không duyệt' : v + ' cấp'}</option>`).join('')}</select></td>
      <td><select class="form-control form-control-sm" data-cfg="delivery" data-id="${s.code}">
            <option value="1" ${s.delivery ? 'selected' : ''}>Có</option><option value="0" ${!s.delivery ? 'selected' : ''}>Không</option></select></td>
      <td><select class="form-control form-control-sm" data-cfg="confirm" data-id="${s.code}">
            <option value="1" ${s.confirm ? 'selected' : ''}>Có</option><option value="0" ${!s.confirm ? 'selected' : ''}>Không</option></select></td>
      <td><select class="form-control form-control-sm" data-cfg="lockLevel" data-id="${s.code}">
            ${[1, 2, 3].map(v => `<option value="${v}" ${s.lockLevel === v ? 'selected' : ''}>Mức ${v}</option>`).join('')}</select></td>
      <td class="nowrap">${esc(s.alerts)}</td>
      <td>${s.active ? '<span class="st st-ok">Đang dùng</span>' : '<span class="st st-idle">Tạm ngưng</span>'}</td>
    </tr>`).join('');

  const kRows = CFG.keyTypes.map((t, i) => `
    <tr>
      <td class="text-center">${i + 1}</td>
      <td class="mono">${esc(t.code)}</td>
      <td>${esc(t.name)}</td>
      <td><span class="st st-info">${esc(t.engine)}</span></td>
      <td class="muted">${esc(t.algos)}</td>
      <td class="text-center">${t.maxMonths} tháng</td>
      <td>${t.auto ? '<span class="st st-ok">Tự động</span>' : '<span class="st st-warn">Không tự động</span>'}
          <div class="muted" style="font-size:11.5px">${esc(t.rotate)}</div></td>
      <td>${(ENGINE_FIELDS[t.engine] || []).map(fn => `<span class="fname" style="font-size:12px">${esc(fn)}${tt(fn)}</span>`).join('<br>')}</td>
      <td class="text-center">${DB.keys.filter(k => k.kt === t.code).length}</td>
    </tr>`).join('');

  const matrix = CFG.subjects.filter(s => s.active).map(s => `
    <tr>
      <td>${subjTag(s.code)}</td>
      <td class="muted" style="font-size:12.5px">${esc(flowOf(s.code).join('  →  '))}</td>
      <td class="text-center">${s.levels === 0 ? '<span class="muted">—</span>' : s.levels}</td>
      <td class="text-center">${s.delivery ? '<i class="fa fa-check" style="color:#1b7a4b"></i>' : '<span class="muted">—</span>'}</td>
      <td class="text-center">${s.confirm ? '<i class="fa fa-check" style="color:#1b7a4b"></i>' : '<span class="muted">—</span>'}</td>
      <td class="text-center">Mức ${s.lockLevel}</td>
      <td class="nowrap">${esc(s.alerts)}</td>
    </tr>`).join('');

  return `
  ${note('Đây là màn trả lời câu hỏi “hệ thống phải động chứ”. <b>Không có chỗ nào trong code viết cứng “đối tác FI”.</b> Đổi các ô dropdown bên dưới rồi quay lại các màn khác — quy trình, cột hiển thị và bộ lọc đổi theo ngay.')}

  <div class="card">
    <div class="card-header">Danh mục loại đối tượng sử dụng khóa</div>
    <div class="card-body font-size-14">
      <div class="text-right mb-3"><button class="btn btn-primary" data-act="addsubj"><i class="fa fa-plus"></i> Thêm loại đối tượng</button></div>
      <div class="ui-table"><table>
        <thead><tr>
          <th style="width:50px">STT</th><th>Mã</th><th>Tên loại đối tượng</th><th style="width:150px">Phạm vi</th>
          <th>Hồ sơ ràng buộc</th><th style="width:120px">Cấp duyệt</th><th style="width:95px">Bàn giao</th>
          <th style="width:95px">Xác nhận</th><th style="width:105px">Mức lock</th><th>Mốc cảnh báo</th><th style="width:110px">Trạng thái</th>
        </tr></thead>
        <tbody>${sRows}</tbody>
      </table></div>
      <div class="hint mt-3"><b>Đọc bảng này thế nào:</b> mỗi dòng là một loại đối tượng có thể được cấp khóa.
        Các cột bên phải là <b>chính sách</b> áp cho loại đó. Thêm dòng mới = hệ thống phục vụ thêm một nhóm đối tượng, không phải sửa code.</div>
    </div>
  </div>

  <div class="card">
    <div class="card-header">Danh mục loại khóa &amp; ánh xạ xuống OpenBao</div>
    <div class="card-body font-size-14">
      ${note('Cột <b>Engine OpenBao</b> là ranh giới giữa hai tầng: bên trái là nghiệp vụ mình tự định nghĩa, bên phải là phép nguyên thủy OpenBao cung cấp. Thêm loại khóa mới chỉ cần trỏ vào một engine sẵn có.')}
      <div class="ui-table"><table>
        <thead><tr><th style="width:50px">STT</th><th>Mã</th><th>Tên loại khóa</th><th style="width:130px">Engine OpenBao</th><th>Thuật toán OpenBao chấp nhận</th><th style="width:110px">Trần hiệu lực</th><th style="width:150px">Cơ chế xoay</th><th style="width:190px">Trường API chính</th><th style="width:90px">Số khóa</th></tr></thead>
        <tbody>${kRows}</tbody>
      </table></div>
    </div>
  </div>

  <div class="card">
    <div class="card-header">Ma trận chính sách đang áp dụng (suy ra tự động)</div>
    <div class="card-body font-size-14">
      <div class="ui-table"><table>
        <thead><tr><th style="width:200px">Loại đối tượng</th><th>Quy trình sinh ra</th><th style="width:100px">Cấp duyệt</th><th style="width:95px">Bàn giao</th><th style="width:95px">Xác nhận</th><th style="width:100px">Mức lock</th><th style="width:180px">Mốc cảnh báo</th></tr></thead>
        <tbody>${matrix}</tbody>
      </table></div>
      <div class="hint warn mt-3"><b><i class="fa fa-question-circle"></i> Câu hỏi cho anh Tú &amp; anh Tộ:</b>
        chính sách nên <b>cấu hình được trên giao diện</b> như thế này, hay <b>cố định trong quy chế</b> và chỉ người quản trị hệ thống mới đổi được?
        Cấu hình được thì linh hoạt nhưng khó kiểm soát tuân thủ — đây là đánh đổi cần chốt trước khi thiết kế phân quyền.</div>
    </div>
  </div>`;
}

function viewAudit() {
  const rows = DB.audit.map((a, i) => `
    <tr>
      <td class="text-center">${i + 1}</td>
      <td class="nowrap mono">${esc(a.at)}</td>
      <td>${esc(a.user)}</td>
      <td>${(a.act.indexOf('TẠM KHÓA') === 0 || a.act.indexOf('Thu hồi') >= 0) ? `<b class="req-mark">${esc(a.act)}</b>` : esc(a.act)}</td>
      <td class="mono">${esc(a.obj)}</td>
      <td>${a.reason ? esc(a.reason) : '<span class="muted">—</span>'}</td>
      <td class="mono muted">${esc(a.ip)}</td>
    </tr>`).join('');

  return `
  ${note('Nhật ký là <b>đầu ra bắt buộc cho kiểm toán</b>. Các trường cần lưu phải chốt <b>ngay từ đầu</b> — nếu sau này kiểm toán đòi thêm cột mà hệ thống chưa ghi thì không truy hồi được dữ liệu quá khứ.')}
  <div class="card">
    <div class="card-header">Kết xuất báo cáo</div>
    <div class="card-body font-size-14">
      <div class="row">
        <div class="col-md-4 form-group"><label>Loại báo cáo</label>
          <select class="form-control">
            <option>Danh mục khóa theo loại đối tượng</option>
            <option>Khóa sắp hết hạn / quá hạn</option>
            <option>Lịch sử tạm khóa &amp; thu hồi</option>
            <option>Nhật ký bàn giao và xác nhận</option>
            <option>Tuân thủ trần hiệu lực theo loại khóa</option>
          </select></div>
        <div class="col-md-3 form-group"><label>Lọc theo loại đối tượng</label>
          <select class="form-control"><option>Tất cả</option>
            ${CFG.subjects.filter(s => s.active).map(s => `<option>${esc(s.name)}</option>`).join('')}</select></div>
        <div class="col-md-3 form-group"><label>Khoảng thời gian</label><input class="form-control" value="01/08/2026 - 26/08/2026"></div>
        <div class="col-md-2 form-group d-flex align-items-end pb-3">
          <button class="btn btn-primary" data-act="export"><i class="fa fa-file-excel"></i> Kết xuất</button></div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-header">Nhật ký thao tác (audit log)</div>
    <div class="card-body font-size-14">
      <div class="ui-table"><table>
        <thead><tr><th style="width:55px">STT</th><th>Thời điểm</th><th>Tài khoản</th><th>Hành động</th><th>Đối tượng</th><th>Lý do</th><th>IP</th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>
    </div>
  </div>`;
}

/* ---------------- MODALS ---------------- */
function modal(html) { $('#modalRoot').innerHTML = html; }
function closeModal() { $('#modalRoot').innerHTML = ''; }

function shell(title, body, foot, size) {
  return `<div class="modal-backdrop-x" data-close="1">
    <div class="modal-x ${size || ''}">
      <div class="m-head"><span>${title}</span><span class="close-x" data-close="1"><i class="fa fa-times"></i></span></div>
      <div class="m-body">${body}</div>
      <div class="m-foot">${foot}</div>
    </div></div>`;
}

function openDetail(id) {
  const k = DB.keys.find(x => x.id === id);
  const s = SUBJ(k.subj), t = KT(k.kt);
  const tab = window.__tab || 'info';
  const T = (i2, label) => `<div class="${tab === i2 ? 'active' : ''}" data-act="tab" data-id="${i2}">${label}</div>`;

  let body = '';
  if (tab === 'info') {
    const e = EX(k.id);
    body = `<div class="hint">Toàn bộ trường ở tab này là <b>trường nghiệp vụ</b> — do mình tự định nghĩa, OpenBao không biết chúng tồn tại. Tham số kỹ thuật nằm ở tab <b>Tham số OpenBao</b>.</div>
    <div class="kv">
      <div class="k">Mã khóa</div><div class="v mono">${esc(k.id)}</div>
      <div class="k">Tên khóa</div><div class="v">${esc(k.name)}</div>
      <div class="k">Môi trường</div><div class="v"><span class="env-badge env-${esc(e.env)}">${esc(e.env)}</span></div>
      <div class="k">Loại đối tượng</div><div class="v">${subjTag(k.subj)}</div>
      <div class="k">Đối tượng cụ thể</div><div class="v">${esc(k.obj)}</div>
      <div class="k">Đầu mối liên hệ</div><div class="v" style="font-weight:400">${esc(e.contact)}</div>
      <div class="k">Hồ sơ ràng buộc</div><div class="v">${esc(k.dossier)} <span class="muted">(loại: ${esc(s.dossier)})</span></div>
      <div class="k">Mã yêu cầu gốc</div><div class="v mono">${esc(e.ticket)}</div>
      <div class="k">Loại khóa</div><div class="v">${esc(t.name)} <span class="muted">→ engine ${esc(t.engine)}</span></div>
      <div class="k">Mục đích sử dụng</div><div class="v" style="font-weight:400">${esc(k.purpose)}</div>
      <div class="k">Hệ thống sử dụng</div><div class="v" style="font-weight:400">${esc(e.sys)}</div>
      <div class="k">Thuật toán</div><div class="v">${esc(k.algo)}</div>
      <div class="k">Phiên bản hiện tại</div><div class="v">${esc(k.ver)}</div>
      <div class="k">Hiệu lực</div><div class="v">${fmt(k.eff)} → ${fmt(k.exp)} <span class="muted">(trần ${t.maxMonths} tháng)</span></div>
      <div class="k">Chủ quản</div><div class="v">${esc(k.owner)}</div>
      <div class="k">Người tạo hồ sơ</div><div class="v" style="font-weight:400">${esc(e.createdBy)} · ${fmt(e.createdAt)}</div>
      <div class="k">Người phê duyệt</div><div class="v" style="font-weight:400">${esc(e.approvedBy)}${e.approvedAt ? ' · ' + fmt(e.approvedAt) : ''}</div>
      <div class="k">Vị trí trong OpenBao</div><div class="v mono">${esc(k.path)}</div>
      <div class="k">Quy trình áp dụng</div><div class="v" style="font-weight:400">${esc(flowOf(k.subj).join('  →  '))}</div>
      <div class="k">Trạng thái</div><div class="v">${stBadge(k.status)}</div>
      ${k.lockReason ? `<div class="k">Lý do</div><div class="v" style="font-weight:400">${esc(k.lockReason)}</div>` : ''}
    </div>
    <div class="hint mt-3"><b><i class="fa fa-lock"></i> Lưu ý:</b> màn hình này <b>không bao giờ hiển thị private key</b>. Chìa bí mật nằm trong OpenBao tại đường dẫn trên; CMS chỉ giữ hồ sơ và gọi API.</div>`;
  } else if (tab === 'api') {
    const p = apiParams(k);
    body = `<div class="hint"><b>Đây là các trường OpenBao quy định</b> — tên trường không đổi được, chỉ giá trị là do nghiệp vụ quyết.
      CMS <b>tự dịch</b> từ tab Thông tin chung, người dùng không gõ tay. Rê chuột vào <i class="tt">i</i> để xem trường đó là gì.
      <div class="src-note">Engine đang dùng: <b>${esc(p.engine)}</b> · nguồn: openbao.org/api-docs/secret/${p.engine === 'KV v2' ? 'kv' : p.engine.toLowerCase()}</div></div>

    <div class="ui-table api-tbl"><table>
      <thead><tr><th style="width:34%">Trường gửi xuống API</th><th>Giá trị CMS sẽ gửi</th><th style="width:26%">Suy ra từ đâu</th></tr></thead>
      <tbody>${p.req.map(r => `<tr class="${r.locked ? 'locked' : ''}">
        <td class="fname">${esc(r.n)}${tt(r.n)}</td>
        <td class="fval">${esc(String(r.v))}</td>
        <td class="muted" style="font-size:12px">${r.locked ? '<b class="req-mark">Khóa cứng — không cho sửa</b>' : 'Hồ sơ nghiệp vụ'}</td></tr>`).join('')}
      </tbody></table></div>

    <h6 class="mt-4" style="font-size:14px;font-weight:600">Giá trị OpenBao trả về — CMS bắt buộc lưu lại</h6>
    <div class="ui-table api-tbl"><table>
      <thead><tr><th style="width:34%">Trường</th><th>Giá trị hiện tại</th></tr></thead>
      <tbody>${p.res.map(r => `<tr><td class="fname">${esc(r.n)}${tt(r.n)}</td><td class="fval">${esc(String(r.v))}</td></tr>`).join('')}</tbody>
    </table></div>

    <div class="hint warn mt-3"><b>Vì sao phải lưu nhóm dưới:</b>
      ${p.engine === 'PKI' ? 'PKI chỉ thu hồi được bằng <code>serial_number</code>. Không lưu serial = vĩnh viễn không thu hồi được chứng thư đó.'
        : p.engine === 'Database' ? 'Muốn thu hồi credential đang phát ra ngoài thì phải gọi revoke theo <code>lease_id</code>.'
          : p.engine === 'Transit' ? 'Không lưu <code>latest_version</code> thì không đối soát được bản khóa nào đang chạy, và không biết đặt <code>min_decryption_version</code> bằng bao nhiêu khi cắt bản cũ.'
            : 'KV v2 không có TTL và không tự xoay — CMS phải tự theo dõi <code>version</code> và tự nhắc thay.'}</div>`;
  } else if (tab === 'ver') {
    body = `<div class="ui-table"><table>
      <thead><tr><th>Phiên bản</th><th>Hiệu lực</th><th>Hết hạn</th><th>Trạng thái</th><th>Ghi chú</th></tr></thead>
      <tbody>
        <tr><td class="mono">${esc(k.ver)}</td><td>${fmt(k.eff)}</td><td>${fmt(k.exp)}</td><td>${stBadge(k.status)}</td><td>Phiên bản hiện tại</td></tr>
        <tr><td class="mono">v2</td><td>02/11/2024</td><td>02/11/2025</td><td><span class="st st-bad">Thu hồi</span></td><td>Thu hồi theo lịch xoay khóa 2025</td></tr>
        <tr><td class="mono">v1</td><td>15/10/2023</td><td>02/11/2024</td><td><span class="st st-idle">Hết hiệu lực</span></td><td>—</td></tr>
      </tbody></table></div>
      <div class="hint mt-3">OpenBao giữ đồng thời nhiều phiên bản khóa — nhờ vậy mới có <b>cửa sổ song song</b> lúc xoay khóa mà không đứt dịch vụ.</div>`;
  } else if (tab === 'bg') {
    const dl = DB.deliveries.filter(x => x.keyId === k.id);
    body = s.delivery
      ? (dl.length ? `<div class="ui-table"><table>
          <thead><tr><th>Mã bàn giao</th><th>Kênh</th><th>Ngày gửi</th><th>Người nhận / xác nhận</th></tr></thead>
          <tbody>${dl.map(x => `<tr><td class="mono">${esc(x.id)}</td><td>${esc(x.channel)}</td><td>${x.sentAt ? fmt(x.sentAt) : '<span class="muted">chưa gửi</span>'}</td><td>${x.receiver ? esc(x.receiver) : '<span class="muted">chưa xác nhận</span>'}</td></tr>`).join('')}</tbody>
          </table></div>` : '<div class="muted">Chưa phát sinh bàn giao.</div>')
      : `<div class="hint">Loại đối tượng <b>${esc(s.name)}</b> được cấu hình <b>không có bước bàn giao</b> — khóa được ứng dụng lấy trực tiếp từ OpenBao, không phát sinh hồ sơ bàn giao.</div>`;
  } else {
    body = `<ul class="timeline">
      ${DB.audit.filter(a => a.obj.indexOf(k.id) >= 0).concat([
      { at: fmt(k.eff), user: 'system', act: 'Kích hoạt khóa', reason: '' },
      { at: fmt(k.eff), user: 'openbao', act: 'Sinh khóa trên OpenBao', reason: k.path },
    ]).map(a => `<li><div><b>${esc(a.act)}</b> — ${esc(a.user)}</div><div class="tl-time">${esc(a.at)}${a.reason ? ' · ' + esc(a.reason) : ''}</div></li>`).join('')}
    </ul>`;
  }

  modal(shell(`<i class="fa fa-key"></i> Chi tiết khóa — ${esc(k.id)}`,
    `<div class="tabs">${T('info', 'Thông tin chung')}${T('api', 'Tham số OpenBao')}${T('ver', 'Lịch sử phiên bản')}${T('bg', 'Bàn giao')}${T('log', 'Nhật ký thao tác')}</div>${body}`,
    `<button class="btn btn-secondary" data-close="1">Đóng</button>`));
  window.__detailId = id;
}

function openLock(id) {
  const k = DB.keys.find(x => x.id === id);
  const s = SUBJ(k.subj);
  modal(shell(`<i class="fa fa-lock"></i> Tạm khóa — ${esc(k.id)}`, `
    <div class="hint warn"><b>Phạm vi của thao tác này còn chờ chốt.</b> Mức mặc định đang lấy từ cấu hình của loại đối tượng
      <b>${esc(s.name)}</b> (Mức ${s.lockLevel}). Đổi thử để thấy hệ quả khác nhau — đây chính là câu hỏi <b>L1</b> cần anh Tú và anh Tộ quyết.</div>
    <div class="form-group">${lb('Mức tạm khóa', 'f_lockLevel', 1)}
      <select class="form-control" id="lockLevel">
        <option value="1" ${s.lockLevel === 1 ? 'selected' : ''}>Mức 1 — Hành chính: chỉ đánh dấu hồ sơ, nghiệp vụ vẫn chạy</option>
        <option value="2" ${s.lockLevel === 2 ? 'selected' : ''}>Mức 2 — Chặn cấp mới: không được xoay / cấp thêm / bàn giao</option>
        <option value="3" ${s.lockLevel === 3 ? 'selected' : ''}>Mức 3 — Vô hiệu thật: mọi thao tác ký / giải mã bị từ chối</option>
      </select></div>
    <div id="lockEffect"></div>
    <div class="form-group">${lb('Lý do tạm khóa', 'f_lockReason', 1)}
      <textarea class="form-control" id="lockReason" rows="3" placeholder="Ví dụ: Nghi ngờ lộ khóa theo PYC-..., hợp đồng tạm dừng, hệ thống bảo trì..."></textarea></div>
    ${s.external ? `<div class="form-group"><label>Thông báo cho đối tượng</label>
      <select class="form-control"><option>Có — gửi email + thông báo trên portal</option><option>Không — xử lý nội bộ trước</option></select></div>`
      : '<div class="hint">Đối tượng nội bộ — không phát sinh thông báo ra ngoài tổ chức.</div>'}
  `, `<button class="btn btn-secondary" data-close="1">Hủy</button>
      <button class="btn btn-primary ml-2" data-act="doLock" data-id="${id}"><i class="fa fa-lock"></i> Xác nhận tạm khóa</button>`, 'sm'));
  renderLockEffect();
}

function renderLockEffect() {
  const el = $('#lockEffect'); if (!el) return;
  const v = $('#lockLevel').value;
  const map = {
    '1': ['hint', 'Nghiệp vụ của bên sử dụng <b>không bị ảnh hưởng</b>. Chỉ chặn thao tác quản trị trên khóa. Rẻ nhất, nhưng không cứu được tình huống nghi ngờ lộ khóa.'],
    '2': ['hint warn', 'Khóa <b>vẫn dùng được</b> nhưng không được xoay / cấp thêm / bàn giao. Ảnh hưởng bắt đầu xuất hiện khi đến kỳ xoay khóa.'],
    '3': ['hint bad', '<b>Nghiệp vụ dừng ngay lập tức.</b> Phải chạm tới cả ứng dụng đầu cuối, chi phí cài đặt cao nhất. Cần trả lời thêm: giao dịch đang chạy dở thì cắt ngay hay chạy nốt phiên?'],
  };
  const [c, t] = map[v] || map['3'];
  el.innerHTML = `<div class="${c}">${t}</div>`;
}

function openRevoke(id) {
  modal(shell(`<i class="fa fa-ban"></i> Thu hồi khóa — ${esc(id)}`, `
    <div class="hint bad"><b>Thu hồi là vĩnh viễn, không mở lại được.</b> Nếu chỉ muốn tạm dừng và còn khả năng khôi phục, hãy dùng <b>Tạm khóa</b>.</div>
    <div class="form-group"><label>Lý do thu hồi <span class="req-mark">*</span></label>
      <textarea class="form-control" id="revReason" rows="3" placeholder="Xác định đã lộ khóa / chấm dứt hợp đồng / cấp nhầm..."></textarea></div>
    <div class="form-group"><label>Cấp phê duyệt</label>
      <select class="form-control"><option>Lãnh đạo đơn vị + ATTT (đề xuất)</option><option>Chỉ trưởng nhóm</option></select></div>
  `, `<button class="btn btn-secondary" data-close="1">Hủy</button>
      <button class="btn btn-danger ml-2" data-act="doRevoke" data-id="${id}">Xác nhận thu hồi</button>`, 'sm'));
}

/** Thuật toán hợp lệ theo từng engine — đúng danh sách OpenBao chấp nhận. */
const ALGOS = {
  Transit: ['rsa-2048', 'rsa-3072', 'rsa-4096', 'ecdsa-p256', 'ecdsa-p384', 'ecdsa-p521', 'ed25519', 'aes256-gcm96', 'chacha20-poly1305'],
  PKI: ['rsa/2048', 'rsa/3072', 'rsa/4096', 'ec/256', 'ec/384', 'ec/521', 'ed25519/0'],
  Database: ['— engine tự sinh user/password'],
  'KV v2': ['— chỉ lưu dữ liệu, không có khái niệm thuật toán'],
};

function openNewReq() {
  const act = CFG.subjects.filter(s => s.active);
  modal(shell('<i class="fa fa-plus"></i> Tạo yêu cầu cấp khóa', `
    <div class="hint">Rê chuột vào <i class="tt">i</i> cạnh mỗi ô để xem ô đó là gì, có gửi xuống OpenBao không, và <b>căn cứ nào bắt phải có ô đó</b>.</div>

    <div class="fieldset-hd">Bắt buộc — 7 ô, đều có căn cứ</div>
    <div class="row">
      <div class="col-md-5 form-group">${lb('Loại đối tượng', 'f_subj', 1)}
        <select class="form-control" id="nrSubj">${act.map(s => `<option value="${s.code}">${esc(s.name)}</option>`).join('')}</select></div>
      <div class="col-md-7 form-group">${lb('Loại khóa', 'f_kt', 1)}
        <select class="form-control" id="nrKt">${CFG.keyTypes.filter(t => t.active).map(t => `<option value="${t.code}">${esc(t.name)} — engine ${esc(t.engine)}</option>`).join('')}</select></div>
      <div class="col-12" id="nrFlow"></div>

      <div class="col-md-6 form-group">${lb('Đối tượng cụ thể', 'f_obj', 1)}
        <input class="form-control" id="nrObj" placeholder="Ví dụ: Ngân hàng Đối tác A / Report Service"></div>
      <div class="col-md-6 form-group">${lb('Hồ sơ ràng buộc', 'f_dossier', 1)}
        <input class="form-control" placeholder="Số hợp đồng / thỏa thuận / phiếu yêu cầu"></div>

      <div class="col-md-6 form-group">${lb('Tên khóa', 'f_name', 1)}
        <input class="form-control" id="nrName" placeholder="Ví dụ: Khóa ký dữ liệu điểm tín dụng"></div>
      <div class="col-md-6 form-group">${lb('Thuật toán', 'f_algo', 1)}
        <select class="form-control" id="nrAlgo"></select>
        <div class="src-note" id="nrAlgoNote"></div></div>

      <div class="col-md-6 form-group">${lb('Thời hạn hiệu lực', 'f_ttl', 1)}
        <select class="form-control" id="nrTtl"><option value="12">12 tháng (trần tối đa)</option><option value="6">6 tháng</option><option value="3">3 tháng</option><option value="1">1 tháng</option></select>
        <div class="src-note" id="nrTtlNote"></div></div>
    </div>

    <div class="fieldset-hd opt">Mình đề xuất thêm — 4 ô, chưa ai yêu cầu</div>
    <div class="opt-wrap">
      <div class="row">
        <div class="col-md-4 form-group">${lb('Môi trường', 'f_env')}
          <select class="form-control" id="nrEnv"><option>PROD</option><option>UAT</option><option>DEV</option></select></div>
        <div class="col-md-8 form-group">${lb('Đầu mối liên hệ phía đối tượng', 'f_contact')}
          <input class="form-control" placeholder="Họ tên · email · điện thoại"></div>
        <div class="col-md-5 form-group">${lb('Hệ thống sử dụng khóa', 'f_sys')}
          <input class="form-control" placeholder="Ví dụ: ScoreHub Backend"></div>
        <div class="col-md-7 form-group">${lb('Mục đích sử dụng', 'f_purpose')}
          <input class="form-control" placeholder="Khóa này dùng để làm gì"></div>
      </div>
      <div class="src-note" style="padding-bottom:10px">Bốn ô này <b>không có căn cứ từ yêu cầu của anh Tộ hay anh Tú</b> — mình suy ra. Rê chuột vào <i class="tt">i</i> để xem lý do và hệ quả nếu bỏ. Chốt được thì mình xóa hoặc chuyển lên khối bắt buộc.</div>
    </div>

    <div class="fieldset-hd">CMS tự ghi — người dùng không nhập</div>
    <div class="src-note" style="margin-bottom:4px">
      Mã yêu cầu · người đề nghị · thời điểm đề nghị · người duyệt từng cấp · thời điểm duyệt ·
      mã khóa · đường dẫn khóa trong OpenBao · phiên bản khóa · serial / lease do OpenBao trả về.
    </div>
  `, `<button class="btn btn-secondary" data-close="1">Hủy</button>
      <button class="btn btn-primary ml-2" data-act="doNewReq"><i class="fa fa-paper-plane"></i> Gửi yêu cầu</button>`));
  renderNewReqFlow();
}

function renderNewReqFlow() {
  const fl = $('#nrFlow'), al = $('#nrAlgo');
  if (!fl || !al) return;
  const s = SUBJ($('#nrSubj').value);
  const t = KT($('#nrKt').value);
  const months = +($('#nrTtl') ? $('#nrTtl').value : 12);

  // dropdown thuật toán bám theo engine
  const opts = ALGOS[t.engine] || ['—'];
  const keep = al.value;
  al.innerHTML = opts.map(o => `<option ${o === keep ? 'selected' : ''}>${esc(o)}</option>`).join('');
  const algo = al.value || opts[0];

  fl.innerHTML = `<div class="hint"><b>Quy trình áp dụng cho “${esc(s.name)}”:</b><br>
    ${esc(flowOf(s.code).join('  →  '))}<br>
    <span class="muted">Trần hiệu lực ${t.maxMonths} tháng · mức lock mặc định Mức ${s.lockLevel} · cảnh báo ${esc(s.alerts)}</span></div>`;

  const eff = Math.min(months, t.maxMonths);

  // ghi chú nhỏ ngay dưới ô, thay cho bảng
  const an = $('#nrAlgoNote');
  if (an) an.innerHTML = t.engine === 'Transit' ? `→ gửi xuống <code>type=${esc(algo)}</code>`
    : t.engine === 'PKI' ? `→ gửi xuống <code>key_type=${esc(algo.split('/')[0])}</code>, <code>key_bits=${esc(algo.split('/')[1])}</code>`
      : `engine <b>${esc(t.engine)}</b> không dùng thuật toán`;

  const tn = $('#nrTtlNote');
  if (tn) tn.innerHTML = (months > t.maxMonths
    ? `<span class="req-mark">Loại khóa này trần ${t.maxMonths} tháng — CMS sẽ ép xuống ${eff} tháng.</span> `
    : '') + (t.engine === 'Transit' ? `→ gửi xuống <code>auto_rotate_period=${hours(eff)}</code>`
      : t.engine === 'PKI' ? `→ gửi xuống <code>ttl=${hours(eff)}</code>`
        : t.engine === 'Database' ? `→ gửi xuống <code>default_ttl=${hours(eff)}</code>`
          : `KV v2 không có TTL — CMS phải tự nhắc thay`);
}

function openSend(id) {
  const dl = DB.deliveries.find(x => x.id === id);
  const s = SUBJ(dl.subj);
  modal(shell(`<i class="fa fa-paper-plane"></i> Bàn giao khóa — ${esc(dl.id)}`, `
    <div class="hint"><b>Chỉ public key / chứng thư được bàn giao.</b> Private key ở lại trong OpenBao — điểm này phải nói rõ với bên nhận trong biên bản.</div>
    <div class="form-group">${lb('Kênh bàn giao', 'f_channel', 1)}
      <select class="form-control" id="sendCh"><option>Portal đối tượng — bên nhận tự tải</option><option>Email ký số</option><option>SFTP + biên bản giấy</option></select></div>
    <div class="form-group"><label>Người nhận phía đối tượng</label><input class="form-control" placeholder="Họ tên / bộ phận / email"></div>
    ${s.confirm ? `<div class="form-group"><label>Hạn xác nhận đã nhận</label><input class="form-control" value="05/09/2026"></div>`
      : `<div class="hint">Loại đối tượng <b>${esc(s.name)}</b> được cấu hình <b>không yêu cầu bước xác nhận</b> — bàn giao xong là kết thúc quy trình.</div>`}
    <div class="form-group"><label>Đính kèm</label><input class="form-control" value="public-key.pem, bien-ban-ban-giao.pdf" readonly></div>
  `, `<button class="btn btn-secondary" data-close="1">Hủy</button>
      <button class="btn btn-primary ml-2" data-act="doSend" data-id="${id}">Xác nhận bàn giao</button>`, 'sm'));
}

function openConfirm(id) {
  modal(shell(`<i class="fa fa-check"></i> Ghi nhận xác nhận — ${esc(id)}`, `
    <div class="hint warn"><b>Câu hỏi D4 chưa chốt:</b> bên nhận bấm nút trên portal là đủ, hay bắt buộc phải có biên bản ký đóng dấu để phục vụ kiểm toán?</div>
    <div class="form-group">${lb('Hình thức xác nhận', 'f_confirmType', 1)}
      <select class="form-control"><option>Xác nhận trên portal</option><option>Biên bản bàn giao có ký đóng dấu</option><option>Email phản hồi có chữ ký số</option></select></div>
    <div class="form-group"><label>Người xác nhận</label><input class="form-control" id="cfName" placeholder="Họ tên / bộ phận"></div>
    <div class="form-group"><label>Ngày xác nhận</label><input class="form-control" value="26/08/2026"></div>
  `, `<button class="btn btn-secondary" data-close="1">Hủy</button>
      <button class="btn btn-primary ml-2" data-act="doConfirm" data-id="${id}">Ghi nhận &amp; kích hoạt khóa</button>`, 'sm'));
}

function openAddSubj() {
  modal(shell('<i class="fa fa-plus"></i> Thêm loại đối tượng sử dụng khóa', `
    <div class="hint">Thêm một dòng ở đây là hệ thống phục vụ thêm một nhóm đối tượng — <b>không phải sửa code, không phải build lại</b>.
      Sau khi thêm, quay lại màn Danh mục khóa và Tạo yêu cầu để thấy lựa chọn mới xuất hiện.</div>
    <div class="row">
      <div class="col-md-4 form-group"><label>Mã <span class="req-mark">*</span></label><input class="form-control" id="asCode" placeholder="VD: INSUR"></div>
      <div class="col-md-8 form-group"><label>Tên loại đối tượng <span class="req-mark">*</span></label><input class="form-control" id="asName" placeholder="VD: Doanh nghiệp bảo hiểm"></div>
      <div class="col-md-6 form-group"><label>Phạm vi</label>
        <select class="form-control" id="asExt"><option value="1">Bên ngoài tổ chức</option><option value="0">Nội bộ</option></select></div>
      <div class="col-md-6 form-group"><label>Hồ sơ ràng buộc</label><input class="form-control" id="asDos" value="Hợp đồng / phụ lục"></div>
      <div class="col-md-4 form-group"><label>Số cấp duyệt</label>
        <select class="form-control" id="asLv"><option value="0">Không duyệt</option><option value="1">1 cấp</option><option value="2" selected>2 cấp</option><option value="3">3 cấp</option></select></div>
      <div class="col-md-4 form-group"><label>Có bước bàn giao</label>
        <select class="form-control" id="asDel"><option value="1" selected>Có</option><option value="0">Không</option></select></div>
      <div class="col-md-4 form-group"><label>Yêu cầu xác nhận</label>
        <select class="form-control" id="asCf"><option value="1" selected>Có</option><option value="0">Không</option></select></div>
      <div class="col-md-6 form-group"><label>Mức lock mặc định</label>
        <select class="form-control" id="asLock"><option value="1">Mức 1</option><option value="2">Mức 2</option><option value="3" selected>Mức 3</option></select></div>
      <div class="col-md-6 form-group"><label>Mốc cảnh báo</label><input class="form-control" id="asAl" value="T-90 · T-30 · T-7"></div>
    </div>
  `, `<button class="btn btn-secondary" data-close="1">Hủy</button>
      <button class="btn btn-primary ml-2" data-act="doAddSubj"><i class="fa fa-save"></i> Lưu danh mục</button>`));
}

/* ---------------- ROUTER ---------------- */
function route() { return (location.hash.replace('#/', '') || 'dashboard'); }

function render() {
  const r = route();
  const fn = {
    dashboard: viewDashboard, keys: viewKeys, requests: viewRequests, delivery: viewDelivery,
    rotation: viewRotation, config: viewConfig, audit: viewAudit,
  }[r] || viewDashboard;
  $('#crumb').innerHTML = `<div style="display:flex;align-items:center;justify-content:space-between">
      <span><i class="fa fa-home"></i> Trang chủ <span class="sep">/</span> Quản trị khóa <span class="sep">/</span> <b>${esc(TITLES[r] || '')}</b></span>
      <span><label style="margin:0;cursor:pointer;user-select:none">
        <input type="checkbox" id="tgNotes" ${SHOW_NOTES ? 'checked' : ''}> Hiện ghi chú nghiệp vụ
      </label></span>
    </div>`;
  $('#view').innerHTML = fn();
  renderNav();
  window.scrollTo(0, 0);
}

/* ---------------- SỰ KIỆN ---------------- */
document.addEventListener('click', (e) => {
  const t = e.target.closest('[data-act],[data-close],#btnSearch,#btnReset,#btnCollapse');
  if (!t) return;

  if (t.id === 'btnCollapse') { $('#sidebar').classList.toggle('collapsed'); return; }
  if (t.dataset.close) {
    if (t.classList.contains('modal-backdrop-x') && e.target !== t) return;
    closeModal(); return;
  }
  if (t.id === 'btnSearch') {
    window.__kf = { q: $('#fq').value, subj: $('#fsubj').value, kt: $('#fkt').value, status: $('#fstatus').value, env: $('#fenv').value };
    render(); return;
  }
  if (t.id === 'btnReset') { window.__kf = null; render(); return; }

  const id = t.dataset.id;
  switch (t.dataset.act) {
    case 'detail': window.__tab = 'info'; openDetail(id); break;
    case 'tab': window.__tab = id; openDetail(window.__detailId); break;
    case 'lock': openLock(id); break;
    case 'revoke': openRevoke(id); break;
    case 'newreq': openNewReq(); break;
    case 'send': openSend(id); break;
    case 'confirm': openConfirm(id); break;
    case 'addsubj': openAddSubj(); break;
    case 'rotsel': window.__rotSel = id; render(); break;

    case 'unlock': {
      const k = DB.keys.find(x => x.id === id);
      if (!confirm(`Mở khóa ${id}?\n\nĐề xuất nghiệp vụ: unlock phải do cấp cao hơn lock phê duyệt — lock sai chỉ gây gián đoạn, unlock sai gây mất an toàn.`)) return;
      k.status = 'HIEU_LUC'; k.lockReason = '';
      log('MỞ KHÓA', id, 'Đã xác minh không có dấu hiệu lộ khóa');
      render(); break;
    }
    case 'doLock': {
      const reason = $('#lockReason').value.trim();
      if (!reason) { alert('Lý do tạm khóa là bắt buộc — kiểm toán sẽ hỏi tới trường này.'); return; }
      const lv = $('#lockLevel').value;
      const k = DB.keys.find(x => x.id === id);
      k.status = 'TAM_KHOA'; k.lockReason = `[Mức ${lv}] ${reason}`;
      log('TẠM KHÓA', id, `Mức ${lv} — ${reason}`);
      closeModal(); render(); break;
    }
    case 'doRevoke': {
      const reason = $('#revReason').value.trim();
      if (!reason) { alert('Lý do thu hồi là bắt buộc.'); return; }
      const k = DB.keys.find(x => x.id === id);
      k.status = 'THU_HOI'; k.lockReason = reason;
      log('Thu hồi khóa', id, reason);
      closeModal(); render(); break;
    }
    case 'doNewReq': {
      const name = $('#nrName').value.trim();
      const obj = $('#nrObj').value.trim();
      if (!name || !obj) { alert('Vui lòng nhập tên khóa và đối tượng cụ thể.'); return; }
      const subj = $('#nrSubj').value;
      const n = 'YC-2026-' + (100 + DB.requests.length);
      DB.requests.unshift({
        id: n, kind: 'Cấp mới', keyName: name, subj, obj,
        algo: $('#nrAlgo').value, by: 'hangttm9', at: '2026-08-26',
        status: SUBJ(subj).levels === 0 ? 'DA_SINH' : 'DE_NGHI',
        step: SUBJ(subj).levels === 0 ? 0 : 1, note: 'Tạo từ bản demo',
      });
      log('Tạo yêu cầu cấp khóa', n, `${name} — ${SUBJ(subj).name}`);
      closeModal(); location.hash = '#/requests'; render(); break;
    }
    case 'doAddSubj': {
      const code = ($('#asCode').value || '').trim().toUpperCase();
      const name = ($('#asName').value || '').trim();
      if (!code || !name) { alert('Vui lòng nhập mã và tên loại đối tượng.'); return; }
      if (CFG.subjects.some(s => s.code === code)) { alert('Mã này đã tồn tại.'); return; }
      CFG.subjects.push({
        code, name, external: $('#asExt').value === '1', dossier: $('#asDos').value || '—',
        levels: +$('#asLv').value, delivery: $('#asDel').value === '1', confirm: $('#asCf').value === '1',
        lockLevel: +$('#asLock').value, alerts: $('#asAl').value || '—', active: true,
      });
      log('Thêm loại đối tượng', code, name);
      closeModal(); render(); break;
    }
    case 'approve': {
      const r = DB.requests.find(x => x.id === id);
      const s = SUBJ(r.subj);
      if (r.step < s.levels) { r.step++; log(`Duyệt cấp ${r.step - 1 || 1}`, id, ''); }
      if (r.step >= s.levels) { r.status = 'DA_SINH'; r.step = 0; log('Duyệt xong → sinh khóa trên OpenBao', id, ''); }
      render(); break;
    }
    case 'reject': {
      const reason = prompt('Lý do từ chối:'); if (!reason) return;
      const r = DB.requests.find(x => x.id === id);
      r.status = 'TU_CHOI'; r.step = 0; r.note = reason;
      log('Từ chối yêu cầu', id, reason);
      render(); break;
    }
    case 'doSend': {
      const dl = DB.deliveries.find(x => x.id === id);
      dl.channel = $('#sendCh').value; dl.sentAt = '2026-08-26';
      if (SUBJ(dl.subj).confirm) { dl.status = 'CHO_XAC_NHAN'; dl.dueAt = '2026-09-05'; }
      else { dl.status = 'DA_BAN_GIAO_KXN'; dl.note = 'Loại đối tượng này không yêu cầu bước xác nhận'; }
      log('Bàn giao khóa', `${dl.id} / ${dl.keyId}`, dl.channel);
      closeModal(); render(); break;
    }
    case 'doConfirm': {
      const dl = DB.deliveries.find(x => x.id === id);
      dl.status = 'DA_XAC_NHAN'; dl.receiver = ($('#cfName').value || 'Bộ phận CNTT bên nhận') + ' — 26/08/2026';
      const k = DB.keys.find(x => x.id === dl.keyId);
      if (k && k.status === 'DA_BAN_GIAO') { k.status = 'HIEU_LUC'; k.eff = '2026-08-26'; }
      log('Xác nhận đã nhận khóa → kích hoạt', `${dl.id} / ${dl.keyId}`, dl.receiver);
      closeModal(); render(); break;
    }
    case 'remind': alert('Đã gửi nhắc tới đối tượng qua email + thông báo portal.\n\n(Mốc nhắc lấy từ cấu hình loại đối tượng — câu hỏi C1 chưa chốt con số cụ thể.)'); break;
    case 'bienban': alert('Mở biên bản bàn giao đã ký.\n\n(Câu hỏi D4 chưa chốt: bấm nút trên portal có đủ giá trị pháp lý không, hay bắt buộc biên bản ký đóng dấu.)'); break;
    case 'export': alert('Kết xuất báo cáo ra Excel.\n\n(Câu hỏi C2 chưa chốt: báo cáo kiểm toán cần đúng những cột nào — phải chốt sớm vì quyết định trường dữ liệu lưu ngay từ đầu.)'); break;
    case 'rotate': location.hash = '#/rotation'; window.__rotSel = id; render(); break;
  }
});

document.addEventListener('change', (e) => {
  const el = e.target;
  if (el.id === 'tgNotes') { SHOW_NOTES = el.checked; render(); return; }
  if (el.id === 'lockLevel') { renderLockEffect(); return; }
  if (el.id === 'selOverlap') { window.__overlap = +el.value; render(); return; }
  if (['nrSubj', 'nrKt', 'nrTtl', 'nrAlgo'].indexOf(el.id) >= 0) { renderNewReqFlow(); return; }
  if (el.dataset && el.dataset.cfg) {
    const s = CFG.subjects.find(x => x.code === el.dataset.id);
    const f = el.dataset.cfg;
    s[f] = (f === 'levels' || f === 'lockLevel') ? +el.value : el.value === '1';
    log('Sửa cấu hình loại đối tượng', s.code, `${f} = ${el.value}`);
    render();
  }
});

/* ---------------- TOOLTIP: vẽ ở tầng trên cùng ---------------- */
function showTip(el) {
  const box = $('#tipbox'); if (!box) return;
  const html = tipHtml(el.dataset.tip); if (!html) return;
  box.innerHTML = html;
  box.style.display = 'block';
  const r = el.getBoundingClientRect();
  const b = box.getBoundingClientRect();
  const vw = document.documentElement.clientWidth;
  const vh = document.documentElement.clientHeight;
  let left = r.left + r.width / 2 - b.width / 2;
  left = Math.max(10, Math.min(left, vw - b.width - 10));
  let top = r.top - b.height - 10;
  if (top < 10) top = Math.min(r.bottom + 10, vh - b.height - 10); // không đủ chỗ phía trên thì lật xuống
  box.style.left = left + 'px';
  box.style.top = Math.max(10, top) + 'px';
}
function hideTip() { const b = $('#tipbox'); if (b) b.style.display = 'none'; }

document.addEventListener('mouseover', (e) => {
  const el = e.target.closest ? e.target.closest('[data-tip]') : null;
  if (el) showTip(el);
});
document.addEventListener('mouseout', (e) => {
  const el = e.target.closest ? e.target.closest('[data-tip]') : null;
  if (el) hideTip();
});
document.addEventListener('focusin', (e) => {
  const el = e.target.closest ? e.target.closest('[data-tip]') : null;
  if (el) showTip(el);
});
document.addEventListener('focusout', hideTip);
window.addEventListener('scroll', hideTip, true);

function log(act, obj, reason) {
  DB.audit.unshift({ at: nowStamp(), user: 'hangttm9', act, obj, reason: reason || '', ip: '10.60.12.44' });
}

window.addEventListener('hashchange', render);
render();
