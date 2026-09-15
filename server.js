/* Máy chủ tĩnh tối giản cho bản demo — không cần npm install.
   Chạy: node server.js   →   http://localhost:4300 */
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 4300;
const ROOT = __dirname;
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2', '.woff': 'font/woff', '.ttf': 'font/ttf',
  '.ico': 'image/x-icon', '.map': 'application/json',
};

http.createServer((req, res) => {
  let rel = decodeURIComponent(req.url.split('?')[0]);
  if (rel.charAt(rel.length - 1) === '/') rel += 'index.html'; // /  → /index.html
  const file = path.join(ROOT, path.normalize(rel).replace(/^([/\\])+/, ''));

  if (!file.startsWith(ROOT)) { res.writeHead(403).end('Forbidden'); return; }

  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Không tìm thấy: ' + rel); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream', 'Cache-Control': 'no-store' });
    res.end(buf);
  });
}).listen(PORT, '0.0.0.0', () => {
  // 0.0.0.0 = cho phép máy khác trong mạng nội bộ truy cập.
  // Đổi lại '127.0.0.1' nếu chỉ muốn mở trên máy này.
  const os = require('os');
  const lan = [].concat(...Object.values(os.networkInterfaces()))
    .filter(i => i && i.family === 'IPv4' && !i.internal)
    .map(i => i.address);

  console.log('');
  console.log('  CMS Quản trị khóa — bản demo');
  console.log('');
  console.log('  Trên máy này :  http://localhost:' + PORT);
  lan.forEach(ip => console.log('  Trong mạng LAN:  http://' + ip + ':' + PORT));
  console.log('');
  console.log('  Gửi link LAN cho người cùng mạng công ty.');
  console.log('  Dừng: Ctrl + C');
  console.log('');
});
