/**
 * 控制面进程入口
 *
 * 环境变量：
 *   LP_DATA_DIR      数据目录（默认 runtime/cloud）
 *   LP_CONTROL_PORT  监听端口（默认 18080）
 *   LP_ADMIN_TOKEN   管理端令牌（默认仅本地可用的开发令牌）
 *   LP_SEED          设为 0 时不写入演示数据
 */
import fs from 'node:fs';
import path from 'node:path';
import { createControlPlane } from './server.ts';
import { seedDemo } from './seed.ts';

const dataDir = process.env.LP_DATA_DIR ?? path.resolve('runtime/cloud');
const port = Number(process.env.LP_CONTROL_PORT ?? 18080);
// 默认只听本机：后台带管理令牌，暴露到公网前必须先换令牌、加反代与 TLS
const host = process.env.LP_CONTROL_HOST ?? '127.0.0.1';
const adminToken = process.env.LP_ADMIN_TOKEN ?? 'dev-admin-token';

fs.mkdirSync(dataDir, { recursive: true });

const plane = createControlPlane({ dataDir, port, adminToken, host });

if (process.env.LP_SEED !== '0' && plane.store.data.devices.length === 0) {
  const seeded = seedDemo(plane.store, plane.keys);
  const tokenFile = path.join(dataDir, 'enrollment-token.txt');
  fs.writeFileSync(tokenFile, seeded.enrollmentToken, 'utf8');
  console.log('──────────────────────────────────────────────');
  console.log('已写入演示数据');
  console.log(`  设备 ID     ${seeded.deviceId}`);
  console.log(`  注册令牌    ${seeded.enrollmentToken}`);
  console.log(`  令牌文件    ${tokenFile}`);
  console.log(`  管理令牌    ${adminToken}`);
  console.log('──────────────────────────────────────────────');
}

console.log(`控制面已启动 http://${host}:${port}（后台 /admin）`);
console.log('  GET  /healthz');
console.log('  POST /agent/enrollment');
console.log('  GET  /api/admin/overview  (Authorization: Bearer <admin token>)');
console.log('  GET  /admin               运营后台（浏览器打开）');
