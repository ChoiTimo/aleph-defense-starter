// 공개 전 비밀값 검사입니다. 키처럼 보이는 문자열이 있으면 위치만 알리고 값은 출력하지 않습니다.
import { execFileSync } from 'node:child_process';
import { lstatSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const PATTERNS = [
  ['Supabase 서버 키', /\bsb_secret_[A-Za-z0-9_-]{16,}/u],
  ['JWT(서비스 키 등)', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/u],
  ['개인키', /-----BEGIN [A-Z ]*PRIVATE KEY-----/u],
  ['비밀번호가 든 DB 주소', /\bpostgres(?:ql)?:\/\/[^\s:@/]+:[^\s@/]+@/u],
  ['API 키', /\bsk-[A-Za-z0-9]{20,}/u],
];

export function findSecrets(files) {
  const found = [];
  for (const [name, text] of files) {
    for (const [label, pattern] of PATTERNS) {
      if (pattern.test(text)) found.push(`${name}: ${label}`);
    }
  }
  return found;
}

export function readFolder(folder, base = folder) {
  return readdirSync(folder).flatMap((entry) => {
    const path = join(folder, entry);
    return statSync(path).isDirectory() ? readFolder(path, base)
      : [[relative(base, path), readFileSync(path, 'utf8')]];
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const root = resolve(import.meta.dirname, '..');
  const tracked = execFileSync('git', ['-C', root, 'ls-files'], { encoding: 'utf8' })
    .split('\n')
    .filter((name) => name && name !== 'package-lock.json' && lstatSync(join(root, name)).isFile());
  const found = findSecrets(tracked.map((name) => [name, readFileSync(join(root, name), 'utf8')]));
  if (found.length) {
    console.error(`비밀값으로 보이는 문자열 ${found.length}곳(값은 출력하지 않음):\n${found.join('\n')}`);
    process.exitCode = 1;
  } else {
    console.log(`비밀값 검사 통과: Git 추적 파일 ${tracked.length}개에서 키처럼 보이는 문자열이 없습니다.`);
  }
}
