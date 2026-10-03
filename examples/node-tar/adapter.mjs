#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import * as tar from 'tar';

function arg(name, fallback = undefined) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : fallback;
}

const archive = arg('--archive');
const destination = arg('--destination');
const linkPolicy = arg('--link-policy', 'allow');
const overwritePolicy = arg('--overwrite-policy', 'replace');

if (process.argv.includes('--version')) {
  const pkg = JSON.parse(
    fs.readFileSync(
      '/opt/unpackproof-node-adapter/node_modules/tar/package.json',
      'utf8',
    ),
  );
  console.log(`node=${process.version} tar=${pkg.version}`);
  process.exit(0);
}

if (!archive || !destination) {
  console.error('usage: node-tar --archive PATH --destination PATH');
  process.exit(2);
}

function safeTarget(entryPath) {
  const target = path.resolve(destination, entryPath);
  const root = path.resolve(destination);
  if (target !== root && !target.startsWith(root + path.sep)) {
    throw new Error(`path outside destination: ${entryPath}`);
  }
  return target;
}

await tar.x({
  // Policy decisions must observe the result of the previous archive member.
  sync: true,
  file: archive,
  cwd: destination,
  preservePaths: false,
  unlink: overwritePolicy === 'replace',
  filter: (entryPath, entry) => {
    const target = safeTarget(entryPath);
    if (entry.type === 'SymbolicLink' || entry.type === 'Link') {
      if (linkPolicy === 'skip') return false;
      if (linkPolicy === 'reject')
        throw new Error(`link rejected by policy: ${entryPath}`);
    }
    if (entry.type === 'File' && fs.existsSync(target)) {
      if (overwritePolicy === 'preserve') return false;
      if (overwritePolicy === 'reject')
        throw new Error(`overwrite rejected by policy: ${entryPath}`);
    }
    return true;
  },
});
