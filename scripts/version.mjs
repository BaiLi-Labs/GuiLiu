import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const versionFile = path.join(root, 'internal/version/VERSION');
const packageFile = path.join(root, 'web/package.json');
const lockFile = path.join(root, 'web/package-lock.json');
const changelogFile = path.join(root, 'CHANGELOG.md');

function validate(version) {
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.exec(version);
  if (!match || match[4]?.split('.').some(id => /^\d+$/.test(id) && id.length > 1 && id.startsWith('0'))) {
    throw new Error('Use a version such as 0.2.0-dev, 0.2.0-rc.1 or 0.2.0, without a v prefix.');
  }
}

try {
  const [command = 'check', nextVersion, ...extra] = process.argv.slice(2);
  if (!['check', 'set'].includes(command) || extra.length) throw new Error('Usage: node scripts/version.mjs check [expected-version] | set <version>');
  const pkg = JSON.parse(readFileSync(packageFile, 'utf8'));
  const lock = JSON.parse(readFileSync(lockFile, 'utf8'));
  if (!lock.packages?.['']) throw new Error('package-lock.json is missing its root package metadata.');
  if (command === 'set') {
    if (!nextVersion) throw new Error('A new version is required.');
    validate(nextVersion);
    pkg.version = nextVersion;
    lock.version = nextVersion;
    lock.packages[''].version = nextVersion;
    writeFileSync(versionFile, `${nextVersion}\n`);
    writeFileSync(packageFile, `${JSON.stringify(pkg, null, 2)}\n`);
    writeFileSync(lockFile, `${JSON.stringify(lock, null, 2)}\n`);
    console.log(`Version set to ${nextVersion}. Update its CHANGELOG.md entry, then run make version-check.`);
  } else {
    const version = readFileSync(versionFile, 'utf8').trim();
    validate(version);
    for (const [label, actual] of [['web/package.json', pkg.version], ['web/package-lock.json', lock.version], ['web/package-lock.json root', lock.packages[''].version]]) {
      if (actual !== version) throw new Error(`${label} is ${actual}; expected ${version}. Run make version-set NEXT_VERSION=${version}.`);
    }
    if (nextVersion && nextVersion !== version) throw new Error(`Build version ${nextVersion} differs from the source version ${version}. Update the source version first.`);
    const heading = `## [${version}]`;
    if (!readFileSync(changelogFile, 'utf8').split(/\r?\n/).some(line => line === heading || line.startsWith(`${heading} - `))) {
      throw new Error(`CHANGELOG.md has no entry for ${version}.`);
    }
    console.log(`Version ${version}: source, frontend metadata and changelog agree.`);
  }
} catch (error) {
  console.error(`Version check failed: ${error.message}`);
  process.exitCode = 1;
}
