"""Create a source archive without user data, credentials, caches or SDKs."""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import os

root = Path(__file__).resolve().parent.parent
target = root / 'artifacts' / 'crypto-pigeon-source.zip'
excluded = {'node_modules', 'dist', 'build', '.gradle', '__pycache__', '.git'}
secret_suffixes = {'.key', '.keystore', '.jks', '.p12', '.pfx', '.pem'}
root_files = ['package.json', 'package-lock.json', '.npmrc', '.gitignore',
              '.dockerignore', '.env.example', 'README.md', 'Dockerfile',
              'docker-compose.yml', 'compose.production.yml']
files = [root / name for name in root_files if (root / name).is_file()]
for folder in ['apps', 'packages', 'scripts', 'docs', 'deploy']:
    for current, directories, names in os.walk(root / folder):
        directories[:] = [name for name in directories if name not in excluded
                          and not name.startswith('.crypto_pigeon')
                          and not (name == 'ui' and Path(current).as_posix().endswith('app/src/main/assets'))]
        for name in names:
            file = Path(current) / name
            if file.name.startswith('.env') or file.name == 'local.properties':
                continue
            if file.suffix in secret_suffixes or file.name.endswith('.private.json'):
                continue
            files.append(file)
for name in ['crypto-pigeon-debug.apk', 'release-manifest.json',
             'dependency-audit-after.json', 'daemon-http-check.json']:
    file = root / 'artifacts' / name
    if file.is_file():
        files.append(file)
target.parent.mkdir(exist_ok=True)
with ZipFile(target, 'w', compression=ZIP_DEFLATED, compresslevel=9) as archive:
    for file in sorted(set(files)):
        archive.write(file, 'crypto-pigeon/' + file.relative_to(root).as_posix())
with ZipFile(target) as archive:
    assert archive.testzip() is None
    names = archive.namelist()
    assert 'crypto-pigeon/.env' not in names
    assert not any('/node_modules/' in name or '.private.json' in name for name in names)
print(f'Created {target.name}: {len(names)} files, {target.stat().st_size} bytes; archive integrity verified.')
