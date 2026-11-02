"""Verification-only extraction from the ISO linked by Microsoft Learn.

Reads ISO metadata and selected packages over bounded HTTP ranges; never executes
downloaded content. Requires pycdlib in the caller's local dependency directory.
"""
import collections
import hashlib
import io
import json
import pathlib
import re
import sys
import urllib.request

ISO_URL = ('https://software-static.download.prss.microsoft.com/dbazure/'
           '888969d5-f34g-4e03-ac9d-1f9786c66749/'
           '26100.1.240331-1435.ge_release_amd64fre_CLIENT_LOF_PACKAGES_OEM.iso')


class RemoteIso(io.RawIOBase):
    def __init__(self):
        self.position = 0
        self.size = None
        self.cache = collections.OrderedDict()
        self.transferred = 0
        self.chunk_size = 4 * 1024 * 1024
        self._chunk(0)

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        offset += self.position if whence == 1 else self.size if whence == 2 else 0
        if not 0 <= offset <= self.size:
            raise ValueError('ISO seek outside image')
        self.position = offset
        return offset

    def _chunk(self, offset):
        if offset in self.cache:
            self.cache.move_to_end(offset)
            return self.cache[offset]
        end = offset + self.chunk_size - 1
        if self.size is not None:
            end = min(end, self.size - 1)
        request = urllib.request.Request(ISO_URL, headers={
            'Range': f'bytes={offset}-{end}', 'Accept-Encoding': 'identity'})
        with urllib.request.urlopen(request, timeout=60) as response:
            if not response.url.startswith('https://software-static.download.prss.microsoft.com/'):
                raise ValueError('Unexpected media redirect')
            match = re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)', response.headers.get('Content-Range', ''))
            if response.status != 206 or not match or int(match[1]) != offset or int(match[2]) != end:
                raise ValueError('Server did not return the exact requested ISO range')
            total = int(match[3])
            if self.size is not None and total != self.size:
                raise ValueError('Media size changed')
            self.size = total
            data = response.read(self.chunk_size + 1)
            if len(data) != end - offset + 1:
                raise ValueError('Truncated or oversized ISO range')
        self.transferred += len(data)
        self.cache[offset] = data
        if len(self.cache) > 32:
            self.cache.popitem(last=False)
        print(f'ISO range {offset}-{end}; downloaded {self.transferred} bytes', flush=True)
        return data

    def read(self, size=-1):
        if size < 0 or size > 128 * 1024 * 1024:
            raise ValueError('Unbounded ISO read refused')
        size = min(size, self.size - self.position)
        answer = bytearray()
        while size:
            offset = self.position // self.chunk_size * self.chunk_size
            chunk = self._chunk(offset)
            start = self.position - offset
            take = min(size, len(chunk) - start)
            answer.extend(chunk[start:start + take])
            self.position += take
            size -= take
        return bytes(answer)


def main():
    root = pathlib.Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(root / 'python-libs'))
    import pycdlib
    output = root / 'Packages'
    output.mkdir(exist_ok=True)
    remote = RemoteIso()
    iso = pycdlib.PyCdlib()
    iso.open_fp(remote)
    found = []
    candidates = []
    for directory, _, files in iso.walk(udf_path='/'):
        for name in files:
            low = name.lower()
            if any(token in low for token in ('netfx3', 'metadata', 'deployment')):
                candidates.append(directory.rstrip('/') + '/' + name)
            if (('netfx3-ondemand-package' in low and '~amd64~' in low and
                 ('~amd64~~' in low or '~amd64~en-us~' in low)) or
                    low == 'desktopdeployment.cab'):
                found.append(directory.rstrip('/') + '/' + name)
    if '--metadata-only' in sys.argv:
        found = [name for name in candidates if name.startswith('/LanguagesAndOptionalFeatures/')
                 and ('metadata' in name.lower())]
    print('Selected packages: ' + json.dumps(found), flush=True)
    (root / 'source-candidates.json').write_text(json.dumps(candidates, indent=2))
    if '--inventory-only' in sys.argv:
        iso.close()
        return
    records = []
    for source in found:
        relative = source.removeprefix('/LanguagesAndOptionalFeatures/')
        if '..' in pathlib.PurePosixPath(relative).parts:
            raise ValueError('Unexpected package path')
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            iso.get_file_from_iso_fp(stream, udf_path=source)
        records.append({'IsoPath': source, 'File': target.name,
                        'Bytes': target.stat().st_size,
                        'Sha256': hashlib.file_digest(target.open('rb'), 'sha256').hexdigest()})
    iso.close()
    provenance = 'metadata-provenance.json' if '--metadata-only' in sys.argv else 'source-provenance.json'
    (root / provenance).write_text(json.dumps({
        'Documentation': 'https://learn.microsoft.com/en-us/azure/virtual-desktop/windows-11-language-packs',
        'IsoUrl': ISO_URL, 'IsoBytes': remote.size, 'DownloadedBytes': remote.transferred,
        'Files': records, 'Scope': 'Verification only; no host servicing or package execution'}, indent=2))
    if '--metadata-only' not in sys.argv and not any('netfx3' in record['File'].lower() for record in records):
        raise ValueError('No matching amd64 NetFx3 package found')


if __name__ == '__main__':
    main()
