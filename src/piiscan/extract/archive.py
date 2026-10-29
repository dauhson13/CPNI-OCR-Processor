import zipfile
import zlib

from ..model import Child, TooLarge

MAX_MEMBER = 512 << 20
MAX_TOTAL = 2 << 30
MAX_MEMBERS = 10_000


def extract(f, name):
    with zipfile.ZipFile(f) as z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        if len(infos) > MAX_MEMBERS:
            raise TooLarge
        total = 0
        for info in infos:
            if info.flag_bits & 0x1:
                yield Child(info.filename, None, "encrypted")
                continue
            if info.file_size > MAX_MEMBER or total + info.file_size > MAX_TOTAL:
                yield Child(info.filename, None, "too_large")
                continue
            try:
                with z.open(info) as m:
                    data = m.read(MAX_MEMBER + 1)
            except NotImplementedError:
                yield Child(info.filename, None, "unsupported")
                continue
            except (zipfile.BadZipFile, zlib.error, EOFError):
                yield Child(info.filename, None, "corrupt")
                continue
            if len(data) > MAX_MEMBER:
                yield Child(info.filename, None, "too_large")
                continue
            total += len(data)
            yield Child(info.filename, data)
