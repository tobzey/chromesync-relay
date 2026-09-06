#!/usr/bin/python3
"""Secret Service bridge. OS-packaged python3-secretstorage, bounded stdin, no argv secrets."""
import re
import sys

def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ('store', 'lookup') or not re.fullmatch('[a-f0-9]{64}', sys.argv[2]):
        raise ValueError()
    import secretstorage
    connection = secretstorage.dbus_init()
    try:
        collection = secretstorage.collection.get_collection_by_alias(connection, 'default')
        if collection.is_locked():
            raise ValueError()
        attributes = {'service': 'io.chromesync.v2', 'account': sys.argv[2]}
        if sys.argv[1] == 'store':
            value = sys.stdin.buffer.read(1024 * 1024 + 1)
            if len(value) > 1024 * 1024:
                raise ValueError()
            collection.create_item('ChromeSync', attributes, value, replace=True, content_type='text/plain')
        else:
            items = list(collection.search_items(attributes))
            if len(items) != 1 or items[0].is_locked():
                raise ValueError()
            sys.stdout.buffer.write(items[0].get_secret())
    finally:
        connection.close()

if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit('Secret Service unavailable, locked, or python3-secretstorage missing')
