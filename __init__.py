"""Binary Ninja plugin to import and export symbols and comments to x64dbg database format."""
import json
import pathlib

from binaryninja.enums import SymbolType
from binaryninja.interaction import get_save_filename_input, get_open_filename_input
from binaryninja.plugin import PluginCommand
from binaryninja.settings import Settings
from binaryninja.types import Symbol

s = Settings()
s.register_group('dd', 'x64dbg Database Export')
setting = {
    'description': 'Always export comments to the x64dbg database.',
    'title': 'Export Comments',
    'default': True,
    'type': 'boolean'
}
s.register_setting('dd.comments', json.dumps(setting))


def export_db(bv):
    """Export symbols and optionally comments from Binary Ninja to an x64dbg database."""
    db = dict()
    module = pathlib.Path(bv.file.original_filename)
    dbext = 'dd{}'.format(bv.arch.default_int_size * 8)

    if not (f := get_save_filename_input('Export database', dbext, f'{module.stem}.{dbext}')):
        return
    file = pathlib.Path(f)
    print(f'Exporting database: {file}')

    print('Exporting symbols')
    db['labels'] = [
        {
            'text': symbol.name,
            'manual': not symbol.auto,
            'module': module.name.lower(),
            'address': '0x{:X}'.format(symbol.address - bv.start)
        }
        for symbol in bv.get_symbols()
    ]
    print('Label(s) exported: {}'.format(len(db['labels'])))

    s = Settings()
    if s.get_bool('dd.comments'):
        db['comments'] = [
            {
                'text': func.comments[address].replace('{', '{{').replace('}', '}}'),
                'manual': True,
                'module': module.name.lower(),
                'address': '0x{:X}'.format(address - bv.start)
            }
            for func in bv.functions for address in func.comments
        ]
        print('Comment(s) exported: {}'.format(len(db['comments'])))

    file.write_text(json.dumps(db))
    print('Done!')


def import_db(bv):
    """Import x64dbg database to Binary Ninja."""
    module = pathlib.Path(bv.file.original_filename).name.lower()

    if not (f := get_open_filename_input('Import database', '*.dd{}'.format(bv.arch.default_int_size * 8))):
        return
    file = pathlib.Path(f)
    print(f'Importing database: {file}')

    db = json.load(file.open())

    count = 0
    labels = db.get('labels', list())
    with bv.bulk_modify_symbols():
        for label in labels:
            if label['module'] != module:
                continue
            address = int(label['address'], 16) + bv.start
            if not (func := bv.get_function_at(address)):
                continue
            if func.name == label['text']:
                continue
            func.name = label['text']
            count += 1
    print('Label(s) imported: {}/{}'.format(count, len(labels)))

    count = 0
    comments = db.get('comments', list())
    for comment in comments:
        if comment['module'] != module:
            continue
        address = int(comment['address'], 16) + bv.start
        for func in bv.get_functions_containing(address):
            func.set_comment_at(address, comment['text'])
        count += 1
    print('Comment(s) imported: {}/{}'.format(count, len(comments)))

    print('Done!')


PluginCommand.register('Export x64dbg database', 'Export x64dbg database', export_db)
PluginCommand.register('Import x64dbg database', 'Import x64dbg database', import_db)
