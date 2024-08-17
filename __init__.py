"""Binary Ninja plugin to import and export symbols and comments to x64dbg database format."""
import json
import pathlib

from binaryninja.enums import LogLevel, SymbolType
from binaryninja.interaction import get_save_filename_input, get_open_filename_input
from binaryninja.log import log
from binaryninja.plugin import PluginCommand
from binaryninja.settings import Settings

s = Settings()
s.register_group('dd', 'x64dbg Database Export')
setting = {
    'description': 'Always export comments to the x64dbg database.',
    'title': 'Export Comments',
    'default': True,
    'type': 'boolean'
}
s.register_setting('dd.comments', json.dumps(setting))
setting = {
    'description': 'Overwrite LibraryFunctionSymbol name',
    'title': 'Overwrite LibraryFunctionSymbol',
    'default': False,
    'type': 'boolean'
}
s.register_setting('dd.libfs', json.dumps(setting))
setting = {
    'description': 'Overwrite ImportedFunctionSymbol name',
    'title': 'Overwrite ImportedFunctionSymbol',
    'default': False,
    'type': 'boolean'
}
s.register_setting('dd.impfs', json.dumps(setting))


def export_db(bv):
    """Export symbols and optionally comments from Binary Ninja to an x64dbg database."""
    db = dict()
    module = pathlib.Path(bv.file.original_filename)
    dbext = 'dd{}'.format(bv.arch.default_int_size * 8)

    if not (f := get_save_filename_input('Export database', dbext, f'{module.stem}.{dbext}')):
        return
    file = pathlib.Path(f)
    log(LogLevel.InfoLog, f'Exporting database: {file}')

    # Export symbols to x64dbg labels
    db['labels'] = [
        {
            'text': symbol.name,
            'manual': not symbol.auto,
            'module': module.name.lower(),
            'address': '0x{:X}'.format(symbol.address - bv.start)
        }
        for symbol in bv.get_symbols()
    ]
    log(LogLevel.DebugLog, 'Label(s) exported: {}'.format(len(db['labels'])))

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
        log(LogLevel.DebugLog, 'Comment(s) exported: {}'.format(len(db['comments'])))

    file.write_text(json.dumps(db))
    log(LogLevel.InfoLog, 'Done!')


def import_db(bv):
    """Import x64dbg database to Binary Ninja."""
    module = pathlib.Path(bv.file.original_filename).name.lower()

    if not (f := get_open_filename_input('Import database', '*.dd{}'.format(bv.arch.default_int_size * 8))):
        return
    file = pathlib.Path(f)
    log(LogLevel.InfoLog, f'Importing database: {file}')

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
            if func.symbol.type is SymbolType.LibraryFunctionSymbol and not s.get_bool('dd.libfs'):
                continue
            if func.symbol.type is SymbolType.ImportedFunctionSymbol and not s.get_bool('dd.impfs'):
                continue
            func.name = label['text']
            count += 1
    log(LogLevel.DebugLog, 'Label(s) imported: {}/{}'.format(count, len(labels)))

    count = 0
    comments = db.get('comments', list())
    for comment in comments:
        if comment['module'] != module:
            continue
        address = int(comment['address'], 16) + bv.start
        for func in bv.get_functions_containing(address):
            func.set_comment_at(address, comment['text'])
        count += 1
    log(LogLevel.DebugLog, 'Comment(s) imported: {}/{}'.format(count, len(comments)))

    log(LogLevel.InfoLog, 'Done!')


PluginCommand.register('x64dbg\\Export database', 'Export x64dbg database', export_db)
PluginCommand.register('x64dbg\\Import database', 'Import x64dbg database', import_db)
