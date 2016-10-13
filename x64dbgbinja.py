from binaryninja import *
import os, sqlite3, traceback


def get_module_name(view):
    filename = view.file.filename
    if filename.endswith(".bndb"):
        try:
            conn = sqlite3.connect(filename)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM global WHERE name='filename'")
            _, rawfilename = cursor.fetchone()
            filename = rawfilename[5:-2]
        except:
            pass
    return os.path.basename(filename)


def export_db(view):
    db = {}
    module = get_module_name(view)
    base = view.start
    dbext = "dd%d" % (view.arch.default_int_size * 8)

    file = get_save_filename_input("Export database", "*.%s" % dbext, "%s.%s" %
                                   (module, dbext))
    if not file:
        return
    print "Exporting database %s" % file

    print "Exporting symbols"
    db["labels"] = [{
        "text": symbol.name,
        "manual": False,
        "module": module,
        "address": "0x%X" % (symbol.address - base)
    } for symbol in view.get_symbols()]
    print "%d label(s) exported" % len(db["labels"])

    db["comments"] = [{
        "text": func.comments[comment].replace("{", "{{").replace("}", "}}"),
        "manual": False,
        "module": module,
        "address": "0x%X" % (comment - base)
    } for func in view.functions for comment in func.comments]
    print "%d comment(s) exported" % len(db["comments"])

    with open(file, "w") as outfile:
        json.dump(db, outfile, indent=1)
    print "Done!"


def import_db(view):
    db = {}
    module = get_module_name(view)
    base = view.start

    file = get_open_filename_input("Import database", "*.dd%d" %
                                   (view.arch.default_int_size * 8))
    if not file:
        return
    print "Importing database %s" % file

    with open(file) as dbdata:
        db = json.load(dbdata)

    count = 0
    labels = db.get("labels", [])
    for label in labels:
        try:
            if label["module"] != module:
                continue
            address = int(label["address"], 16) + base
            name = label["text"]
            symbol = view.get_symbol_at(address)
            if not symbol or symbol.name != name:
                view.define_user_symbol(Symbol(FunctionSymbol, address, name))
                count += 1
        except:
            traceback.print_exc()
            pass
    print "%d/%d label(s) imported" % (count, len(labels))

    count = 0
    comments = db.get("comments", [])
    for comment in comments:
        try:
            if comment["module"] != module:
                continue
            address = int(comment["address"], 16) + base
            comment = comment["text"]
            for func in view.functions:
                func.set_comment(address, comment)
            count += 1
        except:
            traceback.print_exc()
            pass
    print "%d/%d comment(s) imported" % (count, len(comments))

    print "Done!"


PluginCommand.register("Export x64dbg database", "Export x64dbg database",
                       export_db)
PluginCommand.register("Import x64dbg database", "Import x64dbg database",
                       import_db)