import json, sys
def load_lenient(path):
    raw = open(path, encoding="utf-8", errors="replace").read()
    out, in_str, escaped = [], False, False
    for c in raw:
        if in_str:
            if escaped: out.append(c); escaped = False
            elif c == "\\": out.append(c); escaped = True
            elif c == '"': in_str = False; out.append(c)
            elif ord(c) < 0x20: out.append("\\u%04x" % ord(c))
            else: out.append(c)
        else:
            if c == '"': in_str = True
            out.append(c)
    return json.loads("".join(out))
if __name__ == "__main__":
    d = load_lenient(sys.argv[1])
    print(json.dumps(d, indent=2, ensure_ascii=False))
