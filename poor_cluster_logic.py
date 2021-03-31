def cluster_sort(l):
    """
    merge list that have shared elements
    source https://stackoverflow.com/a/4842897
    """
    out = []
    while len(l) > 0:
        first, *rest = l
        first = set(first)
        lf = -1
        while len(first) > lf:
            lf = len(first)
            rest2 = []
            for r in rest:
                if len(first.intersection(set(r)))>0:
                    first |= set(r)
                else:
                    rest2.append(r)
            rest = rest2
        out.append(first)
        l = rest
    return out

def cluster(export):
    hashes = []
    samples = []
    nope = []
    for ii in export:
        file, attr = ii
        go_hash = []
        if attr["hash_import_all"]:
            go_hash.append(attr["hash_import_all"])
        if attr["hash_import_no_main"]:
            go_hash.append(attr["hash_import_no_main"])
        if attr["hash_import_main"]:
            go_hash.append(attr["hash_import_main"])
        if attr["hash_file_path"]:
            go_hash.append(attr["hash_file_path"])
        complete = go_hash.copy()
        complete.append(file)
        # skip files that don't have hash values
        if not go_hash:
            nope.append(file)
            continue
        # hashes & samples is a list of lists
        hashes.append(go_hash)
        samples.append(complete)

    clustered_matches = cluster_sort(hashes)
    cluster = {}
    for c, match in enumerate(clustered_matches):
        ss = set([])
        for m in match:
            for aa in samples:
                if m in aa:
                    ss.add((aa[-1]))
        cluster[c] = ss
    cluster["nope"] = nope
    return cluster

