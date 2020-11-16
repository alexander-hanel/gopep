def cluster_sort(l):
    # source https://stackoverflow.com/a/4842897
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
        if attr["stripped"] == True:
            tt = [attr["hash_import_all"], attr["hash_import_no_main"], attr["hash_import_main"], attr["hash_file_path"]]
            yy = [attr["hash_import_all"], attr["hash_import_no_main"], attr["hash_import_main"], attr["hash_file_path"],
                 file]
        else:
            tt = [attr["hash_import_all"], attr["hash_import_no_main"], attr["hash_import_main"], attr["hash_file_path"],
                  attr["hash_itabs"]]
            yy = [attr["hash_import_all"], attr["hash_import_no_main"], attr["hash_import_main"], attr["hash_file_path"],
                  attr["hash_itabs"], file]
        if None in tt:
            nope.append(file)
            continue
        hashes.append(tt)
        samples.append(yy)
    clustered = cluster_sort(hashes)
    matches = clustered
    for c, match in enumerate(matches):
        ss = set([])
        for m in match:
            for aa in samples:
                if m in aa:
                    ss.add((aa[-1]))
        print("Cluster %s %s" % (c, ss))
    print("Nope Cluster %s" % nope)

