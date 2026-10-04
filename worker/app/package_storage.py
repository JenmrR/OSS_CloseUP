"""Lockfile package occurrences + Syft declared-license enrichment (not Finding normalization)."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
from uuid import UUID

from psycopg.types.json import Jsonb

DEPENDENCY_KINDS = {'dependencies':'runtime','devDependencies':'dev',
                    'optionalDependencies':'optional','peerDependencies':'peer'}


def package_name(path, entry):
    if entry.get('name'): return entry['name']
    return path.rsplit('node_modules/',1)[-1]


def resolve_dependency(parent, name, paths):
    current=parent
    while current:
        candidate=f'{current}/node_modules/{name}'
        if candidate in paths: return candidate
        current=current.rsplit('/node_modules/',1)[0] if '/node_modules/' in current else ''
    candidate=f'node_modules/{name}'
    return candidate if candidate in paths else None


def build_packages(package, lock, syft):
    entries=lock['packages']
    if not isinstance(entries,dict) or '' not in entries: raise ValueError('invalid_lock_packages')
    index=defaultdict(list)
    if syft is not None:
        if not isinstance(syft,dict) or not isinstance(syft.get('artifacts'),list): raise ValueError('invalid_syft_artifacts')
        for i,a in enumerate(syft['artifacts']):
            if a.get('type')=='npm': index[(a.get('name'),a.get('version'))].append((i,a))
    declared={n for field in DEPENDENCY_KINDS for n in package.get(field,{})}
    rows=[]
    for path,entry in entries.items():
        if not isinstance(entry,dict) or entry.get('link'): raise ValueError('unsupported_lock_entry')
        if path and (not path.startswith('node_modules/') or '..' in Path(path).parts): raise ValueError('invalid_lock_path')
        name=package_name(path,entry) if path else package.get('name',entry.get('name','uploaded-project'))
        version=entry.get('version')
        relationship='root' if not path else ('direct' if path in {f'node_modules/{n}' for n in declared} else 'indirect')
        candidates=index.get((name,version),[])
        # Syft lock metadata lacks occurrence paths: narrow by provenance if available.
        for field in ('integrity','resolved'):
            if entry.get(field):
                candidates=[(i,a) for i,a in candidates if not a.get('metadata',{}).get(field) or a['metadata'][field]==entry[field]]
        signatures={json.dumps({'licenses':a.get('licenses',[]),'purl':a.get('purl')},sort_keys=True) for _,a in candidates}
        match='unavailable' if syft is None else ('missing' if not candidates else ('matched' if len(signatures)==1 else 'ambiguous'))
        licenses=set()
        if match=='matched':
            for lic in candidates[0][1].get('licenses',[]):
                if lic.get('type')=='declared':
                    value=lic.get('spdxExpression') or lic.get('value')
                    if isinstance(value,str) and value.strip(): licenses.add(value)
        evidence={'lockfile_path':path,'lockfile_license':entry.get('license'),
            'install_name':path.rsplit('node_modules/',1)[-1] if path else None,
            'syft_match':match,'syft_artifacts':[{'id':a.get('id'),'json_pointer':f'/artifacts/{i}',
            'licenses':a.get('licenses',[])} for i,a in candidates],
            'license_status':'known' if licenses else 'unknown'}
        rows.append(dict(path=path,name=name,version=version,relationship=relationship,
            purl=candidates[0][1].get('purl') if match=='matched' else None,
            licenses=sorted(licenses),evidence=evidence))
    edges=[];unresolved=[]
    for parent,entry in entries.items():
        declarations=package if parent=='' else entry
        for field,kind in DEPENDENCY_KINDS.items():
            for name in declarations.get(field,{}):
                child=resolve_dependency(parent,name,entries)
                if child is None: unresolved.append({'parent':parent,'name':name,'kind':kind})
                elif child != parent: edges.append((parent,child,kind))
    return rows,edges,unresolved


def load_syft(conn, scan_id, result_root):
    row=conn.execute("""SELECT a.artifact_id,a.storage_key,a.sha256,a.size_bytes
        FROM scan_artifacts a JOIN scan_tool_runs t ON t.tool_run_id=a.tool_run_id AND t.scan_id=a.scan_id
        WHERE a.scan_id=%s AND a.kind='raw_result' AND a.deleted_at IS NULL
          AND t.tool_name='syft' AND t.status='completed'
        ORDER BY t.attempt_no DESC,a.created_at DESC LIMIT 1""",(scan_id,)).fetchone()
    if row is None: return None,None
    path=(result_root/row['storage_key']).resolve()
    if not path.is_relative_to((result_root/str(scan_id)).resolve()): raise ValueError('invalid_syft_path')
    data=path.read_bytes()
    if len(data)!=row['size_bytes'] or hashlib.sha256(data).hexdigest()!=row['sha256']: raise ValueError('syft_hash_mismatch')
    return json.loads(data),str(row['artifact_id'])


def store_packages(conn, scan_id, paths, result_root, allow_running=False):
    with conn.transaction():
        scan=conn.execute('SELECT status FROM scan_runs WHERE scan_id=%s FOR UPDATE',(scan_id,)).fetchone()
        if scan is None: raise ValueError('scan_not_found')
        if not allow_running and scan['status'] in ('queued','running'): raise ValueError('scan_not_finished')
        package=json.loads(paths['package_json'].read_bytes())
        lock=json.loads(paths['package_lock'].read_bytes())
        syft,artifact_id=load_syft(conn,scan_id,result_root)
        rows,edges,unresolved=build_packages(package,lock,syft)
        ids={}
        for row in rows:
            row['evidence']['syft_artifact_id']=artifact_id
            record=conn.execute("""INSERT INTO packages
                (scan_id,name,installed_version,lockfile_path,relationship,purl,licenses,evidence)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (scan_id,lockfile_path) DO UPDATE SET
                    name=EXCLUDED.name,installed_version=EXCLUDED.installed_version,
                    relationship=EXCLUDED.relationship,purl=EXCLUDED.purl,
                    licenses=EXCLUDED.licenses,evidence=packages.evidence || EXCLUDED.evidence
                RETURNING package_id""",(scan_id,row['name'],row['version'],row['path'],row['relationship'],
                    row['purl'],row['licenses'],Jsonb(row['evidence']))).fetchone()
            ids[row['path']]=record['package_id']
        for parent,child,kind in edges:
            conn.execute("""INSERT INTO dependencies(scan_id,parent_package_id,child_package_id,dependency_kind,evidence)
                VALUES(%s,%s,%s,%s,%s) ON CONFLICT(scan_id,parent_package_id,child_package_id,dependency_kind)
                DO UPDATE SET evidence=EXCLUDED.evidence""",(scan_id,ids[parent],ids[child],kind,
                    Jsonb({'source':'package-lock.json','parent_path':parent,'child_path':child})))
        summary={'status':'completed' if syft is not None else 'partial','total_including_root':len(rows),
            'root':sum(r['relationship']=='root' for r in rows),'direct':sum(r['relationship']=='direct' for r in rows),
            'indirect':sum(r['relationship']=='indirect' for r in rows),
            'license_known':sum(bool(r['licenses']) for r in rows),'syft_available':syft is not None,
            'ambiguous_matches':sum(r['evidence']['syft_match']=='ambiguous' for r in rows),
            'dependency_edges':len(edges),'unresolved_dependencies':unresolved}
        conn.execute('UPDATE scan_runs SET tool_status=tool_status || %s WHERE scan_id=%s',
            (Jsonb({'package_storage':summary}),scan_id))
    return summary


def main():
    from .main import connect, verify_inputs, OUTPUT_ROOT
    parser=argparse.ArgumentParser(description='Store packages for an existing finished scan without rescanning')
    parser.add_argument('scan_id',type=UUID)
    args=parser.parse_args()
    with connect() as conn:
        paths=verify_inputs(conn,args.scan_id)
        print(json.dumps(store_packages(conn,args.scan_id,paths,OUTPUT_ROOT),ensure_ascii=False,indent=2))

if __name__=='__main__': main()
