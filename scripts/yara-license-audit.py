"""Retain license texts from every registry crate in the pinned upstream Cargo.lock."""
import concurrent.futures,hashlib,io,json,pathlib,tarfile,time,tomllib,urllib.request
root=pathlib.Path(__file__).resolve().parent.parent;deps=root/'build/dependencies';source=deps/'yara-source/yara-x-1.21.0';output=root/'assets/licenses/yara-transitive';output.mkdir(parents=True,exist_ok=True)
lock=tomllib.loads((source/'Cargo.lock').read_text());crates=[p for p in lock['package'] if p.get('source','').startswith('registry+')]
def audit(crate):
    name,version=crate['name'],crate['version'];archive=deps/'crates'/f'{name}-{version}.crate';archive.parent.mkdir(exist_ok=True)
    if not archive.exists():
        for attempt in range(3):
            try:
                with urllib.request.urlopen(f'https://static.crates.io/crates/{name}/{name}-{version}.crate',timeout=30) as response:archive.write_bytes(response.read(32*1048576))
                break
            except Exception:
                if attempt==2:raise
                time.sleep(attempt+1)
    data=archive.read_bytes();assert hashlib.sha256(data).hexdigest()==crate['checksum'],name
    texts=[];metadata={}
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as tar:
        for member in tar.getmembers():
            if not member.isfile() or member.size>2*1048576:continue
            path=pathlib.PurePosixPath(member.name);leaf=path.name.upper()
            if path.name=='Cargo.toml' and len(path.parts)==2:metadata=tomllib.loads(tar.extractfile(member).read().decode())['package']
            if leaf.startswith(('LICENSE','LICENCE','COPYING','COPYRIGHT','NOTICE')):
                destination=output/f'{name}-{version}'/pathlib.Path(*path.parts[1:]);assert '..' not in path.parts
                destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(tar.extractfile(member).read());texts.append(str(destination.relative_to(output)).replace('\\','/'))
    return {'name':name,'version':version,'checksum':crate['checksum'],'license':metadata.get('license'),'license_files':texts,'source':'https://static.crates.io/crates/'+name+'/'+name+'-'+version+'.crate'}
with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:results=list(pool.map(audit,crates))
(output/'locked-crates.json').write_text(json.dumps({'upstream':'YARA-X 1.21.0','scope':'conservative all registry crates in Cargo.lock; includes unbuilt platforms/features','packages':results},indent=2))
print(f'{len(results)} pinned crate checksums verified; {sum(len(p["license_files"]) for p in results)} license/notice texts retained.')
