"""Generate and compile a genuine x64 WiX MSI from the exact portable bundle."""
import argparse, hashlib, pathlib, re, subprocess, xml.etree.ElementTree as ET
p=argparse.ArgumentParser();p.add_argument('--stage',required=True);p.add_argument('--output',required=True);p.add_argument('--root',required=True);p.add_argument('--version',default='1.0.0');a=p.parse_args()
core_version=a.version.split('-',1)[0]
if not re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,5}',core_version):raise ValueError('MSI requires a major.minor.build numeric version')
parts=[int(part) for part in core_version.split('.')]
if parts[0]>255 or parts[1]>255 or parts[2]>65535:raise ValueError('MSI version exceeds Windows Installer bounds')
core_version='.'.join(str(part) for part in parts)
stage,root=pathlib.Path(a.stage).resolve(),pathlib.Path(a.root).resolve()
ns='http://wixtoolset.org/schemas/v4/wxs';ui='http://wixtoolset.org/schemas/v4/wxs/ui';ET.register_namespace('',ns);ET.register_namespace('ui',ui)
def element(parent,name,**attrs):return ET.SubElement(parent,'{'+ns+'}'+name,{k:str(v) for k,v in attrs.items()})
wix=ET.Element('{'+ns+'}Wix');package=element(wix,'Package',Name='IRForge Preview',Manufacturer='IRForge contributors',Version=core_version,UpgradeCode='C10F065E-DAA9-4C75-A1BC-92374208DA0E',Scope='perMachine',InstallerVersion='500')
element(package,'MajorUpgrade',DowngradeErrorMessage='A newer IRForge version is already installed.',Schedule='afterInstallInitialize')
element(package,'MediaTemplate',EmbedCab='yes',CompressionLevel='high')
programs=element(package,'StandardDirectory',Id='ProgramFiles64Folder');install=element(programs,'Directory',Id='INSTALLFOLDER',Name='IRForge')
directories={'':install};components=[]
for file in sorted(stage.rglob('*')):
    if not file.is_file():continue
    relative=file.relative_to(stage);parent=''
    for part in relative.parts[:-1]:
        key=(parent+'/'+part).strip('/')
        if key not in directories:directories[key]=element(directories[parent],'Directory',Id='D'+hashlib.sha256(key.encode()).hexdigest()[:24],Name=part)
        parent=key
    ident='C'+hashlib.sha256(str(relative).encode()).hexdigest()[:24];component=element(directories[parent],'Component',Id=ident,Guid='*',Bitness='always64')
    element(component,'File',Id='F'+ident[1:],Source=str(file),KeyPath='yes');components.append(ident)
feature=element(package,'Feature',Id='Core',Title='Interactive agent, desktop GUI and collector',Level='1',AllowAbsent='no')
for ident in components:element(feature,'ComponentRef',Id=ident)
# Separate optional service binary owns SCM registration; never auto-starts.
service=element(install,'Component',Id='ServiceBinary',Guid='*',Bitness='always64')
element(service,'File',Id='ServiceExe',Source=str(stage/'irforge.exe'),Name='irforge_service.exe',KeyPath='yes')
element(service,'ServiceInstall',Id='IRForgeSCM',Name='IRForge',DisplayName='IRForge Endpoint Evidence Agent',Description='Visible read-only endpoint evidence collection; no remote execution or remediation.',Type='ownProcess',Start='demand',ErrorControl='normal',Account='LocalSystem',Arguments='service run --config "[CommonAppDataFolder]IRForge\\agent-config.json" --data-dir "[CommonAppDataFolder]IRForge" --rules "[INSTALLFOLDER]rules\\internal"',Vital='yes')
element(service,'ServiceControl',Id='IRForgeServiceControl',Name='IRForge',Stop='both',Remove='uninstall',Wait='yes')
optional=element(package,'Feature',Id='AgentService',Title='Optional Windows Service (manual start)',Description='Registers only IRForge with SCM. Does not start collection. Evidence is retained on uninstall.',Level='200')
element(optional,'ComponentRef',Id='ServiceBinary')
data=element(package,'StandardDirectory',Id='CommonAppDataFolder');data=element(data,'Directory',Id='AgentData',Name='IRForge')
dc=element(data,'Component',Id='ProtectedData',Guid='5B0CB765-0E9C-4B9C-AD91-4A49AB9C8C94',Bitness='always64',Permanent='yes',NeverOverwrite='yes')
folder=element(dc,'CreateFolder');element(folder,'PermissionEx',Sddl='D:P(A;;FA;;;SY)(A;;FA;;;BA)')
element(dc,'RegistryValue',Root='HKLM',Key='Software\\IRForge',Name='DataDirectory',Value='[AgentData]',Type='string',KeyPath='yes')
element(optional,'ComponentRef',Id='ProtectedData')
config_component=element(data,'Component',Id='PersistentAgentConfig',Guid='5A0EB434-CC92-41D2-BB20-BEC9813A3C7B',Bitness='always64',Permanent='yes',NeverOverwrite='yes')
element(config_component,'File',Id='AgentConfig',Source=str(stage/'config/service-msi.json'),Name='agent-config.json',KeyPath='yes')
element(optional,'ComponentRef',Id='PersistentAgentConfig')
marker=root/'build/service-data-marker.json';marker.write_text('{"application":"IRForge","schema_version":1,"installer_created":true}')
marker_component=element(data,'Component',Id='ServiceDataMarker',Guid='721A4A99-2244-4F62-AED2-C91480D4CB35',Bitness='always64',Permanent='yes',NeverOverwrite='yes')
element(marker_component,'File',Id='ServiceDataMarkerFile',Source=str(marker),Name='IRForge.service-data.json',KeyPath='yes')
element(optional,'ComponentRef',Id='ServiceDataMarker')
menu=element(package,'StandardDirectory',Id='ProgramMenuFolder');menu=element(menu,'Directory',Id='IRForgeMenu',Name='IRForge')
shortcut=element(menu,'Component',Id='MenuShortcut',Guid='*',Bitness='always64')
element(shortcut,'Shortcut',Id='DesktopUI',Name='IRForge Evidence UI',Target='[INSTALLFOLDER]IRForgeUI.exe',WorkingDirectory='INSTALLFOLDER')
element(shortcut,'RemoveFolder',Id='RemoveIRForgeMenu',On='uninstall');element(shortcut,'RegistryValue',Root='HKLM',Key='Software\\IRForge',Name='Installed',Type='integer',Value='1',KeyPath='yes');element(feature,'ComponentRef',Id='MenuShortcut')
ET.SubElement(package,'{'+ui+'}WixUI',{'Id':'WixUI_FeatureTree'})
license_text=(root/'LICENSE').read_text();license_rtf=root/'build/installer-license.rtf';license_rtf.write_text('{\\rtf1\\ansi '+license_text.replace('\\','\\\\').replace('{','\\{').replace('}','\\}').replace('\n','\\par\n')+'}',encoding='ascii')
element(package,'WixVariable',Id='WixUILicenseRtf',Value=str(license_rtf))
source=root/'build/IRForge-installer.wxs';ET.ElementTree(wix).write(source,encoding='utf-8',xml_declaration=True)
command=[str(root/'build/dependencies/wix/wix.exe'),'build',str(source),'-arch','x64','-ext','WixToolset.UI.wixext/6.0.2','-out',str(pathlib.Path(a.output).resolve()),'-intermediatefolder',str(root/'build/wix-intermediate')]
subprocess.run(command,cwd=root,check=True)
print('Built genuine MSI; clean-VM install/upgrade/uninstall validation is NOT RUN.')
