from __future__ import annotations
import json,re,shutil,zipfile
from pathlib import Path
from xml.etree import ElementTree as ET
from werkzeug.utils import secure_filename
W='http://schemas.openxmlformats.org/wordprocessingml/2006/main';A='http://schemas.openxmlformats.org/drawingml/2006/main';R='http://schemas.openxmlformats.org/officeDocument/2006/relationships';NS={'w':W,'a':A,'r':R};MAX_DOCX=100*1024*1024

def slug(value): return re.sub(r'[^a-z0-9]+','_',value.lower()).strip('_')[:50]
def _extract(docx,work):
 media=work/'_media';media.mkdir(); rels={}; blocks=[]
 with zipfile.ZipFile(docx) as z:
  if 'word/document.xml' not in z.namelist(): raise ValueError('The upload is not a valid DOCX file.')
  if 'word/_rels/document.xml.rels' in z.namelist():
   for x in ET.fromstring(z.read('word/_rels/document.xml.rels')): rels[x.attrib.get('Id')]=x.attrib.get('Target','')
  files={}
  for n in z.namelist():
   if n.startswith('word/media/') and not n.endswith('/'):
    p=media/secure_filename(Path(n).name);p.write_bytes(z.read(n));files['media/'+Path(n).name]=p
  root=ET.fromstring(z.read('word/document.xml'))
 for p in root.findall('.//w:body/w:p',NS):
  text=''.join(x.text or '' for x in p.findall('.//w:t',NS)).strip();pics=[]
  for b in p.findall('.//a:blip',NS):
   target=rels.get(b.attrib.get('{%s}embed'%R),'').replace('../','').lstrip('/');target=target[target.index('media/'):] if 'media/' in target else target
   if target in files:pics.append(files[target])
  if text or pics:blocks.append((text,pics))
 return blocks

def _heading(text):
 return bool(text and len(text)<120 and (re.match(r'^(step\s*)?\d+(?:\.\d+)*[.):-]?\s+',text,re.I) or (text==text.upper() and len(text.split())<=12 and sum(c.isalpha() for c in text)>3)))
def _index(component,folder):
 return '''{% extends "base.html" %}\n{% block content %}\n<link rel="stylesheet" href="{{ url_for('tools_portal.uploaded_wi_file',wi_key=wi_key,filename='static/wi.css') }}">\n<div class="wi-shell" id="wi-app" data-storage-key="wi-'''+folder+'''-progress-v2"><aside class="wi-side"><a class="wi-back" href="{{ url_for('tools_portal.work_instructions') }}">&larr; Work Instructions</a><div class="wi-rev">{{ component.control_no }} {{ component.revision|upper }}</div><h1>{{ component.name|upper }}<br>TEST GUIDE</h1><p>Interactive trainee reference</p><div id="progress-text"></div><div class="progress"><i id="progress-bar"></i></div><nav id="step-nav">{% for step in steps %}<button type="button" data-step="{{ loop.index0 }}"><b>{{ '%02d'|format(loop.index) }}</b><span>{{ step.title }}</span></button>{% endfor %}</nav><button class="reset" id="reset-progress">RESET PROGRESS</button></aside><main class="wi-main"><header><div><h2>{{ component.name|upper }} OSV TESTER</h2><p>Use this guide with the current controlled work instruction</p></div><span id="step-counter"></span></header><section id="step-content"></section><footer><button id="prev">&larr; PREVIOUS</button><button id="complete">MARK STEP COMPLETE</button><button id="next">NEXT &rarr;</button></footer></main></div><script id="wi-data" type="application/json">{{ steps|tojson }}</script><script src="{{ url_for('tools_portal.uploaded_wi_file',wi_key=wi_key,filename='static/wi.js') }}"></script>\n{% endblock %}\n'''
def build(app,upload,component_name,category,accent):
 component=(component_name or '').strip()
 if not component:raise ValueError('Component name is required. It is used to create the wi_component_name folder.')
 if not upload or not upload.filename or Path(upload.filename).suffix.lower()!='.docx':raise ValueError('Select one approved .docx Work Instruction.')
 key=slug(component)
 if not key:raise ValueError('Enter a valid component name.')
 folder_name='wi_'+key;features=Path(app.root_path)/'features';final=features/folder_name
 if final.exists():raise ValueError(f'The folder {folder_name} already exists. Choose a different component name.')
 temp=features/('._building_'+folder_name);shutil.rmtree(temp,ignore_errors=True);temp.mkdir(parents=True)
 source=temp/secure_filename(upload.filename);upload.save(source)
 if source.stat().st_size>MAX_DOCX:shutil.rmtree(temp,ignore_errors=True);raise ValueError('DOCX exceeds the 100 MB limit.')
 blocks=_extract(source,temp);assets=temp/'static'/'assets';assets.mkdir(parents=True);image_map={};seen=[]
 for _,pics in blocks:
  for pic in pics:
   if str(pic) not in seen:seen.append(str(pic))
 for i,pic_s in enumerate(seen,1):
  pic=Path(pic_s);out=assets/f'image_{i:03d}{pic.suffix.lower()}';shutil.copy2(pic,out);image_map[pic_s]=f'static/assets/{out.name}'
 steps=[];intro=[];current=None
 def add(target,text,pics):
  images=[image_map[str(p)] for p in pics if str(p) in image_map]
  if text or images:target.append({'text':re.sub(r'^[•-]+\s*','',text).strip() or 'Review the attached picture.','images':images})
 for text,pics in blocks:
  if _heading(text):
   if current:steps.append(current)
   title=re.sub(r'^(step\s*)?\d+(?:\.\d+)*[.):-]?\s*','',text,flags=re.I).strip().title()
   current={'type':'PROCEDURE','title':title,'subtitle':f'Complete the {title.lower()} requirements.','items':[],'warning':'Follow the approved safety, ESD, and tester requirements.'};add(current['items'],'Review the reference picture.',pics)
  else:add(current['items'] if current else intro,text,pics)
 if current:steps.append(current)
 if intro:steps.insert(0,{'type':'SAFETY','title':'Verify PPE and tester readiness','subtitle':f'Prepare the work area before handling the {component}.','items':intro,'warning':'Stop if the component, fixture, or tester does not match this instruction.'})
 if not steps:steps=[{'type':'PROCEDURE','title':'Review Work Instruction','subtitle':f'Complete the approved {component} procedure.','items':[{'text':'Use the WI editor to add the approved instruction points.','images':[]}],'warning':'Review before production use.'}]
 text='\n'.join(x[0] for x in blocks);control=(re.search(r'\bWI[- ]?\d{3,}\b',text,re.I).group(0).upper().replace(' ','-') if re.search(r'\bWI[- ]?\d{3,}\b',text,re.I) else 'WI-DRAFT');rev_match=re.search(r'\bREV(?:ISION)?\s*[:#-]?\s*([A-Z0-9. -]{1,12})',text,re.I);revision=rev_match.group(1).strip().upper() if rev_match else 'DRAFT'
 accent=(accent or '#00b7e8').lower();accent=accent if re.fullmatch(r'#[0-9a-f]{6}',accent) else '#00b7e8';rgb=','.join(str(int(accent[i:i+2],16)) for i in (1,3,5))
 data={'component':{'name':component,'title':component,'control_no':control,'revision':revision},'steps':steps};(temp/'data.json').write_text(json.dumps(data,indent=2),encoding='utf-8')
 meta={'key':key,'folder':folder_name,'title':component,'category':(category or 'COMPONENT').strip().upper(),'accent':accent,'accent_rgb':rgb,'control_no':control,'revision':revision};(temp/'metadata.json').write_text(json.dumps(meta,indent=2),encoding='utf-8')
 baseline=features/'wi_micron_ddr4';shutil.copy2(baseline/'static'/'wi.css',temp/'static'/'wi.css');js=(baseline/'static'/'wi.js').read_text(encoding='utf-8').replace('wi-micron-ddr4-progress-v2',folder_name+'-progress-v2');(temp/'static'/'wi.js').write_text(js,encoding='utf-8')
 tpl=temp/'templates'/folder_name;tpl.mkdir(parents=True);(tpl/'index.html').write_text(_index(component,folder_name),encoding='utf-8')
 (temp/'__init__.py').write_text('from .routes import register\n__all__=["register"]\n',encoding='utf-8')
 (temp/'routes.py').write_text('''"""Generated WI module. The tools portal serves this module immediately; restart-safe registration is intentionally a no-op."""\ndef register(app):\n    return None\n''',encoding='utf-8')
 shutil.rmtree(temp/'_media',ignore_errors=True);temp.rename(final);return key,folder_name
