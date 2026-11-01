


from __future__ import annotations
import base64, json, mimetypes
import csv, io, os, re, shutil, tempfile, uuid, zipfile, datetime, calendar
from pathlib import Path
from flask import Blueprint, abort, current_app, flash, make_response, redirect, render_template, render_template_string, request, send_file, send_from_directory, session, url_for
from werkzeug.utils import secure_filename
from .dimm_core import analyze_logs, get_recommendation, manufacturer_family
from .wi_module_builder import build as build_wi_module
from ...activity_audit import audit_event
bp=Blueprint("tools_portal",__name__,template_folder="templates",static_folder="static",static_url_path="/static/tools_portal")
LOG_EXT={".txt",".log",".xml"}; FIND_EXT={".log",".html",".htm",".err",".txt",".xml"}; MAX_FILES=500; MAX_BYTES=250*1024*1024

def _core(): return __import__(current_app.import_name,fromlist=["user_can"])
def _allowed():
 c=_core(); s=session.get("active_section")
 return bool((s=="osv" and c.user_can_section("osv") and c.user_can("tools")) or (s=="te" and c.user_can_section("te") and c.user_can_te("te_tools")))
def _guard():
 if not session.get("user_id"): return redirect(url_for("login",next=request.path))
 if not _allowed(): abort(403)
def _work():
 base=Path(current_app.instance_path)/"tool_jobs"; base.mkdir(parents=True,exist_ok=True)
 return Path(tempfile.mkdtemp(prefix="job_",dir=base))
def _uploads(field,work,allowed,zip_ok=True):
 saved=[]; total=0
 for up in request.files.getlist(field):
  if not up.filename: continue
  ext=Path(up.filename).suffix.lower()
  if ext==".zip" and zip_ok:
   zp=work/(uuid.uuid4().hex+".zip"); up.save(zp)
   with zipfile.ZipFile(zp) as z:
    if len(z.infolist())>MAX_FILES: raise ValueError("ZIP has too many entries.")
    for member in z.infolist():
     if member.is_dir() or Path(member.filename).suffix.lower() not in allowed: continue
     total+=member.file_size
     if total>MAX_BYTES: raise ValueError("Extracted upload exceeds 250 MB.")
     target=work/(uuid.uuid4().hex+"_"+secure_filename(Path(member.filename).name))
     with z.open(member) as a,target.open("wb") as b: shutil.copyfileobj(a,b)
     saved.append(target)
  elif ext in allowed:
   target=work/(uuid.uuid4().hex+"_"+secure_filename(Path(up.filename).name)); up.save(target); saved.append(target)
  else: raise ValueError(f"Unsupported file: {up.filename}")
 if not saved: raise ValueError("No supported files were supplied.")
 return saved

def _read(path):
 data=path.read_bytes()
 for enc in (("utf-16","utf-16-le","utf-16-be") if b"\x00" in data[:4096] else ())+('utf-8-sig','utf-8','cp1252','latin-1'):
  try:return data.decode(enc)
  except UnicodeError: pass
 return data.decode('utf-8',errors='replace')

def register(app):
 if bp.name in app.blueprints:return
 @bp.get('/tools')
 def index():
  x=_guard()
  if x:return x
  cards=[
   dict(key='duties',name='Duties',category='Operations Calendar',description='Schedule daily duties and tester maintenance items for the live presentation.',endpoint='tools_portal.duties'),
   dict(key='dimm',name='DIMM Logs Analyzer',category='Memory Diagnostics',description='Analyze DIMM test logs, ECC events, health, trends, and recommendations.',endpoint='tools_portal.dimm'),
   dict(key='serial',name='Serial Number File Finder',category='Log Search',description='Search uploaded log folders for one or more serial numbers.',endpoint='tools_portal.serial'),
   dict(key='remote',name='OSV Remote Access',category='Remote Connections',description='Create a safe RDP connection file for a target OSV system.',endpoint='tools_portal.remote'),
   dict(key='ssh',name='OSV SSH Client',category='Remote Connections',description='Build a validated SSH connection command for use on the user workstation.',endpoint='tools_portal.ssh'),
   dict(key='wi',name='Work Instruction Presentations',category='Training',description='Open the organized work-instruction presentation library.',endpoint='tools_portal.work_instructions')]
  return render_template('tools_portal/index.html',cards=cards)
 @bp.route('/tools/duties', methods=['GET','POST'])
 def duties():
  x=_guard()
  if x:return x
  c=_core(); db=c.get_db()
  if request.method=='POST':
   action=(request.form.get('action') or 'save').strip()
   if action=='delete':
    duty_id=request.form.get('id','').strip()
    if duty_id.isdigit():
     db.execute('DELETE FROM duties WHERE id=?',(int(duty_id),)); db.commit(); flash('Duty deleted.')
    return redirect(url_for('tools_portal.duties',month=request.form.get('month','')))
   duty_date=(request.form.get('duty_date') or '').strip()
   title=(request.form.get('title') or '').strip()
   details=(request.form.get('details') or '').strip()
   duty_type=(request.form.get('duty_type') or 'General').strip()
   priority=(request.form.get('priority') or 'Normal').strip()
   tester_raw=(request.form.get('tester_id') or '').strip()
   try: datetime.datetime.strptime(duty_date,'%Y-%m-%d')
   except ValueError:
    flash('Choose a valid duty date.','error'); return redirect(url_for('tools_portal.duties'))
   if not title:
    flash('Duty title is required.','error'); return redirect(url_for('tools_portal.duties',date=duty_date))
   tester_id=int(tester_raw) if tester_raw.isdigit() else None
   db.execute('INSERT INTO duties (duty_date,title,details,duty_type,priority,tester_id,created_by,created_at) VALUES (?,?,?,?,?,?,?,?)',
              (duty_date,title[:160],details[:2000],duty_type[:40],priority[:20],tester_id,session.get('username',''),c.now_standard()))
   db.commit(); flash('Duty scheduled.')
   return redirect(url_for('tools_portal.duties',date=duty_date,month=duty_date[:7]))
  today=datetime.date.today(); selected=(request.args.get('date') or today.isoformat()).strip()
  try: selected_date=datetime.datetime.strptime(selected,'%Y-%m-%d').date()
  except ValueError: selected_date=today
  month_raw=(request.args.get('month') or selected_date.strftime('%Y-%m')).strip()
  try: month_start=datetime.datetime.strptime(month_raw+'-01','%Y-%m-%d').date()
  except ValueError: month_start=today.replace(day=1)
  cal=calendar.Calendar(firstweekday=6)
  weeks=[]
  for week in cal.monthdatescalendar(month_start.year,month_start.month):
   weeks.append([{'iso':d.isoformat(),'day':d.day,'in_month':d.month==month_start.month,'today':d==today} for d in week])
  month_prefix=month_start.strftime('%Y-%m')+'%'
  rows=db.execute("SELECT d.*, td.osv_tester, td.location FROM duties d LEFT JOIN tester_database td ON td.id=d.tester_id WHERE d.duty_date LIKE ? ORDER BY d.duty_date,d.id",(month_prefix,)).fetchall()
  by_date={}
  for row in rows: by_date.setdefault(row['duty_date'],[]).append(dict(row))
  selected_duties=by_date.get(selected_date.isoformat(),[])
  testers=db.execute('SELECT id,osv_tester,category,brand,memory_type,location,last_maintenance_date FROM tester_database ORDER BY osv_tester COLLATE NOCASE').fetchall()
  prev_month=(month_start-datetime.timedelta(days=1)).strftime('%Y-%m')
  next_month=(month_start.replace(day=28)+datetime.timedelta(days=4)).replace(day=1).strftime('%Y-%m')
  return render_template('tools_portal/duties.html',weeks=weeks,by_date=by_date,selected_date=selected_date,
                         selected_duties=selected_duties,testers=testers,month_start=month_start,
                         month_label=month_start.strftime('%B %Y'),prev_month=prev_month,next_month=next_month,today=today)
 @bp.route('/tools/dimm-logs-analyzer',methods=['GET','POST'])
 def dimm():
  x=_guard()
  if x:return x
  if request.method=='GET':return render_template('tools_portal/dimm.html')
  w=_work()
  try:
   files=_uploads('files',w,LOG_EXT); result=analyze_logs([str(p) for p in files]); rows=[]
   for h in result.get('all_dimm_health',[]) or result.get('findings',[]):
    d=h.dimm; rec=get_recommendation(h); rows.append(dict(locator=(d.device_locator or d.smbios_slot) if d else 'Unresolved',channel=d.channel if d else None,slot=d.slot if d else None,manufacturer=d.manufacturer if d else 'Unknown',family=manufacturer_family(d.manufacturer) if d else 'UNKNOWN',serial=d.serial if d else 'Unknown',part_number=d.part_number if d else 'Unknown',status=h.status,total_events=h.total_events,corrected=h.corrected,uncorrected=h.uncorrected,trend=h.trend,prediction=h.prediction,risk_score=round(float(h.risk_score or 0),2),recommendation=rec))
   report=['DIMM LOGS ANALYZER REPORT',f'Files: {len(files)}',f'Events: {result.get("total_events",0)}','']
   for r in rows: report += [f"{r['locator']} | Ch {r['channel']} Slot {r['slot']}",f"{r['manufacturer']} | {r['serial']} | {r['status']} | Risk {r['risk_score']}",r['recommendation'].get('diagnosis',''),'']
   rp=w/'DIMM_Logs_Analyzer_Report.txt'; rp.write_text('\n'.join(report),encoding='utf-8'); session['tools_dimm_report']=str(rp)
   events=[dict(timestamp=e.timestamp.isoformat(sep=' ') if e.timestamp else 'Unknown',severity=e.severity,err_count=e.err_count,channel=e.channel,slot=e.slot,source_file=e.source_file,raw_line=e.raw_line) for e in result.get('events',[])]
   return render_template('tools_portal/dimm_results.html',rows=rows,events=events,system_findings=result.get('system_findings',[]),total_events=result.get('total_events',0),file_count=len(files))
  except Exception as e: shutil.rmtree(w,ignore_errors=True); flash(f'Analysis failed: {e}','error'); return redirect(url_for('tools_portal.dimm'))
 @bp.get('/tools/dimm-logs-analyzer/report')
 def dimm_report():
  x=_guard()
  if x:return x
  p=Path(session.get('tools_dimm_report',''))
  if not p.is_file(): flash('Report expired. Run the analyzer again.','error'); return redirect(url_for('tools_portal.dimm'))
  return send_file(p,as_attachment=True,download_name='DIMM_Logs_Analyzer_Report.txt')
 @bp.route('/tools/serial-number-file-finder',methods=['GET','POST'])
 def serial():
  x=_guard()
  if x:return x
  if request.method=='GET':return render_template('tools_portal/serial.html')
  w=_work()
  try:
   files=_uploads('files',w,FIND_EXT); serials=[re.sub(r'[^A-Za-z0-9]','',s).upper() for s in re.split(r'[\s,;]+',request.form.get('serials','')) if s.strip()]; serials=list(dict.fromkeys(s for s in serials if s))
   if not serials: raise ValueError('Enter at least one serial number.')
   found=[]
   for p in files:
    text_norm=re.sub(r'[^A-Za-z0-9]','',_read(p)).upper(); hits=[s for s in serials if s in text_norm]
    if hits: found.append(dict(file=p.name.split('_',1)[-1],hits=hits,size=p.stat().st_size))
   return render_template('tools_portal/serial_results.html',found=found,serials=serials,file_count=len(files))
  except Exception as e: shutil.rmtree(w,ignore_errors=True); flash(f'Search failed: {e}','error'); return redirect(url_for('tools_portal.serial'))
 @bp.route('/tools/osv-remote-access',methods=['GET','POST'])
 def remote():
  x=_guard()
  if x:return x
  if request.method=='GET':return render_template('tools_portal/remote.html')
  host=request.form.get('host','').strip(); user=request.form.get('username','').strip(); port=request.form.get('port','3389').strip()
  if not re.fullmatch(r'[A-Za-z0-9._:-]+',host) or not port.isdigit(): flash('Enter a valid host and port.','error'); return redirect(url_for('tools_portal.remote'))
  content=f"full address:s:{host}:{port}\nprompt for credentials:i:1\nauthentication level:i:2\nusername:s:{user}\nredirectclipboard:i:1\nredirectdrives:i:0\n"
  response=make_response(content); response.headers['Content-Type']='application/x-rdp'; response.headers['Content-Disposition']='attachment; filename=OSV_Remote_Access.rdp'; return response
 @bp.route('/tools/osv-ssh-client',methods=['GET','POST'])
 def ssh():
  x=_guard()
  if x:return x
  command=None
  if request.method=='POST':
   host=request.form.get('host','').strip(); user=request.form.get('username','').strip(); port=request.form.get('port','22').strip()
   if re.fullmatch(r'[A-Za-z0-9._:-]+',host) and re.fullmatch(r'[A-Za-z0-9._-]*',user) and port.isdigit(): command=f"ssh -p {port} {user+'@' if user else ''}{host}"
   else: flash('Enter a valid SSH host, user, and port.','error')
  return render_template('tools_portal/ssh.html',command=command)
 def _wi_catalog():
  root=Path(app.root_path)/'features'
  items={
   'fpga': {'label':'Quanta Celestial Peak FPGA','folder':root/'wi_FPGA','endpoint':'wi_fpga.index'},
   'inventec': {'label':'Inventec Motherboard Tester','folder':root/'wi_inventec_mb','endpoint':'wi_inventec_mb.index'},
   'micron': {'label':'Micron DDR4 Tester','folder':root/'wi_micron_ddr4','endpoint':'wi_micron_ddr4.index'},
   'samsung_ddr5': {'label':'Samsung DDR5 OSV','folder':root/'wi_samsung_ddr5','endpoint':'wi_samsung_ddr5.index'},
   'delta_psu': {'label':'Delta PSU Tester','folder':root/'wi_delta_psu','endpoint':'wi_delta_psu.index'},
   'liteon_psu': {'label':'Liteon PSU Tester','folder':root/'wi_liteon_psu','endpoint':'wi_liteon_psu.index'},
  }
  for folder in root.glob('wi_*'):
   meta_path=folder/'metadata.json'
   if not meta_path.is_file(): continue
   try: meta=json.loads(meta_path.read_text(encoding='utf-8'))
   except (OSError,ValueError): continue
   key=str(meta.get('key') or folder.name[3:])
   items[key]={'label':meta.get('title') or key,'folder':folder,'endpoint':'tools_portal.uploaded_work_instruction','generated':True,'meta':meta}
  return items
 def _can_edit_wi():
  if session.get('is_admin'): return True
  row=_core().get_db().execute('SELECT allowed FROM work_instruction_editors WHERE user_id=?',(session.get('user_id'),)).fetchone()
  return bool(row and row['allowed'])
 @bp.get('/tools/work-instructions')
 def work_instructions():
  x=_guard()
  if x:return x
  return render_template('tools_portal/work_instructions.html',can_edit_wi=_can_edit_wi(),uploaded_wis=[item['meta'] for item in _wi_catalog().values() if item.get('generated')])
 @bp.route('/tools/work-instructions/add',methods=['GET','POST'])
 def add_work_instruction():
  x=_guard()
  if x:return x
  if not _can_edit_wi(): abort(403)
  if request.method=='POST':
   try:
    key,folder=build_wi_module(app,request.files.get('wi_file'),request.form.get('component_name',''),request.form.get('category','COMPONENT'),request.form.get('accent','#00b7e8'))
    audit_event(session,'WI_MODULE_CREATED',details={'wi_key':key,'folder':folder},method=request.method,path=request.path,endpoint=request.endpoint or '',ip_address=request.remote_addr or '')
    flash(f'Created and integrated {folder}.','success')
    return redirect(url_for('tools_portal.uploaded_work_instruction',wi_key=key))
   except Exception as exc: flash(str(exc),'error')
  return render_template('tools_portal/work_instruction_upload.html')
 @bp.get('/tools/work-instructions/uploaded/<wi_key>')
 def uploaded_work_instruction(wi_key):
  x=_guard()
  if x:return x
  item=_wi_catalog().get(wi_key)
  if not item or not item.get('generated'): abort(404)
  data=json.loads((item['folder']/'data.json').read_text(encoding='utf-8'))
  for step in data.get('steps',[]):
   for point in step.get('items',[]):
    if isinstance(point,dict):
     point['images']=[url_for('tools_portal.uploaded_wi_file',wi_key=wi_key,filename=image) if isinstance(image,str) and image.startswith('static/') else image for image in point.get('images',[])]
  template=(item['folder']/'templates'/item['folder'].name/'index.html').read_text(encoding='utf-8')
  return render_template_string(template,component=data['component'],steps=data['steps'],wi_key=wi_key)
 @bp.get('/tools/work-instructions/uploaded/<wi_key>/file/<path:filename>')
 def uploaded_wi_file(wi_key,filename):
  x=_guard()
  if x:return x
  item=_wi_catalog().get(wi_key)
  if not item or not item.get('generated'): abort(404)
  return send_from_directory(item['folder'],filename)
 @bp.route('/tools/work-instructions/edit/<wi_key>',methods=['GET','POST'])
 def edit_work_instruction(wi_key):
  x=_guard()
  if x:return x
  if not _can_edit_wi(): abort(403)
  item=_wi_catalog().get(wi_key)
  if not item: abort(404)
  data_path=item['folder']/'data.json'
  data=json.loads(data_path.read_text(encoding='utf-8'))
  if request.method=='POST':
   try:
    idx=int(request.form.get('step_index','-1')); step=data['steps'][idx]
   except (ValueError,IndexError,KeyError): abort(400)
   step['title']=(request.form.get('title') or '').strip()
   step['subtitle']=(request.form.get('subtitle') or '').strip()
   step['type']=(request.form.get('type') or '').strip()
   step['warning']=(request.form.get('warning') or '').strip()
   old_items=step.get('items') or []
   try: item_count=max(0,min(int(request.form.get('item_count','0')),100))
   except (TypeError,ValueError): abort(400)
   rebuilt=[]
   allowed_mimes={'image/png','image/jpeg','image/gif','image/webp'}
   total_upload=0
   for item_pos in range(item_count):
    text=(request.form.get(f'item_text_{item_pos}') or '').strip()
    old_index_raw=(request.form.get(f'item_old_index_{item_pos}') or '').strip()
    existing=[]
    if old_index_raw.isdigit() and int(old_index_raw)<len(old_items):
     old_item=old_items[int(old_index_raw)]
     if isinstance(old_item,dict):
      existing=list(old_item.get('images') or [])
      if old_item.get('image') and old_item.get('image') not in existing: existing.append(old_item.get('image'))
    kept=[image for image_index,image in enumerate(existing) if request.form.get(f'remove_item_image_{item_pos}_{image_index}')!='1']
    for upload in request.files.getlist(f'item_images_{item_pos}'):
     if not upload or not upload.filename: continue
     raw=upload.read(8*1024*1024+1); total_upload+=len(raw)
     if len(raw)>8*1024*1024 or total_upload>32*1024*1024: abort(413)
     mime=upload.mimetype or mimetypes.guess_type(upload.filename)[0] or ''
     if mime not in allowed_mimes: abort(400)
     kept.append('data:'+mime+';base64,'+base64.b64encode(raw).decode('ascii'))
    if text or kept: rebuilt.append({'text':text,'images':kept})
   step['items']=rebuilt
   temp=data_path.with_suffix('.json.tmp'); temp.write_text(json.dumps(data,indent=2,ensure_ascii=False),encoding='utf-8'); temp.replace(data_path)
   audit_event(session,'WI_STEP_UPDATED',details={'work_instruction':wi_key,'step_index':idx,'step_title':step.get('title',''),'point_count':len(rebuilt),'image_count':sum(len(point.get('images',[])) for point in rebuilt)},method=request.method,path=request.path,endpoint=request.endpoint or '',ip_address=request.remote_addr or '')
   flash('Work instruction step updated.','success')
   return redirect(url_for('tools_portal.edit_work_instruction',wi_key=wi_key,step=idx))
  try:
   selected=int(request.args.get('step',0) or 0)
  except (TypeError,ValueError):
   selected=0
  selected=max(0,min(selected,len(data.get('steps',[]))-1))
  if not data.get('steps'): abort(500)
  return render_template('tools_portal/work_instruction_editor.html',wi_key=wi_key,wi=item,data=data,selected=selected,image_url=(lambda image: url_for('tools_portal.uploaded_wi_file',wi_key=wi_key,filename=image) if item.get('generated') and isinstance(image,str) and image.startswith('static/') else image))
 app.register_blueprint(bp)



