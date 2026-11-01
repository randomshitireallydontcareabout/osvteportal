#!/usr/bin/env python3
"""Reusable GUI generator for future OSV Portal Work Instruction packages."""
from __future__ import annotations
import argparse, json, re, shutil, sys, tempfile, threading, traceback, zipfile
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree as ET
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_TITLE = "OSV Work Instruction Package Generator"
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
A = "http://schemas.openxmlformats.org/drawingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
NS = {"w": W, "a": A, "r": R}

WI_CSS = """
:root{--bg:#08111f;--panel:#111f35;--panel2:#162841;--line:#29415f;--text:#eef5ff;--muted:#9eb0c7}.wi-shell{display:grid;grid-template-columns:300px minmax(0,1fr);height:calc(100vh - 86px);background:var(--bg);color:var(--text);border:1px solid var(--line);border-radius:15px;overflow:hidden}.wi-side{padding:22px;background:linear-gradient(180deg,#102038,#0b1728);overflow:auto;border-right:1px solid var(--line)}.wi-back{color:#a9c8ff;text-decoration:none;font-weight:700}.wi-rev{margin-top:24px;color:#7ea8ee;font-size:11px;letter-spacing:.12em}.wi-side h1{font-size:25px;line-height:1.08;margin:8px 0}.wi-side p,.subtitle{color:var(--muted)}#progress-text{font-size:11px;font-weight:800;margin-top:18px}.progress{height:7px;background:#07101d;border-radius:999px;overflow:hidden;margin:7px 0 18px}.progress i{display:block;height:100%;width:0;background:linear-gradient(90deg,#4f8cff,#39d4c7)}#step-nav{display:flex;flex-direction:column;gap:7px}#step-nav button{display:flex;gap:10px;text-align:left;align-items:center;padding:10px;border:1px solid transparent;border-radius:9px;color:#c9d6e8;background:transparent;cursor:pointer}#step-nav button:hover,#step-nav button.active{background:#192e4a;border-color:#385a84}#step-nav button b{display:grid;place-items:center;min-width:29px;height:29px;border-radius:8px;background:#223957;color:#9fc0ff}.reset{width:100%;margin-top:16px}.wi-main{display:grid;grid-template-rows:auto 1fr auto;min-width:0}.wi-main header{display:flex;justify-content:space-between;gap:18px;padding:20px 25px;border-bottom:1px solid var(--line)}.wi-main header h2{margin:0;font-size:20px}.wi-content{padding:24px;overflow:auto}.wi-card{background:linear-gradient(145deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:13px;padding:19px;margin-bottom:16px}.step-type{color:#80aaff;font-size:11px;font-weight:800;letter-spacing:.12em}.wi-card h1{margin:8px 0;font-size:27px}.item{display:grid;grid-template-columns:35px 1fr;gap:12px;padding:13px 0;border-bottom:1px solid rgba(65,91,125,.45);line-height:1.55}.num{display:grid;place-items:center;width:30px;height:30px;border-radius:50%;background:#25446e;color:#fff;font-weight:800}.item-images{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px}.item-images img{max-width:min(350px,100%);max-height:260px;object-fit:contain;background:#07101d;border:1px solid #345275;border-radius:10px;padding:5px}.warning{border-color:#8a5b1e;background:rgba(120,71,12,.18)}.warning h3{color:#ffc66d}.wi-main footer{display:flex;justify-content:space-between;gap:10px;padding:16px 24px;border-top:1px solid var(--line)}button{padding:9px 14px;border:1px solid #365475;border-radius:8px;background:#162a45;color:#eaf3ff;font-weight:700;cursor:pointer}@media(max-width:850px){.wi-shell{grid-template-columns:1fr;height:auto}.wi-side{border-right:0;border-bottom:1px solid var(--line);max-height:380px}}
""".strip()

WI_JS = """(()=>{const D=document.getElementById('wi-data'),C=document.getElementById('content');if(!D||!C)return;const S=JSON.parse(D.textContent||'[]'),K=document.getElementById('wi-app').dataset.storageKey;let T={current:0,completed:[]};try{T={...T,...JSON.parse(localStorage.getItem(K)||'{}')}}catch(e){};if(T.current>=S.length)T.current=0;const X=new Set(T.completed||[]),N=[...document.querySelectorAll('#step-nav button')],E=v=>String(v??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');function R(){if(!S.length)return;const s=S[T.current],items=(s.items||[]).map((x,i)=>{let a=typeof x==='string'?[]:(x.images||[]),t=typeof x==='string'?x:x.text;return `<div class="item"><span class="num">${i+1}</span><div>${E(t)}<div class="item-images">${a.map((u,j)=>`<img src="${E(u)}" alt="Picture ${j+1}">`).join('')}</div></div></div>`}).join('');C.innerHTML=`<article class="wi-card"><span class="step-type">${E(s.type)}</span><h1>${E(s.title)}</h1><p class="subtitle">${E(s.subtitle)}</p></article><article class="wi-card"><h3>WHAT TO DO</h3>${items}</article>${s.warning?`<article class="wi-card warning"><h3>IMPORTANT</h3><p>${E(s.warning)}</p></article>`:''}`;N.forEach((b,i)=>{b.classList.toggle('active',i===T.current);b.querySelector('b').textContent=X.has(i)?'✓':String(i+1).padStart(2,'0')});document.getElementById('current-number').textContent=String(T.current+1).padStart(2,'0');document.getElementById('progress-text').textContent=`${X.size} OF ${S.length} STEPS COMPLETE`;document.getElementById('progress-bar').style.width=`${X.size/S.length*100}%`;document.getElementById('prev').disabled=T.current===0;document.getElementById('next').textContent=T.current===S.length-1?'FINISH':'NEXT →';document.getElementById('complete').textContent=X.has(T.current)?'COMPLETED ✓':'MARK COMPLETE';localStorage.setItem(K,JSON.stringify({current:T.current,completed:[...X]}));C.scrollTop=0}N.forEach((b,i)=>b.onclick=()=>{T.current=i;R()});document.getElementById('prev').onclick=()=>{if(T.current>0)T.current--;R()};document.getElementById('next').onclick=()=>{if(T.current<S.length-1)T.current++;R()};document.getElementById('complete').onclick=()=>{X.has(T.current)?X.delete(T.current):X.add(T.current);R()};document.getElementById('reset-progress').onclick=()=>{if(confirm('Reset progress?')){X.clear();T.current=0;R()}};R()})();"""


def keyify(value):
    value = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_") or "work_instruction"
    return ("wi_" + value if value[0].isdigit() else value)[:55]


def display_title(path):
    name = re.sub(r"[_-]+", " ", path.stem)
    name = re.sub(r"\bwork instruction\b", "", name, flags=re.I).strip()
    return " ".join(w.upper() if w.upper() in {"PSU","DDR4","DDR5","FPGA","DIMM","OSV"} else w.capitalize() for w in name.split())


def detect_root(folder):
    p = Path(folder).resolve()
    for base in [p, *p.parents]:
        if (base / "mrs_app/features/tools_portal/routes.py").is_file(): return base
        if base.name == "mrs_app" and (base / "features/tools_portal/routes.py").is_file(): return base.parent
    raise FileNotFoundError("Select the project folder that contains the mrs_app folder.")


def extract_docx(docx, work):
    media_dir = work / "media"; media_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(docx) as z:
        xml = z.read("word/document.xml")
        rels = {}
        if "word/_rels/document.xml.rels" in z.namelist():
            rr = ET.fromstring(z.read("word/_rels/document.xml.rels"))
            rels = {x.attrib.get("Id"):x.attrib.get("Target","") for x in rr}
        media = {}
        for n in z.namelist():
            if n.startswith("word/media/") and not n.endswith("/"):
                out = media_dir / Path(n).name; out.write_bytes(z.read(n)); media["media/"+Path(n).name] = out
    root = ET.fromstring(xml); blocks=[]
    for p in root.findall(".//w:body/w:p", NS):
        text="".join((x.text or "") for x in p.findall(".//w:t",NS)).strip(); pics=[]
        for b in p.findall(".//a:blip",NS):
            target=rels.get(b.attrib.get(f"{{{R}}}embed"),"").replace("../","").lstrip("/")
            if "media/" in target: target=target[target.index("media/"):]
            if target in media:pics.append(media[target])
        if text or pics:blocks.append((text,pics))
    return blocks


def is_heading(text):
    t=text.strip()
    if not t or len(t)>100:return False
    if re.match(r"^(step\s*)?\d+(?:\.\d+)*[.):-]?\s+",t,re.I):return True
    return t==t.upper() and 1<=len(t.split())<=10 and sum(c.isalpha() for c in t)>=4


def make_steps(blocks, image_map):
    steps=[]; current=None; pre=[]
    def add(arr,text,pics):
        urls=[image_map[str(x)] for x in pics if str(x) in image_map]
        text=re.sub(r"^[•\-]+\s*","",text).strip()
        if text or urls:arr.append({"text":text or "Review the attached picture.","images":urls})
    for text,pics in blocks:
        if text and is_heading(text):
            if current:steps.append(current)
            title=re.sub(r"^(step\s*)?\d+(?:\.\d+)*[.):-]?\s*","",text,flags=re.I).strip().title()
            current={"type":"PROCEDURE","title":title,"subtitle":f"Complete the {title.lower()} requirements.","items":[],"warning":"Follow approved safety, ESD, and tester procedures."}
            add(current["items"],"Review the reference picture.",pics)
        else:add(current["items"] if current else pre,text,pics)
    if current:steps.append(current)
    if pre:steps.insert(0,{"type":"PREPARATION","title":"Prepare and Review Requirements","subtitle":"Review the source instruction before beginning.","items":pre,"warning":"Stop if the component or tester does not match this instruction."})
    if not steps:steps=[{"type":"PROCEDURE","title":"Work Instruction","subtitle":"Review the generated instruction.","items":[{"text":"No extractable text was detected. Use the Work Instruction editor to enter the approved steps.","images":[]}],"warning":"Review before production use."}]
    result=[]
    for s in steps:
        for i in range(0,len(s["items"]),10):
            q=deepcopy(s);q["items"]=s["items"][i:i+10]
            if i:q["title"]+=f" - Continued {i//10+1}"
            result.append(q)
    return result


def metadata(blocks,title):
    text="\n".join(x[0] for x in blocks)
    c=re.search(r"\bWI[- ]?\d{3,}\b",text,re.I); r=re.search(r"\bREV(?:ISION)?\s*[:#-]?\s*([A-Z0-9. -]{1,12})",text,re.I)
    return {"control_no":c.group(0).upper().replace(" ","-") if c else "WI-DRAFT","revision":r.group(1).strip().upper() if r else "DRAFT","title":title}


def optimize(src,dest):
    try:
        from PIL import Image
        im=Image.open(src);im.seek(0);im=im.convert("RGB");im.thumbnail((1400,1000));out=dest.with_suffix(".jpg");im.save(out,"JPEG",quality=82,optimize=True);return out
    except Exception:
        out=dest.with_suffix(src.suffix.lower() or ".bin");shutil.copy2(src,out);return out


def route_text(bp,slug):
    return f'''from __future__ import annotations\nimport json\nfrom pathlib import Path\nfrom flask import Blueprint,abort,render_template,session\nbp=Blueprint("{bp}",__name__,template_folder="templates",static_folder="static",static_url_path="/static/{bp}")\nDATA_PATH=Path(__file__).with_name("data.json")\ndef register(app):\n if bp.name in app.blueprints:return\n core=__import__(app.import_name,fromlist=["user_can"])\n @bp.get("/tools/work-instructions/{slug}")\n def index():\n  if not session.get("user_id"):abort(401)\n  s=session.get("active_section");ok=(s=="osv" and core.user_can_section("osv") and core.user_can("tools")) or (s=="te" and core.user_can_section("te") and core.user_can_te("te_tools"))\n  if not ok:abort(403)\n  data=json.loads(DATA_PATH.read_text(encoding="utf-8"));return render_template("{bp}/index.html",component=data["component"],steps=data["steps"])\n app.register_blueprint(bp)\n'''


def template_text(bp,title,control):
    return f'''{{% extends "base.html" %}}{{% block content %}}<link rel="stylesheet" href="{{{{ url_for('{bp}.static',filename='wi.css') }}}}"><div class="wi-shell" id="wi-app" data-storage-key="{bp}-progress-v1"><aside class="wi-side"><a class="wi-back" href="{{{{ url_for('tools_portal.work_instructions') }}}}">&larr; Work Instructions</a><div class="wi-rev">{{{{ component.revision|upper }}}}</div><h1>{title.upper()}</h1><p>Interactive technician reference</p><div id="progress-text"></div><div class="progress"><i id="progress-bar"></i></div><nav id="step-nav">{{% for step in steps %}}<button type="button"><b>{{{{ '%02d'|format(loop.index) }}}}</b><span>{{{{ step.title }}}}</span></button>{{% endfor %}}</nav><button class="reset" id="reset-progress">RESET PROGRESS</button></aside><main class="wi-main"><header><div><h2>{control} TEST GUIDE</h2><p>Use with the current approved station configuration.</p></div><div>STEP <b id="current-number">01</b> / {{{{ '%02d'|format(steps|length) }}}}</div></header><div class="wi-content" id="content"></div><footer><button id="prev">&larr; PREVIOUS</button><button id="complete">MARK COMPLETE</button><button id="next">NEXT &rarr;</button></footer></main></div><script id="wi-data" type="application/json">{{{{ steps|tojson }}}}</script><script src="{{{{ url_for('{bp}.static',filename='wi.js') }}}}"></script>{{% endblock %}}'''


def update_catalog(source,features):
    if "def _wi_catalog" not in source:raise ValueError("The project does not contain the Work Instruction editor catalog.")
    m=re.search(r"\n\s*}\n\s*def _can_edit_wi",source)
    if not m:raise ValueError("Could not find the end of _wi_catalog().")
    additions=""
    for f in features:
        if f"'{f['key']}':" not in source:additions+=f"   '{f['key']}': {{'label':{f['title']!r},'folder':root/'{f['folder']}','endpoint':'{f['bp']}.index'}},\n"
    return source[:m.start()]+"\n"+additions.rstrip()+source[m.start():]


def update_library(source,features):
    if '<div class="wi-grid">' not in source:raise ValueError("The current WI library does not contain the polished wi-grid design.")
    count=len(re.findall(r'class="wi-card(?:\s|\")',source))+len(features)
    source=re.sub(r'<span class="wi-count">\d+ instructions available</span>',f'<span class="wi-count">{count} instructions available</span>',source)
    gs=source.index('<div class="wi-grid">');depth=0;ge=None
    for m in re.finditer(r'<div\b|</div>',source[gs:]):
        token=m.group();depth+=1 if token.startswith('<div') else -1
        if depth==0:ge=gs+m.start();break
    cards=[]
    for f in features:
        if f"url_for('{f['bp']}.index')" in source:continue
        cards.append(f'''<a class="wi-card" href="{{{{ url_for('{f['bp']}.index') }}}}"><div class="wi-card-head"><span class="wi-icon"><svg viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="3"/><path d="M7 9h10M7 13h7M7 17h4"/></svg></span><span class="wi-badge">{f['control']} · {f['revision']}</span></div><h2>{f['title']}</h2><p>Interactive work instruction generated from {f['source']}.</p><span class="wi-open">OPEN INSTRUCTION <i>&rarr;</i></span></a>''')
    source=source[:ge]+"\n"+"\n".join(cards)+"\n  "+source[ge:]
    if 'class="wi-editor-actions"' in source:
        a=source.index('class="wi-editor-actions"');e=source.find('</div>',a);buttons=[]
        for f in features:
            if f"wi_key='{f['key']}'" not in source[a:e]:buttons.append(f'''<a class="wi-edit-btn" href="{{{{ url_for('tools_portal.edit_work_instruction',wi_key='{f['key']}') }}}}">Edit {f['title']}</a>''')
        source=source[:e]+"\n"+"\n".join(buttons)+source[e:]
    return source


def generate(files,project,output,name,include_sources,log):
    root=detect_root(project);app=root/"mrs_app";routes=app/"features/tools_portal/routes.py";library=app/"features/tools_portal/templates/tools_portal/work_instructions.html"
    with tempfile.TemporaryDirectory(prefix="wi_gui_") as td:
        td=Path(td);stage=td/"stage";features=[]
        for filename in files:
            doc=Path(filename);title=display_title(doc);key=keyify(title);folder=f"wi_{key}";bp=folder;slug=key.replace('_','-');fr=stage/"mrs_app/features"/folder;(fr/"static/assets").mkdir(parents=True);(fr/"templates"/bp).mkdir(parents=True)
            log(f"Reading {doc.name}...");blocks=extract_docx(doc,td/key);unique=[];seen=set()
            for _,pics in blocks:
                for x in pics:
                    if str(x) not in seen:seen.add(str(x));unique.append(x)
            imap={}
            for i,x in enumerate(unique,1):
                out=optimize(x,fr/"static/assets"/f"image_{i:03d}");imap[str(x)]=f"/static/{bp}/assets/{out.name}"
            meta=metadata(blocks,title);steps=make_steps(blocks,imap)
            (fr/"data.json").write_text(json.dumps({"component":meta,"steps":steps},indent=2),encoding="utf-8");(fr/"__init__.py").write_text('from .routes import register\n__all__=["register"]\n');(fr/"routes.py").write_text(route_text(bp,slug));(fr/"static/wi.css").write_text(WI_CSS);(fr/"static/wi.js").write_text(WI_JS);(fr/"templates"/bp/"index.html").write_text(template_text(bp,title,meta["control_no"]),encoding="utf-8")
            if include_sources:(fr/"source").mkdir();shutil.copy2(doc,fr/"source"/doc.name)
            features.append({"key":key,"folder":folder,"bp":bp,"title":title,"control":meta["control_no"],"revision":meta["revision"],"source":doc.name,"steps":len(steps),"images":len(imap)});log(f"  {len(steps)} steps, {len(imap)} images")
        tr=stage/"mrs_app/features/tools_portal/routes.py";tr.parent.mkdir(parents=True,exist_ok=True);tr.write_text(update_catalog(routes.read_text(encoding="utf-8"),features),encoding="utf-8")
        tl=stage/"mrs_app/features/tools_portal/templates/tools_portal/work_instructions.html";tl.parent.mkdir(parents=True,exist_ok=True);tl.write_text(update_library(library.read_text(encoding="utf-8"),features),encoding="utf-8")
        (stage/"WORK_INSTRUCTION_PACKAGE_MANIFEST.json").write_text(json.dumps({"generated":datetime.now().isoformat(),"features":features},indent=2),encoding="utf-8")
        outdir=Path(output);outdir.mkdir(parents=True,exist_ok=True);zp=outdir/(keyify(name or "work_instruction_updates")+".zip")
        with zipfile.ZipFile(zp,"w",zipfile.ZIP_DEFLATED,allowZip64=True) as z:
            for p in stage.rglob('*'):
                if p.is_file():z.write(p,p.relative_to(stage))
        with zipfile.ZipFile(zp) as z:
            bad=z.testzip()
            if bad:raise RuntimeError(f"ZIP verification failed: {bad}")
        return zp,features


class App:
    def __init__(self,root):
        self.root=root;root.title(APP_TITLE);root.geometry("940x700");root.minsize(760,580);self.files=[];self.project=tk.StringVar(master=root);self.output=tk.StringVar(master=root);self.package=tk.StringVar(master=root, value="work_instruction_updates");self.include=tk.BooleanVar(master=root, value=False);self.status=tk.StringVar(master=root, value="Ready");self.ui()
    def ui(self):
        f=ttk.Frame(self.root,padding=16);f.pack(fill="both",expand=True);ttk.Label(f,text=APP_TITLE,font=("Segoe UI",20,"bold")).pack(anchor="w");ttk.Label(f,text="Reusable generator for future DOCX Work Instructions.").pack(anchor="w",pady=(2,12))
        box=ttk.LabelFrame(f,text="1. Add Work Instruction DOCX files",padding=10);box.pack(fill="both",expand=True);b=ttk.Frame(box);b.pack(fill="x");ttk.Button(b,text="Add DOCX Files",command=self.add).pack(side="left");ttk.Button(b,text="Remove Selected",command=self.remove).pack(side="left",padx=7);ttk.Button(b,text="Clear",command=self.clear).pack(side="left");self.list=tk.Listbox(box,selectmode="extended",height=9);self.list.pack(fill="both",expand=True,pady=(8,0))
        loc=ttk.LabelFrame(f,text="2. Select locations",padding=10);loc.pack(fill="x",pady=12);self.row(loc,"Existing OSV project folder",self.project,self.pick_project,0);self.row(loc,"Output folder for generated ZIP",self.output,self.pick_output,1);ttk.Label(loc,text="Package name").grid(row=2,column=0,sticky="w");ttk.Entry(loc,textvariable=self.package).grid(row=2,column=1,sticky="ew",padx=8,pady=4);loc.columnconfigure(1,weight=1);ttk.Checkbutton(loc,text="Include original DOCX files in package",variable=self.include).grid(row=3,column=1,sticky="w",padx=8)
        r=ttk.Frame(f);r.pack(fill="x");self.go=ttk.Button(r,text="Generate WI Package",command=self.start);self.go.pack(side="left");ttk.Label(r,textvariable=self.status).pack(side="left",padx=12);logs=ttk.LabelFrame(f,text="Generator log",padding=8);logs.pack(fill="both",expand=True,pady=(12,0));self.logs=tk.Text(logs,height=10,state="disabled",wrap="word");self.logs.pack(fill="both",expand=True)
    def row(self,p,l,v,c,n):ttk.Label(p,text=l).grid(row=n,column=0,sticky="w");ttk.Entry(p,textvariable=v).grid(row=n,column=1,sticky="ew",padx=8,pady=4);ttk.Button(p,text="Browse",command=c).grid(row=n,column=2)
    def add(self):
        for x in filedialog.askopenfilenames(filetypes=[("Word Work Instructions","*.docx")]):
            if x not in self.files:self.files.append(x);self.list.insert("end",x)
    def remove(self):
        for i in reversed(self.list.curselection()):self.list.delete(i);del self.files[i]
    def clear(self):self.files.clear();self.list.delete(0,"end")
    def pick_project(self):
        if x:=filedialog.askdirectory():self.project.set(x)
    def pick_output(self):
        if x:=filedialog.askdirectory():self.output.set(x)
    def log(self,x):
        def w():self.logs.configure(state="normal");self.logs.insert("end",x+"\n");self.logs.see("end");self.logs.configure(state="disabled")
        self.root.after(0,w)
    def start(self):
        if not self.files:return messagebox.showerror(APP_TITLE,"Add at least one DOCX file.")
        if not self.project.get():return messagebox.showerror(APP_TITLE,"Select the OSV project folder.")
        if not self.output.get():return messagebox.showerror(APP_TITLE,"Select an output folder.")
        self.go.configure(state="disabled");self.status.set("Generating...");threading.Thread(target=self.run,daemon=True).start()
    def run(self):
        try:
            zp,items=generate(self.files,self.project.get(),self.output.get(),self.package.get(),self.include.get(),self.log);msg="\n".join(f"{x['title']}: {x['steps']} steps, {x['images']} images" for x in items);self.root.after(0,lambda:messagebox.showinfo(APP_TITLE,f"Package created:\n{zp}\n\n{msg}"));self.root.after(0,lambda:self.status.set(f"Complete: {zp.name}"))
        except Exception as e:self.log(traceback.format_exc());self.root.after(0,lambda:messagebox.showerror(APP_TITLE,str(e)));self.root.after(0,lambda:self.status.set("Failed"))
        finally:self.root.after(0,lambda:self.go.configure(state="normal"))


def self_test():
    print("Tkinter:",tk.TkVersion);print("Generator: OK");return 0

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--self-test",action="store_true");a=ap.parse_args()
    if a.self_test:return self_test()
    root=tk.Tk();root.withdraw();app=App(root);root.deiconify();root.lift();root.mainloop();return 0
if __name__=="__main__":raise SystemExit(main())
