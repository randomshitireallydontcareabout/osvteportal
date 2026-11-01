import importlib.util
from importlib.machinery import SourceFileLoader
import json
import sys
import traceback
from pathlib import Path
import customtkinter as ctk

BASE=Path(__file__).resolve().parent
LIBRARY=BASE/'WorkInstructions'
INK='#07111D'; PANEL='#0A1A2A'; CARD='#0D2235'; HOVER='#12304A'; LINE='#173A55'
BLUE='#0D7CC1'; CYAN='#22B8EE'; TEXT='#F3F7FB'; MUTED='#9BB3C7'; DANGER='#FF6B6B'

def discover_presentations():
    """Return every valid component folder. Folders beginning with _ are templates."""
    items=[]
    LIBRARY.mkdir(exist_ok=True)
    for folder in sorted((p for p in LIBRARY.iterdir() if p.is_dir() and not p.name.startswith('_')), key=lambda p:p.name.lower()):
        manifest=folder/'component.json'
        if not manifest.is_file(): continue
        try: data=json.loads(manifest.read_text(encoding='utf-8'))
        except Exception: continue
        entry=folder/str(data.get('entrypoint','presentation.wi'))
        if not entry.is_file(): continue
        items.append({'folder':folder,'entry':entry,'name':str(data.get('name') or folder.name.replace('_',' ')),
          'description':str(data.get('description') or 'Interactive work instruction'),
          'category':str(data.get('category') or 'COMPONENT'),'revision':str(data.get('revision') or ''),
          'order':int(data.get('order',999))})
    return sorted(items,key=lambda x:(x['order'],x['name'].lower()))

class PresentationLibrary:
    def __init__(self,parent,master_root=None):
        self.parent=parent; self.master_root=master_root; self.active=None
        parent.configure(fg_color=INK); parent.grid_rowconfigure(0,weight=1); parent.grid_columnconfigure(0,weight=1)
        self.show_library()
    def clear(self):
        for child in self.parent.winfo_children(): child.destroy()
        self.active=None
    def show_library(self):
        self.clear()
        shell=ctk.CTkScrollableFrame(self.parent,fg_color=INK,corner_radius=0,scrollbar_button_color=INK)
        shell.grid(row=0,column=0,sticky='nsew'); shell.grid_columnconfigure((0,1),weight=1,uniform='wi')
        hero=ctk.CTkFrame(shell,fg_color=PANEL,corner_radius=20,border_width=1,border_color=LINE)
        hero.grid(row=0,column=0,columnspan=2,sticky='ew',padx=18,pady=(18,22))
        ctk.CTkLabel(hero,text='OSV TRAINING LIBRARY',text_color=CYAN,font=('Segoe UI',11,'bold')).pack(anchor='w',padx=28,pady=(24,5))
        ctk.CTkLabel(hero,text='Work Instruction Presentations',text_color=TEXT,font=('Segoe UI',30,'bold')).pack(anchor='w',padx=28)
        ctk.CTkLabel(hero,text='Select a component to open its clear, step-by-step trainee guide.',text_color=MUTED,font=('Segoe UI',12)).pack(anchor='w',padx=28,pady=(6,24))
        items=discover_presentations()
        if not items:
            ctk.CTkLabel(shell,text='No component presentations found. Copy _TEMPLATE_COMPONENT to add one.',text_color=MUTED,font=('Segoe UI',14)).grid(row=1,column=0,columnspan=2,pady=80)
        for i,item in enumerate(items):
            card=ctk.CTkFrame(shell,fg_color=CARD,corner_radius=18,border_width=1,border_color=LINE)
            card.grid(row=1+i//2,column=i%2,sticky='nsew',padx=9,pady=9)
            ctk.CTkLabel(card,text=item['category'],fg_color='#0A4669',corner_radius=7,text_color=CYAN,font=('Segoe UI',9,'bold'),height=24).pack(anchor='w',padx=22,pady=(22,12))
            ctk.CTkLabel(card,text=item['name'],text_color=TEXT,font=('Segoe UI',20,'bold'),anchor='w',justify='left',wraplength=360).pack(fill='x',padx=22)
            ctk.CTkLabel(card,text=item['description'],text_color=MUTED,font=('Segoe UI',11),anchor='w',justify='left',wraplength=360).pack(fill='x',padx=22,pady=(7,4))
            if item['revision']: ctk.CTkLabel(card,text=item['revision'],text_color=CYAN,font=('Segoe UI',10,'bold')).pack(anchor='w',padx=22,pady=(3,8))
            ctk.CTkButton(card,text='OPEN PRESENTATION  →',height=38,fg_color=BLUE,hover_color=CYAN,command=lambda x=item:self.open_item(x)).pack(fill='x',padx=22,pady=(12,20))
    def open_item(self,item):
        self.clear()
        wrapper=ctk.CTkFrame(self.parent,fg_color=INK,corner_radius=0)
        wrapper.grid(row=0,column=0,sticky='nsew'); wrapper.grid_rowconfigure(1,weight=1); wrapper.grid_columnconfigure(0,weight=1)
        bar=ctk.CTkFrame(wrapper,fg_color=PANEL,corner_radius=0,height=52); bar.grid(row=0,column=0,sticky='ew'); bar.grid_propagate(False)
        ctk.CTkButton(bar,text='←  ALL WORK INSTRUCTIONS',width=190,fg_color='transparent',border_width=1,border_color=LINE,hover_color=HOVER,command=self.show_library).pack(side='left',padx=16,pady=9)
        ctk.CTkLabel(bar,text=item['name'],text_color=TEXT,font=('Segoe UI',14,'bold')).pack(side='left',padx=8)
        host=ctk.CTkFrame(wrapper,fg_color=INK,corner_radius=0); host.grid(row=1,column=0,sticky='nsew'); host.grid_rowconfigure(0,weight=1); host.grid_columnconfigure(0,weight=1)
        try:
            module_name='wi_component_'+str(abs(hash(str(item['entry'].resolve()))))
            loader=SourceFileLoader(module_name, str(item['entry']))
            spec=importlib.util.spec_from_loader(module_name, loader); module=importlib.util.module_from_spec(spec)
            sys.modules[module_name]=module; spec.loader.exec_module(module)
            factory=getattr(module,'create_embedded_app',None)
            if not callable(factory): raise RuntimeError('presentation.wi must define create_embedded_app(parent, master_root=None).')
            self.active=factory(host,self.master_root)
        except Exception as exc:
            traceback.print_exc(); ctk.CTkLabel(host,text='PRESENTATION COULD NOT OPEN',text_color=DANGER,font=('Segoe UI',20,'bold')).pack(pady=(100,12))
            ctk.CTkLabel(host,text=str(exc),text_color=MUTED,wraplength=760).pack()

def create_embedded_app(parent,master_root=None): return PresentationLibrary(parent,master_root)
if __name__=='__main__':
    ctk.set_appearance_mode('dark'); root=ctk.CTk(); root.title('stockcode Work Instruction'); root.geometry('1320x850'); root.minsize(980,650)
    root.grid_rowconfigure(0,weight=1); root.grid_columnconfigure(0,weight=1); host=ctk.CTkFrame(root,fg_color=INK,corner_radius=0); host.grid(row=0,column=0,sticky='nsew')
    create_embedded_app(host,root); root.mainloop()
