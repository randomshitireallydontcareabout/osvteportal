from pathlib import Path
p=Path('mrs_app/features/tools_portal/routes.py')
s=p.read_text(encoding='utf-8')
needle="   'micron': {'label':'Micron DDR4 Tester','folder':root/'wi_micron_ddr4','endpoint':'wi_micron_ddr4.index'},\n"
addition=needle+"   'samsung_ddr5': {'label':'Samsung DDR5 OSV','folder':root/'wi_samsung_ddr5','endpoint':'wi_samsung_ddr5.index'},\n   'delta_psu': {'label':'Delta PSU Tester','folder':root/'wi_delta_psu','endpoint':'wi_delta_psu.index'},\n   'liteon_psu': {'label':'Liteon PSU Tester','folder':root/'wi_liteon_psu','endpoint':'wi_liteon_psu.index'},\n"
if "'samsung_ddr5':" not in s:
    if needle not in s: raise SystemExit('Could not find _wi_catalog() Micron entry in routes.py')
    p.write_text(s.replace(needle,addition,1),encoding='utf-8')
print('Work Instruction editor catalog updated.')
