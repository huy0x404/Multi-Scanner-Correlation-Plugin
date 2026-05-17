from mscp.analysis_modules import analyze_nikto_path
from mscp.advisor import enrich_assets_with_ai
from pprint import pprint

assets, errors = analyze_nikto_path('sample_data/nikto.json')
print('errors:', errors)
print('before enrich:', [a.ai_suggestions for a in assets])
enrich_assets_with_ai(assets)
print('after enrich:', [a.ai_suggestions for a in assets])
for a in assets:
    pprint(a.to_dict())
