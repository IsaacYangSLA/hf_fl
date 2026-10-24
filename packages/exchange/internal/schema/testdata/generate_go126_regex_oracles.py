import json,re
from hf2l_exchange.schemas import validate_metadata
from hf2l_exchange.domain import ExchangeError
from pathlib import Path
r=Path(__file__).resolve().parent
pairs=[("ΐ","ΐ","ί"),("ΰ","ΰ","ύ"),("ﬅ","ﬆ","st")]
regex_cases=[];schema_cases=[]
for left,right,unrelated in pairs:
 for source,target in [(left,right),(right,left)]:
  code="%04x_%04x"%(ord(source),ord(target))
  patterns={"literal":"(?i)^"+source+"$","class":"(?i)^["+source+"]$","range":"(?i)^["+source+"-"+source+"]$","negated_range":"(?i)^[^"+source+"-"+source+"]$","ascii":"(?ai)^"+source+"$"}
  for form,pattern in patterns.items():
   for n,value in enumerate([target,source,unrelated,"x"]):
    regex_cases.append({"name":code+"_"+form+"_"+str(n),"pattern":pattern,"value":value,"match":bool(re.search(pattern,value))})
  pattern="(?i)^"+source+"$"
  for keyword,body in [
    ("not",{"not":{"pattern":pattern}}),
    ("conditional",{"if":{"pattern":pattern},"then":{"const":"unreachable"},"else":True}),
    ("oneOf",{"oneOf":[{"pattern":pattern},{"const":target}]})
  ]:
   definition={"type":"object","properties":{"v":body}}
   for n,value in enumerate([target,unrelated]):
    c={"name":code+"_"+keyword+"_"+str(n),"args":[{"v":value},definition]}
    try:c["result"]=validate_metadata(*c["args"])
    except ExchangeError as e:c["error"]={"status":e.status,"code":e.code,"detail":e.detail}
    schema_cases.append(c)
(r/'regex_go126_oracle.json').write_text(json.dumps({"python":"3.11","cases":regex_cases},ensure_ascii=False,sort_keys=True,indent=2)+"\n")
(r/'regex_go126_schema_oracle.json').write_text(json.dumps({"python":"3.11","cases":schema_cases},ensure_ascii=False,sort_keys=True,indent=2)+"\n")
print(json.dumps({"regex_cases":len(regex_cases),"schema_cases":len(schema_cases)}))
