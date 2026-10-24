"""Regenerate frozen Python reference results; not required by Go tests."""
import hashlib,json,sys
from pathlib import Path
from hf2l_exchange import schemas,profiles
from hf2l_exchange.domain import ExchangeError
ROOT=Path(__file__).resolve().parent
def run_case(c,fn):
 try:c["result"]=fn()
 except ExchangeError as e:c["error"]={"status":e.status,"code":e.code,"detail":e.detail}
 return c
S=[]
def sc(name,op,args):
 c={"name":name,"operation":op,"args":args}
 funcs={"schema":schemas.validate_schema,"metadata":schemas.validate_metadata,"size":schemas.metadata_size,"digest":schemas.schema_digest,"path":schemas.validate_path,"kind":schemas.validate_kind,"casefold":str.casefold}
 S.append(run_case(c,lambda:funcs[op](*args)))
base={"type":"object"}
sc("empty_object_schema","schema",[base])
for value in [None,[],True,"object"]:
 sc("schema_wrong_type_"+str(value),"schema",[value])
for schema in [{"type":"array"},{"type":["object"]},{"type":"object","$schema":"http://json-schema.org/draft-07/schema#"},{"type":"object","properties":{"a":{"type":"bogus"}}},{"type":"object","required":"a"},{"type":"object","properties":{"x":{"pattern":"["}}}]:
 sc("invalid_schema_"+str(len(S)),"schema",[schema])
for key in ["$id","$dynamicRef","$recursiveRef"]:
 sc("forbidden_"+key,"schema",[{"type":"object","description":{key:"bad"}}])
for ref in ["https://example.invalid/schema","#","plain","#/missing","#/properties/missing"]:
 sc("reference_"+ref,"schema",[{"type":"object","properties":{"x":{"$ref":ref}}}])
recursive={"type":"object","$defs":{"again":{"$ref":"#/$defs/again"}}}
sc("recursive_reference","schema",[recursive])
local={"type":"object","$defs":{"s":{"type":"string","minLength":2}},"properties":{"v":{"$ref":"#/$defs/s"}}}
sc("local_reference_schema","schema",[local]);sc("local_reference_accept","metadata",[{"v":"ab"},local]);sc("local_reference_reject","metadata",[{"v":"a"},local])
escaped={"type":"object","$defs":{"a/b~c":{"type":"integer"}},"properties":{"v":{"$ref":"#/$defs/a~1b~0c"}}}
sc("escaped_pointer","metadata",[{"v":3},escaped])
sc("required_reject","metadata",[{},{"type":"object","required":["x"]}])
sc("required_accept","metadata",[{"x":1},{"type":"object","required":["x"],"additionalProperties":True}])
sc("additional_reject","metadata",[{"x":1},{"type":"object","additionalProperties":False}])
for i,v in enumerate([1,1.0,True,1.1,"1",10**100]):
 sc("integer_type_"+str(i),"metadata",[{"v":v},{"type":"object","properties":{"v":{"type":"integer"}}}])
for i,v in enumerate([None,[],1,"x"]):sc("metadata_root_"+str(i),"size",[v])
sc("metadata_exact_bytes","size",[{"x":"a"*(65536-8)}]);sc("metadata_over_bytes","size",[{"x":"a"*(65536-7)}])
for depth in [16,17]:
 value=1
 for _ in range(depth):value={"v":value}
 sc("metadata_depth_"+str(depth),"size",[value])
sc("schema_oversized","schema",[{"type":"object","description":"a"*65536}])
for i,s in enumerate([{},{"é":"😀","v":1.0,"n":-0.0},{"a":10**100,"z":[True,None,0.00001,1e20]}]):sc("canonical_digest_"+str(i),"digest",[s])
for i,path in enumerate(["model.bin","a/b","é"*128,"é"*129,"a\\b","../x","a/./b","a//b","/a","a/","a:b","","a\nb","a\x7fb",None,123]):
 sc("path_"+str(i),"path",[path])
for i,kind in enumerate(["x","training.update","A_0-x","a"*128,"a"*129,"é","_a","a/b","",None,3]):
 sc("kind_"+str(i),"kind",[kind])
for i,path in enumerate(["Straße","STRAẞE","ΟΣ","ος","οσ","Kelvin","İ","ﬀ","Ａ","😀"]):sc("casefold_"+str(i),"casefold",[path])
constraints=[
 ("arrays",{"type":"object","properties":{"v":{"type":"array","prefixItems":[{"type":"string"},{"type":"integer"}],"items":False}}},{"v":["a",1]},{"v":["a",1,2]}),
 ("contains",{"type":"object","properties":{"v":{"type":"array","contains":{"type":"integer"},"minContains":2,"maxContains":2}}},{"v":[1,"a",2]},{"v":[1,2,3]}),
 ("dependent_required",{"type":"object","dependentRequired":{"a":["b"]}},{"a":1,"b":2},{"a":1}),
 ("dependent_schema",{"type":"object","dependentSchemas":{"a":{"required":["b"]}}},{"a":1,"b":2},{"a":1}),
 ("if_then_else",{"type":"object","if":{"required":["a"]},"then":{"required":["b"]},"else":{"required":["c"]}},{"a":1,"b":2},{"a":1}),
 ("allof_unevaluated",{"type":"object","allOf":[{"properties":{"a":{"type":"integer"}}}],"unevaluatedProperties":False},{"a":1},{"b":1}),
 ("anyof",{"type":"object","properties":{"v":{"anyOf":[{"type":"string"},{"minimum":2,"type":"number"}]}}},{"v":2},{"v":1}),
 ("oneof",{"type":"object","properties":{"v":{"oneOf":[{"type":"integer"},{"minimum":0}]}}},{"v":-1},{"v":1}),
 ("not",{"type":"object","properties":{"v":{"not":{"type":"integer"}}}},{"v":"a"},{"v":1}),
 ("property_names",{"type":"object","propertyNames":{"pattern":"^[a-z]+$"}},{"abc":1},{"A":1}),
 ("pattern_properties",{"type":"object","patternProperties":{"^x":{"type":"integer"}},"additionalProperties":False},{"xyz":1},{"other":1}),
 ("unique_items",{"type":"object","properties":{"v":{"uniqueItems":True}}},{"v":[1,True]},{"v":[1,1.0]}),
 ("enum_bool_distinct",{"type":"object","properties":{"v":{"enum":[1]}}},{"v":1.0},{"v":True}),
 ("const",{"type":"object","properties":{"v":{"const":{"x":[1,2]}}}},{"v":{"x":[1,2]}},{"v":{"x":[2,1]}}),
 ("formats_are_annotations",{"type":"object","properties":{"v":{"format":"email"}}},{"v":"not-an-email"},{"v":"still-not-an-email"}),
 ("content_annotations",{"type":"object","properties":{"v":{"contentEncoding":"base64","contentMediaType":"application/json","contentSchema":{"type":"array"}}}},{"v":"not-base64"},{"v":"also-not-base64"}),
]
for name,definition,good,bad in constraints:
 sc(name+"_schema","schema",[definition]);sc(name+"_good","metadata",[good,definition]);sc(name+"_bad","metadata",[bad,definition])
for i,(v,d) in enumerate([(0.3,0.1),(0.6,0.2),(4.02,0.01),(1e308,0.01),(1.2,0.2),(4,2),(4.0,2),(5,2),(-4.0,2),(10**100,10),(0.3,1),(9007199254740993,2.0),(9007199254740993,2)]):
 definition={"type":"object","properties":{"v":{"multipleOf":d}}}
 sc("multiple_of_"+str(i),"metadata",[{"v":v},definition])
for keyword in ["anyOf","oneOf","allOf"]:
 definition={"type":"object","properties":{"v":{keyword:[{"multipleOf":0.1},{"const":0.3}]}}}
 sc("multiple_of_logic_"+keyword,"metadata",[{"v":0.3},definition])
sc("multiple_of_not","metadata",[{"v":0.3},{"type":"object","properties":{"v":{"not":{"multipleOf":0.1}}}}])
sc("multiple_of_ref","metadata",[{"v":0.3},{"type":"object","$defs":{"n":{"multipleOf":0.1}},"properties":{"v":{"$ref":"#/$defs/n"}}}])
sc("multiple_of_annotation_unchanged","metadata",[{"v":{"multipleOf":0.1}},{"type":"object","properties":{"v":{"const":{"multipleOf":0.1}}},"default":{"multipleOf":0.1}}])
big=10**100
rounded=float(big)
for keyword in ["minimum","maximum","exclusiveMinimum","exclusiveMaximum"]:
 for n,(instance,bound) in enumerate([(big,rounded),(rounded,big),(-big,-rounded),(-rounded,-big)]):
  definition={"type":"object","properties":{"v":{keyword:bound}}}
  sc("mixed_numeric_"+keyword+"_"+str(n),"metadata",[{"v":instance},definition])
for keyword in ["const","enum"]:
 for n,(instance,expected) in enumerate([(big,rounded),(rounded,big),({"n":[big]},{"n":[rounded]}),(True,1),(1.0,1)]):
  value=[expected] if keyword=="enum" else expected
  sc("mixed_equality_"+keyword+"_"+str(n),"metadata",[{"v":instance},{"type":"object","properties":{"v":{keyword:value}}}])
sc("mixed_enum_schema","schema",[{"type":"object","properties":{"v":{"enum":[big,rounded]}}}])
for n,values in enumerate([[big,rounded],[big,big],[rounded,rounded],[True,1],[{"v":[big]},{"v":[rounded]}]]):
 sc("mixed_unique_"+str(n),"metadata",[{"v":values},{"type":"object","properties":{"v":{"uniqueItems":True}}}])
for keyword in ["anyOf","oneOf","allOf"]:
 definition={"type":"object","properties":{"v":{keyword:[{"maximum":big},{"const":rounded}]}}}
 sc("mixed_logical_"+keyword,"metadata",[{"v":rounded},definition])
sc("mixed_not","metadata",[{"v":rounded},{"type":"object","properties":{"v":{"not":{"maximum":big}}}}])
sc("mixed_conditional","metadata",[{"v":rounded},{"type":"object","properties":{"v":{"if":{"maximum":big},"then":False,"else":True}}}])
sc("mixed_reference","metadata",[{"v":rounded},{"type":"object","$defs":{"bound":{"maximum":big}},"properties":{"v":{"$ref":"#/$defs/bound"}}}])
sc("empty_enum_schema","schema",[{"type":"object","properties":{"v":{"enum":[]}}}])
sc("empty_enum_metadata","metadata",[{"v":1},{"type":"object","properties":{"v":{"enum":[]}}}])

P=[]
def pc(name,op,args,profile="fedavg.v1"):
 c={"name":name,"operation":op,"args":args,"profile":profile}
 P.append(run_case(c,lambda:getattr(profiles.get_profile(profile),op)(*args)))
a={"id":"a","kind":"training.update","metadata":{"base_record_id":"base","sample_count":2},"creator_bindings":{"participant":"Alice"},"published_at":1}
b={"id":"b","kind":"training.update","metadata":{"base_record_id":"base","sample_count":3},"creator_bindings":{"participant":"Bob"},"published_at":2}
g={"id":"g","kind":"model.global","metadata":{"base_record_id":"base","inputs":["a","b"]}}
for name in ["generic.v1","fedavg.v1"]:
 for kind in ["training.update","model.global","other"]:pc(name+"_policy_"+kind,"policy_defaults",[kind],name)
for roles in [[],["contributor"],["contributor","contributor"],["publisher"],["publisher","contributor"]]:
 for kind in ["training.update","model.global"]:pc("validate_policy_"+kind+"_"+str(roles),"validate_policy",[kind,roles,"shared"])
for bind in [{},{"participant":None},{"participant":""},{"participant":1},{"participant":"é"*128},{"participant":"x"*129},{"participant":"Alice"}]:
 pc("bindings_"+str(len(P)),"validate_bindings",[bind,[{"participant":"Alice"}]])
for kind in ["training.update","model.global","other"]:pc("base_"+kind,"record_base_id",[kind,{"base_record_id":"base"}])
for sample in [1,1.0,True,0,-1,10**100,"1"]:
 pc("sample_"+str(len(P)),"validate_record",["training.update",{"base_record_id":"base","sample_count":sample},{"participant":"Alice"}])
for meta,bind in [({},{}),({"base_record_id":"base","sample_count":1},{}),({"base_record_id":"","sample_count":1},{"participant":"A"}),({"base_record_id":"base","sample_count":1,"participant":None},{"participant":"A"})]:
 pc("update_invalid_"+str(len(P)),"validate_record",["training.update",meta,bind])
for meta in [{},{"inputs":[]},{"inputs":["a","b"]},{"inputs":["a","a"]},{"inputs":[""]},{"inputs":None},{"base_record_id":1},{"base_record_id":None}]:
 pc("global_"+str(len(P)),"validate_record",["model.global",meta,{}])
pc("publish_valid","validate_publish",["training.update",a["metadata"],a["creator_bindings"],a["creator_bindings"]])
pc("publish_changed","validate_publish",["training.update",a["metadata"],a["creator_bindings"],{"participant":"other"}])
pc("publish_numeric_binding_equal","validate_publish",["training.update",a["metadata"],{"participant":"Alice","number":1},{"participant":"Alice","number":1.0}])
for name in ["main","other"]:pc("selection_"+name,"selection_spec",[name,"base"])
for member in [None,{},{"roles":["reader"],"bindings":{"participant":"Alice"}},{"roles":["contributor"],"bindings":{"participant":"Alice"}},{"roles":["contributor"],"bindings":{"participant":"other"}}]:
 pc("eligible_"+str(len(P)),"input_eligible",[a,member]);pc("current_"+str(len(P)),"validate_input_current",[a,member])
pc("eligible_other","input_eligible",[g,None])
for result in [g,{"metadata":{"inputs":["b","a"]}},{"metadata":{"inputs":["a"]}},{"metadata":{"inputs":["a","a"]}},{"metadata":{"inputs":["a","missing"]}},{"metadata":{"inputs":None}}]:
 pc("complete_"+str(len(P)),"completion_inputs",[result,[a,b],"main"])
pc("complete_nonmain","completion_inputs",[{"metadata":{"inputs":None}},[a,b],"other"])
for definition in [{"type":"object"},{"type":"object","properties":{"base_record_id":{"type":"string"},"sample_count":{"type":"integer"}}},{"type":"object","additionalProperties":False},{"type":"object","properties":{"sample_count":{"type":"integer","minimum":1}}},{"type":"object","allOf":[]},{"type":"object","additionalProperties":{}},{"type":"object","description":"x"}]:
 pc("type_update_"+str(len(P)),"validate_type",["training.update",definition])
for record,inputs,base in [({"kind":"model.global","metadata":{}},[],None),(g,[a,b],"base"),(g,[],"base"),({"kind":"training.update"},[],None),({"kind":"model.global","metadata":{"inputs":["a"]}},[],None),(g,[a],"base"),(g,[a,a],"base"),({"kind":"model.global","metadata":{"base_record_id":"other","inputs":["a","b"]}},[a,b],"base")]:
 pc("reference_"+str(len(P)),"validate_reference",["main",record,inputs,base])
pc("reference_nonmain","validate_reference",["other",a,[],None])
newa=dict(a,id="c",published_at=2)
tiea=dict(a,id="d",published_at=2)
other=dict(b,id="e",metadata={"base_record_id":"other"})
withdrawn=dict(b,id="f",state="withdrawn")
pc("select_latest_sorted","select_inputs",[[b,a,newa,tiea,other,withdrawn],"base"])
# Generic profiles never acquire application-specific constraints.
for op,args in [("validate_policy",["model.global",[],"private"]),("validate_bindings",[{"participant":1},[]]),("validate_publish",["training.update",{}, {},{}]),("selection_spec",["main","base"]),("input_eligible",[a,None]),("validate_input_current",[a,None]),("completion_inputs",[{},[a,b],"main"]),("validate_type",["training.update",{"allOf":[]}]),("validate_record",["training.update",{},{}]),("validate_reference",["main",a,[],"base"]),("select_inputs",[[a,b],"other"])]:
 pc("generic_"+op,op,args,"generic.v1")
for output,cases in [("schema_oracle.json",S),("profiles_oracle.json",P)]:
 (ROOT/output if output=="schema_oracle.json" else ROOT.parent.parent/"profiles"/"testdata"/output).write_text(json.dumps({"python":sys.version.split()[0],"cases":cases},ensure_ascii=False,sort_keys=True,indent=2)+"\n")
print(json.dumps({"schema_cases":len(S),"profile_cases":len(P)}))
