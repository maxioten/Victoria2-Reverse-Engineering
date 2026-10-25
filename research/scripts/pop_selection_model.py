"""Ordered search model for existing destinations, derived from declared branches."""
def select_destination(types,candidates,culture_groups,special,other_region):
    source_type=types[0];trace=[]
    def fits(c):
        limit=types[c['type']]['limit']
        return limit==-1 or c['size']<limit
    def exact(c):return c['type']==0 and c['culture']==0 and c['religion']==0
    def broad(c):
        t=types[c['type']]
        return not t['flag3d9'] and t['level']==source_type['level'] and c['culture']==0
    def group(c):
        return not types[c['type']]['flag3d9'] and c['type']==0 and culture_groups[c['culture']]==culture_groups[0]
    def lower(c):
        t=types[c['type']]
        return not t['flag3d9'] and t['level']<source_type['level'] and c['culture']==0 and c['religion']==0
    stages=[('lower',lower)] if special and other_region else [('exact',exact),('level',broad),('group',group)]
    for stage,predicate in stages:
        for i,c in enumerate(candidates):
            trace.append((stage,i))
            if fits(c) and predicate(c):return i,stage,trace
    return None,None,trace
