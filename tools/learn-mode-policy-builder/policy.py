from cmapi import CMLoadPolicy, CMLoadSecurityRules, CMLoadKeyRules, \
                  CMLoadUserSet, CMLoadProcessSet, CMLoadResourceSet, \
                  CMUploadUserSet, CMUploadProcessSet, CMUploadResourceSet, \
                  CMUploadPolicy, CMUploadSecurityRule, CMUpdateSecurityRule, \
                  CMDeleteSecurityRule, CMDeleteResourceSet, \
                  CMDeleteProcessSet, CMDeleteUserSet, \
                  CMCommandException
from logmodel import LogModel, ItemCache
import os
import util


class CMPolicyItemSet:
    def __init__(self, namehint:[], items:set):
        self.namehint = namehint
        self.items = items

    def name(self):
        return '-'.join(str(_) for _ in self.namehint if str(_) != '')

    def __str__(self):
        return self.name()

    def len(self):
        return len(self.items)


class CMActionSet(CMPolicyItemSet):
    def __init__(self, namehint:[], items:set):
        super(CMActionSet, self).__init__(namehint, items)

    def __eq__(self, other):
        return isinstance(other, CMActionSet) and self.items == other.items

    def __hash__(self):
        ''' dumb hash is sufficient '''
        return hash(len(self.items))

    def __str__(self):
        return self.name() + f' [{len(self.items)}]: |' +  ','.join(set(_.descr() for _ in self.items)) + '|'

    def toprint(self):
        return 'Action set:\n' + 4*' ' + ','.join(set(_.descr() for _ in self.items))

    def todict(self):
        return ','.join(set(_.todict() for _ in self.items))


class CMResourceSet(CMPolicyItemSet):
    def __init__(self, namehint:[], items:set):
        super(CMResourceSet, self).__init__(namehint, items)
        if len(items) > 0:
            self.prefix = os.path.commonpath([_.name for _ in items])
        else:
            self.prefix = None

    def __eq__(self, other):
        return self.prefix == other.prefix

    def __hash__(self):
        return hash(self.prefix)

    def __str__(self):
        return f'{self.name()} [{len(self.items)}]: {self.prefix}'

    def toprint(self):
        return 'Resource set:\n' + 4*' ' + self.prefix

    def todict(self):
        d = {'name':self.name(),
             'description':'created by learn mode',
             'type':'Directory',
             'resources':[]}
        d['resources'].append({'index':0,
                               'directory':self.prefix,
                               'file':'*',
                               'include_subfolders':True,
                               'hdfs':False})
        return d


class CMProcessSet(CMPolicyItemSet):
    def __init__(self, namehint:[], items:set):
        super(CMProcessSet, self).__init__(namehint, items)

    def __eq__(self, other):
        return isinstance(other, CMProcessSet) and self.items == other.items

    def __hash__(self):
        ''' dumb hash is sufficient for policy generation '''
        return hash(len(self.items))

    def __str__(self):
        return self.name() + f' [{len(self.items)}]: <' +  ','.join(str(_) for _ in self.items) + '>'

    def toprint(self):
        return 'Process set:\n' + '\n'.join(4*' ' + str(_) for _ in self.items)

    def todict(self):
        d = {'name':self.name(),
             'description':'created by learn mode',
             'processes':[]}
        for idx,p in enumerate(self.items):
            d['processes'].append({'index':idx,
                                   'directory':os.path.dirname(p.name),
                                   'file':os.path.basename(p.name),
                                   'signature':''})
        return d


class CMUserSet(CMPolicyItemSet):
    def __init__(self, namehint:[], items:set):
        super(CMUserSet, self).__init__(namehint, items)

    def __eq__(self, other):
        return isinstance(other, CMUserSet) and self.items == other.items

    def __hash__(self):
        ''' dumb hash is sufficient for policy generation '''
        return hash(len(self.items))

    def __str__(self):
        return self.name() + f' [{len(self.items)}]: <' +  ','.join(str(_) for _ in self.items) + '>'

    def toprint(self):
        return 'User set:\n' + ','.join(4*' ' + str(_) for _ in self.items)

    def todict(self):
        d = {'name':self.name(),
             'description':'created by learn mode',
             'users':[]}
        for idx,u in enumerate(self.items):
            d['users'].append({'index':idx,
                               'uname':u.name,
                               'uid':int(u.uid) if u.uid is not None else -1,
                               'gname':'',
                               'gid':int(u.gid) if u.gid is not None else -1,
                               'osdomain':''})
        return d


class CMSecurityRuleEffect:
    def __init__(self, permit, applykey, audit):
        self.permit = permit
        self.applykey = applykey
        self.audit = audit

    def todict(self):
        effect = ''
        if self.permit:
            effect += 'permit'
        else:
            effect += 'deny'
        if self.applykey:
            effect += ',applykey'
        if self.audit:
            effect += ',audit'
        return effect


class CMSecurityRule:
    def __init__(self, user, process, resource, action, effect):
        self.user = user
        self.process = process
        self.resource = resource
        self.action = action
        self.effect = effect


class CMSecurityRuleSet:
    def __init__(self, items):
        self.items = set(items)

    def todict(self):
        d = {'resources': []}
        for idx,r in enumerate(self.items):
            d['resources'].append({'order_number':idx,
                                   'partial_match':True,
                                   'exclude_process_set':False,
                                   'exclude_resource_set':False,
                                   'exclude_user_set':False,
                                   'process_set_id':r.process.name(),
                                   'resource_set_id':r.resource.name(),
                                   'user_set_id':r.user.name(),
                                   'action':r.action.todict(),
                                   'effect':r.effect.todict()})
        return d


class CMPolicy:
    pass

class LMPolicyUpdate:
    def __init__(self, name:str, mode:str, lm:LogModel,
                 srcpol:CMPolicy = None, dstpol:CMPolicy = None):
        self.name = name
        self.mode = mode
        self.lm = lm
        self.src_cmpol = srcpol
        self.dst_cmpol = dstpol
        self.user_sets = None
        self.process_sets = None
        self.resource_sets = None
        self.security_rules = None
        self.updated = False
        self.get_update()

    def get_update(self):
        policy_name = self.name
        update_name = self.name
        update_version =''
        if self.src_cmpol and self.src_cmpol.policy:
            policy_name = self.src_cmpol.policy['name']
        if self.dst_cmpol and self.dst_cmpol.policy:
            update_name = self.dst_cmpol.policy['name']
            update_version = self.dst_cmpol.policy['policy_version']

        update_iter,lmpol = self.lm.get_update_iter(policy_name, self.mode)
        if update_iter is None:
            return

        uscache = ItemCache()
        pscache = ItemCache()
        rscache = ItemCache()
        ascache = ItemCache()
        secrules = []

        for new_uset,new_pset,new_rset,new_aset in update_iter(lmpol):
            if len(new_uset) == 1:
                username = list(new_uset)[0].name[:20]
            else:
                username = 'group'
            namehint = [update_name, update_version, username, 'uset', len(uscache)]
            uset = uscache[CMUserSet(namehint, new_uset)]
            if len(new_pset) == 1:
                procname = os.path.basename(list(new_pset)[0].name)[:20]
            else:
                procname = 'group'
            namehint = [update_name, update_version, procname, 'pset', len(pscache)]
            pset = pscache[CMProcessSet(namehint, new_pset)]
            namehint = [update_name, update_version, 'rset', len(rscache)]
            rset = rscache[CMResourceSet(namehint, new_rset)]
            namehint = [update_name, update_version, 'aset', len(ascache)]
            aset = ascache[CMActionSet(namehint, new_aset)]
            secrules.append(CMSecurityRule(uset, pset, rset, aset,
                                           CMSecurityRuleEffect(True,True,False)))

        if self.dst_cmpol and self.dst_cmpol.policy:
            # adjust update version to match yet to be uploaded policy version
            new_count = len(secrules)
            cur_count = len(self.dst_cmpol.security_rules)
            del_count = self.dst_cmpol.lmrule_delete_count()
            update_version += new_count * 2 + int((cur_count+new_count)*(cur_count+new_count-1)/2 - cur_count*(cur_count-1)/2) + int(del_count*(del_count + 1)/2)
            for rset in [*uscache.keys(), *pscache.keys(), *rscache.keys(), *ascache.keys()]:
                rset.namehint[1] = update_version

        self.user_sets = {_.name():_.todict() for _ in uscache.keys()}
        self.process_sets = {_.name():_.todict() for _ in pscache.keys()}
        rsets = rscache.keys()
        # fix resource sets paths based on guarded points directories
        gps = util.get_secfsd_guardpoints(policy_name)
        for rset in rsets:
            for gp in gps:
                if rset.prefix.startswith(gp):
                    rset.prefix = rset.prefix[len(gp):]
                    if rset.prefix == '':
                        rset.prefix = '/'
                    break
        self.resource_sets = {_.name():_.todict() for _ in rsets}
        self.security_rules = CMSecurityRuleSet(secrules).todict()['resources']
        self.updated = True

    def print(self):
        if self.updated is False:
            return
        print(f'Learn mode updates for policy {self.name}:')
        print(f'\nUser sets:')
        for us in self.user_sets.values():
            print(' ', us['name'], '\n    [', ' '.join(u['uname'] for u in us['users']), ']')
        print(f'\nProcess sets:')
        for ps in self.process_sets.values():
            print(' ', ps['name'], '\n    [', ' '.join(p['directory'] + '/' + p['file'] for p in ps['processes']), ']')
        print(f'\nResource sets:')
        for rs in self.resource_sets.values():
            print(' ', rs['name'], '\n    [', ' '.join(r['directory'] + r['file'] for r in rs['resources']), ']')
        print(f'\nSecurity rules:')
        for sr in self.security_rules:
            print('  Rule', sr['order_number'])
            print('    User set    ', sr['user_set_id'])
            print('    Process set ', sr['process_set_id'])
            print('    Resource set', sr['resource_set_id'])
            print('    Action      ', sr['action'])
            print('    Effect      ', sr['effect'])
        print()

class CMPolicy:
    def __init__(self, name:str):
        self.name = name
        try:
            self.load()
        except CMCommandException as e:
            self.policy = None
            self.security_rules = None
            self.key_rules = None
            self.user_sets = None
            self.process_sets = None
            self.resource_sets = None

    def load(self):
        self.policy = CMLoadPolicy(self.name).out
        self.key_rules = CMLoadKeyRules(self.name).out
        self.security_rules = CMLoadSecurityRules(self.name).out
        self.user_sets = {}
        self.process_sets = {}
        self.resource_sets = {}
        for sr in self.security_rules:
            sid = sr['user_set_id']
            if sid and sid not in self.user_sets:
                self.user_sets[sid] = CMLoadUserSet(sid).out
            sid = sr['process_set_id']
            if sid and sid not in self.process_sets:
                self.process_sets[sid] = CMLoadProcessSet(sid).out
            sid = sr['resource_set_id']
            if sid and sid not in self.resource_sets:
                self.resource_sets[sid] = CMLoadResourceSet(sid).out

    def upload_update(self, lmupd:LMPolicyUpdate):
        for sk,sv in lmupd.resource_sets.items():
            CMUploadResourceSet(sv)
        for sk,sv in lmupd.process_sets.items():
            CMUploadProcessSet(sv)
        for sk,sv in lmupd.user_sets.items():
            CMUploadUserSet(sv)
        if self.policy:
            for sru in lmupd.security_rules:
                added_sru = CMUploadSecurityRule(self.name, sru).out
                updated_sru = {
                               'id':added_sru['id'],
                               'order_number':1
                              }
                CMUpdateSecurityRule(self.name, updated_sru)

            self.delete_prev_lmitems()
        else:
            secrules_union = lmupd.security_rules
            order_number = len(secrules_union) + 1
            for srk,srv in enumerate(self.security_rules):
                srv['order_number'] = order_number + srk
                secrules_union.append(srv)
            newpol = {
                      'name':self.name,
                      'policy_type':'standard',
                      'key_rules':self.key_rules,
                      'security_rules':secrules_union
                     }
            CMUploadPolicy(newpol)
        return True


    def is_lmrule(self, rule):
        def is_lmset(rset):
            return rset['description'] == 'created by learn mode'

        sid = rule['user_set_id']
        if sid in self.user_sets and is_lmset(self.user_sets[sid]):
            return True
        sid = rule['process_set_id']
        if sid in self.process_sets and is_lmset(self.process_sets[sid]):
            return True
        sid = rule['resource_set_id']
        if sid in self.resource_sets and is_lmset(self.resource_sets[sid]):
            return True
        return False

    def lmrule_delete_count(self):
        return sum(self.is_lmrule(rule) for rule in self.security_rules)

    def delete_prev_lmitems(self):
        def is_lmset(rset):
            return rset['description'] == 'created by learn mode'

        for r in self.security_rules:
            if self.is_lmrule(r):
                CMDeleteSecurityRule(self.name, r['id'])
        for sk,sv in self.user_sets.items():
            if is_lmset(sv):
                CMDeleteUserSet(sv['id'])
        for sk,sv in self.process_sets.items():
            if is_lmset(sv):
                CMDeleteProcessSet(sv['id'])
        for sk,sv in self.resource_sets.items():
            if is_lmset(sv):
                CMDeleteResourceSet(sv['id'])

