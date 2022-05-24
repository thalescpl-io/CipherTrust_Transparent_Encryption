import os
import re
import util
from cmapi import cmapi_init
from pprint import pprint


def str3dot(s, maxlen):
    ''' return printable short name with 3 dots in middle '''
    if len(s) <= maxlen:
        return s
    sl = int((maxlen-3)/2)
    return s[:sl] + '...' + s[-sl:]


class PolicyItem:
    def __init__(self, name):
        self.name = name

    def __eq__(self, other):
        if isinstance(other, PolicyItem):
            if self.name == other.name:
                return True
        return False

    def __hash__(self):
        return hash(self.name)

    def __str__(self):
        return f'{self.name}'


class PolicyItemFilter:
    def __init__(self, filter_str):
        self.filter_str = filter_str
        self.filter = re.compile(self.filter_str if filter_str else '.')

    def match(self, item):
        return self.filter.search(item.name)


class Action(PolicyItem):
    aops = {'create_file':['creating','f_cre'],
            'flush_dir':['',''],
            'flush_file':['',''],
            'get_key':['',''],
            'ioctl_dir':['',''],
            'ioctl_file':['',''],
            'key_op':['',''],
            # 'f_link,d_link' but d_link is rejected by CM
            'link':['creating','write'],
            'lock_dir':['',''],
            'lock_file':['',''],
            'make_dir':['creating','d_mkdir'],
            'mknod':['creating','d_mknod'],
            'read_attr':['reading meta','f_rd_att'],
            'read_dir':['listing','d_rd'],
            'read_dir_attr':['reading meta','d_rd_att'],
            'read_dir_sec_attr':['reading meta','d_rd_sec'],
            'read_file':['reading','f_rd'],
            'read_file_sec_attr':['reading meta','f_rd_sec'],
            'remove_dir':['removing','d_rmdir'],
            'remove_file':['removing','f_rm'],
            'rename':['renaming','f_ren'],
            # 'f_link,d_link' but d_link is rejected by CM
            'symlink':['creating','write'],
            'unknown_acc':['unknown',''],
            'write_app':['writing','f_wr_app'],
            'write_dir_attr':['writing meta','d_chg_att'],
            'write_dir_sec_attr':['writing meta','d_chg_sec'],
            'write_dir_sec_attr_size':['writing meta','d_chg_sec'],
            'write_file':['writing','f_wr'],
            'write_file_attr':['writing meta','f_chg_att'],
            'write_file_sec_attr':['writing meta','f_chg_sec'],
            'write_file_sec_attr_size':['writing meta','f_chg_sec']}

    def descr(self):
        if self.name in Action.aops:
            return Action.aops[self.name][0]
        else:
            return f'unknown ({self.name})'

    def todict(self):
        if self.name in Action.aops:
            return Action.aops[self.name][1]
        else:
            return f'unknown ({self.name})'


class Resource(PolicyItem):
    pass


class Process(PolicyItem):
    def __init__(self, process, pareninfo):
        super(Process, self).__init__(process['name'])


class User(PolicyItem):
    def __init__(self, user, process, parentinfo):
        super(User, self).__init__(user['name'])
        self.uid = user['uid']
        self.euid = user['euid']
        self.gid = user['gid']
        self.fakedas = set(user['fakedas']) if user['fakedas'] else set()
        self.auth = self.get_auth(process, parentinfo) if not user['authenticated'] else set()

    # discover authenticator processes
    def get_auth(self, process, parentinfo):
        auth = set()
        prev_uid = process['uid']
        prev_euid = process['euid']
        prev_name = os.path.basename(process['name'])
        found_auth = False
        for pinfo in parentinfo:
            if prev_uid != pinfo[2] or prev_euid != pinfo[3]:
                auth.add(prev_name)
                found_auth = True
                break
            prev_uid = pinfo[2]
            prev_euid = pinfo[3]
            prev_name = pinfo[0]
        if found_auth is False:
            auth.add('N/A')
        return auth

    def __eq__(self, other):
        if super(User, self).__eq__(other):
            if isinstance(other, User):
                self.fakedas.update(other.fakedas)
                self.auth.update(other.auth)
                return True
        return False

    def __hash__(self):
        return super(User, self).__hash__()


class Policy(PolicyItem):
    pass


class LogEntryInfo:
    def __init__(self):
        self.count = 0

    def __str__(self):
        return f'{self.count}'


''' Nested dictionary for storing learn mode log entries '''
class Log(dict):
    def __init__(self, *args, **kwargs):
        super(Log, self).__init__(*args, **kwargs)

    def __missing__(self, key):
        if isinstance(key, Action):
            logentry_info = self[key] = LogEntryInfo()
            return logentry_info
        else:
            nested_dict = self[key] = type(self)()
            return nested_dict

    def iterfilter(self, filterlist):
        cur_filter = filterlist[0]
        if len(filterlist) == 1 or filterlist[1] is None:
            next_filters = None
        else:
            next_filters = filterlist[1:]
        for k,v in self.items():
            if cur_filter.match(k):
                if next_filters is None:
                    yield [k, v]
                    continue
                for _ in v.iterfilter(next_filters):
                    r = [k]
                    r.extend(_)
                    if len(r) > 1:
                        yield r


''' dict for caching policy items '''
class ItemCache(dict):
    def __init__(self, *args, **kwargs):
        super(ItemCache, self).__init__(*args, **kwargs)

    def __missing__(self, item):
        self[item] = item
        return item


''' learn model main class '''
class LogModel:
    def __init__(self):
        self.policy_cache = ItemCache()
        self.user_cache = ItemCache()
        self.process_cache = ItemCache()
        self.resource_cache = ItemCache()
        self.action_cache = ItemCache()
        self.log = Log()
        self.lastlog_ino = None
        self.lastlog_size = None

    def update(self, policy, user, parentinfo, process, resource, action):
        # update internal model
        # policy -> user -> process -> resource -> action
        pol = self.policy_cache[Policy(policy)]
        usr = self.user_cache[User(user, process, parentinfo)]
        prc = self.process_cache[Process(process, parentinfo)]
        res = self.resource_cache[Resource(resource)]
        act = self.action_cache[Action(action)]
        logentryinfo = self.log[pol][usr][prc][res][act]
        logentryinfo.count += 1
        return True

    def iter_policy_names(self):
        for policy in self.log.keys():
            yield policy.name

    def iter_byproc(self, policy:Policy):
        for uk,uv in self.log[policy].items():
            new_uset = set([uk])
            for pk,pv in uv.items():
                new_pset = set([pk])
                new_rset = set(pv.keys())
                new_aset = set()
                for rk,rv in pv.items():
                    new_aset.update(rv.keys())
                yield new_uset,new_pset,new_rset,new_aset

    def iter_byuser(self, policy:Policy):
        for uk,uv in self.log[policy].items():
            new_uset = set([uk])
            new_pset = set(uv.keys())
            new_rset = set()
            new_aset = set()
            for tk,tv in uv.items():
                new_rset.update(tv.keys())
                for rk,rv in tv.items():
                    new_aset.update(rv.keys())
            yield new_uset,new_pset,new_rset,new_aset

    def get_update_iter(self, policy_name, update_type):
        pol = self.policy_cache[Policy(policy_name)]
        if pol not in self.log:
            print(f'Unknown policy {policy_name}')
            return None,None
        if update_type == 'user':
            return self.iter_byuser,pol
        else:
            return self.iter_byproc,pol

    def print_report_short(self):
        for pk, pv in self.log.items():
            print(f'Policy: [ {pk.name} ]')
            for uk,uv in pv.items():
                print()
                print(f'  User [ {uk.name} ] running {len(uv)} processes:')
                if uk.auth:
                    print(f'      WARNING! {uk.name} is not always authenticated! Discovered authenticator processes: ' + ' '.join(_ for _ in uk.auth))
                if uk.fakedas:
                    print(f'      WARNING! {uk.name} has faked following users: ' + ' '.join(_ for _ in uk.fakedas))
                for psk,psv in uv.items():
                    print()
                    print(f'      Process: [ {psk.name} ]')
                    print_lineno = 1
                    printed_dots = False
                    actset = set()
                    for rsk,rsv in psv.items():
                        actset.update(rsv.keys())
                    print('      Access:  [ ', end='')
                    for act in actset:
                        print(f'{act.name}', end=' ')
                    print(']')
                    print(f'      Files/dirs: {len(psv.items())}')
                    print(f'      ---------------')

                    for rsk,rsv in psv.items():
                        if print_lineno <= 3 or print_lineno > len(psv) - 2:
                            print(f'      {print_lineno} {rsk.name}')
                        else:
                            if not printed_dots:
                                print(f'        ...')
                                printed_dots = True
                        print_lineno += 1
                    print(f'      ---------------')

    def print_report(self, policy, user, process, resource, action):
        colhead  = ('', 'Policy', 'User', 'Process', 'Resource', 'Action', 'Count')
        colwidth = (7, 15, 15, 25, 50, 20, 5)
        colfilter = (PolicyItemFilter(policy), PolicyItemFilter(user), PolicyItemFilter(process),
                     PolicyItemFilter(resource), PolicyItemFilter(action))
        printwidth  = sum(width+1 for width in colwidth)-1
        print('_'* printwidth)
        for col, colw in zip(colhead, colwidth):
            print(f'%-{colw}s'% col, end=' ')
        print()
        print('_'* printwidth)
        count = 1
        for r in self.log.iterfilter(colfilter):
            r.insert(0, count)
            count += 1
            for item, itemwidth in zip(r, colwidth):
                print(f'%-{itemwidth}s'% str3dot(str(item), itemwidth), end=' ')
            print()
        print('_'* printwidth)

    def print_info(self):
        print(f'LogModel info: policies({len(self.policy_cache)}) users({len(self.user_cache)}) '
              f'process({len(self.process_cache)}) resources({len(self.resource_cache)}) '
              f'actions({len(self.action_cache)})')
