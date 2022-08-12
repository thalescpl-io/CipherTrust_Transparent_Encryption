import glob
import multiprocessing as mp
import os
import re
import pickle
import time
import sys
from logmodel import LogModel

# regex for parsing learn mode and audit log lines
logline_regex = re.compile(r'''
    (?P<DATE>[\d-]+)                    # date 2020-10-01
    \s+
    (?P<TIME>[\d\:\.]+)                 # time 06:25:01.829
    \s+
    \[([\w\s]+)\]                       # [CGP]
    \s+
    \[([\w\s]+)\]                       # [INFO]
    \s+
    \[(?P<PID>\d+)\]                    # pid [591115]
    \s+
    \[([\w\s]+)\]                       # [CGP2603I]
    \s+
    \[(?P<TYPE>LEARN\sMODE|AUDIT)\]     # [LEARN MODE] support AUDIT and ALARM?
    \s+
    Policy\[(?P<POLICY>[\w-]+)\]        # Policy [policy-learnmode]
    \s+
    User\[(?P<USER>                     # User [...
      (?P<UNAME>\w+),                     # user name
      uid=(?P<UID>\d+),                   # uid
      (
      (?P<NOAUTH>                         # user not autenticated
        euid=(?P<NA_EUID>\d+)             # euid
        \s\(User\sNot\sAuthenticated\)) | #
      (?P<AUTH>                           # user authenticated
        gid=(?P<A_GID>\d+)                # gid
        \\\\(?P<A_GNAMES>.*)\\\\) |       # group names
      (?P<FAKEDAS>                        # user authenticated but faked as another user
        euid=(?P<F_EUID>\d+),             # euid
        gid=(?P<F_GID>\d+)                # gid
        \\\\(?P<F_GNAMES>.*)\\\\          # group names
        \s\(faked\sas\(
          (?P<FAKEDAS_UNAME>\w+),
          (?P<FAKEDAS_UID>\d+)\)\))
      )
      (
        \s
        \((?P<PINFO>                    # parent info may be present
            ((?P<PNAME0>[^\[\]\(\): ]+)                # parent 0
              \[pid=(?P<PPID0>[^\[\]: ]+),
              uid=(?P<PUID0>[^\[\]: ]+),
              euid=(?P<PEUID0>[^\[\]: ]+)\]\s\:\s)?
            ((?P<PNAME1>[^\[\]\(\): ]+)                # parent 1
              \[pid=(?P<PPID1>[^\[\]: ]+),
              uid=(?P<PUID1>[^\[\]: ]+),
              euid=(?P<PEUID1>[^\[\]: ]+)\]\s\:\s)?
            ((?P<PNAME2>[^\[\]\(\): ]+)                # parent 2
              \[pid=(?P<PPID2>[^\[\]: ]+),
              uid=(?P<PUID2>[^\[\]: ]+),
              euid=(?P<PEUID2>[^\[\]: ]+)\]\s\:\s)?
            ((?P<PNAME3>[^\[\]\(\): ]+)                # parent 3
              \[pid=(?P<PPID3>[^\[\]: ]+),
              uid=(?P<PUID3>[^\[\]: ]+),
              euid=(?P<PEUID3>[^\[\]: ]+)\]\s\:\s)?
            ((?P<PNAME4>[^\[\]\(\): ]+)                # parent 4
              \[pid=(?P<PPID4>[^\[\]: ]+),
              uid=(?P<PUID4>[^\[\]: ]+),
              euid=(?P<PEUID4>[^\[\]: ]+)\])?
        )\)
      )?
    )\]                                 # User ...]
    \s+
    Process\[(?P<PROCESS>[^\]]+)\]      # Process [/usr/bin/updatedb.mlocate]
    \s+
    Action\[(?P<ACTION>\w+)\]           # Action [read_dir_attr]
    \s+
    Res\[(?P<RESOURCE>[^\]]+)\]         # Res [/gp/]
    \s+
    (\[([^\]])+\]\s+)?                  # rename second path
    (Key\[(?P<KEY>[^\]]+)\]\s+)?        # Key may be present
    Effect\[(?P<EFFECT>[^\]]+)\]        # Effect [DENIED  Code (1M)]
''', re.X)


def parse_log_line(log_line:str, logmodel:LogModel):
    match = logline_regex.match(log_line)
    if match is None:
        return False

    policy = match.group('POLICY')

    user = {}
    user['name'] = match.group('UNAME')
    user['uid'] = match.group('UID')
    if match.group('NOAUTH'):
        user['authenticated'] = False
        user['fakedas'] = None
        user['euid'] = match.group('NA_EUID')
        user['gid'] = None
    else:
        user['authenticated'] = True
        if match.group('FAKEDAS'):
            user['fakedas'] = (match.group('FAKEDAS_UNAME'), match.group('FAKEDAS_UID'))
            user['euid'] = match.group('F_EUID')
            user['gid'] = match.group('F_GID')
        else:
            # don't have euid, use uid value for now
            user['fakedas'] = None
            user['euid'] = user['uid']
            user['gid'] = match.group('A_GID')

    parentinfo = list()
    for idx in range(5):
        sidx = str(idx)
        if match.group('PNAME' + sidx):
            parentinfo.append((match.group('PNAME' + sidx),
                               match.group('PPID' + sidx),
                               match.group('PUID' + sidx),
                               match.group('PEUID'+ sidx)))

    process = {}
    process['name'] = match.group('PROCESS')
    process['uid'] = user['uid']
    process['euid'] = user['euid']

    resource = match.group('RESOURCE')

    action = match.group('ACTION')

    # update internal model
    return logmodel.update(policy, user, parentinfo, process, resource, action)

def log_work(logfiles:[], logs_size, maxworksize=32*1024*1024):
    """A generator that returns a block of text of max size maxworksize
    
    Keyword arguments:
    logfiles -- a list of the new logs needed to be processed
    maxworksize -- the max size (in bytes)each log_worker can 
    be assigned (default 32 * 1024 * 1024)
    """
    curr_size = 0
    for log in logfiles:
        logend = os.path.getsize(log)
        with open(log, 'rb') as logf:
            workend = 0
            while workend < logend:
                workstart = workend
                logf.seek(min(maxworksize, logend - workstart), 1)
                logf.readline()
                workend = logf.tell()
                curr_size += (logend - workstart)
                yield [log, workstart, workend - workstart, curr_size, logs_size]

def log_worker(loginfo:[]) -> []:
    """The "worker" function that each child process runs.
    Goes line by line, parsing each and then updating an 
    intermediate logmodel.
    
    Keyword arguments:
    loginfo -- a list containing the logfile name, 
    where to start reading, as well as how much to read

    Returns:
    A LogModel and a list of skipped lines
    """
    skipped = []
    logmodel = LogModel()
    logfile, wstart, wsize, curr_size, logs_size = loginfo
    with open(logfile, 'r') as lf:
        lf.seek(wstart)
        sys.stdout.flush()
        lines = lf.read(wsize).splitlines()
        for line in lines:
            if parse_log_line(line, logmodel):
                pass
            else:
                skipped.append(line)
    return [logmodel, skipped]

def process_logs_mp(logfiles:[], logmodel:LogModel, logs_size) -> LogModel:
    """The main processing function where the multiprocessing happens.
    It creates a workpool and maps each result from log_work(). 
    Then updates logmodel with the results from log_worker
    and saves skipped lines to a separate file.

    Keyword arguments:
    logfiles -- a list of the new logfiles that need to be processed
    logmodel -- the logmodel that needs to be updated

    Returns:
    The updated logmodel
    """
    pool_size = mp.cpu_count() if mp.cpu_count() < 8 else 8
    ts = 0
    tm = 0
    workpool = mp.Pool(pool_size)
    jobs = workpool.map_async(log_worker, log_work(logfiles, logs_size))
    totaljobs = jobs._number_left
    rejfile = None
    rejfilename = f'/tmp/lmskip.{os.getpid()}'
    workpool.close()
    while not jobs.ready():
        print(f'[1/2] Parsing logs files[{round((totaljobs-jobs._number_left)*100/totaljobs):3d}%]', end='\r')
        time.sleep(0.5)
    workpool.join()
    results = jobs.get()
    for i in range(len(results)):
        print(f'[2/2] Updating log model [{round((i+1)*100/len(results)):3d}%]', end='\r')
        lm, skipped = results[i]
        # go through each logmodel entry and update the original logmodel
        for pk, pv in lm.log.items():
            for uk, uv in pv.items():
                user = {'name':uk.name, 'uid':uk.uid, 
                        'authenticated':uk.authenticated, 
                        'fakedas':uk.fakedas, 'euid':uk.euid, 'gid':uk.gid}
                for psk, psv in uv.items():
                    process = {'name':psk.name, 'uid':psk.uid, 'euid':psk.euid}
                    for rk, rv in psv.items():
                        for a in rv.keys():
                            logmodel.update(pk, user, psk.parentinfo, process, rk, a)
                            tm += 1
        # save skipped entries in a separate file
        for skip in skipped:
            if rejfile is None:
                rejfile = open(rejfilename, 'wt')
            rejfile.write(skip)
            ts += 1
    if rejfile:
        rejfile.close()
    stinfo = os.stat(logfiles[-1])
    logmodel.lastlog_size = stinfo.st_size
    print("Successfully parsed all log files")
    if ts > 0:
        print(f'Other log entries: {ts}, saved to {rejfilename}')
    return logmodel

def load_logmodel(dirpath:str) -> (bool,LogModel,float):
    """
    loads saved logmodel from a .logmodel.bin file or 
    returns a new one if there is no saved logmodel
    """
    if not os.path.isdir(dirpath):
        print(f'Invalid directory path {dirpath}')
        return None,None,None
    lmfilepath = dirpath + '/.logmodel.bin'
    if os.path.isfile(lmfilepath):
        # load model file
        lmfile = open(lmfilepath, 'rb')
        logmodel = pickle.load(lmfile)
        lmfile.close()
        lmfile_mtime = os.path.getmtime(lmfilepath)
        loaded = True
    else:
        logmodel = LogModel()
        lmfile_mtime = 0
        loaded = False
    return loaded,logmodel,lmfile_mtime

def save_logmodel(dirpath:str, logmodel:LogModel):
    """saves the logmodel at dirpath"""
    if not os.path.isdir(dirpath):
        print(f'Invalid directory path {dirpath}')
        return None,None,None
    lmfilepath = dirpath + '/.logmodel.bin'
    # save new model
    lmfile = open(lmfilepath, 'wb')
    pickle.dump(logmodel, lmfile)
    lmfile.close()

def size2str(size:float):
    if size < 1024:
        return f'{size} bytes'
    elif size < 1024 * 1024:
        return f'{size/float(1<<10):,.2f} KB'
    else:
        return f'{size/float(1<<20):,.2f} MB'

def get_logfiles(dirpath:str) -> []:
    """gets all logmodel files in specified dirpath directory"""
    if not os.path.isdir(dirpath):
        print(f'Invalid directory path {dirpath}')
        return None
    logfiles = glob.glob(dirpath + '/vorvmd_root.log*')
    if len(logfiles) == 0:
        print(f'Could not find any CTE log files in {dirpath}')
        return None
    return logfiles

def get_newlogs(dirpath:str):
    """gets all new logs from dirpath directory"""
    logfiles = get_logfiles(dirpath)
    if logfiles is None:
        return None,None,None,None,None
    newlogfiles = []
    logs_size = 0
    firstlog_offset = 0
    lm_exists,logmodel,lmfile_mtime = load_logmodel(dirpath)
    if lm_exists:
        newlogfiles = [ _ for _ in logfiles if os.path.getmtime(_) > lmfile_mtime ]
        if len(newlogfiles) > 0:
            newlogfiles.sort(key = os.path.getmtime)
            for logno,logfile in enumerate(newlogfiles):
                if (logno == 0 and logmodel.lastlog_ino and 
                    logmodel.lastlog_size):
                    stinfo = os.stat(logfile)
                    if (stinfo.st_ino == logmodel.lastlog_ino and 
                        stinfo.st_size > logmodel.lastlog_size):
                        logs_size += stinfo.st_size - logmodel.lastlog_size
                        firstlog_offset = logmodel.lastlog_size
                        continue
                logs_size += os.path.getsize(logfile)
    else:
        newlogfiles = logfiles
        logs_size = sum(os.path.getsize(log) for log in logfiles)
    return newlogfiles,logs_size,firstlog_offset,lmfile_mtime,logmodel

def log_status(dirpath:str):
    """prints how many new logs there are to be processed"""
    newlogfiles,logs_size,_,after_mtime,_ = get_newlogs(dirpath)
    if newlogfiles is None:
        return
    if len(newlogfiles) > 0:
        print(f'Found {len(newlogfiles)} log files in {dirpath} with unprocessed entries',
                end=f' since {time.ctime(after_mtime)}\n' if after_mtime else '.\n')
        print(f'Total size of unprocessed entries is {size2str(logs_size)}')
    else:
        print(f'No new log entries in {dirpath}',
                end=f' since {time.ctime(after_mtime)}\n' if after_mtime else '.\n')

def process_log_files(dirpath:str):
    """main function that handles the processing of log files"""
    newlogfiles,logs_size,firstlog_offset,after_mtime,logmodel = get_newlogs(dirpath)
    if newlogfiles is None:
        return
    if len(newlogfiles) == 0:
        print(f'No new log entries in {dirpath}',
                end=f' since {time.ctime(after_mtime)}\n' if after_mtime else '.\n')
        return
    logmodel = process_logs_mp(newlogfiles,logmodel,logs_size)
    save_logmodel(dirpath, logmodel)
