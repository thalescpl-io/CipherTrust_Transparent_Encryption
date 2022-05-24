import os
import subprocess

all_gps = None

def get_secfsd_guardpoints(policy_name:str=None):
    global all_gps

    gps = []
    if all_gps is None:
        secfsd_bin = '/usr/bin/secfsd'
        if os.path.isfile(secfsd_bin):
            cmd = f'{secfsd_bin} -status guard'
            proc = subprocess.Popen(cmd,
                                    shell=True,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    universal_newlines=True)
            rc = proc.wait()
            outs,errs = proc.communicate()
            if rc == 0:
                all_gps = outs.splitlines()[2:]
            else:
                print(errs)

    for gpline in all_gps:
        gp,policy  = gpline.split()[0:2]
        if policy_name and policy_name != policy:
            continue
        gps.append(gp)
    return gps
