#!/usr/bin/env python3

import argparse
import debug
import logparse
import getopt
import sys
from getpass import getpass
from logmodel import LogModel
from policy import CMPolicy,LMPolicyUpdate
from pprint import pprint
from cmapi import cmapi_init


def list_policies(lm:LogModel):
    print('Policies with learn mode updates:')
    print('\n'.join(polname for polname in lm.iter_policy_names()))

def show_policy(policy_name:str, mode:str, lm:LogModel):
    polnames = [policy_name] if policy_name else lm.iter_policy_names()
    for polname in polnames:
        LMPolicyUpdate(name=polname, mode=mode, lm=lm).print()

def upload_policy(policy_name:str, mode:str, lm:LogModel,
                  upload_name:str, cmip:str, cmuser:str, cmpass:str, cmdomain:str):
    if cmapi_init(cmip, cmuser, cmpass, cmdomain) is False:
        return
    srcpol = CMPolicy(policy_name)
    if srcpol.policy is None:
        return
    if policy_name == upload_name:
        dstpol = srcpol
    else:
        dstpol = CMPolicy(upload_name)
        if dstpol.policy is None:
            dstpol.key_rules = srcpol.key_rules
            dstpol.security_rules = srcpol.security_rules

    lmupd = LMPolicyUpdate(name=upload_name, mode=mode, lm=lm,
                           srcpol=srcpol, dstpol=dstpol)
    print(f'Uploading learn mode policy updates for {policy_name} using name {upload_name}')
    dstpol.upload_update(lmupd)

if __name__ == "__main__":

    ap = argparse.ArgumentParser()
    ap.add_argument('--logdir',
                    type=str,
                    default='/var/log/vormetric',
                    help='log directory, defaults to /var/log/vormetric')
    sp = ap.add_subparsers(dest='cmd')

    log = sp.add_parser('log',
                         help='cte learn mode logs')
    log_sp = log.add_subparsers(dest='log_cmd')
    log_status = log_sp.add_parser('status',
                                   help='logs status')
    log_process = log_sp.add_parser('process',
                                    help='process logs')
    log_report = log_sp.add_parser('report',
                                   help='print log report in text format')
    log_report.add_argument('--format',
                            choices=['short','long'],
                            default='short',
                            help='type of report')
    log_report.add_argument('--policy',
                            type=str)
    log_report.add_argument('--user',
                            type=str)
    log_report.add_argument('--process',
                            type=str)
    log_report.add_argument('--resource',
                            type=str)
    log_report.add_argument('--action',
                            type=str)

    policy = sp.add_parser('policy',
                           help='learn mode policy updates')
    policy_sp = policy.add_subparsers(dest='policy_cmd')
    policy_list = policy_sp.add_parser('list',
                                       help='list policies with learn mode updates')
    policy_show = policy_sp.add_parser('show',
                                       help='show learn mode policy updates')
    policy_show.add_argument('--type',
                             choices=['user','process'],
                             default='user',
                             help='update mode for generating learn mode policy')
    policy_show.add_argument('--policy-name',
                             type=str,
                             help='policy name')
    policy_upload = policy_sp.add_parser('upload',
                                         help='upload learn mode policy to CM')
    policy_upload.add_argument('--type',
                               choices=['user','process'],
                               default='user',
                               help='update mode for generating learn mode policy')
    policy_upload.add_argument('--policy-name',
                               type=str,
                               help='policy name')
    policy_upload.add_argument('--upload-name',
                               type=str,
                               help='policy upload name',
                               required=True)
    policy_upload.add_argument('--cmaddr',
                               type=str,
                               help='CM ip address')
    policy_upload.add_argument('--username',
                               type=str,
                               help='CM account name')
    policy_upload.add_argument('--password',
                               type=str,
                               help='CM account password')
    policy_upload.add_argument('--domain',
                               type=str,
                               help='CM domain')

    args = ap.parse_args()

    if args.cmd is None:
        ap.print_help()
        sys.exit(1)

    if args.cmd == 'log':
        if args.log_cmd == 'status':
            logparse.log_status(args.logdir)
        elif args.log_cmd == 'process':
            error = logparse.process_log_files(args.logdir)
            if error:
                sys.exit(2)
        elif args.log_cmd == 'report':
            _,lm_model,_ = logparse.load_logmodel(args.logdir)
            if lm_model is None:
                sys.exit(2)
            if args.format == 'short':
                lm_model.print_report_short()
            else:
                lm_model.print_report(args.policy, args.user, args.process,
                                      args.resource, args.action)
        else:
            log.print_help()
            sys.exit(1)

    if args.cmd == 'policy':
        _,lm_model,_ = logparse.load_logmodel(args.logdir)
        if lm_model is None:
            sys.exit(2)
        if args.policy_cmd == 'list':
            list_policies(lm_model)
        elif args.policy_cmd == 'show':
            show_policy(args.policy_name, args.type, lm_model)
        elif args.policy_cmd == 'upload':
            cmdomain = args.domain if args.domain else input('Domain:')
            cmip = args.cmaddr if args.cmaddr else input('CM address:')
            cmuser = args.username if args.username else input('Username:')
            cmpass = args.password if args.password else getpass('Password:')
            upload_policy(args.policy_name, args.type, lm_model,
                          args.upload_name, cmip, cmuser, cmpass, cmdomain)
        else:
            policy.print_help()
            sys.exit(1)

