title: Learn Mode

`lmpb` is a Python-based tool for processing the CTE Learn Mode audit logs and generating security policies. Learn Mode allows access to guarded path while logging access details. This tool helps admins understand the gap between the current policy and required policy and suggest corrective changes. The CipherTrust Manager and File system administrators are advised to review the changes before pushing them to the CipherTrust Manager.

To collect logs that can be processed by the Learn Mode tool, enable the Learn Mode toggle on the CipherTrust Manager GUI while creating a policy.

1. Clone the CipherTrust Transparent Encryption Git repository.

    
    git clone https://github.com/thalescpl-io/CipherTrust_Transparent_Encryption.git

2. Navigate to the `learn-mode-policy-builder` directory.
    
    cd CipherTrust_Transparent_Encryption/tools/learn-mode-policy-builder

3. View the common commands.

    ./lmpb -h
    
    **Sample Output**
    
        usage: lmpb [-h] [--logdir LOGDIR] {log,policy} ...

        positional arguments:
          {log,policy}
            log            cte learn mode logs
            policy         learn mode policy updates

        options:
          -h, --help       show this help message and exit
          --logdir LOGDIR  log directory, defaults to /var/log/vormetric

## Log Related Commands

    ./lmpb --logdir /home/logs/logs/ubu0/ log

**Sample Output**

    positional arguments:
      {status,process,report}
        status              logs status
        process             process logs
        report              print log report in text format

    options:
      -h, --help            show this help message and exit

    ./lmpb --logdir /home/logs/logs/ubu0/ log status

If unprocessed logs are present, output will be as shown below:

**Sample Output**

    Found 181 log files in /home/logs/logs/ubu0/ with unprocessed entries.
    Total size of unprocessed entries is 326.62 MB

If all log files are already processed, output will be as shown below:

**Sample Output**

    No new log entries in /home/logs/logs/ubu0/ since Mon Dec  5 17:34:39 2022

For processing the unprocessed log files, run the command:

./lmpb --logdir /home/logs/logs/ubu0/ log process

**Sample Output**

    Successfully parsed all log files
    Other log entries: 9, saved to /tmp/lmskip.340576
    Log output saved as JSON at /home/logs/logs/ubu0/output.json

Note that the `output.json` can be fed into Splunk to visualize the data.

    cat /home/logs/logs/ubu0/output.json | nc 10.171.56.220 6666

Where, SPLUNK server is configured to listen on port `6666` for "json_no_timestamp" events. Here, `10.171.56.220` is just an example of the host IP where SPLUNK is hosted.

    ./lmpb --logdir /home/logs/logs/ubu0/ log report

**Sample Ouptut**

The output will show all processes, accesses performed by them and the directories over which they have been performed.

    Process: [ /sdb/anom/vtebuild/_obj_fspem_64_perf_vor_klinux_5.4.0-48-generic/build/env/linux/5.4.0-48-generic/build/scripts/genksyms/genksyms ]
    Access:  [ write_app read_file_sec_attr read_attr ]
    Files/dirs: 20
    ---------------
    1 /sdb/anom/vtebuild/_obj_fspem_64_perf_vor_klinux_5.4.0-48-generic/crypto/sha2/.tmp_sha256.ver
    2 /sdb/anom/vtebuild/_obj_fspem_64_perf_vor_klinux_5.4.0-48-generic/vmcore/cfg/.tmp_vm_cfg_upd.ver
    3 /sdb/anom/vtebuild/_obj_fspem_64_perf_vor_klinux_5.4.0-48-generic/vmcore/cfg/.tmp_vm_cfg.ver
    ...
    19 /sdb/anom/vtebuild/_obj_fspem_64_perf_vor_klinux_5.4.0-48-generic/vmcore/common/.tmp_hexbin.ver
    20 /sdb/anom/vtebuild/_obj_fspem_64_perf_vor_klinux_5.4.0-48-generic/vmcore/ktctl/.tmp_vm_tc.ver

Once the logs are processed by learn mode policy builder tools, following policy related commands can be run to list the existing policies or show updates recommended by tool

## Policy Related Commands

    ./lmpb --logdir /home/logs/logs/ubu0/ policy

**Sample Output**

    positional arguments:
      {list,show,upload}
        list              list policies with learn mode updates
        show              show learn mode policy updates
        upload            upload learn mode policy to CM

    options:
      -h, --help          show this help message and exit

    ./lmpb --logdir /home/logs/logs/ubu0/ policy list

**Sample Output**

    Policies with learn mode updates:
    audit

    ./lmpb --logdir /home/logs/logs/ubu0/ policy show

**Sample Output**

    User sets:
      audit-uset-0
        [ audit ]
      audit-root-uset-1
        [ root ]

    Process sets:
      audit-group-pset-0
        [ /sdb/anom/vtebuild/_obj_pem_64_perf_vor_ulinux_ubuntu20/mk/generate_messages_h.pl /usr/bin/dh_installdeb /usr/bin/dh_testroot /usr/lib/rpm/check-files /usr/lib/gcc/x86_64-linux-gnu/9/collect2 /usr/bin/ar /sdb/anom/vtebuild/_obj_fspem_64_perf_vor_klinux_5.4.0-48-generic/build/env/linux/5.4.0-48-generic/build/scripts/mod/modpost /usr/bin/make /bin/gzip /usr/bin/fakeroot /sdb/anom/vtebuild/_obj_pem_64_perf_vor_ulinux_ubuntu20/mk/process_build_info.pl /sdb/anom/vtebuild/_obj_pem_64_perf_vor_klinux_5.4.0-48-generic/mk/generate_messages_h.pl /sdb/anom/vtebuild/_obj_fspem_64_perf_vor_klinux_5.4.0-48-generic/build/env/linux/5.4.0-48-generic/build/scripts/basic/fixdep /bin/sh /sdb/anom/vtebuild/_obj_pem_64_perf_vor_ulinux_ubuntu20/mk/chkdict.pl /usr/bin/g++ /usr/bin/md5sum /sdb/anom/vtebuild/pem/sdk/sys/tools/gen_preloaded_messages.pl /usr/bin/alien /usr/bin/dh_compress /usr/bin/dpkg-gencontrol /usr/bin/as /usr/bin/touch /usr/lib/gcc/x86_64-linux-gnu/9/cc1 /usr/bin/dh_installchangelogs /bin/bash /usr/bin/rpmbuild /usr/bin/dh_listpackages /bin/cpio /usr/bin/dh_shlibdeps /usr/bin/dh_md5sums /sdb/anom/vtebuild/pem/mk/generate_messages_h.pl /bin/mkdir /bin/ln /usr/bin/perl /usr/bin/gcc /bin/cp /bin/sed /usr/bin/rpm /usr/bin/find /usr/bin/sort /sdb/anom/vtebuild/fspem/build/env/linux/detectrel /bin/rm /sdb/anom/vtebuild/pem/mk/chkdict.pl /usr/bin/dh_makeshlibs /usr/bin/dh_installdirs /usr/bin/dh_gencontrol /usr/bin/which /usr/bin/dh_testdir /bin/grep /sdb/anom/vtebuild/_obj_fspem_64_perf_vor_klinux_5.4.0-48-generic/build/env/linux/5.4.0-48-generic/build/scripts/genksyms/genksyms /sdb/anom/vtebuild/_obj_fspem_64_perf_vor_ulinux_ubuntu20/build/pkg/linux/vee-fs-7.1.0/debian/rules /bin/cat /usr/lib/gcc/x86_64-linux-gnu/9/cc1plus /sdb/anom/vtebuild/_obj_pem_64_perf_vor_ulinux_ubuntu20/apps/common/tools/file_hmac /usr/bin/file /bin/chmod /sdb/anom/vtebuild/fspem/build/env/linux/find_secfs_mod /usr/bin/objdump /usr/bin/ld /sdb/anom/vtebuild/_obj_pem_64_perf_vor_klinux_5.4.0-48-generic/mk/process_build_info.pl /sdb/anom/vtebuild/_obj_fspem_64_perf_vor_ulinux_ubuntu20/apps/tools/buildsign /bin/tar /usr/bin/cc /sdb/anom/vtebuild/_obj_pem_64_perf_vor_ulinux_ubuntu20/mk/chkmsgs.pl /usr/bin/dh_prep /bin/mv /usr/bin/xz /usr/bin/dpkg-shlibdeps /usr/bin/objcopy /usr/bin/rpm2cpio /usr/bin/uniq /usr/bin/strip /usr/bin/dh_installdocs /usr/bin/du /bin/chown /usr/bin/awk /bin/ls /sdb/anom/vtebuild/_obj_pem_64_perf_vor_ulinux_ubuntu20/mk/replacer.pl /usr/bin/dpkg-deb /usr/bin/dh_builddeb ]
      audit-group-pset-1
        [ /bin/mount /bin/df /bin/chmod /usr/bin/make /bin/bash /bin/sh /usr/bin/fakeroot /usr/bin/updatedb.mlocate /bin/ls ]

    Resource sets:
      audit-rset-0
        [ /sdb/anom* ]

    Security rules:
      Rule 0
        User set     audit-root-uset-1
        Process set  audit-group-pset-1
        Resource set audit-rset-0
        Action       d_chg_att,d_rd_att,d_rd_sec,f_rd,d_rd
        Effect       permit,applykey
      Rule 1
        User set     audit-uset-0
        Process set  audit-group-pset-0
        Resource set audit-rset-0
        Action       f_ren,d_chg_att,f_rm,d_rmdir,f_cre,d_rd_att,f_chg_sec,write,f_rd_sec,d_rd_sec,f_rd_att,f_chg_att,f_wr,f_wr_app,f_rd,d_mkdir,d_rd
        Effect       permit,applykey

Policies can be viewed based on users or processes. By default, it is user-based.

    ./lmpb --logdir /home/logs/logs/ubu0/ policy show --type user

The output of policy show in this case will be sorted, based on user sets. This is the default setting for policy show command.

    ./lmpb --logdir /home/logs/logs/ubu0/ policy show --type process

The output of policy show in this case will be sorted, based on process sets.

**Sample Output**

    Learn mode updates for policy audit:

    User sets:
      audit-uset-0
        [ uset ]
      audit-root-uset-1
        [ root ]

    Process sets:
    …
      audit-cc1-pset-10
        [ /usr/lib/gcc/x86_64-linux-gnu/9/cc1 ]
      audit-fixdep-pset-11
        [ /sdb/anom/vtebuild/_obj_fspem_64_perf_vor_klinux_5.4.0-48-generic/build/env/linux/5.4.0-48-generic/build/scripts/basic/fixdep ]
    …
    Resource sets:
    …
      audit-rset-10
        [ /sdb/anom/vtebuild/fspem* ]
      audit-rset-11
        [ /sdb/anom/vtebuild/_obj_fspem_64_perf_vor_klinux_5.4.0-48-generic/agent* ]
    …
    Security rules:
    …
      Rule 10
        User set     audit-uset-0
        Process set  audit-which-pset-26
        Resource set audit-rset-2
        Action       d_rd_att
        Effect       permit,applykey
      Rule 11
        User set     audit-root-uset-1
        Process set  audit-ls-pset-57
        Resource set audit-rset-0
        Action       d_rd_att,d_rd,d_rd_sec
        Effect       permit,applykey
    …

## Uploading Policy to CipherTrust Manager

To upload the policy to the CipherTrust Manager, run the command:

    ./lmpb --logdir /home/logs/logs/ora policy upload --policy-name LEARMODE --type user --upload-name learn-mode-policy --cmaddr IP-ADDR-OF-CM --username admin --password PASSWORD

The above command will upload a policy to the CipherTrust Manager with modifications on top of the  original policy suggested by the Learn Mode policy builder tool. Note that the above command will fail if the original policy is not found on the specified CipherTrust Manager.