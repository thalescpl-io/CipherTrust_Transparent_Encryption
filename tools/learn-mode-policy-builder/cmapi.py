import json
import requests
import urllib3

from requests import RequestException


disable_cert_warnings = True

cmtoken = None


class CMCommandException(RequestException):
    pass


class CMToken:
    def __init__(self, ip, user, password, domain):
        try:
            if disable_cert_warnings:
                urllib3.disable_warnings()
            self.ip = ip
            r = requests.post(url=f'https://{self.ip}/api/v1/auth/tokens/',
                              data={'grant_type':'password',
                                    'username':user,
                                    'password':password},
                              verify=False if disable_cert_warnings else True)
            if r:
                self.jwt = r.json()['jwt']
            else:
                r.raise_for_status()
        except RequestException as re:
            raise CMCommandException(re)


def cmapi_init(cmip:str, cmuser:str, cmpass:str, cmdomain:str):
    global cmtoken

    try:
        cmtoken = CMToken(cmip, cmuser, cmpass, cmdomain)
    except CMCommandException as e:
        print(f'Failed to connect to CM {cmip}')
        print(e)
        return False
    return True


class CMTEGetCommand:
    def __init__(self, cmd:str):
        try:
            r = requests.get(url=f'https://{cmtoken.ip}/api/v1/transparent-encryption/{cmd}',
                             headers={'Authorization': f'Bearer {cmtoken.jwt}'},
                             verify=False if disable_cert_warnings else True)
            if r:
                self.out = r.json()['resources']
            else:
                r.raise_for_status()
        except RequestException as re:
            raise CMCommandException(re)


class CMTEPostCommand:
    def __init__(self, cmd:str, json_data):
        try:
            r = requests.post(url=f'https://{cmtoken.ip}/api/v1/transparent-encryption/{cmd}',
                              headers={'Authorization': f'Bearer {cmtoken.jwt}'},
                              json=json_data,
                              verify=False if disable_cert_warnings else True)
            if r:
                self.out = r.json()
            else:
                r.raise_for_status()
        except RequestException as re:
            raise CMCommandException(re)


class CMTEPatchCommand:
    def __init__(self, cmd:str, json_data):
        try:
            r = requests.patch(url=f'https://{cmtoken.ip}/api/v1/transparent-encryption/{cmd}',
                               headers={'Authorization': f'Bearer {cmtoken.jwt}'},
                               json=json_data,
                               verify=False if disable_cert_warnings else True)
            if r:
                self.out = r.json()
            else:
                r.raise_for_status()
        except RequestException as re:
            raise CMCommandException(re)


class CMTEDeleteCommand:
    def __init__(self, cmd:str):
        try:
            r = requests.delete(url=f'https://{cmtoken.ip}/api/v1/transparent-encryption/{cmd}',
                               headers={'Authorization': f'Bearer {cmtoken.jwt}'},
                               verify=False if disable_cert_warnings else True)
            if r:
                #self.out = r.json()
                pass
            else:
                r.raise_for_status()
        except RequestException as re:
            raise CMCommandException(re)


class CMLoadPolicy(CMTEGetCommand):
    def __init__(self, policy_name:str):
        cmd=f'policies/?skip=0&limit=100&name={policy_name}&sort=updatedAt'
        super(CMLoadPolicy, self).__init__(cmd)
        assert len(self.out) <= 1
        if len(self.out) == 1:
            self.out = self.out[0]
        else:
            raise CMCommandException('Policy not found on CM')

class CMLoadSecurityRules(CMTEGetCommand):
    def __init__(self, policy_name:str):
        cmd=f'policies/{policy_name}/securityrules/?skip=0&limit=100'
        super(CMLoadSecurityRules, self).__init__(cmd)

class CMLoadKeyRules(CMTEGetCommand):
    def __init__(self, policy_name:str):
        cmd=f'policies/{policy_name}/keyrules/?skip=0&limit=100'
        super(CMLoadKeyRules, self).__init__(cmd)

class CMLoadUserSet(CMTEGetCommand):
    def __init__(self, set_name:str):
        cmd=f'usersets/?skip=0&limit=250&name={set_name}&sort=updatedAt'
        super(CMLoadUserSet, self).__init__(cmd)
        assert len(self.out) == 1
        self.out = self.out[0]

class CMLoadProcessSet(CMTEGetCommand):
    def __init__(self, set_name:str):
        cmd=f'processsets/?skip=0&limit=250&name={set_name}&sort=updatedAt'
        super(CMLoadProcessSet, self).__init__(cmd)
        assert len(self.out) == 1
        self.out = self.out[0]

class CMLoadResourceSet(CMTEGetCommand):
    def __init__(self, set_name:str):
        cmd=f'resourcesets/?skip=0&limit=250&name={set_name}&sort=updatedAt'
        super(CMLoadResourceSet, self).__init__(cmd)
        assert len(self.out) == 1
        self.out = self.out[0]

class CMUploadResourceSet(CMTEPostCommand):
    def __init__(self, set_data):
        cmd=f'resourcesets/'
        super(CMUploadResourceSet, self).__init__(cmd, set_data)

class CMUploadProcessSet(CMTEPostCommand):
    def __init__(self, set_data):
        cmd=f'processsets/'
        super(CMUploadProcessSet, self).__init__(cmd, set_data)

class CMUploadUserSet(CMTEPostCommand):
    def __init__(self, set_data):
        cmd=f'usersets/'
        super(CMUploadUserSet, self).__init__(cmd, set_data)

class CMUploadPolicy(CMTEPostCommand):
    def __init__(self, policy_data):
        cmd=f'policies/'
        super(CMUploadPolicy, self).__init__(cmd, policy_data)

class CMUploadSecurityRule(CMTEPostCommand):
    def __init__(self, policy_name:str, secrule_data):
        cmd=f'policies/{policy_name}/securityrules/'
        super(CMUploadSecurityRule, self).__init__(cmd, secrule_data)

class CMUpdateSecurityRule(CMTEPatchCommand):
    def __init__(self, policy_name:str, secrule_data):
        secrule_id = secrule_data['id']
        cmd=f'policies/{policy_name}/securityrules/{secrule_id}/'
        super(CMUpdateSecurityRule, self).__init__(cmd, secrule_data)

class CMDeleteSecurityRule(CMTEDeleteCommand):
    def __init__(self, policy_name:str, secrule_id:str):
        cmd=f'policies/{policy_name}/securityrules/{secrule_id}/'
        super(CMDeleteSecurityRule, self).__init__(cmd)

class CMDeleteResourceSet(CMTEDeleteCommand):
    def __init__(self, set_id:str):
        cmd=f'resourcesets/{set_id}/'
        super(CMDeleteResourceSet, self).__init__(cmd)

class CMDeleteProcessSet(CMTEDeleteCommand):
    def __init__(self, set_id:str):
        cmd=f'processsets/{set_id}/'
        super(CMDeleteProcessSet, self).__init__(cmd)

class CMDeleteUserSet(CMTEDeleteCommand):
    def __init__(self, set_id:str):
        cmd=f'usersets/{set_id}/'
        super(CMDeleteUserSet, self).__init__(cmd)

