import sys
sys.path.insert(0, r'c:\Users\yangyi\Desktop')
import IBMCConfig_New
ip = '172.25.254.11'
print('logging in as Administrator/Cug#hk2024aicc')
token = IBMCConfig_New.login(ip, 'Administrator', 'Cug#hk2024aicc')
print('token ->', token)
IBMCConfig_New.get_ldap_controller_details(ip, token)
