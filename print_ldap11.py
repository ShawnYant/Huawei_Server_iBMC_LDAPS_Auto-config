import sys
sys.path.insert(0, r'c:\Users\yangyi\Desktop')
import IBMCConfig_New
# 填写你要测试的地址和凭据
ip = '输入你的IP地址'
print('logging in as <用户名>/<密码>')
token = IBMCConfig_New.login(ip, '输入你的用户名', '输入你的密码')
print('token ->', token)
IBMCConfig_New.get_ldap_controller_details(ip, token)
